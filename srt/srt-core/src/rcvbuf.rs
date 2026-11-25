//! Receiver ring indexed by sequence number (spec 6.1, 6.2, 6.9).
//!
//! `base` is the next sequence to deliver, `ack` the first sequence not
//! received contiguously, `highest` the highest received. When the head is
//! missing, `hint` caches the first present packet after it, so the TSBPD
//! decision (deliver, wait or drop the gap) is O(1) per call; the cache is
//! rebuilt by a scan over the gap only when a new gap reaches the head.

use crate::pool::{Pool, NONE};
use crate::seq::{seq_dec, seq_inc, seq_le, seq_lt, seq_off};

#[derive(Clone, Copy)]
struct Slot {
    idx: u32,
    len: u16,
    rexmit: bool,
    timestamp: u32,
    msgno: u32,
}

const EMPTY: Slot = Slot {
    idx: NONE,
    len: 0,
    rexmit: false,
    timestamp: 0,
    msgno: 0,
};

/// Result of an insertion.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Insert {
    /// Stored; `loss` is a newly detected gap (first, last) before it.
    Stored {
        loss: Option<(u32, u32)>,
        filled_hole: bool,
    },
    /// Before the delivery point: already delivered or dropped.
    Belated,
    Duplicate,
    /// Beyond the buffer.
    TooFar,
}

/// Head packet metadata.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HeadInfo {
    pub seq: u32,
    pub timestamp: u32,
}

pub(crate) struct RcvBuf {
    mask: u32,
    cap: u32,
    slots: Vec<Slot>,
    pool: Pool,
    pub base: u32,
    pub ack: u32,
    pub highest: u32,
    count: u32,
    hint: Option<u32>,
}

/// A packet taken from the head; its payload stays readable (`payload`)
/// until the next mutation.
pub(crate) struct Popped {
    pub seq: u32,
    pub idx: u32,
    pub len: u16,
    pub timestamp: u32,
    pub msgno: u32,
    pub rexmit: bool,
}

impl RcvBuf {
    pub fn new(cap_pkts: u32, max_payload: usize, isn: u32) -> RcvBuf {
        let cap = cap_pkts.max(32);
        let ring = cap.next_power_of_two();
        RcvBuf {
            mask: ring - 1,
            cap,
            slots: vec![EMPTY; ring as usize],
            pool: Pool::new(max_payload, cap),
            base: isn,
            ack: isn,
            highest: seq_dec(isn),
            count: 0,
            hint: None,
        }
    }

    pub fn capacity(&self) -> u32 {
        self.cap
    }

    /// Packets present in the buffer.
    pub fn len(&self) -> u32 {
        self.count
    }

    /// Room to advertise in ACKs: capacity minus packets acknowledged but
    /// not yet delivered.
    pub fn available(&self) -> u32 {
        self.cap.saturating_sub(seq_off(self.base, self.ack).max(0) as u32)
    }

    pub fn allocated_slots(&self) -> u32 {
        self.pool.allocated()
    }

    #[inline]
    fn present(&self, seq: u32) -> bool {
        self.slots[(seq & self.mask) as usize].idx != NONE
    }

    pub fn insert(&mut self, seq: u32, payload: &[u8], timestamp: u32, msgno: u32, rexmit: bool) -> Insert {
        let off = seq_off(self.base, seq);
        if off < 0 {
            return Insert::Belated;
        }
        if off as u32 >= self.cap {
            return Insert::TooFar;
        }
        let si = (seq & self.mask) as usize;
        if self.slots[si].idx != NONE {
            return Insert::Duplicate;
        }
        let Some(idx) = self.pool.alloc() else { return Insert::TooFar };
        self.pool.get_mut(idx)[..payload.len()].copy_from_slice(payload);
        self.slots[si] = Slot {
            idx,
            len: payload.len() as u16,
            rexmit,
            timestamp,
            msgno,
        };
        self.count += 1;
        let mut loss = None;
        let mut filled_hole = false;
        let h = seq_off(self.highest, seq);
        if h > 0 {
            if h > 1 {
                loss = Some((seq_inc(self.highest), seq_dec(seq)));
            }
            self.highest = seq;
        } else {
            filled_hole = true;
        }
        if seq == self.ack {
            self.advance_ack();
        }
        if seq != self.base && self.hint.map_or(true, |p| seq_lt(seq, p)) {
            self.hint = Some(seq);
        }
        Insert::Stored { loss, filled_hole }
    }

    fn advance_ack(&mut self) {
        while seq_le(self.ack, self.highest) && self.present(self.ack) {
            self.ack = seq_inc(self.ack);
        }
    }

    /// The head packet, if present.
    pub fn head(&self) -> Option<HeadInfo> {
        let s = &self.slots[(self.base & self.mask) as usize];
        (s.idx != NONE).then_some(HeadInfo {
            seq: self.base,
            timestamp: s.timestamp,
        })
    }

    /// `seq` is in the window (not delivered or dropped, not beyond the
    /// highest received) and absent.
    #[inline]
    pub fn is_missing(&self, seq: u32) -> bool {
        seq_le(self.base, seq) && seq_le(seq, self.highest) && !self.present(seq)
    }

    /// The peer has sent up to `seq` (a FEC packet carries the sequence of
    /// the data packet before it): the gap after the highest received, if
    /// any, becomes known. Returns it (first, last).
    pub fn note_sent_upto(&mut self, seq: u32) -> Option<(u32, u32)> {
        let h = seq_off(self.highest, seq);
        if h <= 0 || seq_off(self.base, seq) as u32 >= self.cap {
            return None;
        }
        let gap = (seq_inc(self.highest), seq);
        self.highest = seq;
        Some(gap)
    }

    /// First present packet after a missing head.
    pub fn first_present(&self) -> Option<HeadInfo> {
        if self.count == 0 {
            return None;
        }
        let p = self.hint?;
        let s = &self.slots[(p & self.mask) as usize];
        Some(HeadInfo {
            seq: p,
            timestamp: s.timestamp,
        })
    }

    fn rebuild_hint(&mut self) {
        self.hint = None;
        if self.count == 0 || self.present(self.base) {
            return;
        }
        let mut s = seq_inc(self.base);
        while seq_le(s, self.highest) {
            if self.present(s) {
                self.hint = Some(s);
                return;
            }
            s = seq_inc(s);
        }
    }

    /// Take the head packet (must be present).
    pub fn pop(&mut self) -> Option<Popped> {
        let si = (self.base & self.mask) as usize;
        let s = self.slots[si];
        if s.idx == NONE {
            return None;
        }
        self.slots[si] = EMPTY;
        self.pool.free(s.idx);
        self.count -= 1;
        let seq = self.base;
        self.base = seq_inc(seq);
        if seq_lt(self.ack, self.base) {
            self.ack = self.base;
            self.advance_ack();
        }
        if seq_lt(self.highest, seq) {
            self.highest = seq;
        }
        if self.hint == Some(self.base) || !self.present(self.base) {
            self.rebuild_hint();
        }
        Some(Popped {
            seq,
            idx: s.idx,
            len: s.len,
            timestamp: s.timestamp,
            msgno: s.msgno,
            rexmit: s.rexmit,
        })
    }

    /// Payload of a just-popped packet (valid until the next mutation).
    pub fn payload(&self, p: &Popped) -> &[u8] {
        &self.pool.get(p.idx)[..p.len as usize]
    }

    /// Drop the missing packets before `seq` (the first present packet after
    /// a missing head). Returns how many were dropped.
    pub fn drop_until(&mut self, seq: u32) -> u32 {
        let n = seq_off(self.base, seq);
        if n <= 0 {
            return 0;
        }
        // all between base and the first present packet are missing
        self.base = seq;
        if seq_lt(self.ack, self.base) {
            self.ack = self.base;
            self.advance_ack();
        }
        if seq_lt(self.highest, seq_dec(seq)) {
            self.highest = seq_dec(seq);
        }
        self.rebuild_hint();
        n as u32
    }

    /// Restart the window at `base` (spec 6.2 step 3, done better than
    /// libsrt, which breaks the connection): the buffer is empty and a
    /// packet arrived beyond its capacity, after an outage or a sender-side
    /// drop longer than the buffer. Everything before `base` is given up.
    pub fn resync(&mut self, base: u32) {
        debug_assert_eq!(self.count, 0);
        self.base = base;
        self.ack = base;
        self.highest = seq_dec(base);
        self.hint = None;
    }

    /// The sender will never send `..=last` (DROPREQ): move the delivery
    /// point over the absent packets at the head, up to `last` or the first
    /// present packet. Returns how many were skipped.
    pub fn skip_absent(&mut self, last: u32) -> u32 {
        if !seq_le(self.base, last) || self.present(self.base) {
            return 0;
        }
        let target = match self.first_present() {
            Some(p) if seq_le(p.seq, last) => p.seq,
            _ => seq_inc(last),
        };
        // never past the window (highest stays below base + capacity)
        let target = if seq_off(self.base, target) as u32 > self.cap {
            crate::seq::seq_add(self.base, self.cap as i32)
        } else {
            target
        };
        self.drop_until(target)
    }

    /// The sender dropped up to `last` (DROPREQ) beyond what we received:
    /// the highest "received" moves there (within the window), so the next
    /// packet does not report the dropped range as a new loss.
    pub fn note_dropped_upto(&mut self, last: u32) {
        if !seq_lt(self.highest, last) {
            return;
        }
        let max = crate::seq::seq_add(self.base, self.cap as i32 - 1);
        self.highest = if seq_lt(max, last) { max } else { last };
    }

    /// Timestamp span from the first present packet to the highest, us.
    pub fn timestamp_span_us(&self) -> u32 {
        let first = self.head().or_else(|| self.first_present());
        let last = &self.slots[(self.highest & self.mask) as usize];
        match first {
            Some(f) if last.idx != NONE => last.timestamp.wrapping_sub(f.timestamp),
            _ => 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::seq::SEQ_MAX;

    fn ins(b: &mut RcvBuf, seq: u32) -> Insert {
        b.insert(seq, &seq.to_be_bytes(), seq.wrapping_mul(10), 1, false)
    }

    #[test]
    fn in_order_ack_and_pop() {
        let mut b = RcvBuf::new(64, 1456, 100);
        for s in 100..110 {
            assert_eq!(
                ins(&mut b, s),
                Insert::Stored {
                    loss: None,
                    filled_hole: false
                }
            );
        }
        assert_eq!(b.ack, 110);
        assert_eq!(b.available(), 64 - 10);
        let p = b.pop().unwrap();
        assert_eq!(p.seq, 100);
        assert_eq!(b.payload(&p), &100u32.to_be_bytes());
        assert_eq!(b.available(), 64 - 9);
        assert_eq!(ins(&mut b, 100), Insert::Belated);
        assert_eq!(ins(&mut b, 105), Insert::Duplicate);
        assert_eq!(ins(&mut b, 101 + 64), Insert::TooFar);
    }

    #[test]
    fn gap_detection_hint_and_drop() {
        let isn = SEQ_MAX - 1;
        let mut b = RcvBuf::new(64, 1456, isn);
        assert!(matches!(ins(&mut b, isn), Insert::Stored { loss: None, .. }));
        // isn+1 (= SEQ_MAX) and 0 lost, 1 arrives
        assert_eq!(
            ins(&mut b, 1),
            Insert::Stored {
                loss: Some((SEQ_MAX, 0)),
                filled_hole: false
            }
        );
        assert_eq!(b.ack, SEQ_MAX);
        assert_eq!(
            ins(&mut b, 3),
            Insert::Stored {
                loss: Some((2, 2)),
                filled_hole: false
            }
        );
        b.pop().unwrap();
        assert!(b.head().is_none());
        assert_eq!(b.first_present().unwrap().seq, 1);
        // 0 arrives late: hint moves back to it
        assert_eq!(ins(&mut b, 0), Insert::Stored { loss: None, filled_hole: true });
        assert_eq!(b.first_present().unwrap().seq, 0);
        assert_eq!(b.drop_until(0), 1);
        assert_eq!(b.base, 0);
        assert_eq!(b.ack, 2);
        assert_eq!(b.pop().unwrap().seq, 0);
        assert_eq!(b.pop().unwrap().seq, 1);
        assert!(b.head().is_none());
        assert_eq!(b.first_present().unwrap().seq, 3);
        assert_eq!(b.drop_until(3), 1);
        assert_eq!(b.ack, 4);
        assert_eq!(b.pop().unwrap().seq, 3);
        assert_eq!(b.len(), 0);
        assert!(b.first_present().is_none());
    }

    #[test]
    fn resync_after_a_gap_beyond_capacity() {
        let isn = SEQ_MAX - 10;
        let mut b = RcvBuf::new(64, 1456, isn);
        for i in 0..5 {
            ins(&mut b, isn.wrapping_add(i) & SEQ_MAX);
        }
        while b.pop().is_some() {}
        assert_eq!(b.len(), 0);
        let far = (isn + 500) & SEQ_MAX;
        assert_eq!(ins(&mut b, far), Insert::TooFar);
        let nb = crate::seq::seq_add(far, -32);
        b.resync(nb);
        assert_eq!((b.base, b.ack, b.highest), (nb, nb, seq_dec(nb)));
        assert_eq!(
            ins(&mut b, far),
            Insert::Stored {
                loss: Some((nb, seq_dec(far))),
                filled_hole: false
            }
        );
        assert_eq!(
            ins(&mut b, seq_inc(far)),
            Insert::Stored {
                loss: None,
                filled_hole: false
            }
        );
        assert_eq!(b.first_present().unwrap().seq, far);
        assert_eq!(b.drop_until(far), 32);
        assert_eq!(b.pop().unwrap().seq, far);
    }

    #[test]
    fn dropreq_skips_absent_head_and_moves_highest() {
        let mut b = RcvBuf::new(64, 1456, 100);
        ins(&mut b, 100);
        ins(&mut b, 105);
        b.pop().unwrap();
        // 101..=104 missing; DROPREQ 101..=103: skip to 104
        assert_eq!(b.skip_absent(103), 3);
        assert_eq!((b.base, b.ack), (104, 104));
        // DROPREQ beyond the first present stops at it
        assert_eq!(b.skip_absent(110), 1);
        assert_eq!(b.base, 105);
        assert_eq!(b.skip_absent(110), 0); // head present
        assert_eq!(b.pop().unwrap().seq, 105);
        // empty: a DROPREQ for unsent packets beyond what we received
        b.note_dropped_upto(120);
        assert_eq!(b.highest, 120);
        assert_eq!(b.skip_absent(120), 15);
        assert_eq!((b.base, b.ack), (121, 121));
        assert_eq!(
            ins(&mut b, 121),
            Insert::Stored {
                loss: None,
                filled_hole: false
            }
        );
        // never beyond the window
        b.pop().unwrap();
        b.note_dropped_upto(10_000);
        assert_eq!(b.highest, 122 + 63);
        assert_eq!(b.skip_absent(10_000), 64);
        assert_eq!(b.base, 122 + 64);
    }
}
