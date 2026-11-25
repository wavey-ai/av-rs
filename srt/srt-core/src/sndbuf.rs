//! Sender ring indexed by sequence number, and the LiveCC-style pacer
//! (spec 7.1, 7.2, 7.4, 7.6).

use crate::packet::{DataHeader, Position, HDR_LEN};
use crate::pool::{Pool, NONE};
use crate::seq::{msgno_inc, seq_inc, seq_lt, seq_off};

#[derive(Clone, Copy)]
struct Slot {
    idx: u32,
    len: u16,
    /// Origin time, us on the local clock.
    origin_us: i64,
    /// Last (re)transmission, us on the local clock (`i64::MIN`: not sent).
    last_tx_us: i64,
    /// Retransmissions so far.
    rexmits: u16,
}

const EMPTY: Slot = Slot {
    idx: NONE,
    len: 0,
    origin_us: 0,
    last_tx_us: i64::MIN,
    rexmits: 0,
};

pub(crate) struct SndBuf {
    mask: u32,
    cap: u32,
    slots: Vec<Slot>,
    pool: Pool,
    /// Oldest sequence not acknowledged (or dropped).
    pub una: u32,
    /// Next sequence to transmit for the first time.
    pub next_send: u32,
    /// Next sequence to assign.
    pub next_seq: u32,
    pub next_msgno: u32,
}

pub(crate) enum PushError {
    Full,
}

impl SndBuf {
    pub fn new(cap_pkts: u32, max_payload: usize, isn: u32) -> SndBuf {
        let ring = cap_pkts.max(32).next_power_of_two();
        SndBuf {
            mask: ring - 1,
            cap: cap_pkts.max(32),
            slots: vec![EMPTY; ring as usize],
            pool: Pool::new(HDR_LEN + max_payload, cap_pkts.max(32)),
            una: isn,
            next_send: isn,
            next_seq: isn,
            next_msgno: 1,
        }
    }

    pub fn capacity(&self) -> u32 {
        self.cap
    }

    /// Packets held (sent-unacknowledged plus not yet sent).
    pub fn len(&self) -> u32 {
        seq_off(self.una, self.next_seq) as u32
    }

    /// Packets assigned but not yet transmitted.
    pub fn unsent(&self) -> u32 {
        seq_off(self.next_send, self.next_seq) as u32
    }

    /// Packets in flight (sent, not acknowledged).
    pub fn in_flight(&self) -> u32 {
        seq_off(self.una, self.next_send) as u32
    }

    pub fn allocated_slots(&self) -> u32 {
        self.pool.allocated()
    }

    /// Store one message as one packet; returns its sequence.
    pub fn push(&mut self, payload: &[u8], timestamp: u32, origin_us: i64, dst: u32) -> Result<u32, PushError> {
        if self.len() >= self.cap {
            return Err(PushError::Full);
        }
        let idx = self.pool.alloc().ok_or(PushError::Full)?;
        let seq = self.next_seq;
        let msgno = self.next_msgno;
        let b = self.pool.get_mut(idx);
        DataHeader {
            seq,
            position: Position::Solo,
            in_order: false,
            key: 0,
            rexmit: false,
            msgno,
            timestamp,
            dst,
        }
        .encode(b);
        b[HDR_LEN..HDR_LEN + payload.len()].copy_from_slice(payload);
        self.slots[(seq & self.mask) as usize] = Slot {
            idx,
            len: payload.len() as u16,
            origin_us,
            last_tx_us: i64::MIN,
            rexmits: 0,
        };
        self.next_seq = seq_inc(seq);
        self.next_msgno = msgno_inc(msgno);
        Ok(seq)
    }

    /// The encoded packet (header + payload) of a held sequence.
    pub fn packet(&self, seq: u32) -> Option<&[u8]> {
        let s = &self.slots[(seq & self.mask) as usize];
        if s.idx == NONE || !self.holds(seq) {
            return None;
        }
        Some(&self.pool.get(s.idx)[..HDR_LEN + s.len as usize])
    }

    /// Record a (re)transmission of a held sequence.
    #[inline]
    pub fn mark_sent(&mut self, seq: u32, now_us: i64) {
        self.slots[(seq & self.mask) as usize].last_tx_us = now_us;
    }

    /// Retransmissions of a held sequence so far.
    #[inline]
    pub fn rexmits(&self, seq: u32) -> u16 {
        self.slots[(seq & self.mask) as usize].rexmits
    }

    /// Count one retransmission of a held sequence; returns the new count.
    #[inline]
    pub fn count_rexmit(&mut self, seq: u32) -> u16 {
        let s = &mut self.slots[(seq & self.mask) as usize];
        s.rexmits = s.rexmits.saturating_add(1);
        s.rexmits
    }

    /// Origin time of a held sequence.
    #[inline]
    pub fn origin_us(&self, seq: u32) -> i64 {
        self.slots[(seq & self.mask) as usize].origin_us
    }

    /// Last (re)transmission time of a held sequence.
    #[inline]
    pub fn last_tx_us(&self, seq: u32) -> i64 {
        self.slots[(seq & self.mask) as usize].last_tx_us
    }

    /// Whether `seq` is held and was sent at least once.
    #[inline]
    pub fn holds_sent(&self, seq: u32) -> bool {
        let o = seq_off(self.una, seq);
        o >= 0 && o < seq_off(self.una, self.next_send)
    }

    pub fn holds(&self, seq: u32) -> bool {
        let o = seq_off(self.una, seq);
        o >= 0 && (o as u32) < self.len()
    }

    /// Origin time of the oldest held packet.
    pub fn oldest_origin_us(&self) -> Option<i64> {
        (self.len() > 0).then(|| self.slots[(self.una & self.mask) as usize].origin_us)
    }

    fn release_head(&mut self) -> usize {
        let i = (self.una & self.mask) as usize;
        let s = self.slots[i];
        if s.idx != NONE {
            self.pool.free(s.idx);
        }
        self.slots[i] = EMPTY;
        self.una = seq_inc(self.una);
        s.len as usize
    }

    /// Acknowledge everything before `seq` (`seq` <= next_send). Returns
    /// packets released.
    pub fn ack(&mut self, seq: u32) -> u32 {
        let mut n = 0;
        while seq_lt(self.una, seq) && self.una != self.next_send {
            self.release_head();
            n += 1;
        }
        n
    }

    /// Drop every held packet with origin before `threshold_us` (spec 7.6);
    /// returns (packets, payload bytes, packets that were never sent). The
    /// dropped sequences are `old una ..` the new `una`.
    pub fn drop_older_than(&mut self, threshold_us: i64) -> (u32, u64, u32) {
        let (mut n, mut bytes, mut unsent) = (0u32, 0u64, 0u32);
        while self.len() > 0 && self.slots[(self.una & self.mask) as usize].origin_us < threshold_us {
            if self.una == self.next_send {
                self.next_send = seq_inc(self.next_send);
                unsent += 1;
            }
            bytes += self.release_head() as u64;
            n += 1;
        }
        (n, bytes, unsent)
    }
}

/// Inter-packet pacing as LiveCC: (payload + 44) / max_bw per packet, with a
/// short burst allowance so batching and timer granularity do not cost rate.
pub(crate) struct Pacer {
    /// Bytes per second.
    rate: f64,
    /// Next send time, ns on the local clock.
    next_ns: i64,
    burst_ns: i64,
    // input-rate measurement (max_bw = 0, input_bw = 0)
    measure: bool,
    overhead_pct: u32,
    min_input: f64,
    win_start_ns: i64,
    win_bytes: u64,
    first_window: bool,
}

impl Pacer {
    pub fn new(fixed: Option<f64>, overhead_pct: u32, min_input: f64, now_ns: i64) -> Pacer {
        Pacer {
            rate: fixed.unwrap_or(crate::config::BW_INFINITE as f64),
            next_ns: now_ns,
            burst_ns: 1_000_000,
            measure: fixed.is_none(),
            overhead_pct,
            min_input,
            win_start_ns: now_ns,
            win_bytes: 0,
            first_window: true,
        }
    }

    pub fn rate(&self) -> f64 {
        self.rate
    }

    /// Account application input (only used when measuring the input rate).
    pub fn on_input(&mut self, bytes: usize, now_ns: i64) {
        if !self.measure {
            return;
        }
        self.win_bytes += bytes as u64 + crate::packet::PKT_OVERHEAD as u64;
        let span = now_ns - self.win_start_ns;
        // libsrt samples the input rate over 1 s (500 ms for the first)
        if span >= 1_000_000_000 || (self.first_window && span >= 500_000_000) {
            self.first_window = false;
            let r = (self.win_bytes as f64 * 1e9 / span as f64).max(self.min_input);
            self.rate = r * (100 + self.overhead_pct) as f64 / 100.0;
            self.win_start_ns = now_ns;
            self.win_bytes = 0;
        }
    }

    #[inline]
    pub fn ready(&mut self, now_ns: i64) -> bool {
        if self.next_ns < now_ns - self.burst_ns {
            self.next_ns = now_ns - self.burst_ns;
        }
        self.next_ns <= now_ns
    }

    #[inline]
    pub fn charge(&mut self, wire_bytes: usize) {
        self.next_ns += (wire_bytes as f64 * 1e9 / self.rate) as i64;
    }

    pub fn next_ns(&self) -> i64 {
        self.next_ns
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn push_ack_and_wrap() {
        let isn = crate::seq::SEQ_MAX - 2;
        let mut b = SndBuf::new(32, 1316, isn);
        for i in 0..32u32 {
            let s = b.push(&[i as u8; 10], i, i as i64, 7).ok().unwrap();
            assert_eq!(s, crate::seq::seq_add(isn, i as i32));
        }
        assert!(b.push(&[0; 10], 0, 0, 7).is_err());
        let p = b.packet(isn).unwrap();
        let h = DataHeader::decode(p);
        assert_eq!((h.seq, h.msgno, h.dst, h.position), (isn, 1, 7, Position::Solo));
        // nothing sent yet: ACK cannot release anything
        assert_eq!(b.ack(crate::seq::seq_add(isn, 5)), 0);
        b.next_send = crate::seq::seq_add(isn, 10);
        assert_eq!(b.ack(crate::seq::seq_add(isn, 5)), 5);
        assert_eq!(b.una, 2);
        assert!(b.packet(isn).is_none());
        assert_eq!(b.in_flight(), 5);
        // drop by origin: 5..=9 sent, 10.. unsent
        let (n, bytes, unsent) = b.drop_older_than(12);
        assert_eq!((n, bytes, unsent), (7, 70, 2));
        assert_eq!(b.next_send, b.una);
        assert_eq!(b.len(), 20);
    }

    #[test]
    fn pacer_input_rate_mode() {
        // MAXBW 0, INPUTBW 0: measured input x (1 + OHEADBW); first window 500 ms
        let mut p = Pacer::new(None, 25, 0.0, 0);
        assert_eq!(p.rate(), crate::config::BW_INFINITE as f64);
        let mut t = 0i64;
        // 1000 x 956 B payload (+44) per 500 ms = 2 MB/s
        for _ in 0..1001 {
            p.on_input(956, t);
            t += 500_000;
        }
        assert!((p.rate() - 2_500_000.0).abs() < 10_000.0, "{}", p.rate());
        // explicit INPUTBW via Config: 1 MB/s x 1.25
        let c = crate::Config {
            max_bw: 0,
            input_bw: 1_000_000,
            ..crate::Config::default()
        };
        assert_eq!(c.fixed_pacing_rate(), Some(1_250_000.0));
        let c = crate::Config {
            max_bw: 3_000_000,
            ..crate::Config::default()
        };
        assert_eq!(c.fixed_pacing_rate(), Some(3_000_000.0));
        assert_eq!(crate::Config::default().fixed_pacing_rate(), Some(125_000_000.0));
    }

    #[test]
    fn pacer_rate_and_burst() {
        let mut p = Pacer::new(Some(1_000_000.0), 25, 0.0, 0); // 1 MB/s
        let mut now = 10_000_000i64;
        // after idle, up to 1 ms of burst (1000 bytes)
        let mut sent = 0;
        while p.ready(now) {
            p.charge(100);
            sent += 1;
        }
        assert_eq!(sent, 11);
        now += 1_000_000; // 1 ms later: 10 more
        let mut sent = 0;
        while p.ready(now) {
            p.charge(100);
            sent += 1;
        }
        assert_eq!(sent, 10);
    }
}
