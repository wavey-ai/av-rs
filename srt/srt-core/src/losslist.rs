//! Loss lists (spec 6.2-6.4, 7.5), both kept as ordered runs of sequences
//! in a ring (`VecDeque`) so the hot path never allocates once warmed up and
//! nothing scans the packet window:
//!
//! - `RcvLossList`: the receiver's holes, each with its own NAK schedule
//!   (spec 12 #4: first NAK at detection, re-NAK per hole from the measured
//!   repair time, stop at its delivery deadline). New holes are always past
//!   every existing one (they are found beyond the highest received), so
//!   they are appended; a repaired sequence is found by binary search.
//! - `SndLossList`: the sender's sequences to retransmit, merged runs,
//!   served lowest first.

use crate::seq::{seq_dec, seq_inc, seq_le, seq_lt, seq_off};
use std::collections::VecDeque;

/// "Never" for schedules.
pub(crate) const NEVER: i64 = i64::MAX;

/// One run of missing sequences on the receiver.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Hole {
    pub first: u32,
    pub last: u32,
    /// When the next NAK for this run is due (`NEVER`: not until released
    /// by the reorder tolerance, or past its deadline).
    pub next_nak_us: i64,
    /// When it was last NAKed (meaningful when `naks > 0`).
    pub last_nak_us: i64,
    pub naks: u32,
    pub detected_us: i64,
    /// Packets received (in total) when it was found, for LOSSMAXTTL.
    pub detected_at_pkt: u64,
    /// Delivery time of the packet that revealed it: TSBPD gives the run up
    /// then (it is dropped when the next present packet is due).
    pub deadline_us: i64,
}

impl Hole {
    #[inline]
    fn len(&self) -> u32 {
        (seq_off(self.first, self.last) + 1) as u32
    }
}

/// What `fill` found.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Filled {
    /// The run's NAK count and last NAK time before the fill.
    pub naks: u32,
    pub last_nak_us: i64,
    /// When the run was found missing.
    pub detected_us: i64,
}

#[derive(Default)]
pub(crate) struct RcvLossList {
    holes: VecDeque<Hole>,
    /// The last `waiting` holes are held back by the reorder tolerance
    /// (they are always a suffix: they are released in detection order).
    waiting: usize,
    /// Sequences in the list.
    seqs: u64,
    /// Lower bound of every scheduled `next_nak_us` (may be stale-early).
    next_due: i64,
}

impl RcvLossList {
    pub fn new() -> RcvLossList {
        RcvLossList {
            holes: VecDeque::with_capacity(256),
            waiting: 0,
            seqs: 0,
            next_due: NEVER,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.holes.is_empty()
    }

    /// Number of runs.
    pub fn runs(&self) -> usize {
        self.holes.len()
    }

    /// Number of missing sequences.
    pub fn seqs(&self) -> u64 {
        self.seqs
    }

    /// Earliest time a NAK may be due (a lower bound; `NEVER` if none).
    pub fn next_due(&self) -> i64 {
        self.next_due
    }

    /// The oldest hole still held by the reorder tolerance.
    pub fn oldest_waiting(&self) -> Option<&Hole> {
        if self.waiting == 0 {
            return None;
        }
        self.holes.get(self.holes.len() - self.waiting)
    }

    /// Append a new run (it must lie past every run in the list). With
    /// `wait`, it is held back until `release_waiting` lets it go.
    pub fn push(&mut self, mut h: Hole, wait: bool) {
        debug_assert!(self.holes.back().map_or(true, |b| seq_lt(b.last, h.first)));
        if wait {
            h.next_nak_us = NEVER;
            self.waiting += 1;
        } else {
            self.next_due = self.next_due.min(h.next_nak_us);
        }
        self.seqs += h.len() as u64;
        self.holes.push_back(h);
    }

    /// Release held runs whose reorder tolerance is over: `pkt_count`
    /// packets received in total, `ttl` packets allowed, `max_wait_us` time
    /// allowed. Returns how many were released (their NAK is due now).
    pub fn release_waiting(&mut self, now_us: i64, pkt_count: u64, ttl: u32, max_wait_us: i64) -> usize {
        let mut n = 0;
        while self.waiting > 0 {
            let i = self.holes.len() - self.waiting;
            let h = &mut self.holes[i];
            if pkt_count.saturating_sub(h.detected_at_pkt) >= ttl as u64 || now_us - h.detected_us >= max_wait_us {
                h.next_nak_us = now_us;
                self.next_due = self.next_due.min(now_us);
                self.waiting -= 1;
                n += 1;
            } else {
                break;
            }
        }
        n
    }

    /// Index of the run containing `seq`.
    fn find(&self, seq: u32) -> Option<usize> {
        let i = self.holes.partition_point(|h| seq_lt(h.last, seq));
        match self.holes.get(i) {
            Some(h) if seq_le(h.first, seq) => Some(i),
            _ => None,
        }
    }

    #[inline]
    fn is_waiting(&self, i: usize) -> bool {
        i >= self.holes.len() - self.waiting
    }

    /// `seq` arrived: take it out of its run (splitting the run if it was
    /// inside). Returns the run's NAK history, or None if it was not lost.
    pub fn fill(&mut self, seq: u32) -> Option<Filled> {
        let i = self.find(seq)?;
        let h = self.holes[i];
        let out = Filled {
            naks: h.naks,
            last_nak_us: h.last_nak_us,
            detected_us: h.detected_us,
        };
        self.seqs -= 1;
        if h.first == h.last {
            if self.is_waiting(i) {
                self.waiting -= 1;
            }
            self.holes.remove(i);
        } else if seq == h.first {
            self.holes[i].first = seq_inc(seq);
        } else if seq == h.last {
            self.holes[i].last = seq_dec(seq);
        } else {
            let waiting = self.is_waiting(i);
            let mut tail = h;
            tail.first = seq_inc(seq);
            self.holes[i].last = seq_dec(seq);
            self.holes.insert(i + 1, tail);
            if waiting {
                self.waiting += 1;
            }
        }
        Some(out)
    }

    /// The runs that start before `seq` (for a drop log).
    pub fn front_runs_before(&self, seq: u32) -> impl Iterator<Item = &Hole> {
        self.holes.iter().take_while(move |h| seq_lt(h.first, seq))
    }

    /// Forget every sequence before `seq` (delivered or dropped).
    /// Returns how many sequences were removed.
    pub fn remove_before(&mut self, seq: u32) -> u64 {
        let mut n = 0u64;
        while let Some(h) = self.holes.front_mut() {
            if seq_lt(h.last, seq) {
                n += h.len() as u64;
                self.holes.pop_front();
            } else {
                if seq_lt(h.first, seq) {
                    n += seq_off(h.first, seq) as u64;
                    h.first = seq;
                }
                break;
            }
        }
        self.waiting = self.waiting.min(self.holes.len());
        self.seqs -= n;
        n
    }

    /// Forget `first..=last` (the sender said it will not send them:
    /// DROPREQ). Returns how many sequences were removed.
    pub fn remove_range(&mut self, first: u32, last: u32) -> u64 {
        if seq_lt(last, first) {
            return 0;
        }
        let mut n = 0u64;
        let mut i = self.holes.partition_point(|h| seq_lt(h.last, first));
        while i < self.holes.len() {
            let h = self.holes[i];
            if seq_lt(last, h.first) {
                break;
            }
            let cut_first = if seq_lt(h.first, first) { first } else { h.first };
            let cut_last = if seq_lt(last, h.last) { last } else { h.last };
            n += (seq_off(cut_first, cut_last) + 1) as u64;
            let keep_head = seq_lt(h.first, cut_first);
            let keep_tail = seq_lt(cut_last, h.last);
            match (keep_head, keep_tail) {
                (false, false) => {
                    if self.is_waiting(i) {
                        self.waiting -= 1;
                    }
                    self.holes.remove(i);
                    continue;
                }
                (true, false) => self.holes[i].last = seq_dec(cut_first),
                (false, true) => self.holes[i].first = seq_inc(cut_last),
                (true, true) => {
                    let waiting = self.is_waiting(i);
                    let mut tail = h;
                    tail.first = seq_inc(cut_last);
                    self.holes[i].last = seq_dec(cut_first);
                    self.holes.insert(i + 1, tail);
                    if waiting {
                        self.waiting += 1;
                    }
                    i += 1;
                }
            }
            i += 1;
        }
        self.seqs -= n;
        n
    }

    /// The packet filter found `first..=last` unrebuildable: bring the
    /// first NAK of the not yet NAKed sequences in it forward to `now_us`
    /// (runs are split so the rest keep waiting for FEC). Returns how many
    /// sequences were released.
    pub fn release_range(&mut self, first: u32, last: u32, now_us: i64) -> u64 {
        if seq_lt(last, first) {
            return 0;
        }
        let mut n = 0u64;
        let mut i = self.holes.partition_point(|h| seq_lt(h.last, first));
        while i < self.holes.len() {
            let h = self.holes[i];
            if seq_lt(last, h.first) {
                break;
            }
            if h.naks > 0 || h.next_nak_us <= now_us || self.is_waiting(i) {
                i += 1;
                continue;
            }
            let cut_first = if seq_lt(h.first, first) { first } else { h.first };
            let cut_last = if seq_lt(last, h.last) { last } else { h.last };
            n += (seq_off(cut_first, cut_last) + 1) as u64;
            let mut mid = h;
            mid.first = cut_first;
            mid.last = cut_last;
            mid.next_nak_us = now_us;
            if seq_lt(h.first, cut_first) {
                self.holes[i].last = seq_dec(cut_first);
                i += 1;
                self.holes.insert(i, mid);
            } else {
                self.holes[i] = mid;
            }
            if seq_lt(cut_last, h.last) {
                let mut tail = h;
                tail.first = seq_inc(cut_last);
                self.holes.insert(i + 1, tail);
                i += 1;
            }
            i += 1;
        }
        if n > 0 {
            self.next_due = self.next_due.min(now_us);
        }
        n
    }

    /// The re-NAK interval shrank (first RTT sample, or the repair time
    /// fell): bring every NAKed run's next NAK forward to its last NAK +
    /// `interval_us`.
    pub fn reschedule(&mut self, interval_us: i64) {
        let n_ready = self.holes.len() - self.waiting;
        let mut next = NEVER;
        for h in self.holes.iter_mut().take(n_ready) {
            if h.naks > 0 && h.next_nak_us != NEVER {
                h.next_nak_us = h.next_nak_us.min(h.last_nak_us + interval_us);
            }
            next = next.min(h.next_nak_us);
        }
        self.next_due = next;
    }

    /// Collect the runs whose NAK is due by `now_us + slack_us` into `out`
    /// as (first, last), at most `max_words` NAK words (a single sequence
    /// is one word, a run two), and reschedule them at least `interval_us`
    /// later. Runs that could no longer be repaired before their deadline
    /// (`now + min_repair_us > deadline`) are not NAKed again.
    ///
    /// With `reserve_us` > 0 the re-NAKs a run still has time for are
    /// spread evenly up to `deadline - reserve_us` (the last moment a NAK
    /// can still bring the repair in time): the same number of attempts,
    /// but each one further from the previous repair, so a sender that
    /// suppresses requests arriving within about an RTT of its last copy
    /// (libsrt's RETRANSMITALGO=1, whose queueing behind new data adds to
    /// the RTT) does not swallow one.
    ///
    /// Returns the number of sequences listed and whether any run is a
    /// late attempt (NAKed before, or with no time for another round after
    /// this one). Also recomputes `next_due`.
    #[allow(clippy::too_many_arguments)]
    pub fn collect_due(
        &mut self,
        now_us: i64,
        slack_us: i64,
        interval_us: i64,
        min_repair_us: i64,
        reserve_us: i64,
        max_words: usize,
        out: &mut Vec<(u32, u32)>,
    ) -> (u64, bool) {
        out.clear();
        let mut words = 0usize;
        let mut seqs = 0u64;
        let mut late = false;
        let mut next = NEVER;
        let limit = now_us + slack_us;
        let n_ready = self.holes.len() - self.waiting;
        for h in self.holes.iter_mut().take(n_ready) {
            if h.next_nak_us <= limit {
                if h.naks > 0 && now_us + min_repair_us > h.deadline_us {
                    h.next_nak_us = NEVER;
                    continue;
                }
                let w = if h.first == h.last { 1 } else { 2 };
                if words + w > max_words {
                    // the rest stay due: the caller sends another NAK
                    next = next.min(h.next_nak_us);
                    continue;
                }
                words += w;
                out.push((h.first, h.last));
                seqs += h.len() as u64;
                let mut iv = interval_us;
                if reserve_us > 0 && h.deadline_us != NEVER && interval_us > 0 {
                    let room = h.deadline_us - reserve_us - now_us;
                    if room >= interval_us {
                        iv = room / (room / interval_us);
                    } else {
                        late = true; // no room for another round
                    }
                }
                late |= h.naks > 0;
                h.last_nak_us = now_us;
                h.naks += 1;
                h.next_nak_us = now_us + iv;
            }
            next = next.min(h.next_nak_us);
        }
        self.next_due = next;
        (seqs, late)
    }

    #[cfg(test)]
    fn snapshot(&self) -> Vec<(u32, u32)> {
        self.holes.iter().map(|h| (h.first, h.last)).collect()
    }
}

/// Sender loss list: merged, ordered runs of sequences to retransmit.
#[derive(Default)]
pub(crate) struct SndLossList {
    runs: VecDeque<(u32, u32)>,
}

impl SndLossList {
    pub fn new() -> SndLossList {
        SndLossList {
            runs: VecDeque::with_capacity(256),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.runs.is_empty()
    }

    pub fn runs(&self) -> usize {
        self.runs.len()
    }

    /// Add `first..=last`, merging with overlapping or adjacent runs.
    pub fn insert(&mut self, first: u32, last: u32) {
        if seq_lt(last, first) {
            return;
        }
        // fast path: NAKs mostly arrive in order
        if let Some(b) = self.runs.back_mut() {
            if seq_lt(b.1, first) {
                if seq_inc(b.1) == first {
                    b.1 = last;
                } else {
                    self.runs.push_back((first, last));
                }
                return;
            }
        } else {
            self.runs.push_back((first, last));
            return;
        }
        // first run that ends at or after first - 1
        let i = self.runs.partition_point(|r| seq_lt(seq_inc(r.1), first));
        if i == self.runs.len() || seq_lt(seq_inc(last), self.runs[i].0) {
            self.runs.insert(i, (first, last));
            return;
        }
        // merge into run i and absorb the following ones it now reaches
        let (mut f, mut l) = self.runs[i];
        if seq_lt(first, f) {
            f = first;
        }
        if seq_lt(l, last) {
            l = last;
        }
        while i + 1 < self.runs.len() && seq_le(self.runs[i + 1].0, seq_inc(l)) {
            let r = self.runs.remove(i + 1).unwrap();
            if seq_lt(l, r.1) {
                l = r.1;
            }
        }
        self.runs[i] = (f, l);
    }

    /// The lowest sequence, without taking it.
    pub fn peek(&self) -> Option<u32> {
        self.runs.front().map(|r| r.0)
    }

    /// Take the lowest sequence.
    pub fn pop(&mut self) -> Option<u32> {
        let r = self.runs.front_mut()?;
        let s = r.0;
        if r.0 == r.1 {
            self.runs.pop_front();
        } else {
            r.0 = seq_inc(r.0);
        }
        Some(s)
    }

    /// Forget every sequence before `seq` (acknowledged or dropped).
    pub fn remove_before(&mut self, seq: u32) {
        while let Some(r) = self.runs.front_mut() {
            if seq_lt(r.1, seq) {
                self.runs.pop_front();
            } else {
                if seq_lt(r.0, seq) {
                    r.0 = seq;
                }
                break;
            }
        }
    }

    #[cfg(test)]
    fn snapshot(&self) -> Vec<(u32, u32)> {
        self.runs.iter().copied().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::seq::{seq_add, SEQ_MAX};

    fn hole(first: u32, last: u32, t: i64) -> Hole {
        Hole {
            first,
            last,
            next_nak_us: t,
            last_nak_us: 0,
            naks: 0,
            detected_us: t,
            detected_at_pkt: 0,
            deadline_us: t + 100_000,
        }
    }

    #[test]
    fn rcv_fill_splits_and_removes() {
        let mut l = RcvLossList::new();
        l.push(hole(10, 14, 0), false);
        l.push(hole(20, 20, 0), false);
        assert_eq!(l.seqs(), 6);
        assert!(l.fill(9).is_none());
        assert!(l.fill(15).is_none());
        assert!(l.fill(12).is_some());
        assert_eq!(l.snapshot(), vec![(10, 11), (13, 14), (20, 20)]);
        l.fill(10);
        l.fill(14);
        assert_eq!(l.snapshot(), vec![(11, 11), (13, 13), (20, 20)]);
        l.fill(20);
        l.fill(11);
        assert_eq!(l.snapshot(), vec![(13, 13)]);
        assert_eq!(l.seqs(), 1);
        l.fill(13);
        assert!(l.is_empty());
        assert_eq!(l.seqs(), 0);
    }

    #[test]
    fn release_range_splits_deferred_runs() {
        const LATER: i64 = 50_000;
        // q(29) = SEQ_MAX - 1: the second run crosses the wrap
        let q = |x: i32| seq_add(SEQ_MAX - 30, x);
        let mut l = RcvLossList::new();
        l.push(hole(q(10), q(19), LATER), false); // waiting for FEC
        l.push(hole(q(29), q(33), LATER), false);
        assert_eq!(l.next_due(), LATER);
        // the middle of a run: split in three
        assert_eq!(l.release_range(q(12), q(13), 1000), 2);
        assert_eq!(l.snapshot(), vec![(q(10), q(11)), (q(12), q(13)), (q(14), q(19)), (q(29), q(33))]);
        assert_eq!(l.next_due(), 1000);
        // overlapping a released run: only the new part counts
        assert_eq!(l.release_range(q(13), q(15), 2000), 2);
        assert_eq!(
            l.snapshot(),
            vec![(q(10), q(11)), (q(12), q(13)), (q(14), q(15)), (q(16), q(19)), (q(29), q(33))]
        );
        // the tail of a run, across the wrap
        assert_eq!(l.release_range(0, 2, 3000), 3);
        assert_eq!(
            l.snapshot(),
            vec![(q(10), q(11)), (q(12), q(13)), (q(14), q(15)), (q(16), q(19)), (q(29), SEQ_MAX), (0, 2)]
        );
        let mut out = Vec::new();
        let (n, _) = l.collect_due(3000, 0, 10_000, 0, 0, 100, &mut out);
        assert_eq!((n, out), (7, vec![(q(12), q(13)), (q(14), q(15)), (0, 2)]));
        // NAKed runs are not touched; the rest is released
        assert_eq!(l.release_range(q(12), q(15), 4000), 0);
        assert_eq!(l.seqs(), 15);
        assert_eq!(l.release_range(q(0), 100, 5000), 2 + 4 + 2);
    }

    #[test]
    fn rcv_wraparound_and_remove_before() {
        let mut l = RcvLossList::new();
        l.push(hole(SEQ_MAX - 2, SEQ_MAX, 0), false);
        l.push(hole(1, 3, 0), false);
        l.push(hole(7, 7, 0), false);
        assert_eq!(l.seqs(), 7);
        assert!(l.fill(SEQ_MAX - 1).is_some());
        assert!(l.fill(2).is_some());
        assert_eq!(l.snapshot(), vec![(SEQ_MAX - 2, SEQ_MAX - 2), (SEQ_MAX, SEQ_MAX), (1, 1), (3, 3), (7, 7)]);
        assert_eq!(l.remove_before(0), 2);
        assert_eq!(l.snapshot(), vec![(1, 1), (3, 3), (7, 7)]);
        assert_eq!(l.remove_before(3), 1);
        assert_eq!(l.remove_before(100), 2);
        assert!(l.is_empty());
        assert_eq!(l.seqs(), 0);
        // a run cut in the middle
        l.push(hole(SEQ_MAX - 1, 5, 0), false);
        assert_eq!(l.seqs(), 8);
        assert_eq!(l.remove_before(1), 3);
        assert_eq!(l.snapshot(), vec![(1, 5)]);
    }

    #[test]
    fn rcv_remove_range_dropreq() {
        let mut l = RcvLossList::new();
        l.push(hole(10, 20, 0), false);
        l.push(hole(30, 30, 0), false);
        l.push(hole(40, 45, 0), false);
        assert_eq!(l.remove_range(12, 14), 3);
        assert_eq!(l.snapshot(), vec![(10, 11), (15, 20), (30, 30), (40, 45)]);
        assert_eq!(l.remove_range(18, 42), 3 + 1 + 3);
        assert_eq!(l.snapshot(), vec![(10, 11), (15, 17), (43, 45)]);
        assert_eq!(l.remove_range(5, 100), 2 + 3 + 3);
        assert!(l.is_empty());
        assert_eq!(l.seqs(), 0);
        assert_eq!(l.remove_range(5, 4), 0);
    }

    #[test]
    fn rcv_nak_schedule_and_limits() {
        let mut l = RcvLossList::new();
        let mut out = Vec::new();
        l.push(hole(10, 10, 1000), false);
        l.push(hole(20, 25, 1000), false);
        l.push(hole(30, 30, 5000), false);
        assert_eq!(l.next_due(), 1000);
        // at t=1000: two runs due (3 words), the third not yet
        assert_eq!(l.collect_due(1000, 0, 40_000, 0, 0, 364, &mut out).0, 7);
        assert_eq!(out, vec![(10, 10), (20, 25)]);
        assert_eq!(l.next_due(), 5000);
        assert_eq!(l.collect_due(5000, 0, 40_000, 0, 0, 364, &mut out).0, 1);
        assert_eq!(out, vec![(30, 30)]);
        assert_eq!(l.next_due(), 41_000);
        // word limit: only the single fits in 2 words after...
        assert_eq!(l.collect_due(41_000, 0, 40_000, 0, 0, 2, &mut out).0, 1);
        assert_eq!(out, vec![(10, 10)]);
        assert_eq!(l.next_due(), 41_000, "the run that did not fit stays due");
        assert_eq!(l.collect_due(41_000, 4000, 40_000, 0, 0, 364, &mut out).0, 7);
        assert_eq!(out, vec![(20, 25), (30, 30)]);
        // a shorter interval brings the NAKed runs forward
        l.reschedule(20_000);
        assert_eq!(l.next_due(), 61_000);
        // deadline: no NAK when the repair cannot arrive in time
        assert_eq!(l.collect_due(90_000, 0, 40_000, 30_000, 0, 364, &mut out).0, 0);
        assert!(out.is_empty());
        assert_eq!(l.next_due(), NEVER);
    }

    #[test]
    fn rcv_renak_spread_to_deadline() {
        let mut l = RcvLossList::new();
        let mut out = Vec::new();
        // RTT 250, latency 1000: interval 256 ms, deadline 1 s after
        // detection, the last NAK must leave 255 ms before it
        let mut h = hole(10, 10, 0);
        h.deadline_us = 1_000_000;
        l.push(h, false);
        let (iv, rep, res) = (256_000, 250_000, 255_000);
        assert_eq!(l.collect_due(0, 0, iv, rep, res, 364, &mut out).0, 1);
        // 745 ms of room: two more attempts, 372.5 ms apart (not 256)
        assert_eq!(l.next_due(), 372_500);
        assert_eq!(l.collect_due(372_500, 0, iv, rep, res, 364, &mut out).0, 1);
        assert_eq!(l.next_due(), 745_000);
        assert_eq!(l.collect_due(745_000, 0, iv, rep, res, 364, &mut out).0, 1);
        // no room for a fourth: it is scheduled at the plain interval and
        // then not sent (the repair could not arrive in time)
        assert_eq!(l.collect_due(1_001_000, 0, iv, rep, res, 364, &mut out).0, 0);
        assert_eq!(l.next_due(), NEVER);
    }

    #[test]
    fn rcv_reorder_tolerance() {
        let mut l = RcvLossList::new();
        let mut out = Vec::new();
        let mut h = hole(10, 10, 0);
        h.detected_at_pkt = 100;
        l.push(h, true);
        let mut h = hole(20, 22, 50);
        h.detected_at_pkt = 102;
        l.push(h, true);
        assert_eq!(l.collect_due(10, 0, 1000, 0, 0, 364, &mut out).0, 0);
        // the second hole splits while waiting: both halves stay held
        l.fill(21);
        assert_eq!(l.snapshot(), vec![(10, 10), (20, 20), (22, 22)]);
        assert_eq!(l.release_waiting(100, 103, 3, 2000), 1);
        assert_eq!(l.oldest_waiting().unwrap().first, 20);
        assert_eq!(l.collect_due(100, 0, 1000, 0, 0, 364, &mut out).0, 1);
        assert_eq!(out, vec![(10, 10)]);
        // time cap releases the rest
        assert_eq!(l.release_waiting(2050, 103, 3, 2000), 2);
        assert!(l.oldest_waiting().is_none());
        l.fill(22);
        // (10, 10) is due again (NAKed at 100, interval 1000)
        assert_eq!(l.collect_due(2050, 0, 1000, 0, 0, 364, &mut out).0, 2);
        assert_eq!(out, vec![(10, 10), (20, 20)]);
    }

    #[test]
    fn snd_insert_merge_pop() {
        let mut l = SndLossList::new();
        l.insert(10, 12);
        l.insert(13, 13); // adjacent: merged
        l.insert(20, 25);
        l.insert(5, 6); // before everything
        assert_eq!(l.snapshot(), vec![(5, 6), (10, 13), (20, 25)]);
        l.insert(7, 9); // bridges 5..6 and 10..13
        assert_eq!(l.snapshot(), vec![(5, 13), (20, 25)]);
        l.insert(15, 30); // overlaps 20..25
        assert_eq!(l.snapshot(), vec![(5, 13), (15, 30)]);
        l.insert(1, 40); // covers all
        assert_eq!(l.snapshot(), vec![(1, 40)]);
        l.insert(11, 12); // inside
        assert_eq!(l.snapshot(), vec![(1, 40)]);
        assert_eq!(l.pop(), Some(1));
        assert_eq!(l.peek(), Some(2));
        l.remove_before(39);
        assert_eq!(l.snapshot(), vec![(39, 40)]);
        assert_eq!(l.pop(), Some(39));
        assert_eq!(l.pop(), Some(40));
        assert_eq!(l.pop(), None);
        assert!(l.is_empty());
    }

    #[test]
    fn snd_wraparound() {
        let mut l = SndLossList::new();
        let a = SEQ_MAX - 3;
        l.insert(a, a);
        l.insert(seq_add(a, 2), seq_add(a, 5)); // SEQ_MAX-1 ..= 1
        l.insert(seq_add(a, 1), seq_add(a, 1));
        assert_eq!(l.snapshot(), vec![(a, 1)]);
        l.remove_before(0);
        assert_eq!(l.snapshot(), vec![(0, 1)]);
        let mut l = SndLossList::new();
        l.insert(3, 4);
        l.insert(SEQ_MAX, SEQ_MAX); // before 3 in modular order
        assert_eq!(l.snapshot(), vec![(SEQ_MAX, SEQ_MAX), (3, 4)]);
        assert_eq!(l.pop(), Some(SEQ_MAX));
        assert_eq!(l.pop(), Some(3));
    }
}
