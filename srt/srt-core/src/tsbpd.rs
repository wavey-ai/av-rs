//! TSBPD time base, 32-bit timestamp wrap and drift tracer (spec 6.7, 6.8).
//! All times are microseconds on the local connection clock (`epoch`).

/// 2^32 us: the timestamp wrap period.
const TS_PERIOD: i64 = 1 << 32;
/// Wrap check window (libsrt TSBPD_WRAP_PERIOD): 30 s.
const WRAP_WINDOW: u32 = 30_000_000;
/// Drift samples per update.
const DRIFT_SPAN: u32 = 1000;
/// Largest drift kept before the base moves.
const MAX_DRIFT_US: i64 = 5000;

/// Settle samples kept (decimated to cover the whole window).
const SETTLE_SAMPLES: usize = 1024;

#[derive(Clone, Debug)]
pub struct Tsbpd {
    base_us: i64,
    wrap_check: bool,
    latency_us: i64,
    drift_us: i64,
    drift_sum: i64,
    drift_n: u32,
    first_rtt_us: Option<i64>,
    drift_tracer: bool,
    /// Optional settle (`Config::tsbpd_settle_ms`; off by default, which
    /// is libsrt's rule): armed window, opened by the first data packet.
    settle_window_us: Option<i64>,
    /// Until this local time, data arrival offsets are sampled.
    settle_until_us: Option<i64>,
    /// Arrival offsets (arrival - base time of the packet), µs, every
    /// `settle_stride`-th original data packet of the window.
    settle_samples: Vec<i32>,
    settle_stride: u32,
    settle_seen: u32,
    /// How far the base moved since the handshake (settle and drift
    /// over-steps; not the wrap carry): `moved_us`.
    shift_us: i64,
}

impl Tsbpd {
    /// Base from the packet that carried the peer's HSREQ/HSRSP:
    /// `now - packet.timestamp` (libsrt's rule).
    pub fn new(now_us: i64, hs_timestamp: u32, latency_ms: u16, drift_tracer: bool) -> Tsbpd {
        Tsbpd {
            base_us: now_us - hs_timestamp as i64,
            wrap_check: hs_timestamp > u32::MAX - WRAP_WINDOW,
            latency_us: latency_ms as i64 * 1000,
            drift_us: 0,
            drift_sum: 0,
            drift_n: 0,
            first_rtt_us: None,
            drift_tracer,
            settle_window_us: None,
            settle_until_us: None,
            settle_samples: Vec::new(),
            settle_stride: 1,
            settle_seen: 0,
            shift_us: 0,
        }
    }

    /// Opt-in settle (not libsrt): the base comes from one handshake packet,
    /// whose delay is one draw of the path's delay. For `window_us` after
    /// the first data packet, the arrival offsets of original data packets
    /// are sampled; at the end of the window the base moves to their
    /// median if that is *later* than the handshake base, never earlier.
    /// So playout is never earlier than libsrt's handshake rule (an early,
    /// fast handshake no longer takes the slower packets' repair budget
    /// until the drift tracer catches up), and the drift tracer starts its
    /// average afresh from the settled base, so it does not undo it. A late
    /// handshake is not corrected (that would play earlier than libsrt);
    /// the drift tracer moves it as in libsrt.
    pub fn settle_for(&mut self, _now_us: i64, window_us: i64) {
        self.settle_window_us = (window_us > 0).then_some(window_us);
        self.settle_until_us = None;
        if window_us > 0 {
            self.settle_samples = Vec::with_capacity(SETTLE_SAMPLES);
        }
    }

    /// An original (not retransmitted) data packet with timestamp `ts`
    /// arrived at `arrival_us`. Returns how far the settle moved the base
    /// (µs, >= 0: later), once, at the end of the window.
    #[inline]
    pub fn observe_arrival(&mut self, ts: u32, arrival_us: i64) -> i64 {
        if let Some(w) = self.settle_window_us.take() {
            // the window opens with the first data packet
            self.settle_until_us = Some(arrival_us + w);
        }
        match self.settle_until_us {
            Some(t) if arrival_us <= t => {
                self.settle_seen += 1;
                if self.settle_seen % self.settle_stride == 0 {
                    let o = (arrival_us - self.base_time_us(ts)).clamp(i32::MIN as i64, i32::MAX as i64) as i32;
                    if self.settle_samples.len() == SETTLE_SAMPLES {
                        // keep every second sample, sample half as often
                        let mut i = 0;
                        self.settle_samples.retain(|_| {
                            i += 1;
                            i % 2 == 0
                        });
                        self.settle_stride *= 2;
                    }
                    self.settle_samples.push(o);
                }
                0
            }
            Some(_) => {
                self.settle_until_us = None;
                self.settle()
            }
            None => 0,
        }
    }

    fn settle(&mut self) -> i64 {
        let mut v = std::mem::take(&mut self.settle_samples);
        if v.is_empty() {
            return 0;
        }
        let mid = v.len() / 2;
        let m = *v.select_nth_unstable(mid).1 as i64;
        if m <= 0 {
            return 0; // the handshake was not faster than the median: libsrt's base stays
        }
        self.base_us += m;
        self.shift_us += m;
        // the drift average restarts from the settled base
        self.drift_sum = 0;
        self.drift_n = 0;
        m
    }

    pub fn latency_us(&self) -> i64 {
        self.latency_us
    }

    pub fn drift_us(&self) -> i64 {
        self.drift_us
    }

    /// How far delivery times moved since the handshake set the base
    /// (settle, drift; not the timestamp wrap): a due time computed earlier
    /// plus the change of this is the due time now.
    #[inline]
    pub fn moved_us(&self) -> i64 {
        self.shift_us + self.drift_us
    }

    /// Base time of a timestamp, with the carry during a wrap.
    #[inline]
    pub fn base_time_us(&self, ts: u32) -> i64 {
        let carry = if self.wrap_check && ts <= 2 * WRAP_WINDOW { TS_PERIOD } else { 0 };
        self.base_us + carry + ts as i64
    }

    /// Delivery time of a packet with this timestamp.
    #[inline]
    pub fn due_us(&self, ts: u32) -> i64 {
        self.base_time_us(ts) + self.latency_us + self.drift_us
    }

    /// Wrap tracking from the delivery-head packet or a KEEPALIVE.
    pub fn update_wrap(&mut self, ts: u32) {
        if self.wrap_check {
            if (WRAP_WINDOW..=2 * WRAP_WINDOW).contains(&ts) {
                self.wrap_check = false;
                self.base_us += TS_PERIOD;
            }
        } else if ts > u32::MAX - WRAP_WINDOW {
            self.wrap_check = true;
        }
    }

    /// One drift sample (ACKACK with an RTT sample, KEEPALIVE without).
    /// Returns true when the drift was updated.
    pub fn drift_sample(&mut self, ts: u32, arrival_us: i64, rtt_us: Option<i64>) -> bool {
        if !self.drift_tracer {
            return false;
        }
        let rtt_delta = match rtt_us {
            Some(r) => {
                let first = *self.first_rtt_us.get_or_insert(r);
                (r - first) / 2
            }
            None => 0,
        };
        let sample = arrival_us - self.base_time_us(ts) - rtt_delta;
        self.drift_sum += sample;
        self.drift_n += 1;
        if self.drift_n < DRIFT_SPAN {
            return false;
        }
        let mut drift = self.drift_sum / self.drift_n as i64;
        self.drift_sum = 0;
        self.drift_n = 0;
        if drift.abs() > MAX_DRIFT_US {
            let over = if drift < 0 { -MAX_DRIFT_US } else { MAX_DRIFT_US };
            drift -= over;
            self.base_us += over;
            self.shift_us += over;
        }
        self.drift_us = drift;
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn settle_moves_the_base_later_to_the_median_only() {
        // the handshake was fast (owd 10 ms); data packets arrive with 10..30 ms
        let mut t = Tsbpd::new(1_010_000, 0, 120, true);
        t.settle_for(1_010_000, 1_000_000);
        let hs_due = t.due_us(500_000);
        for i in 0..900u32 {
            let ts = 2_000_000 + i * 1000;
            let owd = 10_000 + (i % 21) as i64 * 1000; // median 20 ms
            assert_eq!(t.observe_arrival(ts, 1_000_000 + ts as i64 + owd), 0);
        }
        // the first packet after the window settles: 10 ms later, never earlier
        assert_eq!(t.observe_arrival(3_100_000, 4_120_000), 10_000);
        assert_eq!(t.due_us(500_000), hs_due + 10_000);
        assert_eq!(t.observe_arrival(3_200_000, 4_220_000), 0);
        // a late handshake (owd 22 ms, data 10..30): the base stays
        let mut t = Tsbpd::new(1_022_000, 0, 120, true);
        t.settle_for(1_022_000, 1_000_000);
        let hs_due = t.due_us(500_000);
        for i in 0..900u32 {
            let ts = 2_000_000 + i * 1000;
            t.observe_arrival(ts, 1_000_000 + ts as i64 + 10_000 + (i % 21) as i64 * 1000);
        }
        assert_eq!(t.observe_arrival(3_100_000, 4_120_000), 0);
        assert_eq!(t.due_us(500_000), hs_due);
        // off (0): nothing is sampled or moved
        let mut t = Tsbpd::new(1_010_000, 0, 120, true);
        t.settle_for(1_010_000, 0);
        assert_eq!(t.observe_arrival(2_000_000, 3_030_000), 0);
        assert_eq!(t.observe_arrival(5_000_000, 6_030_000), 0);
        assert!(t.settle_samples.capacity() == 0);
    }

    #[test]
    fn settle_samples_are_decimated_over_the_window() {
        // 40 000 packets in the window: the samples still span all of it
        let mut t = Tsbpd::new(0, 0, 120, false);
        t.settle_for(0, 1_000_000);
        for i in 0..40_000u32 {
            let ts = i * 24;
            // the first 40 % of the window 0 ms late, the rest 4 ms
            let late = if i < 16_000 { 0 } else { 4000 };
            t.observe_arrival(ts, ts as i64 + late);
        }
        assert!(t.settle_samples.len() <= SETTLE_SAMPLES);
        assert!(t.settle_samples.iter().any(|&o| o == 0));
        // the median is 4 ms only if the samples cover the whole window
        assert_eq!(t.observe_arrival(1_100_000, 1_104_000), 4000);
    }

    #[test]
    fn due_time_is_base_plus_ts_plus_latency() {
        let t = Tsbpd::new(1_000_000, 400_000, 120, true);
        assert_eq!(t.due_us(400_000), 1_000_000 + 120_000);
        assert_eq!(t.due_us(410_000), 1_010_000 + 120_000);
    }

    #[test]
    fn wrap_carries_and_ends() {
        let near = u32::MAX - 1_000_000;
        let mut t = Tsbpd::new(10_000_000, near, 100, false);
        assert!(t.wrap_check);
        let before = t.due_us(near);
        // 2 s later the timestamp has wrapped to ~1 s
        let after_wrap = 1_000_000u32 - 1;
        assert_eq!(t.due_us(after_wrap) - before, 2_000_000);
        // head reaches [30 s, 60 s]: base moves by 2^32 and carry ends
        let ts40 = 40_000_000u32;
        let due40 = t.due_us(ts40);
        t.update_wrap(ts40);
        assert!(!t.wrap_check);
        assert_eq!(t.due_us(ts40), due40);
        // and a later approach starts the check again
        t.update_wrap(u32::MAX - 10);
        assert!(t.wrap_check);
    }

    #[test]
    fn drift_moves_base_by_at_most_5ms() {
        let mut t = Tsbpd::new(0, 0, 100, true);
        // peer clock runs 7 ms behind: every sample says +7 ms
        for i in 0..DRIFT_SPAN {
            let ts = i * 10_000;
            let updated = t.drift_sample(ts, ts as i64 + 7000, Some(1000));
            assert_eq!(updated, i == DRIFT_SPAN - 1);
        }
        assert_eq!(t.drift_us(), 2000);
        assert_eq!(t.base_us, 5000);
        assert_eq!(t.due_us(0), 5000 + 100_000 + 2000);
    }
}
