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
    /// Until this local time, the base moves earlier to the least-delayed
    /// data packet seen (`settle`); None = off.
    settle_until_us: Option<i64>,
}

impl Tsbpd {
    /// Base from the packet that carried the peer's HSREQ/HSRSP:
    /// `now - packet.timestamp`.
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
            settle_until_us: None,
        }
    }

    /// Refine the base from data packets for `window_us` after `now_us`:
    /// the handshake packet the base comes from may itself have been
    /// delayed (jitter, queueing), and then every packet plays that much
    /// late for the whole connection (libsrt has the same rule and the
    /// same weakness; its drift tracer moves only after 1000 samples and
    /// at most 5 ms per step).
    pub fn settle_for(&mut self, now_us: i64, window_us: i64) {
        self.settle_until_us = Some(now_us + window_us);
    }

    /// An original (not retransmitted) data packet with timestamp `ts`
    /// arrived at `arrival_us`: during the settle window, a packet earlier
    /// than the base says moves the base back to it (never later). Returns
    /// how far the base moved (µs, >= 0).
    #[inline]
    pub fn observe_arrival(&mut self, ts: u32, arrival_us: i64) -> i64 {
        match self.settle_until_us {
            Some(t) if arrival_us <= t => {
                let early = self.base_time_us(ts) - arrival_us;
                if early > 0 {
                    self.base_us -= early;
                    return early;
                }
                0
            }
            Some(_) => {
                self.settle_until_us = None;
                0
            }
            None => 0,
        }
    }

    pub fn latency_us(&self) -> i64 {
        self.latency_us
    }

    pub fn drift_us(&self) -> i64 {
        self.drift_us
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
        }
        self.drift_us = drift;
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn settle_moves_the_base_earlier_only_within_the_window() {
        // the handshake came 12 ms late: base 12 ms too late
        let mut t = Tsbpd::new(1_012_000, 0, 100, false);
        t.settle_for(1_012_000, 1_000_000);
        // a data packet stamped 10 ms after the handshake arrives on time (owd as the
        // undelayed handshake would have had): 12 ms earlier than the base says
        assert_eq!(t.observe_arrival(10_000, 1_010_000), 12_000);
        assert_eq!(t.due_us(10_000), 1_010_000 + 100_000);
        // a later (more delayed) packet does not move it back
        assert_eq!(t.observe_arrival(20_000, 1_025_000), 0);
        assert_eq!(t.due_us(20_000), 1_020_000 + 100_000);
        // after the window nothing moves
        assert_eq!(t.observe_arrival(1_500_000, 2_400_000), 0);
        assert_eq!(t.observe_arrival(1_600_000, 2_500_000), 0);
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
