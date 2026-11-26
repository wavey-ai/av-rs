//! Connection configuration (libsrt option names in brackets).

use std::time::Duration;

/// libsrt's "infinite" bandwidth: SRTO_MAXBW -1 paces at 1 Gbit/s.
pub const BW_INFINITE: i64 = 125_000_000;

/// Shortest passphrase libsrt accepts (SRTO_PASSPHRASE), bytes.
pub const PASSPHRASE_MIN: usize = 10;
/// Longest passphrase libsrt accepts (`HAICRYPT_SECRET_MAX_SZ`), bytes.
pub const PASSPHRASE_MAX: usize = 80;

#[derive(Clone)]
pub struct Config {
    /// Our receive latency [SRTO_RCVLATENCY], ms.
    pub rcv_latency_ms: u16,
    /// Latency we ask the peer to use for receiving our data [SRTO_PEERLATENCY], ms.
    pub peer_latency_ms: u16,
    /// Largest message [SRTO_PAYLOADSIZE], bytes (1316 default, <= MSS - 44).
    pub payload_size: usize,
    /// [SRTO_MSS], bytes incl. IP/UDP.
    pub mss: u32,
    /// Flow window [SRTO_FC], packets.
    pub flow_window: u32,
    /// Receive buffer [SRTO_RCVBUF / 1472], packets.
    pub rcv_buf_pkts: u32,
    /// Send buffer [SRTO_SNDBUF / 1472], packets.
    pub snd_buf_pkts: u32,
    /// [SRTO_MAXBW], bytes/s: -1 = 1 Gbit/s (libsrt's BW_INFINITE), 0 = relative to input.
    pub max_bw: i64,
    /// [SRTO_INPUTBW], bytes/s; with max_bw 0, 0 = measure the input rate.
    pub input_bw: i64,
    /// [SRTO_MININPUTBW], bytes/s.
    pub min_input_bw: i64,
    /// [SRTO_OHEADBW], percent.
    pub overhead_bw_pct: u32,
    /// [SRTO_STREAMID] (caller), at most 512 bytes.
    pub stream_id: Option<String>,
    /// [SRTO_PACKETFILTER]: the libsrt `fec` filter
    /// (`fec,cols:C[,rows:R][,layout:even|staircase][,arq:never|onreq|always]`),
    /// negotiated in the handshake. Needs payload_size <= 1452.
    pub packet_filter: Option<String>,
    /// FEC with `arq:onreq`/`always`: the longest a new loss waits for the
    /// filter before its first NAK, us (0 = from the latency and RTT, see
    /// `Connection`). Not an SRT option.
    pub fec_nak_cap_us: u32,
    /// [SRTO_CONNTIMEO]: how long the caller keeps re-sending on the same socket.
    pub connect_timeout: Duration,
    /// [SRTO_PEERIDLETIMEO].
    pub peer_idle_timeout: Duration,
    /// [SRTO_TSBPDMODE]
    pub tsbpd: bool,
    /// [SRTO_TLPKTDROP]
    pub tlpktdrop: bool,
    /// [SRTO_SNDDROPDELAY], ms; -1 disables the sender drop.
    pub snd_drop_delay_ms: i32,
    /// [SRTO_DRIFTTRACER]
    pub drift_tracer: bool,
    /// Opt-in TSBPD settle, ms (0 = off: libsrt's rule, the base from the
    /// handshake packet alone). For this long after the first data packet,
    /// arrival offsets are sampled; then the base moves to their median if
    /// that is later than the handshake base (never earlier: playout is
    /// never earlier than libsrt's rule). See `Tsbpd::settle_for`. Not an
    /// SRT option (receiver timing).
    pub tsbpd_settle_ms: u32,
    /// [SRTO_LOSSMAXTTL]: reorder tolerance in packets before a gap is
    /// NAKed (0 = NAK at once). Ours is also bounded in time by
    /// `reorder_window_us`.
    pub loss_max_ttl: u32,
    /// With `loss_max_ttl` > 0, NAK a gap after at most this long even if
    /// fewer packets arrived (spec 12 #14). Not an SRT option.
    pub reorder_window_us: u32,
    /// With `loss_max_ttl` 0 (libsrt's default, the bench's setting): when
    /// an original (not retransmitted) packet fills a hole, the path
    /// reorders; new holes then wait the observed reorder lateness (max over
    /// the current and previous 1 s, capped at min(latency / 8,
    /// max(SRTT / 2, 2 ms))) before their first NAK, instead of a NAK and a
    /// needless retransmission per reordered packet. Back to 0 two seconds
    /// after the last reordering. Not an SRT option (receiver-side timing).
    pub auto_reorder: bool,
    /// Sender tail probe (spec 12 #5): when the newest packets stay
    /// unacknowledged for SRTT + 4 RTTVar + one ACK period and nothing newer
    /// is queued, retransmit the newest one so a lost tail is seen at once.
    /// Not an SRT option.
    pub tail_probe: bool,
    /// Every NAK is sent twice (at once for a first attempt; max(RTT/8,
    /// 10 ms) later for a late one: a hole NAKed before, or with no time
    /// for another round), and a packet is sent twice from its second
    /// retransmission on (or when too little time is left for another
    /// round). A late attempt then fails only if both copies are lost.
    /// Costs a small NAK per NAK and a copy for about loss% of repairs.
    /// Not an SRT option; wire-compatible (duplicates are dropped).
    pub repair_copies: bool,
    /// Tail, head and stall probes wait at least the peer's measured ACK
    /// hold-off (how long after the newest packet arrives its ACK comes:
    /// ours <= 10 ms, libsrt's up to ~20 ms when its receive worker idles
    /// between frames), capped at latency / 2, instead of one ACK period.
    /// Without it a probe toward a slow-ACKing peer is mostly a duplicate.
    /// Not an SRT option.
    pub probe_ack_lag: bool,
    /// ACKs report RTTVar >= SRTT / 4. A libsrt sender (RETRANSMITALGO=1)
    /// then serves every NAK instead of dropping requests that arrive
    /// within SRTT - 4 RTTVar of its last copy: our receiver paces its own
    /// NAKs per hole, and its delayed NAK copy on a late attempt then
    /// yields a second repair. The RTT itself is reported unchanged. Not an
    /// SRT option.
    pub ack_rttvar_floor: bool,
    /// The too-late skip, last-chance copy and probe deadline of a
    /// retransmission follow the receiver's give-up of a hole: when the
    /// next packet after it is due (the later of its own and the next
    /// packet's origin + latency), not its own origin + latency. Not an
    /// SRT option (sender timing).
    pub rexmit_deadline_next: bool,
    /// Always serve the first request for a packet never retransmitted
    /// (its original's send time does not suppress it; libsrt does the
    /// same); later requests keep the suppression window of the last copy.
    /// A libsrt FEC `onreq` receiver NAKs a loss once, and under jitter that
    /// NAK can come sooner than SRTT - RTTVar after the original:
    /// suppressing it lost the packet (bench: srt-rs FEC -> libsrt FEC, 166
    /// Mbit/s, 1 %, jitter 5 ms: 319 -> 53 frames lost, n = 3; libsrt ->
    /// libsrt 199). Not an SRT option.
    pub rexmit_first_always: bool,
    /// Suppress a requested retransmission as libsrt's RETRANSMITALGO=1:
    /// only within SRTT - 4 RTTVar of the last *retransmission* (the first
    /// request is always served), instead of within max(SRTT - RTTVar,
    /// SRTT / 2) of the last copy, original included. Not an SRT option.
    pub rexmit_suppress_libsrt: bool,
    /// When the pacer holds packets back, wake this long after the next
    /// packet is allowed, so each wake-up sends a batch (the pacer's 1 ms
    /// burst allowance keeps the rate). Not an SRT option.
    pub pace_quantum_us: u32,
    /// With FEC, the extra time an ACK may stop at a never-retransmitted
    /// packet before the sender takes it as lost (ACK-head check and stall
    /// probe), us; negative = auto (max(latency / 4, 10 ms)). Not an SRT
    /// option.
    pub fec_ack_head_delay_us: i32,
    /// [SRTO_PASSPHRASE] (10..=80 bytes, as libsrt accepts): encrypt the payload with AES-CTR
    /// (needs the `aes` feature; without it a passphrase is refused by
    /// `validate`). A listener's is the default for every caller (see
    /// `Listener::set_accept_secret_callback`).
    pub passphrase: Option<String>,
    /// [SRTO_PBKEYLEN] 0 (16, or what the listener advertises), 16, 24, 32.
    pub pbkeylen: u8,
}

/// The passphrase is never printed.
impl std::fmt::Debug for Config {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Config")
            .field("rcv_latency_ms", &self.rcv_latency_ms)
            .field("peer_latency_ms", &self.peer_latency_ms)
            .field("payload_size", &self.payload_size)
            .field("mss", &self.mss)
            .field("flow_window", &self.flow_window)
            .field("rcv_buf_pkts", &self.rcv_buf_pkts)
            .field("snd_buf_pkts", &self.snd_buf_pkts)
            .field("max_bw", &self.max_bw)
            .field("input_bw", &self.input_bw)
            .field("min_input_bw", &self.min_input_bw)
            .field("overhead_bw_pct", &self.overhead_bw_pct)
            .field("stream_id", &self.stream_id)
            .field("packet_filter", &self.packet_filter)
            .field("fec_nak_cap_us", &self.fec_nak_cap_us)
            .field("connect_timeout", &self.connect_timeout)
            .field("peer_idle_timeout", &self.peer_idle_timeout)
            .field("tsbpd", &self.tsbpd)
            .field("tlpktdrop", &self.tlpktdrop)
            .field("snd_drop_delay_ms", &self.snd_drop_delay_ms)
            .field("drift_tracer", &self.drift_tracer)
            .field("loss_max_ttl", &self.loss_max_ttl)
            .field("reorder_window_us", &self.reorder_window_us)
            .field("tail_probe", &self.tail_probe)
            .field("repair_copies", &self.repair_copies)
            .field("ack_rttvar_floor", &self.ack_rttvar_floor)
            .field("pace_quantum_us", &self.pace_quantum_us)
            .field("fec_ack_head_delay_us", &self.fec_ack_head_delay_us)
            .field("passphrase", &self.passphrase.as_ref().map(|_| "<redacted>"))
            .field("pbkeylen", &self.pbkeylen)
            .finish()
    }
}

impl Default for Config {
    fn default() -> Self {
        Config {
            rcv_latency_ms: 120,
            peer_latency_ms: 0,
            payload_size: 1316,
            mss: 1500,
            flow_window: 25600,
            rcv_buf_pkts: 8192,
            snd_buf_pkts: 8192,
            max_bw: -1,
            input_bw: 0,
            min_input_bw: 0,
            overhead_bw_pct: 25,
            stream_id: None,
            packet_filter: None,
            fec_nak_cap_us: 0,
            connect_timeout: Duration::from_secs(8),
            peer_idle_timeout: Duration::from_secs(5),
            tsbpd: true,
            tlpktdrop: true,
            snd_drop_delay_ms: 0,
            drift_tracer: true,
            tsbpd_settle_ms: 0,
            loss_max_ttl: 0,
            reorder_window_us: 2000,
            auto_reorder: true,
            tail_probe: true,
            repair_copies: true,
            probe_ack_lag: true,
            ack_rttvar_floor: true,
            rexmit_deadline_next: true,
            rexmit_first_always: true,
            rexmit_suppress_libsrt: false,
            pace_quantum_us: 250,
            fec_ack_head_delay_us: -1,
            passphrase: None,
            pbkeylen: 0,
        }
    }
}

/// Overwrite a passphrase with zeros (volatile: not optimised away).
pub(crate) fn wipe_passphrase(p: &mut Option<String>) {
    if let Some(p) = p.as_mut() {
        // SAFETY: zero bytes are valid UTF-8
        for x in unsafe { p.as_bytes_mut() } {
            // SAFETY: `x` is a valid, aligned, exclusive reference
            unsafe { std::ptr::write_volatile(x, 0) };
        }
        std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
    }
}

impl Config {
    /// [SRTO_LATENCY]: sets both receive and peer latency.
    pub fn with_latency_ms(mut self, ms: u16) -> Self {
        self.rcv_latency_ms = ms;
        self.peer_latency_ms = ms;
        self
    }

    /// The flow window we advertise in the handshake: min(rcvbuf, FC).
    pub fn advertised_flow_window(&self) -> u32 {
        self.flow_window.min(self.rcv_buf_pkts).max(2)
    }

    /// Check the settings; `Err` explains what is wrong.
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.mss < 76 || self.mss > 1500 {
            return Err("mss must be in 76..=1500");
        }
        if self.payload_size == 0 || self.payload_size > self.mss as usize - 44 {
            return Err("payload_size must be in 1..=mss-44");
        }
        if self.packet_filter.is_some() && self.payload_size > 1452 {
            return Err("payload_size must be <= 1452 with a packet filter");
        }
        if let Some(s) = &self.stream_id {
            if s.len() > crate::handshake::MAX_SID_LEN {
                return Err("stream_id longer than 512 bytes");
            }
        }
        if let Some(f) = &self.packet_filter {
            if !crate::filter::validate(f) {
                return Err("invalid packet_filter");
            }
        }
        if self.rcv_buf_pkts < 32 || self.snd_buf_pkts < 32 {
            return Err("buffers must hold at least 32 packets");
        }
        if let Some(p) = &self.passphrase {
            if p.len() < PASSPHRASE_MIN || p.len() > PASSPHRASE_MAX {
                return Err("passphrase must be 10..=80 bytes");
            }
            if !cfg!(feature = "aes") {
                return Err("a passphrase needs srt-core's `aes` feature");
            }
        }
        if !matches!(self.pbkeylen, 0 | 16 | 24 | 32) {
            return Err("pbkeylen must be 0, 16, 24 or 32");
        }
        Ok(())
    }

    /// Pacing rate in bytes/s for a fixed configuration (None = measure input).
    pub(crate) fn fixed_pacing_rate(&self) -> Option<f64> {
        if self.max_bw > 0 {
            Some(self.max_bw as f64)
        } else if self.max_bw < 0 {
            Some(BW_INFINITE as f64)
        } else if self.input_bw > 0 {
            Some(self.input_bw as f64 * (100 + self.overhead_bw_pct) as f64 / 100.0)
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_redacts_the_passphrase() {
        let c = Config {
            passphrase: Some("very-secret-passphrase".into()),
            stream_id: Some("sid".into()),
            ..Config::default()
        };
        let d = format!("{c:?}");
        assert!(!d.contains("very-secret"), "{d}");
        assert!(d.contains("<redacted>") && d.contains("sid") && d.contains("pbkeylen"), "{d}");
        assert!(format!("{:?}", Config::default()).contains("passphrase: None"));
    }

    #[test]
    fn wipe_passphrase_zeroes() {
        let mut p = Some("secret-passphrase".to_string());
        wipe_passphrase(&mut p);
        assert_eq!(p.as_deref(), Some("\0".repeat(17).as_str()));
        wipe_passphrase(&mut None);
    }

    #[test]
    fn passphrase_length_as_libsrt() {
        let with = |n: usize| Config {
            passphrase: Some("p".repeat(n)),
            ..Config::default()
        };
        let ok = cfg!(feature = "aes");
        assert!(with(9).validate().is_err());
        assert_eq!(with(10).validate().is_ok(), ok);
        assert_eq!(with(80).validate().is_ok(), ok);
        assert!(with(81).validate().is_err());
    }
}
