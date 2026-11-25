//! Connection configuration (libsrt option names in brackets).

use std::time::Duration;

/// libsrt's "infinite" bandwidth: SRTO_MAXBW -1 paces at 1 Gbit/s.
pub const BW_INFINITE: i64 = 125_000_000;

#[derive(Clone, Debug)]
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
    /// [SRTO_PACKETFILTER]; negotiated and carried, FEC itself not yet implemented.
    pub packet_filter: Option<String>,
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
    /// [SRTO_LOSSMAXTTL]: reorder tolerance in packets before a gap is
    /// NAKed (0 = NAK at once). Ours is also bounded in time by
    /// `reorder_window_us`.
    pub loss_max_ttl: u32,
    /// With `loss_max_ttl` > 0, NAK a gap after at most this long even if
    /// fewer packets arrived (spec 12 #14). Not an SRT option.
    pub reorder_window_us: u32,
    /// Sender tail probe (spec 12 #5): when the newest packets stay
    /// unacknowledged for SRTT + 4 RTTVar + one ACK period and nothing newer
    /// is queued, retransmit the newest one so a lost tail is seen at once.
    /// Not an SRT option.
    pub tail_probe: bool,
    /// Late repair attempts go twice: a NAK for a hole NAKed before (or
    /// with no time for another round) is sent again max(RTT/8, 10 ms)
    /// later, and a packet is sent twice from its second retransmission on
    /// (or when too little time is left for another round). A late attempt
    /// then fails only if both copies are lost. Costs a copy for about
    /// loss% of repairs. Not an SRT option; wire-compatible (duplicates are
    /// dropped).
    pub repair_copies: bool,
    /// ACKs report RTTVar >= SRTT / 4. A libsrt sender (RETRANSMITALGO=1)
    /// then serves every NAK instead of dropping requests that arrive
    /// within SRTT - 4 RTTVar of its last copy: our receiver paces its own
    /// NAKs per hole, and its delayed NAK copy on a late attempt then
    /// yields a second repair. The RTT itself is reported unchanged. Not an
    /// SRT option.
    pub ack_rttvar_floor: bool,
    /// When the pacer holds packets back, wake this long after the next
    /// packet is allowed, so each wake-up sends a batch (the pacer's 1 ms
    /// burst allowance keeps the rate). Not an SRT option.
    pub pace_quantum_us: u32,
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
            connect_timeout: Duration::from_secs(8),
            peer_idle_timeout: Duration::from_secs(5),
            tsbpd: true,
            tlpktdrop: true,
            snd_drop_delay_ms: 0,
            drift_tracer: true,
            loss_max_ttl: 0,
            reorder_window_us: 2000,
            tail_probe: true,
            repair_copies: true,
            ack_rttvar_floor: true,
            pace_quantum_us: 250,
        }
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
