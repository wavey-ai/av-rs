//! Counters, named after libsrt's `CBytePerfMon` fields (snake case).
//! Byte counters follow libsrt: data packets only, payload + 44 bytes
//! (IPv4 20 + UDP 8 + SRT 16) per packet.

#[derive(Clone, Debug, Default, PartialEq)]
pub struct Stats {
    // ---- sender
    /// Data packets sent, incl. retransmissions (pktSentTotal).
    pub pkt_sent: u64,
    /// Data packets sent once (pktSentUniqueTotal).
    pub pkt_sent_unique: u64,
    pub byte_sent: u64,
    pub byte_sent_unique: u64,
    /// Retransmissions (pktRetransTotal).
    pub pkt_retrans: u64,
    pub byte_retrans: u64,
    /// Sequences reported lost by the peer's NAKs (pktSndLossTotal).
    pub pkt_snd_loss: u64,
    /// Packets dropped by the sender as too late (pktSndDropTotal).
    pub pkt_snd_drop: u64,
    pub byte_snd_drop: u64,
    /// Of those, packets that had never been sent.
    pub pkt_snd_drop_unsent: u64,
    pub pkt_snd_filter_extra: u64,
    pub pkt_recv_ack: u64,
    pub pkt_recv_light_ack: u64,
    pub pkt_recv_nak: u64,
    pub pkt_sent_ackack: u64,
    /// ACKs ignored because they acknowledged beyond what was sent.
    pub ack_invalid: u64,
    /// NAKs with sequences beyond what was sent.
    pub nak_invalid: u64,
    /// Messages refused because the send buffer was full.
    pub send_would_block: u64,
    /// NAKed sequences not retransmitted because they had been (re)sent
    /// less than about one RTT before (the request crossed the repair).
    pub pkt_rexmit_suppressed: u64,
    /// Tail probes sent (newest packet retransmitted after a quiet RTT).
    pub pkt_tail_probe: u64,
    /// Head probes: the oldest unacknowledged packet sent again after a
    /// probe delay without an ACK past it.
    pub pkt_head_probe: u64,
    /// Retransmissions queued because an ACK still stopped at a packet
    /// sent more than an RTT before (its last copy was lost).
    pub pkt_ack_rexmit: u64,
    /// Extra copies sent of late repairs (second retransmission on, or too
    /// close to the deadline for another round).
    pub pkt_rexmit_copies: u64,
    /// DROPREQ packets sent (sequences we no longer hold).
    pub pkt_sent_dropreq: u64,

    // ---- receiver
    /// Data packets received incl. duplicates and FEC (pktRecvTotal).
    pub pkt_recv: u64,
    /// Data packets stored once (pktRecvUniqueTotal).
    pub pkt_recv_unique: u64,
    pub byte_recv: u64,
    pub byte_recv_unique: u64,
    /// Sequences detected missing (pktRcvLossTotal).
    pub pkt_rcv_loss: u64,
    pub byte_rcv_loss: u64,
    /// Retransmitted packets received (pktRcvRetrans).
    pub pkt_rcv_retrans: u64,
    /// Packets given up at their play time (pktRcvDropTotal).
    pub pkt_rcv_drop: u64,
    pub byte_rcv_drop: u64,
    /// Packets arriving after their slot was delivered or dropped (pktRcvBelated).
    pub pkt_rcv_belated: u64,
    pub pkt_rcv_duplicate: u64,
    pub pkt_rcv_too_far: u64,
    /// FEC packets received (pktRcvFilterExtraTotal).
    pub pkt_rcv_filter_extra: u64,
    pub pkt_rcv_filter_supply: u64,
    pub pkt_rcv_filter_loss: u64,
    /// Data packets with a non-zero key (we do not decrypt).
    pub pkt_rcv_undecrypt: u64,
    pub pkt_sent_ack: u64,
    pub pkt_sent_light_ack: u64,
    pub pkt_sent_nak: u64,
    /// Sequences listed in the NAKs we sent (counting repeats).
    pub nak_seqs_sent: u64,
    /// Lost sequences that arrived later (repaired or reordered).
    pub pkt_rcv_repaired: u64,
    /// Lost sequences the sender told us (DROPREQ) it will not send.
    pub pkt_rcv_dropreq_seqs: u64,
    pub pkt_recv_ackack: u64,
    /// Messages handed to the application.
    pub msg_delivered: u64,
    pub byte_delivered: u64,

    // ---- both
    pub pkt_sent_keepalive: u64,
    pub pkt_recv_keepalive: u64,
    pub pkt_sent_handshake: u64,
    pub pkt_recv_handshake: u64,
    pub pkt_recv_dropreq: u64,
    pub pkt_recv_other_ctrl: u64,
    pub pkt_recv_wrong_peer: u64,
    pub pkt_recv_malformed: u64,
    /// Datagrams emitted in total (data + control).
    pub datagrams_sent: u64,
    pub datagrams_recv: u64,
}

/// A point-in-time view of the connection's state (libsrt "instant" fields).
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Snapshot {
    pub rtt_us: u32,
    pub rtt_var_us: u32,
    /// The RTT is a real sample (not the 100 ms initial value).
    pub rtt_valid: bool,
    pub mss: u32,
    pub max_payload: usize,
    /// Peer's flow window (pktFlowWindow).
    pub flow_window: u32,
    /// Packets in flight (pktFlightSize).
    pub flight: u32,
    /// Packets held by the sender (pktSndBuf).
    pub snd_buf: u32,
    /// Span of the sender buffer, ms (msSndBuf).
    pub snd_buf_ms: u32,
    /// Packets in the receive buffer (pktRcvBuf).
    pub rcv_buf: u32,
    pub rcv_buf_ms: u32,
    pub rcv_avail: u32,
    pub rcv_capacity: u32,
    /// Our receive latency (msRcvTsbPdDelay).
    pub rcv_tsbpd_delay_ms: u16,
    /// Peer's receive latency for our data (msSndTsbPdDelay).
    pub snd_tsbpd_delay_ms: u16,
    /// Pacing rate, bytes/s (mbpsMaxBW x 1e6 / 8).
    pub pacing_bytes_per_s: f64,
    pub drift_us: i64,
    /// Receiver: smoothed time from a NAK to the repair arriving, us (0
    /// until measured), and the re-NAK interval in use.
    pub nak_rtt_us: u32,
    pub renak_interval_us: u32,
    /// Receiver loss list: runs and sequences; sender loss list runs.
    pub rcv_loss_runs: u32,
    pub rcv_loss_seqs: u64,
    pub snd_loss_runs: u32,
    pub snd_slots_allocated: u32,
    pub rcv_slots_allocated: u32,
    pub peer_srt_version: u32,
    pub peer_flags: u32,
    pub packet_filter: Option<String>,
    pub peer_stream_id: Option<String>,
    pub local_socket_id: u32,
    pub peer_socket_id: u32,
    pub isn: u32,
}
