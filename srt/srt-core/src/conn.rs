//! One SRT connection (caller or listener side), sans-IO.
//!
//! Drive it with `handle_datagram`, `handle_timeout` (when `poll_timeout`
//! is reached), `poll_transmit` (until `None`) and `recv_message` (until
//! `None`). All times are `Instant`s passed in; internally they are
//! microseconds since the connection's `epoch`, which is also the origin of
//! every timestamp this side puts on the wire.

use crate::config::Config;
use crate::fec::{ArqLevel, FecConfig, FecRx, FecTx};
use crate::handshake::{flags, ip_to_words, req, Handshake, RejectReason, SrtHsExt, HS_MAGIC, SRT_VERSION, UDT_DGRAM};
use crate::losslist::{Hole, RcvLossList, SndLossList, NEVER};
use crate::packet::{self, rd32, Ack, AckKind, Control, DataHeader, LossList, Packet, HDR_LEN, PKT_OVERHEAD};
use crate::rcvbuf::{Insert, RcvBuf};
use crate::seq::{ackno_inc, seq_dec, seq_inc, seq_le, seq_lt, seq_off};
use crate::sndbuf::{Pacer, SndBuf};
use crate::stats::{Snapshot, Stats};
use crate::tsbpd::Tsbpd;
use std::collections::VecDeque;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

/// Full/small ACK period (libsrt SYN interval).
const SYN_US: i64 = 10_000;
const KEEPALIVE_US: i64 = 1_000_000;
const LIGHT_ACK_PKTS: u32 = 64;
const ACK_WINDOW: usize = 1024;
const INIT_RTT_US: u32 = 100_000;
const INIT_RTTVAR_US: u32 = 50_000;
/// Caller handshake re-send: first interval before an RTT is known, cap.
const HS_FIRST_US: i64 = 250_000;
const HS_MIN_US: i64 = 100_000;
const HS_MAX_US: i64 = 1_000_000;
/// Listener: re-send the conclusion response until the caller is heard.
const HS_RSP_RESENDS: u32 = 5;
const MAX_ACKACK_QUEUE: usize = 64;
const MAX_DROPREQ_QUEUE: usize = 64;
const DROP_LOG_MAX: usize = 32;
/// Send a full ACK at least this often while holes keep its value
/// unchanged (libsrt then sends none): the ACKACK keeps RTT samples coming.
const ACK_RTT_PROBE_US: i64 = 50_000;
/// Re-NAK a hole this long after its last NAK, beyond the measured repair
/// time + 4 x its variation (spec 12 #4).
const NAK_MARGIN_US: i64 = 2_000;
/// Smallest re-NAK interval.
const NAK_MIN_INTERVAL_US: i64 = 5_000;
/// Re-NAKs are spread up to the hole's deadline minus the expected repair
/// time and max(RTT / 8, this).
const SPREAD_MARGIN_US: i64 = 10_000;
/// A NAK also carries holes due within this much (fewer, fuller NAKs).
const NAK_SLACK_US: i64 = 1_000;
/// Tail probe: after SRTT + 4 RTTVar (at most SRTT / 2) + one ACK period
/// + this.
const PROBE_MARGIN_US: i64 = 1_000;
/// Automatic reorder wait: margin over the observed lateness, and the
/// smallest cap (min(latency / 8, max(SRTT / 2, this))).
const REORDER_MARGIN_US: i64 = 500;
const REORDER_MIN_CAP_US: i64 = 2_000;
/// Window of the ACK hold-off maximum (current and previous one count).
const HOLDOFF_WINDOW_US: i64 = 1_000_000;
/// ACK-head retransmission: the packet an ACK stops at is taken as lost
/// if it was last sent more than SRTT + 2 RTTVar + this before the ACK.
const ACK_HEAD_MARGIN_US: i64 = 1_000;
/// A repair is the last possible one when less than 1.5 SRTT + 4 RTTVar
/// (at most SRTT / 2) + this remains before the receiver plays the packet: send it twice.
const LAST_CHANCE_MARGIN_US: i64 = 5_000;
/// Sender drop: hold a packet at least latency + max(latency / 4, this)
/// (+ 2 SRTT + 10 ms) past its origin (spec 12 #8; libsrt holds >= 1 s).
const SND_DROP_MARGIN_US: i64 = 20_000;
/// FEC receiver: group history kept, packets (at most the receive buffer).
const FEC_RX_WINDOW: u32 = 4096;
/// FEC (`arq:onreq`/`always`): the first NAK of a loss waits for the filter
/// to find it unrebuildable, at most this long at least (see
/// `fec_nak_cap_us`).
const FEC_NAK_CAP_MIN_US: i64 = 5_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    Caller,
    Listener,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CloseReason {
    /// `close()` was called.
    Local,
    /// The peer sent SHUTDOWN.
    PeerShutdown,
    /// Nothing heard for the peer idle timeout.
    PeerIdle,
    /// The caller's handshake did not complete before the deadline.
    ConnectTimeout,
    /// The handshake was rejected (by the peer, or by us for a bad response).
    Rejected(RejectReason),
    /// The peer wants encryption, which this implementation does not do.
    Encrypted,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum State {
    /// Caller: induction sent.
    Induction,
    /// Caller: conclusion sent.
    Conclusion,
    Connected,
    Closed(CloseReason),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Event {
    Connected,
    Closed(CloseReason),
}

/// One datagram written by `poll_transmit`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Transmit {
    pub len: usize,
    pub dst: SocketAddr,
}

/// A message handed to the application.
#[derive(Debug)]
pub struct Delivered<'a> {
    pub payload: &'a [u8],
    pub seq: u32,
    pub msgno: u32,
    /// Sender timestamp (us on the sender's clock).
    pub timestamp: u32,
    pub rexmit: bool,
    /// Its TSBPD delivery time (None without TSBPD).
    pub due: Option<Instant>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SendError {
    NotConnected,
    TooLarge,
    /// The send buffer is full; retry after the peer acknowledges.
    WouldBlock,
}

impl std::fmt::Display for SendError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for SendError {}

#[derive(Clone, Copy, Default)]
struct AckRec {
    ackno: u32,
    seq: u32,
    sent_us: i64,
}

/// What the listener decided about a caller's conclusion.
#[derive(Clone, Debug)]
pub(crate) struct Negotiated {
    pub mss: u32,
    pub filter: Option<String>,
    pub rcv_latency_ms: u16,
    pub snd_latency_ms: u16,
    pub peer_flags: u32,
    pub peer_version: u32,
}

pub struct Connection {
    cfg: Config,
    role: Role,
    state: State,
    epoch: Instant,
    peer: SocketAddr,
    local_sid: u32,
    peer_sid: u32,
    isn: u32,

    // handshake
    hs: Option<Box<Handshake>>,
    hs_pending: bool,
    hs_dst: u32,
    hs_next_us: i64,
    hs_interval_us: i64,
    hs_deadline_us: i64,
    hs_sent_us: i64,
    /// Handshake packets sent in the current step (RTT is measured only
    /// from an unrepeated request, as Karn).
    hs_sends: u32,
    hs_resends_left: u32,
    peer_heard: bool,

    // negotiated
    mss: u32,
    max_payload: usize,
    peer_fw: u32,
    rcv_latency_ms: u16,
    snd_latency_ms: u16,
    peer_flags: u32,
    peer_version: u32,
    filter: Option<String>,
    peer_stream_id: Option<String>,
    tsbpd_rcv: bool,

    // sender
    snd: SndBuf,
    pacer: Pacer,

    // receiver
    rcv: RcvBuf,
    tsbpd: Option<Tsbpd>,
    rcv_started: bool,
    next_ack_us: i64,
    ackno: u32,
    last_ack_seq: u32,
    last_ack_us: i64,
    last_full_ack_us: i64,
    last_ackack_seq: u32,
    /// Receive room advertised in the last full/small ACK.
    adv_avail: u32,
    pkts_since_ack: u32,
    ack_window: Vec<AckRec>,
    ack_due: Option<AckKind>,
    rate_pkts: u64,
    rate_bytes: u64,
    pkt_rate: u32,
    byte_rate: u32,
    rcv_loss: RcvLossList,
    nak_scratch: Vec<(u32, u32)>,
    rcv_pkt_count: u64,
    /// Measured NAK -> repair time (Karn: only holes NAKed once).
    nak_srtt: i64,
    nak_rttvar: i64,
    nak_rtt_valid: bool,
    nak_rtt_max: i64,

    // sender loss recovery
    snd_loss: SndLossList,
    dropreqs: VecDeque<(u32, u32)>,
    /// Last data transmission (new or retransmitted): the tail probe base.
    last_data_tx_us: i64,
    probe_armed: bool,
    /// The head sequence whose probes were given up (a copy would arrive
    /// after its play time).
    probe_dead: Option<u32>,
    /// A stall probe is queued for this sequence (speculative: no copy).
    stall_probe_seq: Option<u32>,
    /// Highest sequence ever retransmitted for a hole (NAK, ACK-head, head
    /// or stall probe; not a tail probe): ACK hold-off samples skip ACKs
    /// whose range may hold one (a hole held them, not the ACK timer).
    rexmit_hi: Option<u32>,
    /// The tail probe queued for this sequence (its retransmission is no hole).
    tail_probe_seq: Option<u32>,
    /// ACK hold-off: max of (ACK arrival - last send of the newest packet
    /// it covers - SRTT) over the current and the previous 1 s window.
    holdoff_cur_us: i64,
    holdoff_prev_us: i64,
    holdoff_win_us: i64,
    /// Observed reorder lateness (auto_reorder), two 1 s windows.
    reorder_cur_us: i64,
    reorder_prev_us: i64,
    reorder_win_us: i64,
    /// The first holes given up (diagnosis).
    drop_log: Vec<crate::stats::DroppedHole>,
    /// The re-NAK interval last used to schedule holes.
    renak_sched_us: i64,
    /// A copy of the last NAK, sent right after it (`repair_copies`).
    nak_copy: Vec<u8>,
    /// When the NAK copy goes out.
    nak_copy_at_us: i64,
    /// A sequence to send once more right after its retransmission.
    rexmit_copy: Option<u32>,

    // packet filter (FEC)
    fec_tx: Option<Box<FecTx>>,
    fec_rx: Option<Box<FecRx>>,
    /// The filter's ARQ level (None: no filter = libsrt's "always" without
    /// FEC).
    arq: Option<ArqLevel>,
    /// Offsets the filter found unrebuildable (scratch).
    fec_rel: Vec<i64>,
    /// Timestamp of the newest data packet received (deadline of a loss
    /// a FEC packet reveals).
    last_data_ts: u32,
    /// Highest sequence of any data packet received (loss statistics).
    phy_highest: u32,

    // RTT
    srtt: u32,
    rttvar: u32,
    rtt_own: bool,
    rtt_valid: bool,
    /// srtt/rttvar hold a handshake estimate (timers may use it).
    rtt_seeded: bool,

    // control out
    ackacks: VecDeque<u32>,
    keepalive_due: bool,
    shutdown_due: bool,
    last_send_us: i64,
    last_recv_us: i64,

    events: VecDeque<Event>,
    stats: Stats,
}

fn our_flags(cfg: &Config) -> u32 {
    let mut f = flags::LIVE;
    if !cfg.tlpktdrop {
        f &= !flags::TLPKTDROP;
    }
    if !cfg.tsbpd {
        f &= !(flags::TSBPDSND | flags::TSBPDRCV);
    }
    f
}

impl Connection {
    fn base(cfg: Config, role: Role, now: Instant, peer: SocketAddr, local_sid: u32, isn: u32, max_payload: usize) -> Self {
        let pacer = Pacer::new(cfg.fixed_pacing_rate(), cfg.overhead_bw_pct, cfg.min_input_bw as f64, 0);
        Connection {
            snd: SndBuf::new(cfg.snd_buf_pkts, max_payload, isn),
            rcv: RcvBuf::new(cfg.rcv_buf_pkts, max_payload, isn),
            pacer,
            role,
            state: State::Induction,
            epoch: now,
            peer,
            local_sid,
            peer_sid: 0,
            isn,
            hs: None,
            hs_pending: false,
            hs_dst: 0,
            hs_next_us: 0,
            hs_interval_us: HS_FIRST_US,
            hs_deadline_us: cfg.connect_timeout.as_micros() as i64,
            hs_sent_us: 0,
            hs_sends: 0,
            hs_resends_left: 0,
            peer_heard: false,
            mss: cfg.mss,
            max_payload,
            peer_fw: 0,
            rcv_latency_ms: 0,
            snd_latency_ms: 0,
            peer_flags: 0,
            peer_version: 0,
            filter: None,
            peer_stream_id: None,
            tsbpd_rcv: false,
            tsbpd: None,
            rcv_started: false,
            next_ack_us: 0,
            ackno: 0,
            last_ack_seq: isn,
            last_ack_us: 0,
            last_full_ack_us: 0,
            last_ackack_seq: isn,
            adv_avail: u32::MAX,
            pkts_since_ack: 0,
            ack_window: vec![AckRec::default(); ACK_WINDOW],
            ack_due: None,
            rate_pkts: 0,
            rate_bytes: 0,
            pkt_rate: 0,
            byte_rate: 0,
            rcv_loss: RcvLossList::new(),
            nak_scratch: Vec::with_capacity(512),
            rcv_pkt_count: 0,
            nak_srtt: 0,
            nak_rttvar: 0,
            nak_rtt_valid: false,
            nak_rtt_max: 0,
            snd_loss: SndLossList::new(),
            dropreqs: VecDeque::with_capacity(MAX_DROPREQ_QUEUE),
            last_data_tx_us: 0,
            probe_armed: false,
            probe_dead: None,
            stall_probe_seq: None,
            rexmit_hi: None,
            tail_probe_seq: None,
            holdoff_cur_us: 0,
            holdoff_prev_us: 0,
            holdoff_win_us: 0,
            reorder_cur_us: 0,
            reorder_prev_us: 0,
            reorder_win_us: 0,
            renak_sched_us: NEVER,
            drop_log: Vec::new(),
            nak_copy: Vec::new(),
            nak_copy_at_us: NEVER,
            rexmit_copy: None,
            fec_tx: None,
            fec_rx: None,
            arq: None,
            fec_rel: Vec::new(),
            last_data_ts: 0,
            phy_highest: seq_dec(isn),
            srtt: INIT_RTT_US,
            rttvar: INIT_RTTVAR_US,
            rtt_own: false,
            rtt_valid: false,
            rtt_seeded: false,
            ackacks: VecDeque::with_capacity(MAX_ACKACK_QUEUE),
            keepalive_due: false,
            shutdown_due: false,
            last_send_us: 0,
            last_recv_us: 0,
            events: VecDeque::new(),
            stats: Stats::default(),
            cfg,
        }
    }

    /// Start a caller handshake to `peer` (non-blocking: progress through
    /// `poll_transmit` / `handle_datagram` / `handle_timeout`).
    /// `isn` must be below 0x7FFF_FFFF; `local_sid` in 1..2^30.
    pub fn connect(cfg: Config, now: Instant, peer: SocketAddr, local_sid: u32, isn: u32) -> Connection {
        let max_payload = cfg.mss as usize - PKT_OVERHEAD;
        let mut c = Connection::base(cfg, Role::Caller, now, peer, local_sid, isn % 0x7FFF_FFFF, max_payload);
        let hs = Handshake {
            version: 4,
            encryption: 0,
            ext_field: UDT_DGRAM as u16,
            isn: c.isn,
            mss: c.cfg.mss,
            flow_window: c.cfg.advertised_flow_window(),
            req_type: req::INDUCTION,
            socket_id: local_sid,
            cookie: 0,
            peer_ip: ip_to_words(peer.ip()),
            ..Default::default()
        };
        c.hs = Some(Box::new(hs));
        c.hs_pending = true;
        c.hs_dst = 0;
        c.hs_next_us = HS_FIRST_US;
        c
    }

    /// A listener-side connection, created by `Listener` on a valid
    /// conclusion (it is connected at once; its conclusion response is the
    /// first thing `poll_transmit` returns).
    pub(crate) fn accepted(cfg: Config, now: Instant, peer: SocketAddr, local_sid: u32, caller: &Handshake, hs_timestamp: u32, n: Negotiated) -> Connection {
        let max_payload = n.mss as usize - PKT_OVERHEAD;
        let mut c = Connection::base(cfg, Role::Listener, now, peer, local_sid, caller.isn, max_payload);
        c.peer_sid = caller.socket_id;
        c.mss = n.mss;
        c.peer_fw = caller.flow_window;
        c.rcv_latency_ms = n.rcv_latency_ms;
        c.snd_latency_ms = n.snd_latency_ms;
        c.peer_flags = n.peer_flags;
        c.peer_version = n.peer_version;
        c.peer_stream_id.clone_from(&caller.stream_id);
        c.tsbpd_rcv = c.cfg.tsbpd && n.peer_flags & flags::TSBPDSND != 0;
        c.tsbpd = Some(Tsbpd::new(0, hs_timestamp, n.rcv_latency_ms, c.cfg.drift_tracer));
        let send_filter = n.filter.is_some() && n.peer_flags & flags::FILTERCAP != 0;
        c.filter = n.filter;
        c.setup_filter(); // the listener checked the config
        let mut rsp = Handshake {
            version: 5,
            encryption: 0,
            ext_field: 0,
            isn: caller.isn,
            mss: n.mss,
            flow_window: c.cfg.advertised_flow_window(),
            req_type: req::CONCLUSION,
            socket_id: local_sid,
            cookie: caller.cookie,
            peer_ip: ip_to_words(peer.ip()),
            hsrsp: Some(SrtHsExt {
                version: SRT_VERSION,
                flags: our_flags(&c.cfg),
                recv_delay_ms: n.rcv_latency_ms,
                send_delay_ms: n.snd_latency_ms,
            }),
            filter: if send_filter { c.filter.clone() } else { None },
            ..Default::default()
        };
        rsp.ext_field = rsp.conclusion_ext_flags();
        c.hs = Some(Box::new(rsp));
        c.hs_pending = true;
        c.hs_dst = caller.socket_id;
        c.hs_interval_us = HS_MIN_US;
        c.hs_next_us = HS_MIN_US;
        c.hs_resends_left = HS_RSP_RESENDS;
        c.set_connected(0);
        c
    }

    // ------------------------------------------------------------ time

    #[inline]
    fn us(&self, t: Instant) -> i64 {
        match t.checked_duration_since(self.epoch) {
            Some(d) => d.as_micros() as i64,
            None => -(self.epoch.duration_since(t).as_micros() as i64),
        }
    }

    #[inline]
    fn at(&self, us: i64) -> Instant {
        if us >= 0 {
            self.epoch + Duration::from_micros(us as u64)
        } else {
            self.epoch.checked_sub(Duration::from_micros((-us) as u64)).unwrap_or(self.epoch)
        }
    }

    // ------------------------------------------------------------ accessors

    pub fn state(&self) -> &State {
        &self.state
    }

    pub fn is_connected(&self) -> bool {
        self.state == State::Connected
    }

    pub fn is_closed(&self) -> bool {
        matches!(self.state, State::Closed(_))
    }

    pub fn role(&self) -> Role {
        self.role
    }

    pub fn peer_addr(&self) -> SocketAddr {
        self.peer
    }

    pub fn local_socket_id(&self) -> u32 {
        self.local_sid
    }

    pub fn peer_socket_id(&self) -> u32 {
        self.peer_sid
    }

    pub fn stream_id(&self) -> Option<&str> {
        self.peer_stream_id.as_deref().or(self.cfg.stream_id.as_deref())
    }

    pub fn config(&self) -> &Config {
        &self.cfg
    }

    /// Smoothed RTT in µs and whether it is a real sample (cheap; for I/O
    /// policies such as read coalescing).
    pub fn rtt_us(&self) -> (u32, bool) {
        (self.srtt, self.rtt_valid)
    }

    pub fn stats(&self) -> &Stats {
        &self.stats
    }

    /// Largest message `send_message` accepts.
    pub fn max_message(&self) -> usize {
        let m = self.cfg.payload_size.min(self.max_payload);
        if self.fec_tx.is_some() {
            m.min(self.max_payload - 4) // a FEC packet carries 4 bytes more
        } else {
            m
        }
    }

    /// The `fec` filter in use (negotiated), if any.
    pub fn fec_config(&self) -> Option<FecConfig> {
        self.fec_rx.as_ref().map(|r| r.cfg)
    }

    /// Set up the packet filter from the negotiated config (spec 8): both
    /// directions are grouped from the caller's ISN. False if it is not a
    /// `fec` filter we can run.
    fn setup_filter(&mut self) -> bool {
        self.fec_tx = None;
        self.fec_rx = None;
        self.arq = None;
        let Some(f) = self.filter.as_deref() else { return true };
        let Some(fc) = FecConfig::parse(f) else { return false };
        // P: the sender's SRTO_PAYLOADSIZE, as libsrt (a libsrt receiver
        // abandons rebuilds longer than its own)
        let p = self.cfg.payload_size.min(self.max_payload - 4);
        self.fec_tx = Some(Box::new(FecTx::new(&fc, p, self.isn)));
        let window = self.rcv.capacity().min(FEC_RX_WINDOW);
        self.fec_rx = Some(Box::new(FecRx::new(&fc, self.max_payload, self.isn, window)));
        self.arq = Some(fc.arq);
        true
    }

    /// Our sender may retransmit on its own (ACK-head, probes): not with
    /// `arq:never`, which asks for FEC only.
    #[inline]
    fn sender_arq(&self) -> bool {
        self.arq != Some(ArqLevel::Never)
    }

    /// Packets held by the sender (sent-unacknowledged + unsent).
    pub fn send_buffer_len(&self) -> u32 {
        self.snd.len()
    }

    /// Room left in the send buffer, packets.
    pub fn send_buffer_room(&self) -> u32 {
        self.snd.capacity() - self.snd.len()
    }

    /// Instant values (RTT, buffers, negotiated settings).
    pub fn snapshot(&self, now: Instant) -> Snapshot {
        let now_us = self.us(now);
        let snd_buf_ms = self.snd.oldest_origin_us().map_or(0, |o| ((now_us - o).max(0) / 1000) as u32);
        Snapshot {
            ack_holdoff_us: self.holdoff_cur_us.max(self.holdoff_prev_us).min(u32::MAX as i64) as u32,
            reorder_wait_us: self.reorder_wait_us().clamp(0, u32::MAX as i64) as u32,
            rtt_us: self.srtt,
            rtt_var_us: self.rttvar,
            rtt_valid: self.rtt_valid,
            mss: self.mss,
            max_payload: self.max_payload,
            flow_window: self.peer_fw,
            flight: self.snd.in_flight(),
            snd_buf: self.snd.len(),
            snd_buf_ms,
            rcv_buf: self.rcv.len(),
            rcv_buf_ms: self.rcv.timestamp_span_us() / 1000,
            rcv_avail: self.rcv.available(),
            rcv_capacity: self.rcv.capacity(),
            rcv_tsbpd_delay_ms: self.rcv_latency_ms,
            snd_tsbpd_delay_ms: self.snd_latency_ms,
            pacing_bytes_per_s: self.pacer.rate(),
            drift_us: self.tsbpd.as_ref().map_or(0, |t| t.drift_us()),
            nak_rtt_us: if self.nak_rtt_valid { self.nak_srtt as u32 } else { 0 },
            nak_rtt_var_us: self.nak_rttvar as u32,
            nak_rtt_max_us: self.nak_rtt_max as u32,
            renak_interval_us: self.renak_interval_us() as u32,
            rcv_loss_runs: self.rcv_loss.runs() as u32,
            rcv_loss_seqs: self.rcv_loss.seqs(),
            snd_loss_runs: self.snd_loss.runs() as u32,
            snd_slots_allocated: self.snd.allocated_slots(),
            rcv_slots_allocated: self.rcv.allocated_slots(),
            peer_srt_version: self.peer_version,
            peer_flags: self.peer_flags,
            packet_filter: self.filter.clone(),
            peer_stream_id: self.peer_stream_id.clone(),
            local_socket_id: self.local_sid,
            peer_socket_id: self.peer_sid,
            isn: self.isn,
        }
    }

    pub fn poll_event(&mut self) -> Option<Event> {
        self.events.pop_front()
    }

    // ------------------------------------------------------------ state changes

    fn set_connected(&mut self, now_us: i64) {
        self.state = State::Connected;
        self.events.push_back(Event::Connected);
        self.next_ack_us = now_us + SYN_US;
        self.last_recv_us = now_us;
        self.last_send_us = now_us;
    }

    fn set_closed(&mut self, r: CloseReason) {
        if self.is_closed() {
            return;
        }
        self.hs_pending = false;
        self.events.push_back(Event::Closed(r.clone()));
        self.state = State::Closed(r);
    }

    /// Close: sends one SHUTDOWN if connected. Buffered received messages
    /// stay readable.
    pub fn close(&mut self, _now: Instant) {
        if self.state == State::Connected {
            self.shutdown_due = true;
        }
        self.set_closed(CloseReason::Local);
    }

    // ------------------------------------------------------------ input

    /// Process one datagram from `from`.
    pub fn handle_datagram(&mut self, now: Instant, from: SocketAddr, data: &[u8]) {
        self.stats.datagrams_recv += 1;
        if from != self.peer {
            self.stats.pkt_recv_wrong_peer += 1;
            return;
        }
        if self.is_closed() {
            return;
        }
        let now_us = self.us(now);
        let pkt = match packet::decode(data) {
            Ok(p) => p,
            Err(_) => {
                self.stats.pkt_recv_malformed += 1;
                return;
            }
        };
        match pkt {
            Packet::Data { hdr, payload } => {
                if hdr.dst != self.local_sid {
                    self.stats.pkt_recv_wrong_peer += 1;
                    return;
                }
                self.last_recv_us = now_us;
                self.seed_rtt_from_handshake(now_us);
                self.peer_heard = true;
                match self.state {
                    // the listener already thinks we are connected: our
                    // conclusion response was lost, ask again now
                    State::Conclusion => self.hs_pending = true,
                    State::Connected => self.on_data(now_us, &hdr, payload),
                    _ => {}
                }
            }
            Packet::Control { hdr, body } => {
                let is_hs = matches!(body, Control::Handshake(_));
                if hdr.dst != self.local_sid && !(is_hs && hdr.dst == 0) {
                    self.stats.pkt_recv_wrong_peer += 1;
                    return;
                }
                self.last_recv_us = now_us;
                if let Control::Handshake(hs) = body {
                    self.on_handshake(now_us, hdr.timestamp, &hs);
                    return;
                }
                self.seed_rtt_from_handshake(now_us);
                self.peer_heard = true;
                if self.state == State::Conclusion {
                    self.hs_pending = true;
                    return;
                }
                if self.state != State::Connected {
                    return;
                }
                match body {
                    Control::KeepAlive => {
                        self.stats.pkt_recv_keepalive += 1;
                        if let Some(t) = self.tsbpd.as_mut() {
                            t.update_wrap(hdr.timestamp);
                            t.drift_sample(hdr.timestamp, now_us, None);
                        }
                    }
                    Control::Ack(a) => self.on_ack(now_us, hdr.info, &a),
                    Control::Nak(l) => self.on_nak(&l),
                    Control::AckAck => self.on_ackack(now_us, hdr.info, hdr.timestamp),
                    Control::Shutdown => self.set_closed(CloseReason::PeerShutdown),
                    Control::DropReq { first, last } => self.on_dropreq(first, last),
                    _ => self.stats.pkt_recv_other_ctrl += 1,
                }
            }
        }
    }

    /// Listener: the first packet from the caller after our conclusion
    /// response gives a first RTT estimate (if the response was sent once).
    fn seed_rtt_from_handshake(&mut self, now_us: i64) {
        if self.role == Role::Listener && !self.peer_heard && !self.rtt_valid && self.hs_sends == 1 {
            let rtt = now_us - self.hs_sent_us;
            if rtt > 0 {
                self.srtt = rtt.min(10_000_000) as u32;
                self.rttvar = self.srtt / 2;
                self.rtt_seeded = true;
            }
        }
    }

    fn on_handshake(&mut self, now_us: i64, ts: u32, hs: &Handshake) {
        self.stats.pkt_recv_handshake += 1;
        match (self.role, &self.state) {
            (Role::Caller, State::Induction) => {
                if let Some(r) = hs.reject_reason() {
                    return self.set_closed(CloseReason::Rejected(r));
                }
                if hs.req_type != req::INDUCTION || hs.socket_id != self.local_sid {
                    return;
                }
                if hs.version < 5 {
                    return self.set_closed(CloseReason::Rejected(RejectReason::Version));
                }
                if hs.ext_field != HS_MAGIC {
                    return self.set_closed(CloseReason::Rejected(RejectReason::Rogue));
                }
                if hs.encryption != 0 {
                    return self.set_closed(CloseReason::Encrypted);
                }
                let rtt = (now_us - self.hs_sent_us).max(0);
                self.hs_interval_us = (2 * rtt).clamp(HS_MIN_US, HS_MAX_US);
                if rtt > 0 && self.hs_sends == 1 {
                    // seed the timers (tail probe, re-NAK) until a real
                    // sample arrives; not reported as valid
                    self.srtt = rtt.min(10_000_000) as u32;
                    self.rttvar = self.srtt / 2;
                    self.rtt_seeded = true;
                }
                self.hs_sends = 0;
                let mut c = Handshake {
                    version: 5,
                    encryption: 0,
                    ext_field: 0,
                    isn: self.isn,
                    mss: self.cfg.mss,
                    flow_window: self.cfg.advertised_flow_window(),
                    req_type: req::CONCLUSION,
                    socket_id: self.local_sid,
                    cookie: hs.cookie,
                    peer_ip: ip_to_words(self.peer.ip()),
                    hsreq: Some(SrtHsExt {
                        version: SRT_VERSION,
                        flags: our_flags(&self.cfg),
                        recv_delay_ms: self.cfg.rcv_latency_ms,
                        send_delay_ms: self.cfg.peer_latency_ms,
                    }),
                    stream_id: self.cfg.stream_id.clone().filter(|s| !s.is_empty()),
                    filter: self.cfg.packet_filter.clone(),
                    ..Default::default()
                };
                c.ext_field = c.conclusion_ext_flags();
                self.hs = Some(Box::new(c));
                self.hs_pending = true;
                self.hs_next_us = now_us + self.hs_interval_us;
                self.state = State::Conclusion;
            }
            (Role::Caller, State::Conclusion) => {
                if let Some(r) = hs.reject_reason() {
                    return self.set_closed(CloseReason::Rejected(r));
                }
                if hs.req_type == req::CONCLUSION {
                    self.complete_caller(now_us, ts, hs);
                }
            }
            (Role::Listener, State::Connected) => {
                // repeated conclusion: answer with the same response
                if hs.req_type == req::CONCLUSION && hs.socket_id == self.peer_sid && hs.isn == self.isn {
                    self.hs_pending = true;
                }
            }
            _ => {}
        }
    }

    fn complete_caller(&mut self, now_us: i64, ts: u32, hs: &Handshake) {
        let reject = |c: &mut Self, r| c.set_closed(CloseReason::Rejected(r));
        if hs.version != 5 {
            return reject(self, RejectReason::Version);
        }
        if hs.mss > 1500 || hs.mss < 76 || hs.isn != self.isn || hs.flow_window < 2 {
            return reject(self, RejectReason::Rogue);
        }
        if hs.encryption != 0 || hs.kmrsp {
            return self.set_closed(CloseReason::Encrypted);
        }
        let Some(rsp) = hs.hsrsp else { return reject(self, RejectReason::Rogue) };
        if rsp.flags & flags::STREAM != 0 {
            return reject(self, RejectReason::MessageApi);
        }
        let filter = match crate::filter::negotiate_caller(self.cfg.packet_filter.as_deref(), hs.filter.as_deref()) {
            Ok(f) => f,
            Err(_) => return reject(self, RejectReason::Filter),
        };
        self.peer_sid = hs.socket_id;
        self.mss = hs.mss.min(self.cfg.mss);
        self.max_payload = self.mss as usize - PKT_OVERHEAD;
        self.peer_fw = hs.flow_window;
        self.peer_flags = rsp.flags;
        self.peer_version = rsp.version;
        self.filter = filter;
        if !self.setup_filter() {
            return reject(self, RejectReason::Filter);
        }
        self.snd_latency_ms = if rsp.flags & flags::TSBPDRCV != 0 { rsp.recv_delay_ms } else { 0 };
        self.rcv_latency_ms = if rsp.flags & flags::TSBPDSND != 0 { rsp.send_delay_ms } else { 0 };
        self.tsbpd_rcv = self.cfg.tsbpd && rsp.flags & flags::TSBPDSND != 0;
        self.tsbpd = Some(Tsbpd::new(now_us, ts, self.rcv_latency_ms, self.cfg.drift_tracer));
        self.hs_pending = false;
        self.set_connected(now_us);
    }

    fn on_data(&mut self, now_us: i64, hdr: &DataHeader, payload: &[u8]) {
        let st = &mut self.stats;
        st.pkt_recv += 1;
        st.byte_recv += (payload.len() + PKT_OVERHEAD) as u64;
        if hdr.msgno == 0 {
            // packet-filter (FEC) packet: never enters the buffer
            st.pkt_rcv_filter_extra += 1;
            if self.fec_rx.is_some() {
                self.on_fec_packet(now_us, hdr, payload);
            }
            return;
        }
        if hdr.key != 0 {
            // as libsrt without crypto: count it and drop it (one stray or
            // forged packet must not close the connection)
            st.pkt_rcv_undecrypt += 1;
            return;
        }
        if payload.len() > self.max_payload {
            st.pkt_recv_malformed += 1;
            return;
        }
        if hdr.rexmit {
            st.pkt_rcv_retrans += 1;
        }
        // loss as libsrt counts it: gaps in the arrival sequence, before
        // any FEC rebuild
        let d = seq_off(self.phy_highest, hdr.seq);
        if d > 1 {
            st.pkt_rcv_loss += (d - 1) as u64;
            st.byte_rcv_loss += (d - 1) as u64 * (payload.len() + PKT_OVERHEAD) as u64;
        }
        if d > 0 {
            self.phy_highest = hdr.seq;
        }
        if !self.rcv_started {
            self.rcv_started = true;
            self.next_ack_us = now_us + SYN_US;
            self.last_full_ack_us = now_us;
        }
        if seq_off(self.rcv.base, hdr.seq) >= self.rcv.capacity() as i32 && self.rcv.len() == 0 && self.tsbpd_rcv && self.cfg.tlpktdrop {
            self.rcv_resync(hdr.seq);
        }
        match self.rcv.insert(hdr.seq, payload, hdr.timestamp, hdr.msgno, hdr.rexmit) {
            Insert::Stored { loss, filled_hole } => {
                if !hdr.rexmit {
                    self.last_data_ts = hdr.timestamp;
                }
                self.on_stored(now_us, hdr.seq, hdr.timestamp, payload.len(), hdr.rexmit, false, loss, filled_hole);
                if let Some(mut rx) = self.fec_rx.take() {
                    rx.feed(hdr.seq, payload, hdr.timestamp, hdr.key, None);
                    self.fec_rebuild(now_us, &mut rx);
                    if !hdr.rexmit {
                        // groups ending before this packet are closed
                        let mut rel = std::mem::take(&mut self.fec_rel);
                        rel.clear();
                        if rx.advance(hdr.seq, &self.rcv, &mut rel) {
                            // beyond the group history: nothing before it
                            // can be rebuilt any more
                            let base = self.rcv.base;
                            self.fec_release_range(now_us, base, seq_dec(hdr.seq));
                        }
                        self.fec_release(now_us, &rx, &mut rel);
                        self.fec_rel = rel;
                    }
                    self.fec_rx = Some(rx);
                }
            }
            Insert::Belated => self.stats.pkt_rcv_belated += 1,
            Insert::Duplicate => self.stats.pkt_rcv_duplicate += 1,
            Insert::TooFar => self.stats.pkt_rcv_too_far += 1,
        }
        self.pkts_since_ack += 1;
        if self.pkts_since_ack >= LIGHT_ACK_PKTS && self.ack_due.is_none() && self.rcv.ack != self.last_ack_seq {
            self.ack_due = Some(AckKind::Light);
            self.pkts_since_ack = 0;
        }
    }

    /// A packet `seq` beyond the receive buffer with the buffer empty: the
    /// gap (an outage, or a sender-side drop longer than the buffer) can no
    /// longer be delivered. libsrt breaks the connection here ("sequence
    /// discrepancy", spec 6.2 step 3); we restart the window half a buffer
    /// before `seq` instead: what came before is given up (counted as
    /// dropped), the half buffer before `seq` becomes an ordinary loss
    /// (NAKed; a sender that no longer holds it answers with DROPREQ) and
    /// reception goes on.
    fn rcv_resync(&mut self, seq: u32) {
        let back = (self.rcv.capacity() / 2) as i32;
        let nb = crate::seq::seq_add(seq, -back);
        let gone = seq_off(self.rcv.base, nb).max(0) as u64;
        self.stats.pkt_rcv_resync += 1;
        self.stats.pkt_rcv_drop += gone;
        self.stats.byte_rcv_drop += gone * (self.cfg.payload_size + PKT_OVERHEAD) as u64;
        self.rcv.resync(nb);
        self.rcv_loss.remove_before(nb);
        if seq_lt(self.phy_highest, seq_dec(nb)) {
            self.phy_highest = seq_dec(nb);
        }
    }

    /// A packet entered the receive buffer (received, or rebuilt by FEC).
    #[allow(clippy::too_many_arguments)]
    fn on_stored(&mut self, now_us: i64, seq: u32, ts: u32, len: usize, rexmit: bool, rebuilt: bool, loss: Option<(u32, u32)>, filled_hole: bool) {
        let st = &mut self.stats;
        if !rebuilt {
            st.pkt_recv_unique += 1;
            st.byte_recv_unique += (len + PKT_OVERHEAD) as u64;
            self.rate_pkts += 1;
            self.rate_bytes += (len + PKT_OVERHEAD) as u64;
            self.rcv_pkt_count += 1;
        }
        if let Some((a, b)) = loss {
            self.on_loss(now_us, a, b, ts);
        }
        if filled_hole {
            if let Some(f) = self.rcv_loss.fill(seq) {
                self.stats.pkt_rcv_repaired += 1;
                if rexmit && f.naks == 1 {
                    self.nak_rtt_sample(now_us - f.last_nak_us);
                }
                if !rexmit && !rebuilt {
                    self.reorder_sample(now_us, now_us - f.detected_us);
                }
            }
        }
        self.release_reordered(now_us);
    }

    /// A FEC packet (spec 8.5, 8.6).
    fn on_fec_packet(&mut self, now_us: i64, hdr: &DataHeader, payload: &[u8]) {
        let Some(mut rx) = self.fec_rx.take() else { return };
        let g = rx.on_fec(hdr.seq, payload, hdr.timestamp);
        self.fec_rebuild(now_us, &mut rx);
        if g.is_some() {
            // the data packet it follows was sent: a loss at the tail of a
            // burst is known now, not when the next burst comes
            if let Some((a, b)) = self.rcv.note_sent_upto(hdr.seq) {
                self.stats.pkt_rcv_fec_tail_loss += (seq_off(a, b) + 1) as u64;
                let ts = self.last_data_ts;
                self.on_loss(now_us, a, b, ts);
            }
        }
        if let Some(g) = g {
            let mut rel = std::mem::take(&mut self.fec_rel);
            rel.clear();
            rx.close(g, &self.rcv, &mut rel);
            self.fec_release(now_us, &rx, &mut rel);
            self.fec_rel = rel;
        }
        self.fec_rx = Some(rx);
    }

    /// Insert every packet the filter can rebuild (iteratively: a rebuilt
    /// packet may complete its other group).
    fn fec_rebuild(&mut self, now_us: i64, rx: &mut FecRx) {
        while let Some(r) = rx.next_rebuild() {
            if let Insert::Stored { loss, filled_hole } = self.rcv.insert(r.seq, rx.rebuilt(&r), r.timestamp, 1, false) {
                self.stats.pkt_rcv_filter_supply += 1;
                self.on_stored(now_us, r.seq, r.timestamp, r.len, false, true, loss, filled_hole);
                rx.feed_rebuilt(&r);
            }
        }
    }

    /// The filter found these offsets unrebuildable: their first NAK is
    /// due now (`arq:onreq`/`always`; nothing with `never`).
    fn fec_release(&mut self, now_us: i64, rx: &FecRx, rel: &mut [i64]) {
        if rel.is_empty() {
            return;
        }
        rel.sort_unstable();
        let mut i = 0;
        while i < rel.len() {
            let a = rel[i];
            let mut b = a;
            while i + 1 < rel.len() && rel[i + 1] <= b + 1 {
                i += 1;
                b = rel[i];
            }
            self.fec_release_range(now_us, rx.seq_of(a), rx.seq_of(b));
            i += 1;
        }
    }

    fn fec_release_range(&mut self, now_us: i64, first: u32, last: u32) {
        match self.arq {
            // counted as libsrt does (fec.cpp reports losses only for onreq)
            Some(ArqLevel::OnReq) => self.stats.pkt_rcv_filter_loss += self.rcv_loss.release_range(first, last, now_us),
            Some(ArqLevel::Always) => {
                self.rcv_loss.release_range(first, last, now_us);
            }
            _ => {}
        }
    }

    /// With FEC (`onreq`/`always`), how long a new loss waits for the filter
    /// before its first NAK at most: half of what the latency leaves after
    /// two NAK rounds, within [5 ms, latency / 4]; with `always` also at
    /// most half an RTT (libsrt: `onreq` NAKs only what the filter reports,
    /// up to two matrices late; `always` NAKs at once).
    fn fec_nak_cap_us(&self) -> i64 {
        if self.cfg.fec_nak_cap_us > 0 {
            return self.cfg.fec_nak_cap_us as i64;
        }
        let lat = self.rcv_latency_ms as i64 * 1000;
        let rt = self.renak_interval_us();
        let cap = ((lat - 2 * rt) / 2).clamp(FEC_NAK_CAP_MIN_US, (lat / 4).max(FEC_NAK_CAP_MIN_US));
        if self.arq == Some(ArqLevel::Always) {
            cap.min((self.srtt as i64 / 2).max(2_000))
        } else {
            cap
        }
    }

    /// How long a new hole waits for a reordered packet before its first
    /// NAK: LOSSMAXTTL's time bound when set, else the automatic reorder
    /// wait (0 until the path is seen to reorder).
    fn reorder_wait_us(&self) -> i64 {
        if self.cfg.loss_max_ttl > 0 {
            return self.cfg.reorder_window_us as i64;
        }
        if !self.cfg.auto_reorder {
            return 0;
        }
        let w = self.reorder_cur_us.max(self.reorder_prev_us);
        if w == 0 {
            return 0;
        }
        let lat = self.rcv_latency_ms as i64 * 1000;
        let cap = (lat / 8).min((self.srtt as i64 / 2).max(REORDER_MIN_CAP_US));
        w.min(cap)
    }

    /// An original packet filled a hole `late` µs after it was found
    /// missing: the path reorders by about that much.
    fn reorder_sample(&mut self, now_us: i64, late: i64) {
        self.stats.pkt_rcv_reordered += 1;
        self.roll_reorder_window(now_us);
        self.reorder_cur_us = self.reorder_cur_us.max(late + REORDER_MARGIN_US);
    }

    fn roll_reorder_window(&mut self, now_us: i64) {
        if now_us - self.reorder_win_us >= HOLDOFF_WINDOW_US {
            // a whole window without reordering ends the previous one too
            self.reorder_prev_us = if now_us - self.reorder_win_us >= 2 * HOLDOFF_WINDOW_US { 0 } else { self.reorder_cur_us };
            self.reorder_cur_us = 0;
            self.reorder_win_us = now_us;
        }
    }

    /// Release waiting holes whose reorder wait (or LOSSMAXTTL) is over.
    fn release_reordered(&mut self, now_us: i64) {
        if self.rcv_loss.oldest_waiting().is_none() {
            return;
        }
        self.roll_reorder_window(now_us);
        let ttl = if self.cfg.loss_max_ttl > 0 { self.cfg.loss_max_ttl } else { u32::MAX };
        let w = self.reorder_wait_us();
        self.rcv_loss.release_waiting(now_us, self.rcv_pkt_count, ttl, w);
    }

    /// A new gap `a..=b`, revealed by a packet with timestamp `ts`: NAK it
    /// at once, or after the reorder tolerance (spec 6.3).
    fn on_loss(&mut self, now_us: i64, a: u32, b: u32, ts: u32) {
        let deadline_us = match (&self.tsbpd, self.tsbpd_rcv && self.cfg.tlpktdrop) {
            (Some(t), true) => t.due_us(ts),
            _ => NEVER,
        };
        // with FEC the first NAK waits for the filter (or the cap); with
        // arq:never there is none
        let first_nak_us = match self.arq {
            None => now_us,
            Some(ArqLevel::Never) => NEVER,
            Some(_) => now_us + self.fec_nak_cap_us(),
        };
        let wait = self.arq.is_none() && self.peer_flags & flags::REXMITFLG != 0 && self.reorder_wait_us() > 0;
        self.rcv_loss.push(
            Hole {
                first: a,
                last: b,
                next_nak_us: first_nak_us,
                last_nak_us: now_us,
                naks: 0,
                detected_us: now_us,
                detected_at_pkt: self.rcv_pkt_count,
                deadline_us,
            },
            wait,
        );
    }

    /// One NAK -> repair time sample (a retransmission filling a hole that
    /// was NAKed exactly once), smoothed as RTT is.
    fn nak_rtt_sample(&mut self, r: i64) {
        if r <= 0 {
            return;
        }
        self.nak_rtt_max = self.nak_rtt_max.max(r);
        if self.nak_rtt_valid {
            self.nak_rttvar = (3 * self.nak_rttvar + (r - self.nak_srtt).abs()) / 4;
            self.nak_srtt = (7 * self.nak_srtt + r) / 8;
        } else {
            self.nak_srtt = r;
            self.nak_rttvar = r / 8;
            self.nak_rtt_valid = true;
        }
        self.maybe_reschedule_naks();
    }

    /// After an RTT or repair-time update: if the re-NAK interval fell by a
    /// quarter, bring the scheduled re-NAKs forward.
    fn maybe_reschedule_naks(&mut self) {
        let i = self.renak_interval_us();
        if self.renak_sched_us != NEVER && i < self.renak_sched_us * 3 / 4 {
            self.rcv_loss.reschedule(i);
            self.renak_sched_us = i;
        }
    }

    /// How long after a NAK a hole is NAKed again: the expected repair time
    /// (the larger of the RTT and the measured NAK -> repair time, which
    /// includes the sender's queueing) + 4 x its variation + a margin.
    fn renak_interval_us(&self) -> i64 {
        let (mut rt, mut rv) = (self.srtt as i64, self.rttvar as i64);
        if self.nak_rtt_valid {
            // the measured repair time and its own variation: many samples
            // (one per repaired loss), while RTTVar (from ACKACKs, rare
            // while a hole holds the ACK) starts at RTT/2 and settles slowly
            rt = rt.max(self.nak_srtt);
            rv = self.nak_rttvar;
        }
        // the variation term is capped at RTT/2: a premature re-NAK only
        // costs a request the sender suppresses (it arrives before the
        // repair could)
        (rt + (4 * rv).min(rt / 2) + NAK_MARGIN_US).max(NAK_MIN_INTERVAL_US)
    }

    fn on_dropreq(&mut self, first: u32, last: u32) {
        self.stats.pkt_recv_dropreq += 1;
        // malformed or absurdly far: ignore (as libsrt)
        if seq_lt(last, first) || seq_off(self.rcv.base, first).unsigned_abs() > (1 << 29) {
            return;
        }
        self.stats.pkt_rcv_dropreq_seqs += self.rcv_loss.remove_range(first, last);
        if !seq_le(first, seq_inc(self.rcv.highest)) {
            return; // a range after a gap we do not know about yet
        }
        // unsent or dropped packets beyond what we received: not a loss
        // when the next packet comes
        self.rcv.note_dropped_upto(last);
        if seq_lt(self.phy_highest, self.rcv.highest) {
            self.phy_highest = self.rcv.highest;
        }
        if seq_le(first, self.rcv.base) {
            // the head is given up by the sender: move the delivery point
            // (and the ACK) over it now instead of at the next packet's
            // play time, so the window never wedges on it
            let n = self.rcv.skip_absent(last);
            if n > 0 {
                self.stats.pkt_rcv_drop += n as u64;
                self.stats.byte_rcv_drop += n as u64 * (self.cfg.payload_size + PKT_OVERHEAD) as u64;
                self.rcv_loss.remove_before(self.rcv.base);
            }
        }
    }

    fn on_nak(&mut self, l: &LossList<'_>) {
        self.stats.pkt_recv_nak += 1;
        for (mut first, last) in l.ranges() {
            if seq_lt(last, first) || !seq_lt(last, self.snd.next_send) {
                // beyond what we sent (libsrt would break the connection)
                self.stats.nak_invalid += 1;
                continue;
            }
            self.stats.pkt_snd_loss += (seq_off(first, last) + 1) as u64;
            let una = self.snd.una;
            if seq_lt(first, una) {
                // acknowledged or dropped: we no longer hold it
                let dl = if seq_lt(last, una) { last } else { seq_dec(una) };
                self.queue_dropreq(first, dl);
                if seq_lt(last, una) {
                    continue;
                }
                first = una;
            }
            self.snd_loss.insert(first, last);
        }
    }

    fn queue_dropreq(&mut self, first: u32, last: u32) {
        if let Some(b) = self.dropreqs.back_mut() {
            if seq_le(b.0, first) && seq_le(first, seq_inc(b.1)) {
                if seq_lt(b.1, last) {
                    b.1 = last;
                }
                return;
            }
        }
        if self.dropreqs.len() >= MAX_DROPREQ_QUEUE {
            self.dropreqs.pop_front();
        }
        self.dropreqs.push_back((first, last));
    }

    /// The ACK stops at `x`, the oldest packet the receiver lacks. If `x`
    /// was last sent more than an RTT ago it should have been there when
    /// the ACK was made: its last copy was lost, so send it again without
    /// waiting for another NAK (the oldest hole is the closest to its
    /// deadline; a NAK crossing this is suppressed as a duplicate).
    fn ack_head_check(&mut self, now_us: i64, x: u32) {
        if !self.sender_arq() || !self.rtt_known() || x == self.snd.next_send || !self.snd.holds_sent(x) {
            return;
        }
        let age = now_us - self.snd.last_tx_us(x);
        if age > self.ack_head_threshold_us(x) {
            self.snd_loss.insert(x, x);
            self.stats.pkt_ack_rexmit += 1;
        }
    }

    /// How long after its last copy an ACK may still stop at `x` before
    /// `x` is taken as lost: SRTT + 2 RTTVar + a margin; with FEC, for a
    /// packet never retransmitted, also the FEC wait (a receiver holds its
    /// ACK on a hole its filter will still rebuild; libsrt: up to two
    /// matrices; only a longer stall means a loss whose one-shot `onreq`
    /// NAK never came or was lost).
    fn ack_head_threshold_us(&self, x: u32) -> i64 {
        let mut thr = self.srtt as i64 + 2 * self.rttvar as i64 + ACK_HEAD_MARGIN_US;
        if self.fec_tx.is_some() && self.snd.rexmits(x) == 0 {
            thr += match self.cfg.fec_ack_head_delay_us {
                d if d >= 0 => d as i64,
                _ => (self.snd_latency_ms as i64 * 1000 / 4).max(SYN_US),
            };
        }
        thr
    }

    /// With FEC: when the oldest unacknowledged packet, never
    /// retransmitted, is still unacknowledged an ACK-head threshold and one
    /// ACK period after it was sent, send it again. A libsrt `onreq`
    /// receiver reports a loss only when a group closes, never one in the
    /// last, unfinished group at the end of a stream, nor those its filter
    /// forgets on a reset; it repeats a stuck ACK only until it is ACKACKed,
    /// so the ACK-head check on ACK arrival may never see the stall.
    fn stall_probe_at_us(&self) -> Option<i64> {
        if self.fec_tx.is_none() || !self.cfg.tail_probe || !self.sender_arq() || self.snd.in_flight() == 0 || !self.rtt_known() {
            return None;
        }
        let una = self.snd.una;
        if self.snd.rexmits(una) > 0 || self.snd_loss.peek() == Some(una) || self.rexmit_copy == Some(una) || self.probe_dead == Some(una) {
            return None; // repaired before: the head probe watches it
        }
        Some(self.snd.last_tx_us(una) + self.ack_head_threshold_us(una) + self.ack_wait_us())
    }

    fn on_ack(&mut self, now_us: i64, ackno: u32, a: &Ack) {
        self.stats.pkt_recv_ack += 1;
        if !seq_le(a.seq, self.snd.next_send) {
            // beyond what we sent (libsrt would break the connection)
            self.stats.ack_invalid += 1;
            return;
        }
        self.holdoff_sample(now_us, a.seq);
        if a.kind == AckKind::Light {
            self.stats.pkt_recv_light_ack += 1;
            self.snd.ack(a.seq);
            self.snd_loss.remove_before(self.snd.una);
            self.ack_head_check(now_us, a.seq);
            return;
        }
        if self.ackacks.len() >= MAX_ACKACK_QUEUE {
            self.ackacks.pop_front();
        }
        self.ackacks.push_back(ackno);
        self.peer_fw = a.avail_buf;
        self.snd.ack(a.seq);
        self.snd_loss.remove_before(self.snd.una);
        if !(a.rtt_us == INIT_RTT_US && a.rtt_var_us == INIT_RTTVAR_US) && a.rtt_us > 0 {
            if self.rtt_own {
                self.rttvar = ((3 * self.rttvar as u64 + (a.rtt_us as i64 - self.srtt as i64).unsigned_abs()) / 4) as u32;
                self.srtt = ((7 * self.srtt as u64 + a.rtt_us as u64) / 8) as u32;
            } else {
                self.srtt = a.rtt_us;
                self.rttvar = a.rtt_var_us;
            }
            self.rtt_valid = true;
        }
        self.ack_head_check(now_us, a.seq);
    }

    /// One ACK hold-off sample from an ACK advancing to `ack`: the newest
    /// packet it covers waited (now - its last send - SRTT) beyond a round
    /// trip for its ACK. Skipped when a retransmitted packet may be in the
    /// newly acknowledged range (the ACK was held by a hole, not by the
    /// peer's ACK timer) or before an RTT sample.
    fn holdoff_sample(&mut self, now_us: i64, ack: u32) {
        if !self.rtt_valid || !seq_lt(self.snd.una, ack) {
            return;
        }
        // the newest packet covered that was sent once (a tail probe's
        // original may have arrived; the packet before it was sent with it)
        let mut newest = seq_dec(ack);
        if self.snd.holds_sent(newest) && self.snd.rexmits(newest) > 0 {
            newest = seq_dec(newest);
            if !seq_le(self.snd.una, newest) || self.snd.rexmits(newest) > 0 {
                return;
            }
        }
        match self.rexmit_hi {
            Some(h) if seq_le(self.snd.una, h) => return,
            Some(_) => self.rexmit_hi = None, // all behind: forget (no wrap ambiguity later)
            None => {}
        }
        if !self.snd.holds_sent(newest) {
            return;
        }
        let h = (now_us - self.snd.last_tx_us(newest) - self.srtt as i64).max(0);
        if now_us - self.holdoff_win_us >= HOLDOFF_WINDOW_US {
            self.holdoff_prev_us = self.holdoff_cur_us;
            self.holdoff_cur_us = 0;
            self.holdoff_win_us = now_us;
        }
        self.holdoff_cur_us = self.holdoff_cur_us.max(h);
    }

    /// How long a probe waits for the peer's ACK beyond the round trip:
    /// one ACK period, or the measured hold-off (capped at latency / 2).
    fn ack_wait_us(&self) -> i64 {
        if !self.cfg.probe_ack_lag {
            return SYN_US;
        }
        let cap = (self.snd_latency_ms as i64 * 1000 / 2).max(SYN_US);
        self.holdoff_cur_us.max(self.holdoff_prev_us).min(cap).max(SYN_US)
    }

    fn on_ackack(&mut self, now_us: i64, ackno: u32, ts: u32) {
        self.stats.pkt_recv_ackack += 1;
        let r = self.ack_window[ackno as usize % ACK_WINDOW];
        if r.ackno != ackno || ackno == 0 {
            return;
        }
        let rtt = now_us - r.sent_us;
        if rtt <= 0 {
            return;
        }
        let rtt32 = rtt.min(u32::MAX as i64) as u32;
        if self.rtt_own {
            self.rttvar = ((3 * self.rttvar as u64 + (rtt32 as i64 - self.srtt as i64).unsigned_abs()) / 4) as u32;
            self.srtt = ((7 * self.srtt as u64 + rtt32 as u64) / 8) as u32;
        } else {
            self.srtt = rtt32;
            self.rttvar = rtt32 / 2;
            self.rtt_own = true;
        }
        self.rtt_valid = true;
        if seq_lt(self.last_ackack_seq, r.seq) {
            self.last_ackack_seq = r.seq;
        }
        if let Some(t) = self.tsbpd.as_mut() {
            t.drift_sample(ts, now_us, Some(rtt));
        }
        self.maybe_reschedule_naks();
    }

    // ------------------------------------------------------------ timers

    /// Run timers; call when `poll_timeout()` is reached (calling more
    /// often is harmless).
    pub fn handle_timeout(&mut self, now: Instant) {
        let now_us = self.us(now);
        match self.state {
            State::Induction | State::Conclusion => {
                if now_us >= self.hs_deadline_us {
                    self.set_closed(CloseReason::ConnectTimeout);
                } else if now_us >= self.hs_next_us {
                    // re-send on the same socket, ID, ISN and port
                    self.hs_pending = true;
                    self.hs_interval_us = (self.hs_interval_us * 2).min(HS_MAX_US);
                    self.hs_next_us = now_us + self.hs_interval_us;
                }
            }
            State::Connected => {
                if now_us - self.last_recv_us > self.cfg.peer_idle_timeout.as_micros() as i64 {
                    return self.set_closed(CloseReason::PeerIdle);
                }
                if self.role == Role::Listener && self.hs_resends_left > 0 && now_us >= self.hs_next_us {
                    if self.peer_heard {
                        self.hs_resends_left = 0;
                    } else {
                        self.hs_pending = true;
                        self.hs_resends_left -= 1;
                        self.hs_interval_us = (self.hs_interval_us * 2).min(HS_MAX_US);
                        self.hs_next_us = now_us + self.hs_interval_us;
                    }
                }
                if now_us >= self.next_ack_us {
                    self.next_ack_us = now_us + SYN_US;
                    if self.rcv_started {
                        self.ack_timer(now_us);
                    }
                }
                if now_us - self.last_send_us >= KEEPALIVE_US {
                    self.keepalive_due = true;
                }
                self.release_reordered(now_us);
                if let Some(t) = self.probe_at_us() {
                    if now_us >= t {
                        // the newest packet: if it was lost the receiver
                        // learns it now; if not, one duplicate
                        self.probe_armed = false;
                        let s = seq_dec(self.snd.next_send);
                        self.snd_loss.insert(s, s);
                        self.tail_probe_seq = Some(s);
                        self.stats.pkt_tail_probe += 1;
                    }
                }
                if let Some(t) = self.head_probe_at_us() {
                    if now_us >= t {
                        let s = self.snd.una;
                        if self.rexmit_too_late(s, now_us) {
                            self.probe_dead = Some(s);
                        } else {
                            self.snd_loss.insert(s, s);
                            self.stats.pkt_head_probe += 1;
                        }
                    }
                }
                if let Some(t) = self.stall_probe_at_us() {
                    if now_us >= t {
                        let s = self.snd.una;
                        if self.rexmit_too_late(s, now_us) {
                            self.probe_dead = Some(s);
                        } else {
                            self.snd_loss.insert(s, s);
                            self.stall_probe_seq = Some(s);
                            self.stats.pkt_stall_probe += 1;
                        }
                    }
                }
                self.sender_drop(now_us);
            }
            State::Closed(_) => {}
        }
    }

    fn ack_timer(&mut self, now_us: i64) {
        let ack = self.rcv.ack;
        let rto = self.srtt as i64 + 4 * self.rttvar as i64;
        let unconfirmed = seq_lt(self.last_ackack_seq, ack);
        // also while holes hold the ACK value, so RTT samples keep coming
        let rtt_probe = !self.rcv_loss.is_empty() && now_us - self.last_ack_us >= ACK_RTT_PROBE_US;
        // flow window (libsrt's m_bBufferWasFull, done a little better):
        // after we advertised little or no room, tell the sender as soon as
        // the reader frees some, and repeat while it stays small; otherwise
        // a sender whose window closed (it then sends nothing, so the ACK
        // value never changes) waits forever
        let small = self.adv_avail < (self.rcv.capacity() / 4).max(1);
        if small && (self.rcv.available() > self.adv_avail || now_us - self.last_ack_us > rto) {
            self.ack_due = Some(AckKind::Full);
            self.stats.pkt_sent_window_ack += 1;
        } else if ack != self.last_ack_seq || (unconfirmed && now_us - self.last_ack_us > rto) || rtt_probe {
            self.ack_due = Some(if now_us - self.last_full_ack_us >= SYN_US {
                AckKind::Full
            } else {
                AckKind::Small
            });
        }
        self.pkts_since_ack = 0;
    }

    /// When the tail probe is due (armed after new data, nothing unsent,
    /// the newest packets not acknowledged).
    fn probe_at_us(&self) -> Option<i64> {
        if !self.cfg.tail_probe || !self.sender_arq() || !self.probe_armed || self.snd.unsent() > 0 || self.snd.in_flight() == 0 {
            return None;
        }
        Some(self.last_data_tx_us + self.probe_delay_us())
    }

    /// How long without an ACK past a packet before probing it: one RTT,
    /// its variation (at most RTT/2), one ACK period and a margin.
    fn probe_delay_us(&self) -> i64 {
        let r = self.srtt as i64;
        r + (4 * self.rttvar as i64).min(r / 2) + self.ack_wait_us() + PROBE_MARGIN_US
    }

    /// RTT from ACK/ACKACK samples or the handshake estimate.
    #[inline]
    fn rtt_known(&self) -> bool {
        self.rtt_valid || self.rtt_seeded
    }

    /// Head probe: when the oldest unacknowledged packet was retransmitted
    /// before, last sent a probe delay ago, and no ACK has passed it, its
    /// last copy (or the NAK for it) was lost: send it again. Covers a lost repair whose re-NAK
    /// would come too late (a libsrt receiver re-NAKs after 300 ms until it
    /// has an RTT sample, then every max(RTT/2, 20 ms) with only one NAK
    /// per attempt), and does not depend on ACKs being repeated.
    fn head_probe_at_us(&self) -> Option<i64> {
        if !self.cfg.tail_probe || !self.sender_arq() || self.snd.in_flight() == 0 || !self.rtt_known() {
            return None;
        }
        let una = self.snd.una;
        // only a packet already repaired at least once (its loss is known;
        // a slow ACK of a packet never reported lost is not a reason)
        if self.snd.rexmits(una) == 0 || self.snd_loss.peek() == Some(una) || self.rexmit_copy == Some(una) || self.probe_dead == Some(una) {
            return None;
        }
        Some(self.snd.last_tx_us(una) + self.probe_delay_us())
    }

    /// Sender drop of too-late packets (spec 7.6, 12 #8), on a timer. The
    /// dropped range is announced with a DROPREQ so the receiver stops
    /// asking for it.
    fn sender_drop(&mut self, now_us: i64) {
        let Some(thr) = self.snd_drop_threshold_us() else { return };
        let first = self.snd.una;
        let (n, bytes, unsent) = self.snd.drop_older_than(now_us - thr);
        if n > 0 {
            self.stats.pkt_snd_drop += n as u64;
            self.stats.byte_snd_drop += bytes + n as u64 * PKT_OVERHEAD as u64;
            self.stats.pkt_snd_drop_unsent += unsent as u64;
            self.snd_loss.remove_before(self.snd.una);
            self.queue_dropreq(first, seq_dec(self.snd.una));
        }
    }

    /// How long past its origin a packet is held: the peer's latency (+
    /// SNDDROPDELAY) + max(latency / 4, 20 ms) + 2 SRTT + one ACK period.
    /// A retransmission later than origin + latency arrives after the
    /// receiver gave the packet up (it drops a gap when the next present
    /// packet is due, one way after), and the ACK past such a gap reaches
    /// us within one ACK period and one way after that; the rest is margin
    /// so that packets the receiver has are released by its ACK, not
    /// dropped here. libsrt holds max(latency + SNDDROPDELAY, 1 s) + 20 ms.
    fn snd_drop_threshold_us(&self) -> Option<i64> {
        if self.peer_flags & flags::TLPKTDROP == 0 || self.cfg.snd_drop_delay_ms < 0 || !self.cfg.tlpktdrop {
            return None;
        }
        let lat = (self.snd_latency_ms as i64 + self.cfg.snd_drop_delay_ms as i64) * 1000;
        let rtt = if self.rtt_known() { 2 * self.srtt as i64 } else { 0 };
        Some(lat + (lat / 4).max(SND_DROP_MARGIN_US) + rtt + SYN_US)
    }

    /// Do not retransmit a packet (re)sent less than this long ago: the
    /// request was sent before the previous copy could have arrived.
    fn rexmit_suppress_us(&self) -> i64 {
        if !self.rtt_known() {
            return 0;
        }
        let (r, v) = (self.srtt as i64, self.rttvar as i64);
        (r - v).max(r / 2)
    }

    /// The earliest time `handle_timeout` should run, or a message becomes
    /// deliverable, or the pacer allows the next packet.
    pub fn poll_timeout(&self) -> Option<Instant> {
        let t = match self.state {
            State::Induction | State::Conclusion => Some(self.hs_next_us.min(self.hs_deadline_us)),
            State::Connected => {
                let mut t = self.last_recv_us + self.cfg.peer_idle_timeout.as_micros() as i64 + 1;
                t = t.min(self.last_send_us + KEEPALIVE_US);
                if self.rcv_started {
                    t = t.min(self.next_ack_us);
                }
                if self.role == Role::Listener && self.hs_resends_left > 0 && !self.peer_heard {
                    t = t.min(self.hs_next_us);
                }
                if let Some(d) = self.next_delivery_us() {
                    t = t.min(d);
                }
                if self.snd.unsent() > 0 && self.window_open() {
                    t = t.min(self.pacer.next_ns() / 1000 + self.cfg.pace_quantum_us as i64);
                }
                if !self.snd_loss.is_empty() || self.rexmit_copy.is_some() || self.fec_tx.as_ref().map_or(false, |f| f.has_pending()) {
                    t = t.min(self.pacer.next_ns() / 1000);
                }
                t = t.min(self.rcv_loss.next_due());
                if !self.nak_copy.is_empty() {
                    t = t.min(self.nak_copy_at_us);
                }
                if let Some(h) = self.rcv_loss.oldest_waiting() {
                    t = t.min(h.detected_us + self.reorder_wait_us());
                }
                if let Some(p) = self.probe_at_us() {
                    t = t.min(p);
                }
                if let Some(p) = self.head_probe_at_us() {
                    t = t.min(p);
                }
                if let Some(p) = self.stall_probe_at_us() {
                    t = t.min(p);
                }
                if let (Some(thr), Some(o)) = (self.snd_drop_threshold_us(), self.snd.oldest_origin_us()) {
                    t = t.min(o + thr + 1);
                }
                Some(t)
            }
            State::Closed(_) => self.next_delivery_us(),
        };
        t.map(|us| self.at(us))
    }

    fn next_delivery_us(&self) -> Option<i64> {
        let tsbpd = self.tsbpd.as_ref()?;
        if let Some(h) = self.rcv.head() {
            return Some(if self.tsbpd_rcv { tsbpd.due_us(h.timestamp) } else { 0 });
        }
        if !self.tsbpd_rcv || !self.cfg.tlpktdrop {
            return None;
        }
        self.rcv.first_present().map(|p| tsbpd.due_us(p.timestamp))
    }

    #[inline]
    fn window_open(&self) -> bool {
        self.snd.in_flight() < self.peer_fw.min(self.snd.capacity())
    }

    // ------------------------------------------------------------ output

    /// Write the next datagram to send into `buf` (>= 1500 bytes).
    pub fn poll_transmit(&mut self, now: Instant, buf: &mut [u8]) -> Option<Transmit> {
        let now_us = self.us(now);
        let ts = now_us as u64 as u32;
        let len = self.next_datagram(now_us, ts, buf)?;
        self.last_send_us = now_us;
        self.stats.datagrams_sent += 1;
        Some(Transmit { len, dst: self.peer })
    }

    fn next_datagram(&mut self, now_us: i64, ts: u32, buf: &mut [u8]) -> Option<usize> {
        if self.shutdown_due {
            self.shutdown_due = false;
            return Some(packet::encode_shutdown(ts, self.peer_sid, buf));
        }
        if self.hs_pending {
            self.hs_pending = false;
            let hs = self.hs.as_ref()?;
            self.hs_sent_us = now_us;
            self.hs_sends += 1;
            self.stats.pkt_sent_handshake += 1;
            return Some(packet::encode_handshake(hs, ts, self.hs_dst, buf));
        }
        if self.state != State::Connected {
            return None;
        }
        if let Some(no) = self.ackacks.pop_front() {
            self.stats.pkt_sent_ackack += 1;
            return Some(packet::encode_ackack(no, ts, self.peer_sid, buf));
        }
        if let Some(kind) = self.ack_due.take() {
            return Some(self.encode_ack(kind, now_us, ts, buf));
        }
        if !self.nak_copy.is_empty() && (now_us >= self.nak_copy_at_us || self.rcv_loss.next_due() <= now_us) {
            let n = self.nak_copy.len();
            buf[..n].copy_from_slice(&self.nak_copy);
            buf[8..12].copy_from_slice(&ts.to_be_bytes()); // control timestamp = now
            self.nak_copy.clear();
            self.nak_copy_at_us = NEVER;
            self.stats.pkt_sent_nak += 1;
            return Some(n);
        }
        if self.rcv_loss.next_due() <= now_us {
            if let Some((n, late)) = self.encode_due_nak(now_us, ts, buf) {
                if self.cfg.repair_copies {
                    // every NAK goes twice, so a lost NAK does not cost a
                    // round: at once for a first attempt (the sender sees
                    // both before it repairs: one repair); a little later
                    // for a late attempt, so a sender that serves every
                    // request (libsrt, given our RTTVar floor) sends a
                    // second repair after its first
                    self.nak_copy.extend_from_slice(&buf[..n]);
                    self.nak_copy_at_us = if late { now_us + self.nak_copy_spacing_us() } else { now_us };
                }
                return Some(n);
            }
        }
        if let Some((first, last)) = self.dropreqs.pop_front() {
            self.stats.pkt_sent_dropreq += 1;
            return Some(packet::encode_dropreq(0, first, last, ts, self.peer_sid, buf));
        }
        if self.keepalive_due {
            self.keepalive_due = false;
            self.stats.pkt_sent_keepalive += 1;
            return Some(packet::encode_keepalive(ts, self.peer_sid, buf));
        }
        // retransmissions first: they are older than any new packet, so
        // their deadline is earlier (spec 12 #6); same pacer
        if let Some(seq) = self.rexmit_copy {
            if !self.snd.holds_sent(seq) {
                self.rexmit_copy = None;
            } else if self.pacer.ready(now_us * 1000) {
                self.rexmit_copy = None;
                return Some(self.write_rexmit(seq, now_us, buf));
            } else {
                return None;
            }
        }
        if !self.snd_loss.is_empty() {
            let suppress = self.rexmit_suppress_us();
            while let Some(seq) = self.snd_loss.peek() {
                if !self.snd.holds_sent(seq) {
                    self.snd_loss.pop();
                    continue;
                }
                if now_us - self.snd.last_tx_us(seq) < suppress {
                    self.snd_loss.pop();
                    self.stats.pkt_rexmit_suppressed += 1;
                    continue;
                }
                if self.rexmit_too_late(seq, now_us) {
                    self.snd_loss.pop();
                    self.stats.pkt_rexmit_too_late += 1;
                    continue;
                }
                if !self.pacer.ready(now_us * 1000) {
                    return None;
                }
                self.snd_loss.pop();
                let n = self.snd.count_rexmit(seq);
                // a stall probe is a guess (the receiver may still rebuild
                // the packet): one copy only
                let speculative = self.stall_probe_seq == Some(seq);
                if speculative {
                    self.stall_probe_seq = None;
                }
                if self.cfg.repair_copies && !speculative && (n >= 2 || self.last_chance(seq, now_us)) {
                    // an earlier repair was lost, or there is no time for
                    // another round: send this one twice
                    self.rexmit_copy = Some(seq);
                    self.stats.pkt_rexmit_copies += 1;
                }
                return Some(self.write_rexmit(seq, now_us, buf));
            }
        }
        // FEC packets right after the data packet that completed their
        // group, before the next new one (as libsrt: after retransmissions)
        if let Some(tx) = self.fec_tx.as_mut() {
            if tx.has_pending() {
                if !self.pacer.ready(now_us * 1000) {
                    return None;
                }
                let n = tx.write_next(self.peer_sid, buf)?;
                let wire = n - HDR_LEN + PKT_OVERHEAD;
                self.pacer.charge(wire);
                self.stats.pkt_snd_filter_extra += 1;
                self.stats.pkt_sent += 1;
                self.stats.byte_sent += wire as u64;
                return Some(n);
            }
        }
        if self.snd.unsent() > 0 && self.window_open() && self.pacer.ready(now_us * 1000) {
            let seq = self.snd.next_send;
            let p = self.snd.packet(seq)?;
            let n = p.len();
            buf[..n].copy_from_slice(p);
            if let Some(tx) = self.fec_tx.as_mut() {
                tx.on_new(seq, &buf[HDR_LEN..n], rd32(buf, 8), (buf[4] >> 3) & 3);
            }
            self.snd.mark_sent(seq, now_us);
            self.snd.next_send = seq_inc(seq);
            self.last_data_tx_us = now_us;
            self.probe_armed = true;
            let wire = n - HDR_LEN + PKT_OVERHEAD;
            self.pacer.charge(wire);
            self.stats.pkt_sent += 1;
            self.stats.pkt_sent_unique += 1;
            self.stats.byte_sent += wire as u64;
            self.stats.byte_sent_unique += wire as u64;
            return Some(n);
        }
        None
    }

    /// A retransmission of `seq` sent now would reach a TSBPD receiver
    /// after its play time (it plays a packet at origin + latency + the
    /// one-way delay; the copy arrives at now + the one-way delay): skip it.
    fn rexmit_too_late(&self, seq: u32, now_us: i64) -> bool {
        if self.snd_latency_ms == 0 || self.peer_flags & flags::TSBPDRCV == 0 {
            return false;
        }
        now_us > self.snd.origin_us(seq) + self.snd_latency_ms as i64 * 1000
    }

    /// Too little time left before the receiver plays `seq` for another
    /// NAK round after this repair.
    fn last_chance(&self, seq: u32, now_us: i64) -> bool {
        if !self.rtt_known() || self.snd_latency_ms == 0 {
            return false;
        }
        let left = self.snd.origin_us(seq) + self.snd_latency_ms as i64 * 1000 - now_us;
        let r = self.srtt as i64;
        let round = 3 * r / 2 + (4 * self.rttvar as i64).min(r / 2) + LAST_CHANCE_MARGIN_US;
        left < round
    }

    /// Write a retransmission of a held, sent sequence (R = 1).
    fn write_rexmit(&mut self, seq: u32, now_us: i64, buf: &mut [u8]) -> usize {
        let p = self.snd.packet(seq).expect("held");
        let n = p.len();
        buf[..n].copy_from_slice(p);
        DataHeader::set_rexmit_in_place(buf);
        self.snd.mark_sent(seq, now_us);
        if self.tail_probe_seq == Some(seq) {
            self.tail_probe_seq = None;
        } else if self.rexmit_hi.map_or(true, |h| seq_lt(h, seq)) {
            self.rexmit_hi = Some(seq);
        }
        // a repair in flight: wait for its ACK before probing
        self.last_data_tx_us = now_us;
        let wire = n - HDR_LEN + PKT_OVERHEAD;
        self.pacer.charge(wire);
        self.stats.pkt_sent += 1;
        self.stats.pkt_retrans += 1;
        self.stats.byte_sent += wire as u64;
        self.stats.byte_retrans += wire as u64;
        n
    }

    /// A NAK listing every hole whose (re-)NAK is due, compressed into
    /// ranges, at most maxPayload / 4 words (the rest follow in the next).
    /// Delay of a NAK copy: max(RTT / 8, 10 ms), enough for the sender to
    /// have sent the first repair (libsrt queues it behind a frame burst).
    fn nak_copy_spacing_us(&self) -> i64 {
        (self.srtt as i64 / 8).max(SPREAD_MARGIN_US)
    }

    fn encode_due_nak(&mut self, now_us: i64, ts: u32, buf: &mut [u8]) -> Option<(usize, bool)> {
        let interval = self.renak_interval_us();
        let min_repair = if self.rtt_known() { self.srtt as i64 } else { 0 };
        let max_words = (self.max_payload / 4).max(2);
        let mut out = std::mem::take(&mut self.nak_scratch);
        // spread the remaining attempts up to deadline - reserve: the last
        // NAK must leave early enough for the repair (expected repair time
        // + its variation) plus the sender's queueing (libsrt sends new
        // data first: a frame burst) and its own drop (libsrt: latency +
        // 20 ms after the origin)
        let reserve = if self.rtt_known() {
            let rt = (self.srtt as i64).max(if self.nak_rtt_valid { self.nak_srtt } else { 0 });
            interval - NAK_MARGIN_US + (rt / 8).max(SPREAD_MARGIN_US)
        } else {
            0
        };
        let (seqs, late) = self
            .rcv_loss
            .collect_due(now_us, NAK_SLACK_US, interval, min_repair, reserve, max_words, &mut out);
        self.renak_sched_us = interval;
        let r = if out.is_empty() {
            None
        } else {
            self.stats.pkt_sent_nak += 1;
            self.stats.nak_seqs_sent += seqs;
            Some((packet::encode_nak(out.iter().copied(), ts, self.peer_sid, max_words, buf), late))
        };
        self.nak_scratch = out;
        r
    }

    fn encode_ack(&mut self, kind: AckKind, now_us: i64, ts: u32, buf: &mut [u8]) -> usize {
        let seq = self.rcv.ack;
        self.last_ack_seq = seq;
        self.pkts_since_ack = 0;
        if kind == AckKind::Light {
            self.stats.pkt_sent_light_ack += 1;
            return packet::encode_ack(&Ack::light(seq), 0, ts, self.peer_sid, buf);
        }
        self.ackno = ackno_inc(self.ackno);
        let mut a = Ack {
            kind,
            seq,
            rtt_us: self.srtt,
            rtt_var_us: if self.cfg.ack_rttvar_floor {
                self.rttvar.max(self.srtt / 4 + 1)
            } else {
                self.rttvar
            },
            avail_buf: self.rcv.available(),
            pkt_rate: 0,
            bandwidth: 0,
            byte_rate: 0,
        };
        if kind == AckKind::Full {
            let dt = now_us - self.last_full_ack_us;
            if dt > 0 {
                let pr = self.rate_pkts as f64 * 1e6 / dt as f64;
                let br = self.rate_bytes as f64 * 1e6 / dt as f64;
                // light smoothing, as libsrt's median filter would
                self.pkt_rate = ((self.pkt_rate as f64 * 7.0 + pr) / 8.0) as u32;
                self.byte_rate = ((self.byte_rate as f64 * 7.0 + br) / 8.0) as u32;
            }
            self.rate_pkts = 0;
            self.rate_bytes = 0;
            self.last_full_ack_us = now_us;
            a.pkt_rate = self.pkt_rate;
            a.bandwidth = self.pkt_rate;
            a.byte_rate = self.byte_rate;
        }
        self.adv_avail = a.avail_buf;
        self.ack_window[self.ackno as usize % ACK_WINDOW] = AckRec {
            ackno: self.ackno,
            seq,
            sent_us: now_us,
        };
        self.last_ack_us = now_us;
        self.stats.pkt_sent_ack += 1;
        packet::encode_ack(&a, self.ackno, ts, self.peer_sid, buf)
    }

    // ------------------------------------------------------------ application

    /// Queue one message (one packet). `origin` is the source time stamped
    /// into the packet (default `now`).
    pub fn send_message(&mut self, now: Instant, data: &[u8], origin: Option<Instant>) -> Result<u32, SendError> {
        if self.state != State::Connected {
            return Err(SendError::NotConnected);
        }
        if data.len() > self.max_message() {
            return Err(SendError::TooLarge);
        }
        let origin_us = self.us(origin.unwrap_or(now));
        let now_us = self.us(now);
        if self.snd.len() >= self.snd.capacity() {
            // free what is already too late before refusing
            self.sender_drop(now_us);
        }
        let ts = origin_us.max(0) as u64 as u32;
        match self.snd.push(data, ts, origin_us, self.peer_sid) {
            Ok(seq) => {
                self.pacer.on_input(data.len(), now_us * 1000);
                Ok(seq)
            }
            Err(_) => {
                self.stats.send_would_block += 1;
                Err(SendError::WouldBlock)
            }
        }
    }

    /// The next message whose TSBPD time has come (gaps before it whose
    /// time has passed are dropped, as libsrt's TLPKTDROP).
    pub fn recv_message(&mut self, now: Instant) -> Option<Delivered<'_>> {
        let now_us = self.us(now);
        loop {
            let tsbpd = self.tsbpd.as_mut()?;
            if let Some(h) = self.rcv.head() {
                let due = if self.tsbpd_rcv {
                    tsbpd.update_wrap(h.timestamp);
                    let d = tsbpd.due_us(h.timestamp);
                    if d > now_us {
                        return None;
                    }
                    Some(d)
                } else {
                    None
                };
                let p = self.rcv.pop()?;
                self.stats.msg_delivered += 1;
                self.stats.byte_delivered += p.len as u64;
                let due = due.map(|d| self.at(d));
                return Some(Delivered {
                    payload: self.rcv.payload(&p),
                    seq: p.seq,
                    msgno: p.msgno,
                    timestamp: p.timestamp,
                    rexmit: p.rexmit,
                    due,
                });
            }
            if !self.tsbpd_rcv || !self.cfg.tlpktdrop {
                return None;
            }
            let f = self.rcv.first_present()?;
            if tsbpd.due_us(f.timestamp) > now_us {
                return None;
            }
            let n = self.rcv.drop_until(f.seq);
            if self.drop_log.len() < DROP_LOG_MAX {
                for h in self.rcv_loss.front_runs_before(self.rcv.base) {
                    if self.drop_log.len() < DROP_LOG_MAX {
                        self.drop_log.push(crate::stats::DroppedHole {
                            first: h.first,
                            last: h.last,
                            naks: h.naks,
                            detected_us: h.detected_us,
                            last_nak_us: h.last_nak_us,
                            deadline_us: h.deadline_us,
                            dropped_us: now_us,
                        });
                    }
                }
            }
            self.rcv_loss.remove_before(self.rcv.base);
            self.stats.pkt_rcv_drop += n as u64;
            self.stats.byte_rcv_drop += n as u64 * (self.cfg.payload_size + PKT_OVERHEAD) as u64;
        }
    }

    /// The first holes the receiver gave up (at most 32), with their NAK
    /// history: for diagnosis.
    pub fn dropped_holes(&self) -> &[crate::stats::DroppedHole] {
        &self.drop_log
    }

    /// Our receive latency and the peer's (for our data), ms.
    pub fn latencies_ms(&self) -> (u16, u16) {
        (self.rcv_latency_ms, self.snd_latency_ms)
    }

    pub(crate) fn caller_key(&self) -> (SocketAddr, u32, u32) {
        (self.peer, self.peer_sid, self.isn)
    }
}
