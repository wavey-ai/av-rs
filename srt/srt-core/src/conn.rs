//! One SRT connection (caller or listener side), sans-IO.
//!
//! Drive it with `handle_datagram`, `handle_timeout` (when `poll_timeout`
//! is reached), `poll_transmit` (until `None`) and `recv_message` (until
//! `None`). All times are `Instant`s passed in; internally they are
//! microseconds since the connection's `epoch`, which is also the origin of
//! every timestamp this side puts on the wire.

use crate::config::Config;
use crate::handshake::{flags, ip_to_words, req, Handshake, RejectReason, SrtHsExt, HS_MAGIC, SRT_VERSION, UDT_DGRAM};
use crate::packet::{self, Ack, AckKind, Control, DataHeader, Packet, HDR_LEN, PKT_OVERHEAD};
use crate::rcvbuf::{Insert, RcvBuf};
use crate::seq::{ackno_inc, seq_le, seq_lt, seq_off};
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
    pkts_since_ack: u32,
    ack_window: Vec<AckRec>,
    ack_due: Option<AckKind>,
    rate_pkts: u64,
    rate_bytes: u64,
    pkt_rate: u32,
    byte_rate: u32,

    // RTT
    srtt: u32,
    rttvar: u32,
    rtt_own: bool,
    rtt_valid: bool,

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
            pkts_since_ack: 0,
            ack_window: vec![AckRec::default(); ACK_WINDOW],
            ack_due: None,
            rate_pkts: 0,
            rate_bytes: 0,
            pkt_rate: 0,
            byte_rate: 0,
            srtt: INIT_RTT_US,
            rttvar: INIT_RTTVAR_US,
            rtt_own: false,
            rtt_valid: false,
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

    pub fn stats(&self) -> &Stats {
        &self.stats
    }

    /// Largest message `send_message` accepts.
    pub fn max_message(&self) -> usize {
        self.cfg.payload_size.min(self.max_payload)
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
                    Control::Ack(a) => self.on_ack(hdr.info, &a),
                    Control::Nak(l) => {
                        self.stats.pkt_recv_nak += 1;
                        for (first, last) in l.ranges() {
                            if seq_lt(last, first) || !seq_lt(last, self.snd.next_send) {
                                self.stats.nak_invalid += 1;
                                continue;
                            }
                            self.stats.pkt_snd_loss += (seq_off(first, last) + 1) as u64;
                        }
                    }
                    Control::AckAck => self.on_ackack(now_us, hdr.info, hdr.timestamp),
                    Control::Shutdown => self.set_closed(CloseReason::PeerShutdown),
                    Control::DropReq { .. } => self.stats.pkt_recv_dropreq += 1,
                    _ => self.stats.pkt_recv_other_ctrl += 1,
                }
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
            return;
        }
        if hdr.key != 0 {
            st.pkt_rcv_undecrypt += 1;
            return self.set_closed(CloseReason::Encrypted);
        }
        if payload.len() > self.max_payload {
            st.pkt_recv_malformed += 1;
            return;
        }
        if hdr.rexmit {
            st.pkt_rcv_retrans += 1;
        }
        if !self.rcv_started {
            self.rcv_started = true;
            self.next_ack_us = now_us + SYN_US;
            self.last_full_ack_us = now_us;
        }
        match self.rcv.insert(hdr.seq, payload, hdr.timestamp, hdr.msgno, hdr.rexmit) {
            Insert::Stored { loss, .. } => {
                st.pkt_recv_unique += 1;
                st.byte_recv_unique += (payload.len() + PKT_OVERHEAD) as u64;
                self.rate_pkts += 1;
                self.rate_bytes += (payload.len() + PKT_OVERHEAD) as u64;
                if let Some((a, b)) = loss {
                    let n = (seq_off(a, b) + 1) as u64;
                    st.pkt_rcv_loss += n;
                    st.byte_rcv_loss += n * (payload.len() + PKT_OVERHEAD) as u64;
                }
            }
            Insert::Belated => st.pkt_rcv_belated += 1,
            Insert::Duplicate => st.pkt_rcv_duplicate += 1,
            Insert::TooFar => st.pkt_rcv_too_far += 1,
        }
        self.pkts_since_ack += 1;
        if self.pkts_since_ack >= LIGHT_ACK_PKTS && self.ack_due.is_none() && self.rcv.ack != self.last_ack_seq {
            self.ack_due = Some(AckKind::Light);
            self.pkts_since_ack = 0;
        }
    }

    fn on_ack(&mut self, ackno: u32, a: &Ack) {
        self.stats.pkt_recv_ack += 1;
        if !seq_le(a.seq, self.snd.next_send) {
            // beyond what we sent (libsrt would break the connection)
            self.stats.ack_invalid += 1;
            return;
        }
        if a.kind == AckKind::Light {
            self.stats.pkt_recv_light_ack += 1;
            self.snd.ack(a.seq);
            return;
        }
        if self.ackacks.len() >= MAX_ACKACK_QUEUE {
            self.ackacks.pop_front();
        }
        self.ackacks.push_back(ackno);
        self.peer_fw = a.avail_buf;
        self.snd.ack(a.seq);
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
                self.sender_drop(now_us);
            }
            State::Closed(_) => {}
        }
    }

    fn ack_timer(&mut self, now_us: i64) {
        let ack = self.rcv.ack;
        let rto = self.srtt as i64 + 4 * self.rttvar as i64;
        let unconfirmed = seq_lt(self.last_ackack_seq, ack);
        if ack != self.last_ack_seq || (unconfirmed && now_us - self.last_ack_us > rto) {
            self.ack_due = Some(if now_us - self.last_full_ack_us >= SYN_US {
                AckKind::Full
            } else {
                AckKind::Small
            });
        }
        self.pkts_since_ack = 0;
    }

    /// Sender drop of too-late packets (spec 7.6, libsrt's threshold).
    fn sender_drop(&mut self, now_us: i64) {
        let Some(thr) = self.snd_drop_threshold_us() else { return };
        let (n, bytes, unsent) = self.snd.drop_older_than(now_us - thr);
        if n > 0 {
            self.stats.pkt_snd_drop += n as u64;
            self.stats.byte_snd_drop += bytes + n as u64 * PKT_OVERHEAD as u64;
            self.stats.pkt_snd_drop_unsent += unsent as u64;
        }
    }

    fn snd_drop_threshold_us(&self) -> Option<i64> {
        if self.peer_flags & flags::TLPKTDROP == 0 || self.cfg.snd_drop_delay_ms < 0 || !self.cfg.tlpktdrop {
            return None;
        }
        let ms = (self.snd_latency_ms as i64 + self.cfg.snd_drop_delay_ms as i64).max(1000) + 20;
        Some(ms * 1000)
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
        if self.keepalive_due {
            self.keepalive_due = false;
            self.stats.pkt_sent_keepalive += 1;
            return Some(packet::encode_keepalive(ts, self.peer_sid, buf));
        }
        if self.snd.unsent() > 0 && self.window_open() && self.pacer.ready(now_us * 1000) {
            let seq = self.snd.next_send;
            let p = self.snd.packet(seq)?;
            let n = p.len();
            buf[..n].copy_from_slice(p);
            self.snd.next_send = crate::seq::seq_inc(seq);
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
            rtt_var_us: self.rttvar,
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
            self.stats.pkt_rcv_drop += n as u64;
            self.stats.byte_rcv_drop += n as u64 * (self.cfg.payload_size + PKT_OVERHEAD) as u64;
        }
    }

    /// Our receive latency and the peer's (for our data), ms.
    pub fn latencies_ms(&self) -> (u16, u16) {
        (self.rcv_latency_ms, self.snd_latency_ms)
    }

    pub(crate) fn caller_key(&self) -> (SocketAddr, u32, u32) {
        (self.peer, self.peer_sid, self.isn)
    }
}
