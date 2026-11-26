//! Listener-side handshake acceptor (spec 4.4 - 4.6, 10.2). Stateless
//! induction with a keyed cookie; on a valid conclusion it builds a
//! connected `Connection`. Repeated conclusions are routed to the existing
//! connection, which re-sends its response.

use crate::config::Config;
use crate::conn::{Connection, Negotiated};
use crate::handshake::{flags, req, Handshake, RejectReason, HS_MAGIC, MAX_SID_LEN, SRT_MIN_VERSION};
use crate::packet::{self, Control, Packet, PKT_OVERHEAD};
use std::collections::hash_map::RandomState;
use std::collections::{HashMap, HashSet};
use std::hash::{BuildHasher, Hash, Hasher};
use std::net::SocketAddr;
use std::time::Instant;

/// What the access-control callback sees.
#[derive(Debug)]
pub struct AcceptRequest<'a> {
    pub peer: SocketAddr,
    pub stream_id: Option<&'a str>,
    pub caller_socket_id: u32,
}

/// Access control: `Err(reason)` rejects (use `RejectReason::App(1403)`
/// for "forbidden", `App(1404)` for "not found").
pub type AcceptCallback = Box<dyn FnMut(&AcceptRequest<'_>) -> Result<(), RejectReason> + Send>;

/// Access control that may also choose the connection's passphrase:
/// `Ok(Some(p))` uses `p`, `Ok(None)` the listener's `Config::passphrase`
/// (libsrt: `srt_listen_callback` setting SRTO_PASSPHRASE on the new
/// socket). A caller whose encryption does not match is rejected
/// (BADSECRET for a wrong passphrase, UNSECURE when only one side
/// encrypts), as libsrt with SRTO_ENFORCEDENCRYPTION.
pub type AcceptSecretCallback = Box<dyn FnMut(&AcceptRequest<'_>) -> Result<Option<String>, RejectReason> + Send>;

pub enum ListenerAction {
    /// Nothing to do.
    Ignore,
    /// Send `out[..len]` back to the sender (induction response or rejection).
    Reply(usize),
    /// A new connection (already connected; its response is queued in it).
    Accept(Box<Connection>),
    /// A repeated conclusion for this existing connection: hand the same
    /// datagram to it.
    Existing(u32),
}

#[derive(Clone, Debug, Default)]
pub struct ListenerStats {
    pub inductions: u64,
    pub conclusions: u64,
    pub accepted: u64,
    pub repeated: u64,
    pub rejected: u64,
    pub bad_cookie: u64,
    pub ignored: u64,
    pub last_reject: Option<RejectReason>,
}

pub struct Listener {
    cfg: Config,
    epoch: Instant,
    secret: RandomState,
    by_caller: HashMap<(SocketAddr, u32, u32), u32>,
    by_sid: HashMap<u32, (SocketAddr, u32, u32)>,
    ids: HashSet<u32>,
    backlog_full: bool,
    accept_cb: Option<AcceptCallback>,
    accept_secret_cb: Option<AcceptSecretCallback>,
    stats: ListenerStats,
}

/// A random socket ID in 1 .. 2^30.
pub fn random_socket_id() -> u32 {
    let v = RandomState::new().build_hasher().finish() as u32 & 0x3FFF_FFFF;
    v.max(1)
}

/// A random initial sequence number in 0 .. 0x7FFF_FFFF.
pub fn random_isn() -> u32 {
    let mut h = RandomState::new().build_hasher();
    h.write_u8(1);
    (h.finish() as u32 & 0x7FFF_FFFF) % 0x7FFF_FFFF
}

/// Listener-side negotiation of a caller's conclusion.
pub(crate) fn negotiate(cfg: &Config, hs: &Handshake) -> Result<Negotiated, RejectReason> {
    // encryption is settled once the passphrase is known (`Listener::handle`)
    if !cfg!(feature = "aes") && (hs.kmreq || hs.encryption != 0) {
        return Err(RejectReason::Unsecure);
    }
    let Some(r) = hs.hsreq else { return Err(RejectReason::Rogue) };
    if hs.ext_field == 0 {
        return Err(RejectReason::Rogue);
    }
    if r.version < SRT_MIN_VERSION {
        return Err(RejectReason::Version);
    }
    if r.flags & flags::STREAM != 0 {
        return Err(RejectReason::MessageApi);
    }
    if let Some(c) = &hs.congestion {
        if c != "live" {
            return Err(RejectReason::Congestion);
        }
    }
    if let Some(s) = &hs.stream_id {
        if s.len() > MAX_SID_LEN {
            return Err(RejectReason::Rogue);
        }
    }
    let filter = crate::filter::negotiate_listener(cfg.packet_filter.as_deref(), hs.filter.as_deref()).map_err(|_| RejectReason::Filter)?;
    // only the built-in `fec` exists (libsrt rejects other types too)
    if filter.as_deref().map_or(false, |f| crate::fec::FecConfig::parse(f).is_none()) {
        return Err(RejectReason::Filter);
    }
    let mss = cfg.mss.min(hs.mss);
    if (mss as usize) < PKT_OVERHEAD + 32 {
        return Err(RejectReason::Rogue);
    }
    let tsbpd_snd = r.flags & flags::TSBPDSND != 0;
    let tsbpd_rcv = r.flags & flags::TSBPDRCV != 0;
    Ok(Negotiated {
        mss,
        filter,
        rcv_latency_ms: if tsbpd_snd { cfg.rcv_latency_ms.max(r.send_delay_ms) } else { 0 },
        snd_latency_ms: if tsbpd_rcv { cfg.peer_latency_ms.max(r.recv_delay_ms) } else { 0 },
        peer_flags: r.flags,
        peer_version: r.version,
        #[cfg(feature = "aes")]
        crypto: None,
    })
}

/// The connection's crypto from the caller's KMREQ and our passphrase.
#[cfg(feature = "aes")]
fn key_exchange(hs: &Handshake, secret: Option<&str>) -> Result<Option<Box<crate::crypto::Crypto>>, RejectReason> {
    use crate::crypto::{Crypto, KmError};
    match (hs.km_req.as_deref(), secret) {
        (None, None) => Ok(None),
        (Some(km), Some(p)) => match Crypto::from_km(p, km) {
            Ok(c) => Ok(Some(Box::new(c))),
            Err(KmError::BadSecret) => Err(RejectReason::BadSecret),
            Err(_) => Err(RejectReason::Unsecure),
        },
        // only one side encrypts
        _ => Err(RejectReason::Unsecure),
    }
}

impl Listener {
    pub fn new(cfg: Config, now: Instant) -> Listener {
        Listener {
            cfg,
            epoch: now,
            secret: RandomState::new(),
            by_caller: HashMap::new(),
            by_sid: HashMap::new(),
            ids: HashSet::new(),
            backlog_full: false,
            accept_cb: None,
            accept_secret_cb: None,
            stats: ListenerStats::default(),
        }
    }

    pub fn config(&self) -> &Config {
        &self.cfg
    }

    pub fn stats(&self) -> &ListenerStats {
        &self.stats
    }

    pub fn set_accept_callback(&mut self, cb: Option<AcceptCallback>) {
        self.accept_cb = cb;
    }

    /// Access control that also picks the passphrase (runs after the
    /// plain callback, if both are set).
    pub fn set_accept_secret_callback(&mut self, cb: Option<AcceptSecretCallback>) {
        self.accept_secret_cb = cb;
    }

    /// While true, new callers are rejected with BACKLOG (1005).
    pub fn set_backlog_full(&mut self, full: bool) {
        self.backlog_full = full;
    }

    /// Forget a connection (closed): its socket ID and caller key are freed.
    pub fn remove(&mut self, sid: u32) {
        if let Some(k) = self.by_sid.remove(&sid) {
            self.by_caller.remove(&k);
        }
        self.ids.remove(&sid);
    }

    fn ts(&self, now: Instant) -> u32 {
        now.saturating_duration_since(self.epoch).as_micros() as u64 as u32
    }

    fn cookie(&self, from: SocketAddr, minute: u64) -> u32 {
        let mut h = self.secret.build_hasher();
        from.hash(&mut h);
        minute.hash(&mut h);
        h.finish() as u32
    }

    fn minute(&self, now: Instant) -> u64 {
        now.saturating_duration_since(self.epoch).as_secs() / 60
    }

    fn new_sid(&mut self) -> u32 {
        loop {
            let s = random_socket_id();
            if self.ids.insert(s) {
                return s;
            }
        }
    }

    fn reject(&mut self, now: Instant, hs: &Handshake, why: RejectReason, out: &mut [u8]) -> ListenerAction {
        self.stats.rejected += 1;
        self.stats.last_reject = Some(why);
        let r = Handshake {
            version: hs.version,
            encryption: 0,
            ext_field: hs.ext_field,
            isn: hs.isn,
            mss: hs.mss,
            flow_window: hs.flow_window,
            req_type: why.to_wire(),
            socket_id: 0,
            cookie: hs.cookie,
            peer_ip: hs.peer_ip,
            ..Default::default()
        };
        ListenerAction::Reply(packet::encode_handshake(&r, self.ts(now), hs.socket_id, out))
    }

    /// Handle one datagram addressed to socket ID 0. `out` (>= 1500 bytes)
    /// receives a reply for `Reply`.
    pub fn handle(&mut self, now: Instant, from: SocketAddr, data: &[u8], out: &mut [u8]) -> ListenerAction {
        let Ok(Packet::Control {
            hdr,
            body: Control::Handshake(hs),
        }) = packet::decode(data)
        else {
            self.stats.ignored += 1;
            return ListenerAction::Ignore;
        };
        match hs.req_type {
            req::INDUCTION => {
                self.stats.inductions += 1;
                // echo the caller's 48 bytes with version 5, the magic and our cookie
                let r = Handshake {
                    version: 5,
                    encryption: 0,
                    ext_field: HS_MAGIC,
                    cookie: self.cookie(from, self.minute(now)),
                    isn: hs.isn,
                    mss: hs.mss,
                    flow_window: hs.flow_window,
                    req_type: req::INDUCTION,
                    socket_id: hs.socket_id,
                    peer_ip: hs.peer_ip,
                    ..Default::default()
                };
                ListenerAction::Reply(packet::encode_handshake(&r, self.ts(now), hs.socket_id, out))
            }
            req::CONCLUSION => {
                self.stats.conclusions += 1;
                let m = self.minute(now);
                if hs.cookie != self.cookie(from, m) && (m == 0 || hs.cookie != self.cookie(from, m - 1)) {
                    self.stats.bad_cookie += 1;
                    return ListenerAction::Ignore;
                }
                if hs.version < 4 || hs.isn >= 0x7FFF_FFFF || hs.mss < 64 || hs.flow_window < 2 {
                    self.stats.ignored += 1;
                    return ListenerAction::Ignore;
                }
                if hs.version != 5 {
                    return self.reject(now, &hs, RejectReason::Version, out);
                }
                let key = (from, hs.socket_id, hs.isn);
                if let Some(&sid) = self.by_caller.get(&key) {
                    self.stats.repeated += 1;
                    return ListenerAction::Existing(sid);
                }
                if self.backlog_full {
                    return self.reject(now, &hs, RejectReason::Backlog, out);
                }
                #[allow(unused_mut)]
                let mut n = match negotiate(&self.cfg, &hs) {
                    Ok(n) => n,
                    Err(r) => return self.reject(now, &hs, r, out),
                };
                let rq = AcceptRequest {
                    peer: from,
                    stream_id: hs.stream_id.as_deref(),
                    caller_socket_id: hs.socket_id,
                };
                if let Some(cb) = self.accept_cb.as_mut() {
                    if let Err(r) = cb(&rq) {
                        return self.reject(now, &hs, r, out);
                    }
                }
                let mut secret = self.cfg.passphrase.clone();
                if let Some(cb) = self.accept_secret_cb.as_mut() {
                    match cb(&rq) {
                        Ok(Some(p)) => secret = Some(p),
                        Ok(None) => {}
                        Err(r) => return self.reject(now, &hs, r, out),
                    }
                }
                #[cfg(feature = "aes")]
                match key_exchange(&hs, secret.as_deref()) {
                    Ok(c) => n.crypto = c,
                    Err(r) => return self.reject(now, &hs, r, out),
                }
                // without AES a passphrase can never be honoured: refuse
                // rather than run unencrypted
                #[cfg(not(feature = "aes"))]
                if secret.is_some() {
                    return self.reject(now, &hs, RejectReason::Unsecure, out);
                }
                let sid = self.new_sid();
                let conn = Connection::accepted(self.cfg.clone(), now, from, sid, &hs, hdr.timestamp, n);
                debug_assert_eq!(conn.caller_key(), key);
                self.by_caller.insert(key, sid);
                self.by_sid.insert(sid, key);
                self.stats.accepted += 1;
                ListenerAction::Accept(Box::new(conn))
            }
            _ => {
                self.stats.ignored += 1;
                ListenerAction::Ignore
            }
        }
    }
}
