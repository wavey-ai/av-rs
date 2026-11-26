//! Encrypted connections (feature `aes`) between a caller and a listener
//! on a simulated wire: key exchange in the handshake, AES-CTR on every
//! data packet (retransmissions and FEC included), rejections.
#![cfg(feature = "aes")]

use srt_core::crypto::Crypto;
use srt_core::handshake::{cmd, req, Handshake};
use srt_core::packet::{self, ctrl, Control, ControlHeader, Packet};
use srt_core::{CloseReason, Config, Connection, Listener, ListenerAction, RejectReason};
use std::collections::HashSet;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

const STEP: Duration = Duration::from_micros(250);

type Mangle = Box<dyn FnMut(Vec<u8>) -> Vec<Vec<u8>>>;

struct Wire {
    now: Instant,
    owd: Duration,
    a: SocketAddr,
    b: SocketAddr,
    caller: Connection,
    listener: Listener,
    conn: Option<Connection>,
    q: Vec<(Instant, bool, Vec<u8>)>,
    rng: u64,
    loss_pct: u64,
    /// Data payloads seen on the wire (caller -> listener).
    wire_payloads: Vec<Vec<u8>>,
    /// Rewrites each caller -> listener datagram into what is delivered.
    mangle: Option<Mangle>,
}

impl Wire {
    fn new(c: Config, l: Config, owd_ms: u64) -> Wire {
        let now = Instant::now();
        let a: SocketAddr = "10.2.0.1:5000".parse().unwrap();
        let b: SocketAddr = "10.2.0.2:6000".parse().unwrap();
        Wire {
            now,
            owd: Duration::from_millis(owd_ms),
            a,
            b,
            caller: Connection::connect(c, now, b, 0x777, 1000),
            listener: Listener::new(l, now),
            conn: None,
            q: Vec::new(),
            rng: 0x2545_F491_4F6C_DD1D,
            loss_pct: 0,
            wire_payloads: Vec::new(),
            mangle: None,
        }
    }

    fn lose(&mut self) -> bool {
        self.rng ^= self.rng << 13;
        self.rng ^= self.rng >> 7;
        self.rng ^= self.rng << 17;
        self.rng % 100 < self.loss_pct
    }

    fn step(&mut self) {
        self.now += STEP;
        let now = self.now;
        let due: Vec<_> = self.q.iter().filter(|(t, _, _)| *t <= now).cloned().collect();
        self.q.retain(|(t, _, _)| *t > now);
        let mut out = [0u8; 1500];
        for (_, to_listener, d) in due {
            if !to_listener {
                self.caller.handle_datagram(now, self.b, &d);
            } else if packet::dst_socket_id(&d) == Some(0) {
                match self.listener.handle(now, self.a, &d, &mut out) {
                    ListenerAction::Reply(n) => self.q.push((now + self.owd, false, out[..n].to_vec())),
                    ListenerAction::Accept(c) => self.conn = Some(*c),
                    ListenerAction::Existing(_) => self.conn.as_mut().unwrap().handle_datagram(now, self.a, &d),
                    ListenerAction::Ignore => {}
                }
            } else if let Some(c) = self.conn.as_mut() {
                c.handle_datagram(now, self.a, &d);
            }
        }
        if self.caller.poll_timeout().map_or(false, |t| t <= now) {
            self.caller.handle_timeout(now);
        }
        if let Some(c) = self.conn.as_mut() {
            if c.poll_timeout().map_or(false, |t| t <= now) {
                c.handle_timeout(now);
            }
        }
        let mut buf = [0u8; 1500];
        while let Some(t) = self.caller.poll_transmit(now, &mut buf) {
            let d = buf[..t.len].to_vec();
            if let Ok(Packet::Data { hdr, payload }) = packet::decode(&d) {
                if hdr.msgno != 0 {
                    self.wire_payloads.push(payload.to_vec());
                }
            }
            let connected = self.caller.is_connected();
            if !(connected && self.lose()) {
                let ds = match self.mangle.as_mut() {
                    Some(f) => f(d),
                    None => vec![d],
                };
                for d in ds {
                    self.q.push((now + self.owd, true, d));
                }
            }
        }
        let mut outq = Vec::new();
        if let Some(c) = self.conn.as_mut() {
            while let Some(t) = c.poll_transmit(now, &mut buf) {
                outq.push(buf[..t.len].to_vec());
            }
        }
        for d in outq {
            if !self.lose() {
                self.q.push((now + self.owd, false, d));
            }
        }
    }

    fn run(&mut self, d: Duration, mut f: impl FnMut(&mut Wire) -> bool) -> bool {
        let end = self.now + d;
        while self.now < end {
            self.step();
            if f(self) {
                return true;
            }
        }
        false
    }
}

fn cfg(pass: Option<&str>) -> Config {
    Config {
        passphrase: pass.map(str::to_string),
        ..Config::default().with_latency_ms(120)
    }
}

fn transfer(c: Config, l: Config, loss: u64) -> (Wire, usize) {
    let mut w = Wire::new(c, l, 15);
    assert!(w.run(Duration::from_secs(5), |w| w.caller.is_connected() && w.conn.is_some()), "{:?}", w.caller.state());
    w.loss_pct = loss;
    let n = 3000u32;
    let mut sent = 0u32;
    let mut got = HashSet::new();
    let mut msg = vec![0u8; 1316];
    w.run(Duration::from_secs(6), |w| {
        // 2 packets per 250 us step: ~84 Mbit/s
        for _ in 0..2 {
            if sent < n {
                msg[..4].copy_from_slice(&sent.to_be_bytes());
                for (i, b) in msg[4..].iter_mut().enumerate() {
                    *b = (sent as usize + i) as u8;
                }
                w.caller.send_message(w.now, &msg, None).unwrap();
                sent += 1;
            }
        }
        let now = w.now;
        while let Some(m) = w.conn.as_mut().unwrap().recv_message(now) {
            let i = u32::from_be_bytes(m.payload[..4].try_into().unwrap());
            assert!(m.payload[4..].iter().enumerate().all(|(j, b)| *b == (i as usize + j) as u8), "payload {i} corrupt");
            got.insert(i);
        }
        false
    });
    (w, got.len())
}

#[test]
fn encrypted_transfer_with_loss_all_key_lengths() {
    for klen in [0u8, 16, 24, 32] {
        let mut c = cfg(Some("correct horse battery"));
        c.pbkeylen = klen;
        let (w, got) = transfer(c, cfg(Some("correct horse battery")), 3);
        let want = if klen == 0 { 16 } else { klen as usize };
        assert_eq!(w.caller.encryption_key_len(), Some(want));
        assert_eq!(w.conn.as_ref().unwrap().encryption_key_len(), Some(want));
        assert_eq!(got, 3000, "klen {klen}");
        // what went over the wire is not the clear payload
        let clear = w.wire_payloads.iter().filter(|p| p.len() > 8 && p[4..8] == [p[3], p[3].wrapping_add(1), p[3].wrapping_add(2), p[3].wrapping_add(3)]).count();
        assert!(clear < 10, "{clear} payloads look clear");
        let st = w.conn.as_ref().unwrap().stats().clone();
        assert!(st.pkt_rcv_loss > 0 && st.pkt_rcv_undecrypt == 0, "{st:?}");
    }
}

#[test]
fn encrypted_transfer_with_fec() {
    let mut c = cfg(Some("0123456789abc"));
    c.packet_filter = Some("fec,cols:10,rows:5,layout:staircase,arq:onreq".into());
    let mut l = cfg(Some("0123456789abc"));
    l.packet_filter.clone_from(&c.packet_filter);
    let (w, got) = transfer(c, l, 2);
    assert_eq!(got, 3000);
    let st = w.conn.as_ref().unwrap().stats().clone();
    assert!(st.pkt_rcv_filter_supply > 0, "FEC rebuilt nothing: {st:?}");
    assert_eq!(st.pkt_rcv_undecrypt, 0);
}

fn connect_result(c: Config, l: Config) -> Wire {
    let mut w = Wire::new(c, l, 5);
    w.run(Duration::from_secs(5), |w| w.caller.is_connected() || w.caller.is_closed());
    w
}

#[test]
fn wrong_passphrase_is_bad_secret() {
    let w = connect_result(cfg(Some("first passphrase")), cfg(Some("second passphrase")));
    assert_eq!(w.caller.state(), &srt_core::State::Closed(CloseReason::Rejected(RejectReason::BadSecret)));
    assert!(w.conn.is_none());
}

#[test]
fn only_one_side_encrypting_is_unsecure() {
    let w = connect_result(cfg(Some("only the caller")), cfg(None));
    assert_eq!(w.caller.state(), &srt_core::State::Closed(CloseReason::Rejected(RejectReason::Unsecure)));
    let w = connect_result(cfg(None), cfg(Some("only the listener")));
    assert_eq!(w.caller.state(), &srt_core::State::Closed(CloseReason::Rejected(RejectReason::Unsecure)));
}

#[test]
fn secret_callback_picks_the_passphrase_per_stream() {
    let mut w = Wire::new(
        Config {
            stream_id: Some("room-a".into()),
            ..cfg(Some("passphrase-of-room-a"))
        },
        cfg(None),
        5,
    );
    w.listener.set_accept_secret_callback(Some(Box::new(|rq| match rq.stream_id {
        Some("room-a") => Ok(Some("passphrase-of-room-a".to_string())),
        _ => Err(RejectReason::App(1403)),
    })));
    assert!(w.run(Duration::from_secs(5), |w| w.caller.is_connected()));
    assert_eq!(w.caller.encryption_key_len(), Some(16));
}

// ------------------------------------------------- hostile input (review B)

const PASS: &str = "0123456789abcdef";

fn hs_of(d: &[u8]) -> Option<Handshake> {
    match packet::decode(d) {
        Ok(Packet::Control {
            body: Control::Handshake(h), ..
        }) => Some(*h),
        _ => None,
    }
}

/// The caller's conclusion with `extra` junk bytes after its KM message
/// (inside the KMREQ block), re-encoded whatever its size.
fn junk_after_kmreq(extra: usize) -> impl FnMut(Vec<u8>) -> Vec<Vec<u8>> {
    move |d: Vec<u8>| {
        if let Some(mut h) = hs_of(&d) {
            if h.req_type == req::CONCLUSION {
                if let Some(k) = h.km_req.as_mut() {
                    k.extend(std::iter::repeat(0xAA).take(extra));
                    let mut b = vec![0u8; 16 + h.encoded_len()];
                    b[..16].copy_from_slice(&d[..16]);
                    let n = h.encode(&mut b[16..]).unwrap();
                    b.truncate(16 + n);
                    return vec![b];
                }
            }
        }
        vec![d]
    }
}

#[test]
fn kmreq_with_trailing_junk_is_refused_not_echoed() {
    // fits in a datagram: the listener parses it and refuses the KM (libsrt
    // takes only the exact length; its failure state is BADSECRET)
    let mut w = Wire::new(cfg(Some(PASS)), cfg(Some(PASS)), 5);
    w.mangle = Some(Box::new(junk_after_kmreq(200)));
    w.run(Duration::from_secs(5), |w| w.caller.is_connected() || w.caller.is_closed());
    assert_eq!(w.caller.state(), &srt_core::State::Closed(CloseReason::Rejected(RejectReason::BadSecret)));
    assert!(w.conn.is_none());
    assert_eq!(w.listener.stats().last_reject, Some(RejectReason::BadSecret));
}

#[test]
fn oversized_kmreq_conclusion_is_dropped_without_panic() {
    // review B case A: 1400 junk bytes, a 1524-byte conclusion; it used to
    // be echoed into the 1500-byte send buffer and panic the I/O thread
    let mut w = Wire::new(cfg(Some(PASS)), cfg(Some(PASS)), 5);
    w.mangle = Some(Box::new(junk_after_kmreq(1400)));
    w.run(Duration::from_secs(2), |w| w.caller.is_connected() || w.caller.is_closed());
    assert!(w.conn.is_none());
    assert!(!w.caller.is_connected());
    assert!(w.listener.stats().ignored > 0, "{:?}", w.listener.stats());
    assert_eq!(w.listener.stats().accepted, 0);
}

fn kmreq_datagram(dst: u32, km: &[u8]) -> Vec<u8> {
    let mut d = vec![0u8; 16 + km.len()];
    let mut h = ControlHeader::new(ctrl::EXT, 0, 1, dst);
    h.subtype = cmd::KMREQ;
    h.encode(&mut d);
    d[16..].copy_from_slice(km);
    d
}

/// Everything the listener's connection sends now; the KMRSP bodies apart.
fn drain_kmrsp(w: &mut Wire) -> Vec<Vec<u8>> {
    let now = w.now;
    let mut buf = [0u8; 1500];
    let mut rsp = Vec::new();
    let mut n = 0;
    while let Some(t) = w.conn.as_mut().unwrap().poll_transmit(now, &mut buf) {
        if let Ok(Packet::Control { hdr, body: Control::Other { cif } }) = packet::decode(&buf[..t.len]) {
            if hdr.ctype == ctrl::EXT && hdr.subtype == cmd::KMRSP {
                rsp.push(cif.to_vec());
            }
        }
        n += 1;
        assert!(n < 1000);
    }
    rsp
}

#[test]
fn oversized_or_padded_key_refresh_while_connected() {
    let mut w = Wire::new(cfg(Some(PASS)), cfg(Some(PASS)), 5);
    assert!(w.run(Duration::from_secs(5), |w| w.caller.is_connected() && w.conn.is_some()));
    let now = w.now;
    let dst = w.conn.as_ref().unwrap().local_socket_id();
    let fresh = Crypto::generate(PASS, 16);
    // review B case B: 1600 junk bytes (1656-byte datagram): dropped
    let mut km = fresh.km_msg().to_vec();
    km.extend(std::iter::repeat(0x55).take(1600));
    let before = w.conn.as_ref().unwrap().stats().pkt_recv_malformed;
    let a = w.a;
    w.conn.as_mut().unwrap().handle_datagram(now, a, &kmreq_datagram(dst, &km));
    assert_eq!(w.conn.as_ref().unwrap().stats().pkt_recv_malformed, before + 1);
    assert!(drain_kmrsp(&mut w).is_empty());
    // 400 junk bytes (fits): refused with the BADSECRET state, keys kept
    let mut km = fresh.km_msg().to_vec();
    km.extend(std::iter::repeat(0x55).take(400));
    w.conn.as_mut().unwrap().handle_datagram(now, a, &kmreq_datagram(dst, &km));
    assert_eq!(drain_kmrsp(&mut w), vec![4u32.to_be_bytes().to_vec()]);
    assert!(w.conn.as_ref().unwrap().is_connected());
    // the session still decrypts the caller's data
    w.caller.send_message(w.now, b"after-bad-refresh", None).unwrap();
    let mut got = Vec::new();
    w.run(Duration::from_millis(500), |w| {
        let now = w.now;
        while let Some(m) = w.conn.as_mut().unwrap().recv_message(now) {
            got.push(m.payload.to_vec());
        }
        false
    });
    assert_eq!(got, vec![b"after-bad-refresh".to_vec()]);
    // an exact KM message is taken and echoed byte for byte
    let now = w.now;
    w.conn.as_mut().unwrap().handle_datagram(now, a, &kmreq_datagram(dst, fresh.km_msg()));
    assert_eq!(drain_kmrsp(&mut w), vec![fresh.km_msg().to_vec()]);
}

#[test]
fn cleartext_packet_in_encrypted_session_is_dropped() {
    // review B case E: an off-path KK=0 packet with the next sequence
    // number must not be delivered; the real (encrypted) one must be
    let mut w = Wire::new(cfg(Some(PASS)), cfg(Some(PASS)), 5);
    assert!(w.run(Duration::from_secs(5), |w| w.caller.is_connected() && w.conn.is_some()));
    let mut injected = 0;
    w.mangle = Some(Box::new(move |d: Vec<u8>| {
        if d[0] & 0x80 == 0 && injected == 0 {
            injected += 1;
            let mut forged = d[..16].to_vec();
            forged[4] &= !0x18; // KK = 0
            forged.extend_from_slice(b"INJECTED-CLEARTEXT-BY-OFF-PATH");
            return vec![forged, d];
        }
        vec![d]
    }));
    for i in 0..5u8 {
        w.caller.send_message(w.now, &[b'r', b'e', b'a', b'l', b'0' + i], None).unwrap();
    }
    let mut got = Vec::new();
    w.run(Duration::from_secs(1), |w| {
        let now = w.now;
        while let Some(m) = w.conn.as_mut().unwrap().recv_message(now) {
            got.push(String::from_utf8_lossy(m.payload).into_owned());
        }
        false
    });
    assert_eq!(got, ["real0", "real1", "real2", "real3", "real4"]);
    assert_eq!(w.conn.as_ref().unwrap().stats().pkt_rcv_undecrypt, 1);
}

#[test]
fn fec_rebuild_with_cleartext_flags_is_dropped() {
    // a row of 5 with one data packet lost: the filter rebuilds it from the
    // FEC packet. Flipping the FEC packet's flag clip makes the rebuilt
    // packet's KK 0: it must be dropped (and counted), not inserted as
    // ciphertext.
    let filter = Some("fec,cols:5,rows:1,arq:never".to_string());
    let run = |tamper: bool| {
        let mut c = cfg(Some(PASS));
        c.packet_filter.clone_from(&filter);
        let mut l = cfg(Some(PASS));
        l.packet_filter.clone_from(&filter);
        let mut w = Wire::new(c, l, 5);
        assert!(w.run(Duration::from_secs(5), |w| w.caller.is_connected() && w.conn.is_some()));
        let mut data = 0;
        w.mangle = Some(Box::new(move |mut d: Vec<u8>| {
            if d[0] & 0x80 != 0 {
                return vec![d];
            }
            let msgno = u32::from_be_bytes([d[4], d[5], d[6], d[7]]) & 0x03FF_FFFF;
            if msgno == 0 {
                if tamper {
                    d[16 + 1] ^= 1; // flag clip
                }
                return vec![d];
            }
            data += 1;
            if data == 3 {
                return vec![]; // lost
            }
            vec![d]
        }));
        for i in 0..5u8 {
            w.caller.send_message(w.now, &[b'm', b'0' + i], None).unwrap();
        }
        let mut got = Vec::new();
        w.run(Duration::from_secs(1), |w| {
            let now = w.now;
            while let Some(m) = w.conn.as_mut().unwrap().recv_message(now) {
                got.push(String::from_utf8_lossy(m.payload).into_owned());
            }
            false
        });
        (got, w.conn.as_ref().unwrap().stats().clone())
    };
    let (got, st) = run(false);
    assert_eq!(got, ["m0", "m1", "m2", "m3", "m4"], "{st:?}");
    assert_eq!(st.pkt_rcv_filter_supply, 1);
    assert_eq!(st.pkt_rcv_undecrypt, 0);
    let (got, st) = run(true);
    assert_eq!(got, ["m0", "m1", "m3", "m4"], "{st:?}");
    assert_eq!(st.pkt_rcv_filter_supply, 0);
    assert_eq!(st.pkt_rcv_undecrypt, 1);
}
