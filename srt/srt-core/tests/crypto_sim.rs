//! Encrypted connections (feature `aes`) between a caller and a listener
//! on a simulated wire: key exchange in the handshake, AES-CTR on every
//! data packet (retransmissions and FEC included), rejections.
#![cfg(feature = "aes")]

use srt_core::packet::{self, Packet};
use srt_core::{CloseReason, Config, Connection, Listener, ListenerAction, RejectReason};
use std::collections::HashSet;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

const STEP: Duration = Duration::from_micros(250);

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
                self.q.push((now + self.owd, true, d));
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
