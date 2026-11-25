//! Caller and listener over a simulated network (fixed one-way delay,
//! scripted drops), with simulated time.

use srt_core::packet::{self, Control, Packet};
use srt_core::{CloseReason, Config, Connection, Event, Listener, ListenerAction, State};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

const STEP: Duration = Duration::from_micros(50);

type DropFn = Box<dyn FnMut(&str, &[u8]) -> bool>;

struct Sim {
    t0: Instant,
    now: Instant,
    owd: Duration,
    a: SocketAddr,
    b: SocketAddr,
    caller: Connection,
    listener: Listener,
    conns: HashMap<u32, Connection>,
    accepted: Vec<u32>,
    wire: Vec<(Instant, SocketAddr, Vec<u8>)>,
    drop: DropFn,
    sent_a: Vec<Vec<u8>>,
    sent_b: Vec<Vec<u8>>,
}

impl Sim {
    fn new(ccfg: Config, lcfg: Config, owd_ms: u64, isn: u32) -> Sim {
        let t0 = Instant::now();
        let a: SocketAddr = "10.1.0.1:5000".parse().unwrap();
        let b: SocketAddr = "10.1.0.2:6000".parse().unwrap();
        Sim {
            t0,
            now: t0,
            owd: Duration::from_millis(owd_ms),
            a,
            b,
            caller: Connection::connect(ccfg, t0, b, 0x1234, isn),
            listener: Listener::new(lcfg, t0),
            conns: HashMap::new(),
            accepted: Vec::new(),
            wire: Vec::new(),
            drop: Box::new(|_, _| false),
            sent_a: Vec::new(),
            sent_b: Vec::new(),
        }
    }

    fn conn(&mut self) -> &mut Connection {
        let sid = *self.accepted.last().expect("accepted");
        self.conns.get_mut(&sid).unwrap()
    }

    /// One step: deliver due datagrams, run timers, transmit.
    fn step(&mut self) {
        self.now += STEP;
        let now = self.now;
        let mut due = Vec::new();
        self.wire.retain(|(t, to, d)| {
            if *t <= now {
                due.push((*to, d.clone()));
                false
            } else {
                true
            }
        });
        let mut out = [0u8; 1500];
        for (to, d) in due {
            if to == self.a {
                self.caller.handle_datagram(now, self.b, &d);
                continue;
            }
            let dst = packet::dst_socket_id(&d).unwrap();
            if dst == 0 {
                match self.listener.handle(now, self.a, &d, &mut out) {
                    ListenerAction::Reply(n) => self.wire.push((now + self.owd, self.a, out[..n].to_vec())),
                    ListenerAction::Accept(c) => {
                        let sid = c.local_socket_id();
                        self.conns.insert(sid, *c);
                        self.accepted.push(sid);
                    }
                    ListenerAction::Existing(sid) => self.conns.get_mut(&sid).unwrap().handle_datagram(now, self.a, &d),
                    ListenerAction::Ignore => {}
                }
            } else if let Some(c) = self.conns.get_mut(&dst) {
                c.handle_datagram(now, self.a, &d);
            }
        }
        if self.caller.poll_timeout().map_or(false, |t| t <= now) {
            self.caller.handle_timeout(now);
        }
        for c in self.conns.values_mut() {
            if c.poll_timeout().map_or(false, |t| t <= now) {
                c.handle_timeout(now);
            }
        }
        let mut buf = [0u8; 1500];
        while let Some(t) = self.caller.poll_transmit(now, &mut buf) {
            let d = buf[..t.len].to_vec();
            self.sent_a.push(d.clone());
            if !(self.drop)("a", &d) {
                self.wire.push((now + self.owd, self.b, d));
            }
        }
        for c in self.conns.values_mut() {
            while let Some(t) = c.poll_transmit(now, &mut buf) {
                let d = buf[..t.len].to_vec();
                self.sent_b.push(d.clone());
                if !(self.drop)("b", &d) {
                    self.wire.push((now + self.owd, self.a, d));
                }
            }
        }
    }

    fn run_until(&mut self, limit: Duration, mut f: impl FnMut(&mut Sim) -> bool) -> bool {
        let end = self.now + limit;
        while self.now < end {
            self.step();
            if f(self) {
                return true;
            }
        }
        false
    }

    fn connect(&mut self) {
        assert!(
            self.run_until(Duration::from_secs(10), |s| s.caller.is_connected()),
            "caller did not connect: {:?}",
            self.caller.state()
        );
    }
}

fn ctl_type(d: &[u8]) -> Option<u16> {
    match packet::decode(d).ok()? {
        Packet::Control { hdr, .. } => Some(hdr.ctype),
        _ => None,
    }
}

fn cfg(lat: u16) -> Config {
    Config::default().with_latency_ms(lat)
}

#[test]
fn connects_and_negotiates_latency_max() {
    let ccfg = Config {
        rcv_latency_ms: 80,
        peer_latency_ms: 200,
        ..Config::default()
    };
    let mut s = Sim::new(ccfg, cfg(120), 15, 1000);
    s.connect();
    assert_eq!(s.accepted.len(), 1);
    // caller -> listener: max(listener rcv 120, caller peer 200) = 200
    // listener -> caller: max(caller rcv 80, listener peer 120) = 120
    assert_eq!(s.caller.latencies_ms(), (120, 200));
    assert_eq!(s.conn().latencies_ms(), (200, 120));
    // caller connected one RTT after the induction response: ~ 2 RTT
    let took = s.now - s.t0;
    assert!(took >= Duration::from_millis(60) && took < Duration::from_millis(62), "{took:?}");
    assert_eq!(s.caller.poll_event(), Some(Event::Connected));
}

#[test]
fn tsbpd_delivers_at_origin_plus_owd_plus_latency_in_order() {
    let mut s = Sim::new(cfg(120), cfg(120), 15, 5000);
    s.connect();
    let mut sent_at = Vec::new();
    let mut got = Vec::new();
    let mut msg = vec![0u8; 1316];
    let start = s.now;
    s.run_until(Duration::from_millis(1500), |s| {
        // a burst of 50 packets every 40 ms for 1 s
        let el = s.now - start;
        if el < Duration::from_secs(1) && el.as_micros() % 40_000 < STEP.as_micros() {
            for _ in 0..50 {
                let i = sent_at.len() as u32;
                msg[..4].copy_from_slice(&i.to_be_bytes());
                s.caller.send_message(s.now, &msg, None).unwrap();
                sent_at.push(s.now);
            }
        }
        let now = s.now;
        while let Some(m) = s.conn().recv_message(now) {
            let i = u32::from_be_bytes(m.payload[..4].try_into().unwrap());
            got.push((i, now));
        }
        false
    });
    assert_eq!(got.len(), sent_at.len());
    for (k, (i, at)) in got.iter().enumerate() {
        assert_eq!(*i as usize, k, "in order");
        let lat = *at - sent_at[k];
        // 15 ms one way + 120 ms, quantised by the 50 us step (and pacing
        // spreads a 50-packet burst over < 1 ms but delivery is by origin)
        assert!(
            lat >= Duration::from_micros(134_900) && lat <= Duration::from_micros(135_200),
            "packet {k}: {lat:?}"
        );
    }
    let st = s.conn().stats().clone();
    assert_eq!(st.pkt_rcv_loss, 0);
    assert_eq!(st.pkt_rcv_drop, 0);
    assert!(st.pkt_sent_ack >= 24, "one ACK per burst at least: {}", st.pkt_sent_ack);
    assert_eq!(st.pkt_recv_ackack, st.pkt_sent_ack);
    // RTT from ACK/ACKACK on the receiver, and copied to the sender from ACKs
    let now = s.now;
    let rs = s.conn().snapshot(now);
    assert!((29_000..=31_500).contains(&rs.rtt_us), "{}", rs.rtt_us);
    let cs = s.caller.snapshot(s.now);
    assert!(cs.rtt_valid);
    assert!((29_000..=31_500).contains(&cs.rtt_us), "{}", cs.rtt_us);
    assert_eq!(s.caller.send_buffer_len(), 0, "everything acknowledged");
    assert_eq!(s.caller.stats().ack_invalid, 0);
}

#[test]
fn gap_is_dropped_when_next_packet_is_due() {
    let mut s = Sim::new(cfg(100), cfg(100), 5, 7);
    s.connect();
    let mut n = 0;
    s.drop = Box::new(move |side, d| {
        if side == "a" && d[0] & 0x80 == 0 {
            n += 1;
            return n == 3; // lose the third data packet
        }
        false
    });
    for i in 0..5u8 {
        s.caller.send_message(s.now, &[i; 100], None).unwrap();
    }
    let mut got = Vec::new();
    s.run_until(Duration::from_millis(300), |s| {
        let now = s.now;
        while let Some(m) = s.conn().recv_message(now) {
            got.push(m.payload[0]);
        }
        false
    });
    assert_eq!(got, vec![0, 1, 3, 4]);
    let st = s.conn().stats().clone();
    assert_eq!(st.pkt_rcv_loss, 1);
    assert_eq!(st.pkt_rcv_drop, 1);
}

#[test]
fn keepalive_when_idle_and_no_idle_timeout() {
    let mut s = Sim::new(cfg(120), cfg(120), 10, 1);
    s.connect();
    s.run_until(Duration::from_millis(7000), |_| false);
    assert!(s.caller.is_connected());
    assert!(s.conn().is_connected());
    let ka_a = s.sent_a.iter().filter(|d| ctl_type(d) == Some(packet::ctrl::KEEPALIVE)).count();
    let ka_b = s.sent_b.iter().filter(|d| ctl_type(d) == Some(packet::ctrl::KEEPALIVE)).count();
    assert!((6..=8).contains(&ka_a) && (6..=8).contains(&ka_b), "{ka_a} {ka_b}");
}

#[test]
fn shutdown_closes_peer_at_once() {
    let mut s = Sim::new(cfg(120), cfg(120), 10, 1);
    s.connect();
    s.caller.close(s.now);
    assert_eq!(s.caller.state(), &State::Closed(CloseReason::Local));
    s.run_until(Duration::from_millis(50), |_| false);
    assert_eq!(s.conn().state(), &State::Closed(CloseReason::PeerShutdown));
    let shut = s.sent_a.iter().filter(|d| ctl_type(d) == Some(packet::ctrl::SHUTDOWN)).count();
    assert_eq!(shut, 1);
}

#[test]
fn peer_idle_breaks_after_5s() {
    let mut s = Sim::new(cfg(120), cfg(120), 10, 1);
    s.connect();
    s.drop = Box::new(|side, _| side == "a");
    let t = s.now;
    assert!(s.run_until(Duration::from_secs(7), |s| s.conn().is_closed()));
    assert_eq!(s.conn().state(), &State::Closed(CloseReason::PeerIdle));
    let e = s.now - t;
    assert!(e > Duration::from_millis(4990) && e < Duration::from_millis(5100), "{e:?}");
}

#[test]
fn lost_induction_and_conclusion_response_same_socket() {
    let mut s = Sim::new(cfg(120), cfg(120), 50, 1);
    let mut n_ind = 0;
    let mut n_rsp = 0;
    s.drop = Box::new(move |side, d| {
        if let Ok(Packet::Control {
            body: Control::Handshake(h), ..
        }) = packet::decode(d)
        {
            if side == "a" && h.req_type == srt_core::handshake::req::INDUCTION {
                n_ind += 1;
                return n_ind == 1;
            }
            if side == "b" && h.req_type == srt_core::handshake::req::CONCLUSION {
                n_rsp += 1;
                return n_rsp <= 2; // first response and its first re-send lost
            }
        }
        false
    });
    s.connect();
    assert_eq!(s.accepted.len(), 1, "one connection on the listener");
    assert!(s.listener.stats().repeated >= 1 || s.conn().stats().pkt_sent_handshake >= 3);
    // the same caller socket id and ISN throughout
    let ids: Vec<u32> = s
        .sent_a
        .iter()
        .filter_map(|d| match packet::decode(d).ok()? {
            Packet::Control {
                body: Control::Handshake(h), ..
            } => Some(h.socket_id),
            _ => None,
        })
        .collect();
    assert!(ids.len() >= 3 && ids.iter().all(|&i| i == 0x1234));
    // connected well before libsrt's 3 s: induction re-sent at 250 ms
    assert!(s.now - s.t0 < Duration::from_millis(1200), "{:?}", s.now - s.t0);
}

#[test]
fn connect_timeout_when_nobody_answers() {
    let ccfg = Config {
        connect_timeout: Duration::from_secs(3),
        ..cfg(120)
    };
    let mut s = Sim::new(ccfg, cfg(120), 10, 1);
    s.drop = Box::new(|_, _| true);
    assert!(s.run_until(Duration::from_secs(5), |s| s.caller.is_closed()));
    assert_eq!(s.caller.state(), &State::Closed(CloseReason::ConnectTimeout));
    let e = s.now - s.t0;
    assert!(e >= Duration::from_secs(3) && e < Duration::from_millis(3010));
    // 250 ms, then doubling to 1 s: 0, 0.25, 0.75, 1.75, 2.75
    assert_eq!(s.sent_a.len(), 5);
}

#[test]
fn sequence_wrap_and_data_from_listener_to_caller() {
    let isn = srt_core::seq::SEQ_MAX - 10;
    let mut s = Sim::new(cfg(50), cfg(50), 2, isn);
    s.connect();
    // listener sends to the caller: same ISN in this direction
    let mut got = Vec::new();
    for i in 0..40u32 {
        let now = s.now;
        let seq = s.conn().send_message(now, &i.to_be_bytes(), None).unwrap();
        assert_eq!(seq, srt_core::seq::seq_add(isn, i as i32));
        s.step();
    }
    s.run_until(Duration::from_millis(200), |s| {
        while let Some(m) = s.caller.recv_message(s.now) {
            got.push(u32::from_be_bytes(m.payload.try_into().unwrap()));
        }
        false
    });
    assert_eq!(got, (0..40).collect::<Vec<_>>());
    assert_eq!(s.conn().send_buffer_len(), 0);
}

#[test]
fn send_buffer_full_and_too_large() {
    let ccfg = Config { snd_buf_pkts: 32, ..cfg(120) };
    let mut s = Sim::new(ccfg, cfg(120), 10, 1);
    assert_eq!(s.caller.send_message(s.now, &[0; 10], None), Err(srt_core::SendError::NotConnected));
    s.connect();
    assert_eq!(s.caller.send_message(s.now, &[0; 1317], None), Err(srt_core::SendError::TooLarge));
    for _ in 0..32 {
        s.caller.send_message(s.now, &[0; 10], None).unwrap();
    }
    assert_eq!(s.caller.send_message(s.now, &[0; 10], None), Err(srt_core::SendError::WouldBlock));
    s.run_until(Duration::from_millis(100), |_| false);
    assert_eq!(s.caller.send_buffer_len(), 0);
    assert!(s.caller.send_message(s.now, &[0; 10], None).is_ok());
}
