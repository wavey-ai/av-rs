//! Caller and listener over a simulated network (fixed one-way delay,
//! scripted drops), with simulated time.

use srt_core::packet::{self, Control, Packet};
use srt_core::seq;
use srt_core::{CloseReason, Config, Connection, Event, Listener, ListenerAction, State};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

const STEP: Duration = Duration::from_micros(50);

type DropFn = Box<dyn FnMut(&str, &[u8]) -> bool>;
type DelayFn = Box<dyn FnMut(&str, &[u8]) -> Duration>;

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
    delay: DelayFn,
    sent_a: Vec<Vec<u8>>,
    sent_b: Vec<Vec<u8>>,
    /// Sim time, readable from drop/delay closures.
    clock: std::rc::Rc<std::cell::Cell<Instant>>,
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
            delay: Box::new(|_, _| Duration::ZERO),
            sent_a: Vec::new(),
            sent_b: Vec::new(),
            clock: std::rc::Rc::new(std::cell::Cell::new(t0)),
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
        self.clock.set(now);
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
                let extra = (self.delay)("a", &d);
                self.wire.push((now + self.owd + extra, self.b, d));
            }
        }
        for c in self.conns.values_mut() {
            while let Some(t) = c.poll_transmit(now, &mut buf) {
                let d = buf[..t.len].to_vec();
                self.sent_b.push(d.clone());
                if !(self.drop)("b", &d) {
                    let extra = (self.delay)("b", &d);
                    self.wire.push((now + self.owd + extra, self.a, d));
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

fn data_seq(d: &[u8]) -> Option<u32> {
    match packet::decode(d).ok()? {
        Packet::Data { hdr, .. } => Some(hdr.seq),
        _ => None,
    }
}

#[test]
fn gap_is_dropped_when_next_packet_is_due() {
    let mut s = Sim::new(cfg(100), cfg(100), 5, 7);
    s.connect();
    // lose the third data packet and every retransmission of it
    s.drop = Box::new(move |side, d| side == "a" && data_seq(d) == Some(9));
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
    // it was NAKed and retransmitted (every copy lost), then given up
    assert!(st.pkt_sent_nak >= 2, "{st:?}");
    assert!(s.caller.stats().pkt_retrans >= 2);
    let now = s.now;
    assert_eq!(s.conn().snapshot(now).rcv_loss_seqs, 0, "dropped holes leave the loss list");
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

/// Deterministic xorshift PRNG for loss patterns.
struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn chance(&mut self, pct: f64) -> bool {
        (self.next() % 1_000_000) as f64 / 10_000.0 < pct
    }
}

/// Send `frames` bursts of `per_frame` packets every `interval` from the
/// caller; return (frame index, packets delivered late or not at all,
/// latency of each delivered packet).
fn run_frames(s: &mut Sim, frames: usize, per_frame: usize, interval: Duration, tail: Duration) -> (Vec<Duration>, usize) {
    let mut sent_at: Vec<Instant> = Vec::new();
    let mut lat = Vec::new();
    let mut msg = vec![0u8; 1316];
    let start = s.now;
    let mut next_frame = start;
    let mut sent_frames = 0;
    let mut got = std::collections::HashSet::new();
    s.run_until(interval * frames as u32 + tail, |s| {
        if sent_frames < frames && s.now >= next_frame {
            for _ in 0..per_frame {
                let i = sent_at.len() as u32;
                msg[..4].copy_from_slice(&i.to_be_bytes());
                s.caller.send_message(s.now, &msg, None).unwrap();
                sent_at.push(s.now);
            }
            sent_frames += 1;
            next_frame += interval;
        }
        let now = s.now;
        while let Some(m) = s.conn().recv_message(now) {
            let i = u32::from_be_bytes(m.payload[..4].try_into().unwrap());
            assert!(got.insert(i), "delivered twice: {i}");
            lat.push(now - sent_at[i as usize]);
        }
        false
    });
    let missing = sent_at.len() - got.len();
    (lat, missing)
}

#[test]
fn single_loss_is_nak_repaired_and_delivered_on_time() {
    let mut s = Sim::new(cfg(120), cfg(120), 15, 100);
    s.connect();
    let mut lost = false;
    // lose the first transmission of seq 102 (the third packet)
    s.drop = Box::new(move |side, d| {
        if side == "a" && data_seq(d) == Some(102) && !lost {
            lost = true;
            return true;
        }
        false
    });
    let (lat, missing) = run_frames(&mut s, 1, 5, Duration::from_millis(40), Duration::from_millis(400));
    assert_eq!(missing, 0);
    // every packet, the repaired one included, at origin + 15 ms + 120 ms:
    // the repair fills the head gap and wakes delivery at once (not one
    // frame later, spec 6.10)
    for l in &lat {
        assert!(*l >= Duration::from_micros(134_900) && *l <= Duration::from_micros(135_200), "{lat:?}");
    }
    let r = s.conn().stats().clone();
    assert_eq!((r.pkt_rcv_loss, r.pkt_rcv_drop, r.pkt_rcv_retrans, r.pkt_rcv_repaired), (1, 0, 1, 1));
    // one immediate NAK, sent twice back to back
    assert_eq!((r.pkt_sent_nak, r.nak_seqs_sent), (2, 1));
    let c = s.caller.stats().clone();
    // both copies arrive; the second finds the request already queued
    assert_eq!((c.pkt_retrans, c.pkt_snd_loss, c.pkt_recv_nak), (1, 2, 2));
    assert_eq!(c.pkt_sent, 6);
}

#[test]
fn lost_retransmission_and_lost_nak_are_renaked() {
    // 1002 and 1004 lost; the first NAK and the first re-NAK lost; the
    // first retransmission of 1002 lost
    let mut s = Sim::new(cfg(200), cfg(200), 15, 1000);
    s.connect();
    s.run_until(Duration::from_millis(200), |_| false); // RTT known
    let (mut n1002, mut n1004, mut naks) = (0, 0, 0);
    s.drop = Box::new(move |side, d| {
        if side == "a" && data_seq(d) == Some(1002) {
            n1002 += 1;
            return n1002 <= 2;
        }
        if side == "a" && data_seq(d) == Some(1004) {
            n1004 += 1;
            return n1004 == 1;
        }
        if side == "b" && ctl_type(d) == Some(packet::ctrl::NAK) {
            naks += 1;
            return naks <= 2;
        }
        false
    });
    let (lat, missing) = run_frames(&mut s, 1, 8, Duration::from_millis(40), Duration::from_millis(600));
    assert_eq!(missing, 0, "{:?}", s.conn().stats());
    for l in &lat {
        assert!(*l >= Duration::from_micros(214_900) && *l <= Duration::from_micros(215_200), "{lat:?}");
    }
    let r = s.conn().stats().clone();
    assert_eq!(r.pkt_rcv_drop, 0);
    // the lost NAKs are NAKed again (late attempts: each sent twice, the
    // copy later); the lost repair of 1002 is sent again by the receiver's
    // re-NAK or the sender's head probe, whichever comes first
    assert!(r.pkt_sent_nak >= 3, "{r:?}");
    let c = s.caller.stats().clone();
    assert!(c.pkt_retrans >= 3 && c.pkt_retrans <= 1 + 3 + c.pkt_tail_probe + c.pkt_head_probe, "{c:?}");
    // one re-NAK interval is about one RTT (30 ms) + capped variation +
    // 2 ms, far below libsrt's 300 ms before its first periodic NAK
    let now = s.now;
    let sn = s.conn().snapshot(now);
    assert!(sn.renak_interval_us < 50_000, "{}", sn.renak_interval_us);
}

#[test]
fn tail_probe_recovers_a_lost_last_packet() {
    let mut s = Sim::new(cfg(120), cfg(120), 15, 500);
    s.connect();
    let mut lost = false;
    s.drop = Box::new(move |side, d| {
        if side == "a" && data_seq(d) == Some(509) && !lost {
            lost = true;
            return true; // the last packet of the only burst
        }
        false
    });
    let (lat, missing) = run_frames(&mut s, 1, 10, Duration::from_millis(40), Duration::from_millis(400));
    assert_eq!(missing, 0);
    assert!(lat.iter().all(|l| *l <= Duration::from_micros(135_200)), "{lat:?}");
    let c = s.caller.stats().clone();
    assert_eq!(c.pkt_tail_probe, 1);
    // the probe, plus a second copy if too little time was left for
    // another round
    assert_eq!(c.pkt_retrans, 1 + c.pkt_rexmit_copies, "{c:?}");
    assert_eq!(s.conn().stats().pkt_rcv_drop, 0);
}

#[test]
fn no_tail_probe_when_acknowledged() {
    let mut s = Sim::new(cfg(120), cfg(120), 15, 500);
    s.connect();
    let (_, missing) = run_frames(&mut s, 5, 10, Duration::from_millis(100), Duration::from_millis(400));
    assert_eq!(missing, 0);
    let c = s.caller.stats().clone();
    assert_eq!((c.pkt_tail_probe, c.pkt_retrans), (0, 0), "{c:?}");
}

#[test]
fn random_loss_5pct_both_ways_rtt30_l120() {
    // 5 % random loss on every datagram (data, NAK, ACK, retransmission) in
    // both directions; 24 frames/s of 100 packets; latency 4 x RTT
    let mut s = Sim::new(cfg(120), cfg(120), 15, 77);
    s.connect();
    let mut rng = Rng(0x9E37_79B9_7F4A_7C15);
    s.drop = Box::new(move |_, _| rng.chance(5.0));
    let (lat, missing) = run_frames(&mut s, 48, 100, Duration::from_micros(41_667), Duration::from_millis(500));
    let r = s.conn().stats().clone();
    let c = s.caller.stats().clone();
    assert_eq!(missing, 0, "rcv {r:?}\nsnd {c:?}");
    assert!(lat.iter().all(|l| *l <= Duration::from_micros(135_300)));
    assert!(r.pkt_rcv_loss > 150, "{}", r.pkt_rcv_loss);
    // retransmissions close to the losses (losses of retransmissions and
    // tail probes add a few); duplicates few
    assert!(c.pkt_retrans < r.pkt_rcv_loss * 14 / 10, "retrans {} loss {}", c.pkt_retrans, r.pkt_rcv_loss);
    // duplicates: mostly the deliberate second copies of late repairs
    assert!(
        r.pkt_rcv_duplicate <= c.pkt_rexmit_copies + r.pkt_rcv_loss / 20,
        "dup {} loss {}\n{c:?}",
        r.pkt_rcv_duplicate,
        r.pkt_rcv_loss
    );
    assert!(c.pkt_rexmit_copies < r.pkt_rcv_loss / 4, "{c:?}");
    assert_eq!((c.ack_invalid, c.nak_invalid), (0, 0));
}

#[test]
fn random_loss_5pct_rtt250_l1000_listener_sends() {
    // the other direction (listener -> caller) on a long path
    let mut s = Sim::new(cfg(1000), cfg(1000), 125, 3);
    s.connect();
    let mut rng = Rng(12345);
    s.drop = Box::new(move |_, _| rng.chance(5.0));
    let mut sent = 0u32;
    let mut got = Vec::new();
    let start = s.now;
    s.run_until(Duration::from_millis(2800), |s| {
        if s.now - start < Duration::from_millis(1500) && (s.now - start).as_micros() % 10_000 < 50 {
            for _ in 0..20 {
                let now = s.now;
                s.conn().send_message(now, &sent.to_be_bytes(), None).unwrap();
                sent += 1;
            }
        }
        while let Some(m) = s.caller.recv_message(s.now) {
            got.push(u32::from_be_bytes(m.payload.try_into().unwrap()));
        }
        false
    });
    let missing: Vec<u32> = (0..sent).filter(|i| !got.contains(i)).collect();
    let snd = s.conn().stats().clone();
    assert_eq!(got.len() as u32, sent, "missing {missing:?}\nrcv {:?}\nsnd {snd:?}", s.caller.stats());
    assert_eq!(got, (0..sent).collect::<Vec<_>>());
    assert_eq!(s.caller.stats().pkt_rcv_drop, 0);
}

#[test]
fn sender_drop_announces_dropreq() {
    let mut s = Sim::new(cfg(100), cfg(100), 5, 50);
    s.connect();
    s.run_until(Duration::from_millis(100), |_| false);
    // every data packet and every ACK lost: the sender holds the packets
    // latency + max(latency/4, 20 ms) + 10 ms + 2 RTT (10 ms, from the
    // handshake) = 155 ms past their origin, then drops them and says so
    s.drop = Box::new(|side, d| (side == "a" && data_seq(d).is_some()) || (side == "b" && ctl_type(d) == Some(packet::ctrl::ACK)));
    let t = s.now;
    for i in 0..6u8 {
        s.caller.send_message(s.now, &[i; 10], None).unwrap();
    }
    assert!(s.run_until(Duration::from_millis(300), |s| s.caller.send_buffer_len() == 0));
    let e = s.now - t;
    assert!(e >= Duration::from_millis(155) && e < Duration::from_millis(157), "{e:?}");
    let c = s.caller.stats().clone();
    assert_eq!(c.pkt_snd_drop, 6, "{c:?}");
    assert_eq!(c.pkt_sent_dropreq, 1);
    s.run_until(Duration::from_millis(20), |_| false);
    assert_eq!(s.conn().stats().pkt_recv_dropreq, 1);
}

#[test]
fn nak_for_unheld_sequence_gets_dropreq_and_dropreq_clears_holes() {
    let mut s = Sim::new(cfg(500), cfg(500), 5, 50);
    s.connect();
    // 51..=54 never arrive
    s.drop = Box::new(|side, d| side == "a" && matches!(data_seq(d), Some(51..=54)));
    for i in 0..6u8 {
        s.caller.send_message(s.now, &[i; 10], None).unwrap();
    }
    s.run_until(Duration::from_millis(60), |_| false);
    let now = s.now;
    assert_eq!(s.conn().snapshot(now).rcv_loss_seqs, 4);
    // the sender says it will not send 52..=53
    let mut b = [0u8; 64];
    let sid = s.conn().local_socket_id();
    let n = packet::encode_dropreq(0, 52, 53, 0, sid, &mut b);
    let a = s.a;
    s.conn().handle_datagram(now, a, &b[..n]);
    assert_eq!(s.conn().snapshot(now).rcv_loss_seqs, 2);
    assert_eq!(s.conn().stats().pkt_rcv_dropreq_seqs, 2);
    // a NAK for 50 (already acknowledged) is answered with a DROPREQ
    s.run_until(Duration::from_millis(30), |_| false);
    assert!(s.caller.send_buffer_len() < 6);
    let before = s.caller.stats().pkt_sent_dropreq;
    let n = packet::encode_nak([(50, 50)], 0, 0x1234, 10, &mut b);
    let (now, bb) = (s.now, s.b);
    s.caller.handle_datagram(now, bb, &b[..n]);
    let mut out = [0u8; 1500];
    let mut seen = None;
    while let Some(t) = s.caller.poll_transmit(now, &mut out) {
        if let Ok(Packet::Control {
            hdr,
            body: Control::DropReq { first, last },
        }) = packet::decode(&out[..t.len])
        {
            seen = Some((hdr.info, first, last));
        }
    }
    assert_eq!(seen, Some((0, 50, 50)));
    assert_eq!(s.caller.stats().pkt_sent_dropreq, before + 1);
    // a NAK beyond what was sent is ignored and counted
    let n = packet::encode_nak([(60, 61)], 0, 0x1234, 10, &mut b);
    s.caller.handle_datagram(now, bb, &b[..n]);
    assert_eq!(s.caller.stats().nak_invalid, 1);
    assert!(s.caller.is_connected());
}

#[test]
fn reorder_tolerance_suppresses_nak_for_late_packet() {
    let ccfg = cfg(120);
    let lcfg = Config { loss_max_ttl: 10, ..cfg(120) };
    let mut s = Sim::new(ccfg, lcfg, 10, 900);
    s.connect();
    // seq 902 arrives 300 us late (after the other 7 of its burst: fewer
    // than 10 packets and well within the 2 ms reorder window)
    s.delay = Box::new(|side, d| {
        if side == "a" && data_seq(d) == Some(902) {
            Duration::from_micros(300)
        } else {
            Duration::ZERO
        }
    });
    let (_, missing) = run_frames(&mut s, 1, 10, Duration::from_millis(40), Duration::from_millis(300));
    assert_eq!(missing, 0);
    let r = s.conn().stats().clone();
    assert_eq!(r.pkt_rcv_loss, 1, "seen as a gap");
    assert_eq!(r.pkt_sent_nak, 0, "but not NAKed: it arrived within the tolerance");
    assert_eq!(s.caller.stats().pkt_retrans, 0);
}

#[test]
fn reorder_beyond_tolerance_is_naked() {
    let lcfg = Config { loss_max_ttl: 4, ..cfg(120) };
    let mut s = Sim::new(cfg(120), lcfg, 10, 900);
    s.connect();
    let mut lost = false;
    s.drop = Box::new(move |side, d| {
        if side == "a" && data_seq(d) == Some(902) && !lost {
            lost = true;
            return true;
        }
        false
    });
    let (_, missing) = run_frames(&mut s, 1, 10, Duration::from_millis(40), Duration::from_millis(300));
    assert_eq!(missing, 0);
    let r = s.conn().stats().clone();
    assert_eq!((r.pkt_sent_nak, r.nak_seqs_sent), (2, 1));
    assert_eq!(s.caller.stats().pkt_retrans, 1);
}

#[test]
fn ack_logic_light_every_64_full_every_10ms_and_quiet_when_idle() {
    let mut s = Sim::new(cfg(120), cfg(120), 10, 40);
    s.connect();
    // 640 packets in one burst (paced at 1 Gbit/s: ~7 ms)
    let mut m = vec![0u8; 1316];
    for i in 0..640u32 {
        m[..4].copy_from_slice(&i.to_be_bytes());
        s.caller.send_message(s.now, &m, None).unwrap();
    }
    s.run_until(Duration::from_millis(100), |s| {
        let now = s.now;
        while s.conn().recv_message(now).is_some() {}
        false
    });
    let r = s.conn().stats().clone();
    // one light ACK per 64 packets between timed ACKs, a handful of timed
    // (full/small) ACKs, each answered by an ACKACK
    assert!((5..=10).contains(&r.pkt_sent_light_ack), "{r:?}");
    assert!((1..=4).contains(&r.pkt_sent_ack), "{r:?}");
    assert_eq!(r.pkt_recv_ackack, r.pkt_sent_ack);
    assert_eq!(s.caller.send_buffer_len(), 0);
    let c = s.caller.stats().clone();
    assert_eq!(c.pkt_sent_ackack, r.pkt_sent_ack);
    assert_eq!(c.pkt_tail_probe, 0);
    // nothing new: no more ACKs while idle (the last one was confirmed)
    let acks = r.pkt_sent_ack + r.pkt_sent_light_ack;
    s.run_until(Duration::from_millis(500), |_| false);
    let r = s.conn().stats().clone();
    assert_eq!(r.pkt_sent_ack + r.pkt_sent_light_ack, acks);
    // RTT from ACK/ACKACK on the receiver, reported to the sender
    let now = s.now;
    let rs = s.conn().snapshot(now);
    assert!(rs.rtt_valid && (19_000..=22_000).contains(&rs.rtt_us), "{rs:?}");
    assert!(s.caller.snapshot(now).rtt_valid);
}

#[test]
fn random_loss_across_sequence_wrap() {
    let isn = srt_core::seq::SEQ_MAX - 300;
    let mut s = Sim::new(cfg(120), cfg(120), 15, isn);
    s.connect();
    let mut rng = Rng(777);
    s.drop = Box::new(move |_, _| rng.chance(5.0));
    let (lat, missing) = run_frames(&mut s, 10, 100, Duration::from_micros(41_667), Duration::from_millis(400));
    let r = s.conn().stats().clone();
    assert_eq!(missing, 0, "{r:?}");
    assert!(lat.iter().all(|l| *l <= Duration::from_micros(135_300)));
    assert!(r.pkt_rcv_loss > 20);
    assert_eq!((s.caller.stats().ack_invalid, s.caller.stats().nak_invalid), (0, 0));
}

#[test]
fn head_probe_repairs_when_the_receiver_does_not_renak() {
    // a receiver that NAKs once and never again (libsrt before its first
    // RTT sample re-NAKs only after 300 ms): the original and the first
    // repair of 302 are lost; the sender's head probe resends it
    let mut s = Sim::new(cfg(120), cfg(120), 15, 300);
    s.connect();
    let (mut n, mut naks) = (0, 0);
    s.drop = Box::new(move |side, d| {
        if side == "a" && data_seq(d) == Some(302) {
            n += 1;
            return n <= 2;
        }
        if side == "b" && ctl_type(d) == Some(packet::ctrl::NAK) {
            naks += 1;
            return naks > 2;
        }
        false
    });
    let (lat, missing) = run_frames(&mut s, 3, 10, Duration::from_millis(40), Duration::from_millis(300));
    assert_eq!(missing, 0, "{:?}", s.caller.stats());
    assert!(lat.iter().all(|l| *l <= Duration::from_micros(135_200)), "{lat:?}");
    assert!(s.caller.stats().pkt_head_probe >= 1);
    assert_eq!(s.conn().stats().pkt_rcv_drop, 0);
}

#[test]
fn late_nak_copy_is_delayed_and_acks_floor_rttvar() {
    let mut s = Sim::new(cfg(200), cfg(200), 15, 2000);
    s.connect();
    s.run_until(Duration::from_millis(300), |_| false);
    // 2002 lost twice: the re-NAK is a late attempt, sent again later
    let mut n = 0;
    s.drop = Box::new(move |side, d| {
        if side == "a" && data_seq(d) == Some(2002) {
            n += 1;
            return n <= 2;
        }
        false
    });
    let (_, missing) = run_frames(&mut s, 1, 8, Duration::from_millis(40), Duration::from_millis(400));
    assert_eq!(missing, 0);
    let mut naks = Vec::new();
    let mut rttvar_ok = 0;
    for d in &s.sent_b {
        match packet::decode(d).unwrap() {
            Packet::Control { hdr, body: Control::Nak(l) } => naks.push((hdr.timestamp, l.raw().to_vec())),
            Packet::Control { body: Control::Ack(a), .. } if a.kind != packet::AckKind::Light && a.rtt_us < 100_000 => {
                assert!(a.rtt_var_us > a.rtt_us / 4, "{a:?}");
                rttvar_ok += 1;
            }
            _ => {}
        }
    }
    assert!(rttvar_ok > 0);
    // first NAK and its copy at once; the re-NAK, then its copy >= 10 ms
    // later
    assert_eq!(naks.len(), 4, "{naks:?}");
    assert_eq!(naks[0].0, naks[1].0);
    assert_eq!(naks[2].1, naks[3].1);
    assert!(naks[3].0 - naks[2].0 >= 10_000, "{naks:?}");
}

// ---------------------------------------------------------------- FEC (stage 3)

fn is_fec(d: &[u8]) -> bool {
    matches!(packet::decode(d), Ok(Packet::Data { hdr, .. }) if hdr.msgno == 0)
}

fn fcfg(lat: u16, filter: &str) -> Config {
    Config {
        packet_filter: Some(filter.to_string()),
        ..cfg(lat)
    }
}

fn vmsg(i: u32) -> Vec<u8> {
    let len = 200 + (i as usize * 97) % 1117;
    let mut m: Vec<u8> = (0..len).map(|j| (i as usize * 31 + j * 7) as u8).collect();
    m[..4].copy_from_slice(&i.to_be_bytes());
    m
}

/// As `run_frames`, with messages of varying length and content, every
/// delivered payload checked byte for byte.
fn run_frames_v(s: &mut Sim, frames: usize, per_frame: usize, interval: Duration, tail: Duration) -> (Vec<Duration>, usize) {
    let mut sent_at: Vec<Instant> = Vec::new();
    let mut lat = Vec::new();
    let start = s.now;
    let mut next_frame = start;
    let mut sent_frames = 0;
    let mut got = std::collections::HashSet::new();
    s.run_until(interval * frames as u32 + tail, |s| {
        if sent_frames < frames && s.now >= next_frame {
            for _ in 0..per_frame {
                let i = sent_at.len() as u32;
                s.caller.send_message(s.now, &vmsg(i), None).unwrap();
                sent_at.push(s.now);
            }
            sent_frames += 1;
            next_frame += interval;
        }
        let now = s.now;
        while let Some(m) = s.conn().recv_message(now) {
            let i = u32::from_be_bytes(m.payload[..4].try_into().unwrap());
            assert_eq!(m.payload, &vmsg(i)[..], "payload of {i}");
            assert!(got.insert(i), "delivered twice: {i}");
            lat.push(now - sent_at[i as usize]);
        }
        false
    });
    (lat, sent_at.len() - got.len())
}

#[test]
fn fec_negotiation_mismatch_rejects_and_merge_connects() {
    let mut s = Sim::new(fcfg(120, "fec,cols:20"), fcfg(120, "fec,cols:10,rows:5"), 15, 9);
    s.run_until(Duration::from_secs(2), |s| s.caller.is_closed());
    assert_eq!(s.caller.state(), &State::Closed(CloseReason::Rejected(srt_core::RejectReason::Filter)));
    // listener "fec" + caller's full config: merged, both sides run it
    let mut s = Sim::new(fcfg(120, "fec,cols:10,rows:5,layout:even,arq:never"), fcfg(120, "fec"), 15, 9);
    s.connect();
    let f = s.caller.fec_config().unwrap();
    assert_eq!((f.cols, f.rows, f.staircase, f.arq), (10, 5, false, srt_core::fec::ArqLevel::Never));
    assert_eq!(s.conn().fec_config(), Some(f));
    // a caller without a filter: the listener drops its own
    let mut s = Sim::new(cfg(120), fcfg(120, "fec,cols:10"), 15, 9);
    s.connect();
    assert!(s.caller.fec_config().is_none() && s.conn().fec_config().is_none());
    assert_eq!(s.caller.max_message(), 1316);
}

#[test]
fn fec_row_only_arq_never_rebuilds_without_naks() {
    let f = "fec,cols:10,rows:1,arq:never";
    let mut s = Sim::new(fcfg(120, f), fcfg(120, f), 15, 0x7FFF_FFF0); // across the wrap
    s.connect();
    let isn = 0x7FFF_FFF0u32;
    // one loss in each of rows 0..=5 (row 5: its last packet), two in row 7
    let lost: Vec<u32> = [3, 11, 25, 37, 42, 59, 71, 75].iter().map(|k| (isn + k) & 0x7FFF_FFFF).collect();
    let l2 = lost.clone();
    s.drop = Box::new(move |side, d| side == "a" && !is_fec(d) && data_seq(d).map_or(false, |q| l2.contains(&q)));
    let (lat, missing) = run_frames_v(&mut s, 4, 20, Duration::from_millis(40), Duration::from_millis(400));
    let r = s.conn().stats().clone();
    let c = s.caller.stats().clone();
    assert_eq!(missing, 2, "row 7 had two losses: arq:never cannot repair them");
    assert_eq!(r.pkt_rcv_filter_supply, 6, "{r:?}");
    assert!(lat.iter().all(|l| *l <= Duration::from_micros(135_300)), "{lat:?}");
    // 8 rows of 10 -> 8 FEC packets, nothing retransmitted, no NAK
    assert_eq!((c.pkt_snd_filter_extra, r.pkt_rcv_filter_extra), (8, 8));
    assert_eq!((r.pkt_sent_nak, c.pkt_retrans, c.pkt_tail_probe, c.pkt_head_probe), (0, 0, 0, 0), "{c:?}");
    assert_eq!(c.pkt_sent, 80 + 8);
}

#[test]
fn fec_onreq_naks_only_what_fec_cannot_rebuild() {
    // 2D staircase 10 x 5. Row 2 (k 20..29) loses 26 and 27; their column
    // groups ({16..56}, {27..67}) lose nothing else, so the columns
    // rebuild both. Rows 3 and 4 lose 30, 31, 40, 41: 30/40 share column
    // group {0..40} and 31/41 {11..51}, so nothing can rebuild them and
    // they are NAKed; the first NAK and the first two copies of 40 are
    // lost (libsrt's onreq would never NAK them again). Ours re-NAKs.
    let f = "fec,cols:10,rows:5,layout:staircase,arq:onreq";
    let mut s = Sim::new(fcfg(200, f), fcfg(200, f), 15, 1000);
    s.connect();
    s.run_until(Duration::from_millis(200), |_| false); // RTT known
    let (mut n1040, mut naks) = (0, 0);
    s.drop = Box::new(move |side, d| {
        if let (true, Ok(Packet::Data { hdr, .. })) = (side == "a", packet::decode(d)) {
            if hdr.msgno != 0 && [1026, 1027, 1030, 1031, 1041].contains(&hdr.seq) {
                return !hdr.rexmit;
            }
            if hdr.msgno != 0 && hdr.seq == 1040 {
                n1040 += 1;
                return n1040 <= 2;
            }
        }
        if side == "b" && ctl_type(d) == Some(packet::ctrl::NAK) {
            naks += 1;
            return naks == 1;
        }
        false
    });
    let (lat, missing) = run_frames_v(&mut s, 2, 100, Duration::from_millis(40), Duration::from_millis(600));
    let r = s.conn().stats().clone();
    let c = s.caller.stats().clone();
    assert_eq!(missing, 0, "rcv {r:?}\nsnd {c:?}");
    assert!(lat.iter().all(|l| *l <= Duration::from_micros(215_300)), "{lat:?}");
    // 26 and 27 by their columns; then, once repairs of 30/31 arrive,
    // their column groups can rebuild 40/41 (FEC and ARQ cooperate)
    assert!(r.pkt_rcv_filter_supply >= 2, "{r:?}");
    // only the four FEC could not rebuild were handed to NAK
    assert_eq!(r.pkt_rcv_filter_loss, 4, "{r:?}");
    assert!(r.pkt_sent_nak >= 2 && c.pkt_retrans >= 2, "rcv {r:?}\nsnd {c:?}");
    assert_eq!(r.pkt_rcv_drop, 0);
    // 200 packets: 20 row FEC + 10 x 4 columns complete (staircase heads
    // excepted)
    assert!(c.pkt_snd_filter_extra >= 50, "{c:?}");
}

#[test]
fn fec_onreq_renaks_after_lost_nak_and_lost_repair() {
    // row only: 40 and 41 in one row, unrebuildable. Both copies of the
    // first NAK and the first repair of 40 are lost; libsrt's onreq NAKs
    // a loss once and would lose 40. Ours NAKs it again.
    let f = "fec,cols:10,rows:1,arq:onreq";
    let mut s = Sim::new(
        Config {
            tail_probe: false,
            ..fcfg(200, f)
        },
        fcfg(200, f),
        15,
        1000,
    );
    s.connect();
    s.run_until(Duration::from_millis(200), |_| false); // RTT known
    let (mut n1040, mut naks) = (0, 0);
    s.drop = Box::new(move |side, d| {
        if let (true, Ok(Packet::Data { hdr, .. })) = (side == "a", packet::decode(d)) {
            if hdr.msgno != 0 && hdr.seq == 1041 {
                return !hdr.rexmit;
            }
            if hdr.msgno != 0 && hdr.seq == 1040 {
                n1040 += 1;
                return n1040 <= 2;
            }
        }
        if side == "b" && ctl_type(d) == Some(packet::ctrl::NAK) {
            naks += 1;
            return naks <= 2;
        }
        false
    });
    let (lat, missing) = run_frames_v(&mut s, 2, 100, Duration::from_millis(40), Duration::from_millis(600));
    let r = s.conn().stats().clone();
    let c = s.caller.stats().clone();
    assert_eq!(missing, 0, "rcv {r:?}\nsnd {c:?}");
    assert!(lat.iter().all(|l| *l <= Duration::from_micros(215_300)), "{lat:?}");
    assert_eq!((r.pkt_rcv_filter_loss, r.pkt_rcv_drop), (2, 0), "{r:?}");
    // NAKed more than once (the sender's ACK-head retransmission may also
    // have repaired 40)
    assert!(r.pkt_sent_nak >= 3 && r.nak_seqs_sent >= 3, "{r:?}");
}

#[test]
fn fec_tail_loss_is_seen_from_the_fec_packet() {
    // the last two packets of a burst (= the end of row 0) are lost; the
    // row FEC that follows them reveals the loss at once (no wait for the
    // next burst, no tail probe needed) and, two missing, it is NAKed
    let f = "fec,cols:10,rows:1,arq:onreq";
    let ccfg = Config {
        tail_probe: false,
        ..fcfg(120, f)
    };
    let mut s = Sim::new(ccfg, fcfg(120, f), 15, 100);
    s.connect();
    s.drop = Box::new(|side, d| {
        side == "a" && !is_fec(d) && matches!(packet::decode(d), Ok(Packet::Data { hdr, .. }) if !hdr.rexmit && (hdr.seq == 108 || hdr.seq == 109))
    });
    let (lat, missing) = run_frames_v(&mut s, 1, 10, Duration::from_millis(40), Duration::from_millis(400));
    let r = s.conn().stats().clone();
    assert_eq!(missing, 0, "{r:?}");
    // (pktRcvLossTotal counts gaps in the arrival sequence, as libsrt: none
    // here, the tail was never followed by a later packet)
    assert_eq!((r.pkt_rcv_fec_tail_loss, r.pkt_rcv_filter_loss, r.pkt_rcv_loss), (2, 2, 0), "{r:?}");
    assert!(lat.iter().all(|l| *l <= Duration::from_micros(135_300)), "{lat:?}");
    // and with a single tail loss the FEC rebuilds it: no loss at all
    let mut s = Sim::new(
        Config {
            tail_probe: false,
            ..fcfg(120, f)
        },
        fcfg(120, f),
        15,
        100,
    );
    s.connect();
    s.drop = Box::new(|side, d| side == "a" && !is_fec(d) && data_seq(d) == Some(109));
    let (_, missing) = run_frames_v(&mut s, 1, 10, Duration::from_millis(40), Duration::from_millis(400));
    let r = s.conn().stats().clone();
    assert_eq!((missing, r.pkt_rcv_filter_supply, r.pkt_rcv_loss, r.pkt_sent_nak), (0, 1, 0, 0), "{r:?}");
}

#[test]
fn fec_random_loss_5pct_both_ways_staircase_onreq() {
    let f = "fec,cols:10,rows:5,layout:staircase,arq:onreq";
    let mut s = Sim::new(fcfg(120, f), fcfg(120, f), 15, 77);
    s.connect();
    let mut rng = Rng(0x9E37_79B9_7F4A_7C15);
    s.drop = Box::new(move |_, _| rng.chance(5.0));
    let (lat, missing) = run_frames_v(&mut s, 48, 100, Duration::from_micros(41_667), Duration::from_millis(500));
    let r = s.conn().stats().clone();
    let c = s.caller.stats().clone();
    assert_eq!(missing, 0, "rcv {r:?}\nsnd {c:?}");
    assert!(lat.iter().all(|l| *l <= Duration::from_micros(135_300)));
    // FEC rebuilt most losses; retransmissions well below the losses
    assert!(r.pkt_rcv_filter_supply > r.pkt_rcv_loss / 2, "rcv {r:?}");
    assert!(
        c.pkt_retrans < r.pkt_rcv_loss * 7 / 10,
        "retrans {} loss {}\nrcv {r:?}",
        c.pkt_retrans,
        r.pkt_rcv_loss
    );
    assert_eq!((c.ack_invalid, c.nak_invalid), (0, 0));
}

#[test]
fn fec_random_loss_both_layouts_and_directions() {
    for (f, owd, lat, pct) in [
        ("fec,cols:10,rows:5,layout:even,arq:onreq", 15, 120, 5.0),
        ("fec,cols:20,rows:1,arq:onreq", 15, 120, 5.0),
        ("fec,cols:8,rows:-4,layout:staircase,arq:always", 15, 120, 5.0),
        ("fec,cols:10,rows:5,layout:staircase,arq:onreq", 125, 1000, 5.0),
    ] {
        // listener -> caller
        let mut s = Sim::new(fcfg(lat, f), fcfg(lat, f), owd, 3);
        s.connect();
        let mut rng = Rng(12345);
        s.drop = Box::new(move |_, _| rng.chance(pct));
        let mut sent = 0u32;
        let mut got = Vec::new();
        let start = s.now;
        let run = Duration::from_millis(lat as u64 + 2 * owd + 1500);
        s.run_until(run, |s| {
            if s.now - start < Duration::from_millis(1000) && (s.now - start).as_micros() % 10_000 < 50 {
                for _ in 0..30 {
                    let now = s.now;
                    s.conn().send_message(now, &vmsg(sent), None).unwrap();
                    sent += 1;
                }
            }
            while let Some(m) = s.caller.recv_message(s.now) {
                let i = u32::from_be_bytes(m.payload[..4].try_into().unwrap());
                assert_eq!(m.payload, &vmsg(i)[..]);
                got.push(i);
            }
            false
        });
        let r = s.caller.stats().clone();
        assert_eq!(got, (0..sent).collect::<Vec<_>>(), "{f}\nrcv {r:?}\nsnd {:?}", s.conn().stats());
        assert!(r.pkt_rcv_filter_supply > 0 && r.pkt_rcv_filter_extra > 0, "{f} {r:?}");
    }
}

#[test]
fn fec_large_drop_is_naked_not_dropped_silently() {
    // a 700-packet outage (more than 10 matrices of 10 x 5 would be 500 in
    // libsrt's reset rule): every lost packet is NAKed and repaired
    let f = "fec,cols:10,rows:5,layout:staircase,arq:onreq";
    let mut s = Sim::new(fcfg(400, f), fcfg(400, f), 15, 10);
    s.connect();
    s.run_until(Duration::from_millis(100), |_| false);
    let mut first = true;
    s.drop = Box::new(move |side, d| {
        if side == "a" && matches!(packet::decode(d), Ok(Packet::Data { hdr, .. }) if !hdr.rexmit) {
            let q = data_seq(d).unwrap();
            if (300..1000).contains(&q) && first {
                if q == 999 {
                    first = false;
                }
                return true;
            }
        }
        false
    });
    let (_, missing) = run_frames_v(&mut s, 10, 200, Duration::from_millis(20), Duration::from_millis(1000));
    let r = s.conn().stats().clone();
    assert_eq!(missing, 0, "{r:?}");
    assert_eq!(r.pkt_rcv_drop, 0);
    assert!(r.pkt_rcv_filter_loss >= 690, "{r:?}");
}

// ------------------------------------------------------------ outages and stalls

struct StreamOut {
    sent: u32,
    /// Send time of each message, from the start.
    sent_at: Vec<Duration>,
    /// (message, delivery time from the start)
    got: Vec<(u32, Duration)>,
}

impl StreamOut {
    /// Messages sent at or after `from` that never arrived.
    fn lost_sent_after(&self, from: Duration) -> Vec<u32> {
        let set: std::collections::HashSet<u32> = self.got.iter().map(|g| g.0).collect();
        (0..self.sent).filter(|i| self.sent_at[*i as usize] >= from && !set.contains(i)).collect()
    }
}

/// The caller sends `per` messages every ms for `dur`; everything is
/// dropped both ways from `out0` to `out1` (an outage) and the reader does
/// not read from `stall0` to `stall1`. Payloads, order and duplicates are
/// checked.
fn run_stream(s: &mut Sim, per: usize, dur: Duration, tail: Duration, out: (Duration, Duration), stall: (Duration, Duration)) -> StreamOut {
    use std::cell::Cell;
    use std::rc::Rc;
    let flag = Rc::new(Cell::new(false));
    let f2 = flag.clone();
    let mut prev = std::mem::replace(&mut s.drop, Box::new(|_, _| false));
    s.drop = Box::new(move |side, d| f2.get() || prev(side, d));
    let start = s.now;
    let mut next = start;
    let mut o = StreamOut {
        sent: 0,
        sent_at: Vec::new(),
        got: Vec::new(),
    };
    let mut seen = std::collections::HashSet::new();
    let mut last: Option<u32> = None;
    s.run_until(dur + tail, |s| {
        let el = s.now - start;
        flag.set(el >= out.0 && el < out.1);
        if el < dur && s.now >= next {
            for _ in 0..per {
                let now = s.now;
                // a full send buffer (window closed) refuses: the message
                // is lost, as a live source would lose it
                let _ = s.caller.send_message(now, &vmsg(o.sent), None);
                o.sent_at.push(el);
                o.sent += 1;
            }
            next += Duration::from_millis(1);
        }
        if el < stall.0 || el >= stall.1 {
            let now = s.now;
            while let Some(m) = s.conn().recv_message(now) {
                let i = u32::from_be_bytes(m.payload[..4].try_into().unwrap());
                assert_eq!(m.payload, &vmsg(i)[..], "payload of {i}");
                assert!(seen.insert(i), "delivered twice: {i}");
                if let Some(l) = last {
                    assert!(i > l, "out of order: {i} after {l}");
                }
                last = Some(i);
                o.got.push((i, el));
            }
        }
        false
    });
    o
}

#[test]
fn outage_longer_than_the_receive_buffer_resyncs_and_resumes() {
    // 10k msg/s, receive buffer 8192: a 2 s outage is 2.4 buffers; libsrt
    // breaks the connection here, we restart the window and go on
    for f in [
        None,
        Some("fec,cols:10,rows:5,layout:staircase,arq:onreq"),
        Some("fec,cols:10,rows:1,arq:never"),
    ] {
        let c = match f {
            Some(f) => fcfg(120, f),
            None => cfg(120),
        };
        let mut s = Sim::new(c.clone(), c, 15, 0x7FFF_F000);
        s.connect();
        let ms = Duration::from_millis;
        let o = run_stream(&mut s, 10, ms(4000), ms(600), (ms(500), ms(2500)), (ms(9999), ms(9999)));
        let r = s.conn().stats().clone();
        assert!(s.caller.is_connected() && s.conn().is_connected(), "{f:?}");
        let lost = o.lost_sent_after(ms(2500) + ms(300));
        assert!(
            lost.is_empty(),
            "{f:?}: lost after the outage {:?} ({} in all)",
            &lost[..lost.len().min(8)],
            lost.len()
        );
        assert!(r.pkt_rcv_resync >= 1, "{f:?}: {r:?}");
        // delivery resumed within latency + a few RTT of the outage's end
        let first_after = o.got.iter().find(|g| o.sent_at[g.0 as usize] >= ms(2500)).expect("nothing after the outage").1;
        assert!(first_after < ms(2500) + ms(250), "{f:?}: resumed at {first_after:?}");
        // nothing sent before the outage went missing
        assert!(
            o.lost_sent_after(Duration::ZERO).iter().all(|i| o.sent_at[*i as usize] >= ms(500) - ms(200)),
            "{f:?}"
        );
    }
}

#[test]
fn dropreq_at_the_head_moves_the_receive_window() {
    // receive buffer 2048 packets (0.41 s at 5k msg/s), latency 120 ms, a
    // 0.3 s outage: 1500 lost + 600 arriving before the first of them is
    // due exceed the buffer. The sender's DROPREQs for what it gave up must
    // move the window past the gap (no TooFar), not each packet's play time
    for f in [None, Some("fec,cols:10,rows:5,layout:staircase,arq:onreq")] {
        let mk = |c: Config| Config {
            rcv_buf_pkts: 2048,
            flow_window: 2048,
            ..c
        };
        let c = match f {
            Some(f) => mk(fcfg(120, f)),
            None => mk(cfg(120)),
        };
        let mut s = Sim::new(c.clone(), c, 15, 77);
        s.connect();
        let ms = Duration::from_millis;
        let o = run_stream(&mut s, 5, ms(2000), ms(500), (ms(500), ms(800)), (ms(9999), ms(9999)));
        let r = s.conn().stats().clone();
        eprintln!(
            "{f:?}: too_far {} resync {} dropreq {} drop {} naks {}",
            r.pkt_rcv_too_far, r.pkt_rcv_resync, r.pkt_recv_dropreq, r.pkt_rcv_drop, r.pkt_sent_nak
        );
        let lost = o.lost_sent_after(ms(800));
        assert!(
            lost.is_empty(),
            "{f:?}: lost after the outage {:?} ({} in all)",
            &lost[..lost.len().min(8)],
            lost.len()
        );
        assert_eq!((r.pkt_rcv_too_far, r.pkt_rcv_resync), (0, 0), "{f:?}");
        assert!(r.pkt_recv_dropreq > 0);
        assert!(s.conn().is_connected());
    }
}

#[test]
fn dropreq_beyond_the_buffer_moves_the_window_without_resync() {
    // receive buffer 256 packets, 1 msg/ms: 300 packets (0.3 s) are lost on
    // the way, then the source pauses 0.5 s. The sender gives them up and its DROPREQ moves
    // the receiver's window past them: the next packets fit (no TooFar, no
    // restart) and are delivered
    let c = Config {
        rcv_buf_pkts: 256,
        flow_window: 256,
        ..cfg(120)
    };
    let mut s = Sim::new(c.clone(), c, 15, 0x7FFF_FF00);
    s.connect();
    let ms = Duration::from_millis;
    let start = s.now;
    let mut next = start;
    let mut sent = 0u32;
    let mut got = Vec::new();
    let lose = std::rc::Rc::new(std::cell::Cell::new(false));
    let l2 = lose.clone();
    s.drop = Box::new(move |side, d| side == "a" && l2.get() && data_seq(d).is_some());
    s.run_until(ms(1600), |s| {
        let el = s.now - start;
        lose.set(el >= ms(300) && el < ms(600));
        // tail probes of the lost tail are lost too
        let sending = el < ms(600) || (el >= ms(1100) && el < ms(1400));
        if sending && s.now >= next {
            for _ in 0..1 {
                let now = s.now;
                s.caller.send_message(now, &vmsg(sent), None).unwrap();
                sent += 1;
            }
        }
        if s.now >= next {
            next += ms(1);
        }
        let now = s.now;
        while let Some(m) = s.conn().recv_message(now) {
            got.push(u32::from_be_bytes(m.payload[..4].try_into().unwrap()));
        }
        false
    });
    let r = s.conn().stats().clone();
    assert!(r.pkt_recv_dropreq > 0, "{r:?}");
    assert_eq!((r.pkt_rcv_too_far, r.pkt_rcv_resync), (0, 0), "{r:?}");
    // all but (some of) the 300 lost ones; everything after the pause
    assert!(got.len() as u32 >= sent - 300, "{r:?}");
    assert!((sent - 300..sent).all(|i| got.contains(&i)));
    assert!(got.windows(2).all(|w| w[0] < w[1]));
}

#[test]
fn reader_stall_longer_than_the_buffer_reopens_the_window() {
    // receive buffer and flow window 2048 packets (0.2 s at 10k msg/s);
    // the reader stalls 1 s: the sender's window closes, and must reopen
    // when the reader drains the buffer although the ACK value is unchanged
    for f in [None, Some("fec,cols:10,rows:5,layout:staircase,arq:onreq")] {
        let mk = |c: Config| Config {
            rcv_buf_pkts: 2048,
            flow_window: 2048,
            ..c
        };
        let c = match f {
            Some(f) => mk(fcfg(120, f)),
            None => mk(cfg(120)),
        };
        let mut s = Sim::new(c.clone(), c, 15, 0x7FFF_FF00);
        s.connect();
        let mut rng = Rng(5);
        s.drop = Box::new(move |side, _| side == "a" && rng.chance(1.0));
        let ms = Duration::from_millis;
        let o = run_stream(&mut s, 10, ms(3000), ms(500), (ms(9999), ms(9999)), (ms(500), ms(1500)));
        let r = s.conn().stats().clone();
        assert!(s.caller.is_connected() && s.conn().is_connected());
        let n_after = o.got.iter().filter(|g| g.1 >= ms(2000)).count();
        assert!(n_after > 9000, "{f:?}: delivered after 2 s: {n_after}");
        // everything sent from an RTT after the reader resumed arrives
        let lost = o.lost_sent_after(ms(1500) + ms(60));
        assert!(
            lost.is_empty(),
            "{f:?}: lost after the stall {:?} ({} in all)",
            &lost[..lost.len().min(8)],
            lost.len()
        );
        assert!(r.pkt_sent_window_ack > 0, "{f:?}: {r:?}");
    }
}

#[test]
fn fec_stall_probe_repairs_an_unreported_loss_in_the_last_group() {
    // FEC 10 x 5 onreq, one burst of 25 packets: packet 2 of the last,
    // unfinished row is lost. A libsrt receiver never reports it (the
    // group never closes) and sends the ACK stuck at it only until it is
    // ACKACKed: model that by dropping every NAK and every repeat of that
    // ACK. The sender's stall probe must repair it in time
    let f = "fec,cols:10,rows:5,layout:staircase,arq:onreq";
    let mut s = Sim::new(fcfg(120, f), fcfg(120, f), 15, 500);
    s.connect();
    let lost_seq = 522;
    let mut lost = false;
    let mut acks_at_hole = 0;
    s.drop = Box::new(move |side, d| {
        if side == "a" && data_seq(d) == Some(lost_seq) && !lost {
            lost = true;
            return true;
        }
        if side == "b" {
            match packet::decode(d) {
                Ok(Packet::Control { body: Control::Nak(_), .. }) => return true,
                Ok(Packet::Control { body: Control::Ack(a), .. }) if a.seq == lost_seq => {
                    acks_at_hole += 1;
                    return acks_at_hole > 1;
                }
                _ => {}
            }
        }
        false
    });
    let (lat, missing) = run_frames_v(&mut s, 1, 25, Duration::from_millis(40), Duration::from_millis(400));
    let c = s.caller.stats().clone();
    assert_eq!(missing, 0, "{c:?}");
    assert!(lat.iter().all(|l| *l <= Duration::from_micros(135_200)), "{lat:?}");
    assert!(c.pkt_stall_probe + c.pkt_ack_rexmit >= 1, "{c:?}");
    assert_eq!(s.conn().stats().pkt_rcv_drop, 0);
}

#[test]
fn data_with_a_key_is_dropped_not_fatal() {
    let mut s = Sim::new(cfg(120), cfg(120), 15, 500);
    s.connect();
    s.run_until(Duration::from_millis(50), |_| false);
    // a data packet with KK = 2 for the listener's socket
    let sid = s.conn().local_socket_id();
    let mut d = vec![0u8; 16 + 100];
    d[0..4].copy_from_slice(&600u32.to_be_bytes());
    d[4..8].copy_from_slice(&(0xC000_0001u32 | (2 << 27)).to_be_bytes());
    d[12..16].copy_from_slice(&sid.to_be_bytes());
    let (now, a) = (s.now, s.a);
    s.conn().handle_datagram(now, a, &d);
    assert!(s.conn().is_connected());
    assert_eq!(s.conn().stats().pkt_rcv_undecrypt, 1);
    let (_, missing) = run_frames(&mut s, 3, 10, Duration::from_millis(20), Duration::from_millis(300));
    assert_eq!(missing, 0);
}

/// A peer that ACKs late (libsrt's receive worker idles between frames:
/// the ACK for a frame's tail can come ~20 ms after it): ACKs pass only
/// ~20 ms after the newest data packet, so RTT samples stay true but the tail's ACK is late.
/// With the measured hold-off (`probe_ack_lag`) the tail probe stops firing
/// on every frame; a lost tail is still repaired well within the latency.
fn slow_ack_run(probe_ack_lag: bool, lose_tail_of: Option<u32>) -> (srt_core::Stats, srt_core::Stats, usize, Vec<Duration>) {
    let mut ccfg = cfg(120);
    ccfg.probe_ack_lag = probe_ack_lag;
    let mut s = Sim::new(ccfg, cfg(120), 1, 1000);
    s.connect();
    let clock = s.clock.clone();
    let mut last_data: Option<Instant> = None;
    let mut lost = false;
    s.drop = Box::new(move |side, d| {
        let now = clock.get();
        if side == "a" && data_seq(d).is_some() {
            last_data = Some(now);
        }
        if side == "b" && ctl_type(d) == Some(2) {
            // an ACK made within 18 ms of the newest data packet is lost:
            // the one that passes comes ~20 ms after a frame's tail
            return last_data.map_or(false, |t| now < t + Duration::from_millis(18));
        }
        if let (Some(f), "a", Some(q)) = (lose_tail_of, side, data_seq(d)) {
            if q == 1000 + 20 * (f + 1) - 1 && !lost {
                lost = true;
                return true;
            }
        }
        false
    });
    let (lat, missing) = run_frames(&mut s, 96, 20, Duration::from_micros(41_667), Duration::from_millis(500));
    (s.caller.stats().clone(), s.conn().stats().clone(), missing, lat)
}

#[test]
fn probes_wait_for_a_slow_acking_peer() {
    let (old, _, m0, _) = slow_ack_run(false, None);
    let (new, rcv, m1, _) = slow_ack_run(true, None);
    eprintln!("probes without {} with {} dup {}", old.pkt_tail_probe, new.pkt_tail_probe, rcv.pkt_rcv_duplicate);
    assert_eq!((m0, m1), (0, 0));
    // one ACK period of wait: most frames' tails are probed for nothing
    assert!(old.pkt_tail_probe >= 20, "without the hold-off: {}", old.pkt_tail_probe);
    // measured hold-off: a few probes while it is learnt
    assert!(new.pkt_tail_probe * 5 <= old.pkt_tail_probe, "with: {} without: {}", new.pkt_tail_probe, old.pkt_tail_probe);
    assert!(rcv.pkt_rcv_duplicate <= new.pkt_tail_probe + new.pkt_head_probe, "{rcv:?}");
}

#[test]
fn lost_tail_is_still_repaired_with_a_slow_acking_peer() {
    let (c, r, missing, lat) = slow_ack_run(true, Some(60));
    assert_eq!(missing, 0, "{c:?}\n{r:?}");
    assert_eq!(r.pkt_rcv_drop, 0);
    assert!(lat.iter().all(|l| *l <= Duration::from_micros(121_500)), "{:?}", lat.iter().max());
}

/// Frames lost (any packet missing or later than `deadline`) for `frames`
/// bursts of `per` packets every 41.667 ms, random loss `pct` both ways.
#[allow(clippy::too_many_arguments)]
fn weak_case(ccfg: Config, lcfg: Config, owd_us: u64, pct: f64, per: usize, frames: usize, seed: u64, deadline: Duration) -> (usize, srt_core::Stats, srt_core::Stats) {
    let mut s = Sim::new(ccfg, lcfg, 0, 9);
    s.owd = Duration::from_micros(owd_us);
    s.connect();
    let mut rng = Rng(seed);
    s.drop = Box::new(move |_, _| rng.chance(pct));
    let mut sent_at: Vec<Instant> = Vec::new();
    let mut ok = std::collections::HashSet::new();
    let interval = Duration::from_micros(41_667);
    let mut next = s.now;
    let mut nf = 0;
    s.run_until(interval * frames as u32 + Duration::from_millis(1500), |s| {
        if nf < frames && s.now >= next {
            for _ in 0..per {
                let i = sent_at.len() as u32;
                s.caller.send_message(s.now, &vmsg(i), None).unwrap();
                sent_at.push(s.now);
            }
            nf += 1;
            next += interval;
        }
        let now = s.now;
        while let Some(m) = s.conn().recv_message(now) {
            let i = u32::from_be_bytes(m.payload[..4].try_into().unwrap()) as usize;
            if now - sent_at[i] <= deadline {
                ok.insert(i);
            }
        }
        false
    });
    let lost = (0..frames).filter(|f| (f * per..(f + 1) * per).any(|i| !ok.contains(&i))).count();
    (lost, s.caller.stats().clone(), s.conn().stats().clone())
}

/// Exploration (not a pass/fail bar): the cells where libsrt is weakest,
/// RTT 1 ms / L 40 ms at 5 % loss on every datagram both ways, ~166 Mbit/s
/// (660 packets per 24 fps frame), 240 frames; plain ARQ and FEC 10x5
/// staircase onreq. libsrt on Linode: 70+18L (plain), 98 (FEC) of 360.
/// `cargo test --release --test sim weak_ -- --ignored --nocapture`
#[test]
#[ignore]
fn weak_rtt1_l40_5pct() {
    let dl = Duration::from_millis(40 + 1 + 10);
    for seed in [1u64, 2, 3] {
        let (l, c, r) = weak_case(cfg(40), cfg(40), 500, 5.0, 660, 240, 0x5EED_0000 + seed, dl);
        eprintln!("plain seed {seed}: frames lost {l}/240; rcv loss {} drop {} naks {} | snd retrans {} copies {} suppressed {} too-late {} probes t{} h{}",
            r.pkt_rcv_loss, r.pkt_rcv_drop, r.pkt_sent_nak, c.pkt_retrans, c.pkt_rexmit_copies, c.pkt_rexmit_suppressed, c.pkt_rexmit_too_late, c.pkt_tail_probe, c.pkt_head_probe);
        let f = "fec,cols:10,rows:5,layout:staircase,arq:onreq";
        let (l, c, r) = weak_case(fcfg(40, f), fcfg(40, f), 500, 5.0, 660, 240, 0x5EED_0000 + seed, dl);
        eprintln!("fec   seed {seed}: frames lost {l}/240; rcv loss {} drop {} supply {} filterloss {} naks {} | snd retrans {} copies {} stall {}",
            r.pkt_rcv_loss, r.pkt_rcv_drop, r.pkt_rcv_filter_supply, r.pkt_rcv_filter_loss, r.pkt_sent_nak, c.pkt_retrans, c.pkt_rexmit_copies, c.pkt_stall_probe);
    }
}

/// Exploration: set C (81.5 Mbit/s, ~322 packets per frame), small buffers.
/// libsrt on Linode, frames lost of 360: RTT 30 / 1 %: L45 28+6L, L75 11;
/// 5 %: L45 275+4L, L75 134, L120 20, L180 4. RTT 250 / 5 %: L375 214, L625 64.
#[test]
#[ignore]
fn weak_set_c_small_buffers() {
    for (rtt, pct, lat) in [(30u64, 1.0, 45u16), (30, 1.0, 75), (30, 5.0, 45), (30, 5.0, 75), (30, 5.0, 120), (30, 5.0, 180), (250, 5.0, 375), (250, 5.0, 625)] {
        let dl = Duration::from_millis(lat as u64 + rtt / 2 + 10);
        let (l, c, r) = weak_case(cfg(lat), cfg(lat), rtt * 500, pct, 322, 240, 0xC0FFEE, dl);
        eprintln!("rtt {rtt} loss {pct}% L {lat}: frames lost {l}/240; rcv loss {} drop {} | snd retrans {} copies {} too-late {} tail {} head {} ackrexmit {} suppressed {}",
            r.pkt_rcv_loss, r.pkt_rcv_drop, c.pkt_retrans, c.pkt_rexmit_copies, c.pkt_rexmit_too_late, c.pkt_tail_probe, c.pkt_head_probe, c.pkt_ack_rexmit, c.pkt_rexmit_suppressed);
    }
}

fn jitter_run(auto: bool, pct: f64, seed: u64) -> (usize, srt_core::Stats, srt_core::Stats) {
    jitter_run_f(auto, pct, seed, None)
}

fn jitter_run_f(auto: bool, pct: f64, seed: u64, filter: Option<&str>) -> (usize, srt_core::Stats, srt_core::Stats) {
    let mut lcfg = cfg(120);
    let mut ccfg = cfg(120);
    if let Some(f) = filter {
        lcfg = fcfg(120, f);
        ccfg = fcfg(120, f);
    }
    lcfg.auto_reorder = auto;
    let mut s = Sim::new(ccfg, lcfg, 15, 21);
    s.connect();
    let mut rng = Rng(seed);
    let mut rng2 = Rng(seed ^ 0xABCD);
    s.drop = Box::new(move |_, _| rng.chance(pct));
    // data from the caller: 0-10 ms extra delay, uniform (netem jitter reorders)
    s.delay = Box::new(move |side, d| if side == "a" && data_seq(d).is_some() { Duration::from_micros(rng2.next() % 10_000) } else { Duration::ZERO });
    let (_, missing) = run_frames(&mut s, 96, 100, Duration::from_micros(41_667), Duration::from_millis(600));
    (missing, s.caller.stats().clone(), s.conn().stats().clone())
}

/// Jitter with LOSSMAXTTL 0: once the path is seen to reorder, holes wait the
/// observed lateness before their first NAK (auto_reorder): far fewer NAKs
/// and needless retransmissions, and still no loss (with 1 % real loss too).
#[test]
fn auto_reorder_cuts_spurious_naks_under_jitter() {
    for pct in [0.0, 1.0] {
        let (m0, c0, r0) = jitter_run(false, pct, 77);
        let (m1, c1, r1) = jitter_run(true, pct, 77);
        eprintln!("loss {pct}%: off: naks {} retrans {} dup {} | auto: naks {} retrans {} dup {} reordered {}",
            r0.nak_seqs_sent, c0.pkt_retrans, r0.pkt_rcv_duplicate, r1.nak_seqs_sent, c1.pkt_retrans, r1.pkt_rcv_duplicate, r1.pkt_rcv_reordered);
        assert_eq!((m0, m1), (0, 0), "loss {pct}");
        assert!(r1.pkt_rcv_reordered > 100);
        assert!(c1.pkt_retrans * 20 < c0.pkt_retrans, "auto {} off {}", c1.pkt_retrans, c0.pkt_retrans);
    }
}

/// Row FEC without ARQ at random loss: every data packet that was the only
/// loss of its row (20 data + 1 FEC) must be rebuilt, every other loss must
/// stay missing. Checks the receiver against the row arithmetic, packet by
/// packet (the bench saw ~10 % more unrecovered losses than libsrt).
fn row_fec_check(per: usize, frames: usize, pct: f64, fixed: bool, seed: u64) {
    let f = "fec,cols:20,rows:1,arq:never";
    let isn = 1000u32;
    let mut s = Sim::new(fcfg(120, f), fcfg(120, f), 15, isn);
    s.connect();
    let dropped: std::rc::Rc<std::cell::RefCell<(Vec<u32>, Vec<u32>)>> = Default::default();
    let dd = dropped.clone();
    let mut rng = Rng(seed);
    s.drop = Box::new(move |side, d| {
        if side != "a" {
            return false;
        }
        let Some(q) = data_seq(d) else { return false };
        if rng.chance(pct) {
            if is_fec(d) {
                dd.borrow_mut().1.push(q);
            } else {
                dd.borrow_mut().0.push(q);
            }
            return true;
        }
        false
    });
    let mut sent_at: Vec<Instant> = Vec::new();
    let mut got = std::collections::HashSet::new();
    let interval = Duration::from_micros(41_667);
    let mut next = s.now;
    let mut nf = 0;
    s.run_until(interval * frames as u32 + Duration::from_millis(600), |s| {
        if nf < frames && s.now >= next {
            for _ in 0..per {
                let i = sent_at.len() as u32;
                let m = if fixed { let mut m = vec![0x47u8; 1316]; m[..4].copy_from_slice(&i.to_be_bytes()); m } else { vmsg(i) };
                s.caller.send_message(s.now, &m, None).unwrap();
                sent_at.push(s.now);
            }
            nf += 1;
            next += interval;
        }
        let now = s.now;
        while let Some(m) = s.conn().recv_message(now) {
            got.insert(u32::from_be_bytes(m.payload[..4].try_into().unwrap()));
        }
        false
    });
    let (data_lost, fec_lost) = dropped.borrow().clone();
    let total = sent_at.len() as u32;
    let row = |q: u32| (q - isn) / 20;
    let mut lost_in_row = std::collections::HashMap::<u32, u32>::new();
    for &q in &data_lost {
        *lost_in_row.entry(row(q)).or_default() += 1;
    }
    for &q in &fec_lost {
        *lost_in_row.entry(row(q)).or_default() += 1; // a FEC packet carries its row's last seq
    }
    let last_row = (total - 1) / 20;
    let mut should_rebuild = 0;
    let mut missed = Vec::new();
    let mut extra = 0;
    for &q in &data_lost {
        let i = q - isn;
        let r = row(q);
        let recoverable = lost_in_row[&r] == 1 && r < last_row;
        if recoverable {
            should_rebuild += 1;
            if !got.contains(&i) {
                missed.push(q);
            }
        } else if got.contains(&i) {
            extra += 1;
        }
    }
    let st = s.conn().stats().clone();
    eprintln!("data lost {} fec lost {} should rebuild {} missed {} extra {} supply {}", data_lost.len(), fec_lost.len(), should_rebuild, missed.len(), extra, st.pkt_rcv_filter_supply);
    assert!(missed.is_empty(), "rebuildable losses not rebuilt: {:?} (of {should_rebuild})", &missed[..missed.len().min(20)]);
    assert_eq!(extra, 0);
}

#[test]
fn fec_row_arq_never_rebuilds_every_single_loss_row() {
    row_fec_check(330, 120, 2.0, false, 0xFEC0_0001);
    // the bench's shape: 1316-byte payloads, 657 per frame (166 Mbit/s)
    row_fec_check(657, 120, 1.0, true, 0xFEC0_0002);
}

/// One TSBPD timing run: caller -> listener, owd 15 ms, every caller packet
/// (data, ACKACK, keepalive) delayed by a further ~N(15 ms, 5 ms) (sum of
/// 12 uniforms, as netem's normal jitter), except the conclusion handshake
/// that sets the listener's base, which gets `hs_extra`. 10 packets every
/// 5 ms for `dur`. Returns, per delivered packet, (delivery time - stream
/// start, its due time - libsrt's handshake rule due time, both µs), and
/// the listener's stats.
fn tsbpd_timing_run(settle_ms: u32, hs_extra: Duration, dur: Duration, seed: u64) -> (Vec<(i64, i64)>, srt_core::Stats) {
    let mut l = cfg(120);
    l.tsbpd_settle_ms = settle_ms;
    let mut s = Sim::new(cfg(120), l, 15, 4000);
    let mut rng = Rng(seed);
    let hs_ts = std::rc::Rc::new(std::cell::Cell::new(None::<u32>));
    let hs2 = hs_ts.clone();
    s.delay = Box::new(move |side, d| {
        if side != "a" {
            return Duration::ZERO;
        }
        if let Ok(Packet::Control { hdr, body: Control::Handshake(h) }) = packet::decode(d) {
            if h.req_type == srt_core::handshake::req::CONCLUSION {
                assert!(hs2.get().is_none(), "one conclusion only (lossless)");
                hs2.set(Some(hdr.timestamp));
                return hs_extra;
            }
            return Duration::ZERO;
        }
        let mut z = -6.0f64;
        for _ in 0..12 {
            z += (rng.next() % 1_000_000) as f64 / 1e6;
        }
        Duration::from_micros((15_000.0 + 5_000.0 * z).max(0.0) as u64)
    });
    let mut accepted_at = None;
    assert!(s.run_until(Duration::from_secs(5), |s| {
        if accepted_at.is_none() && !s.accepted.is_empty() {
            accepted_at = Some(s.now);
        }
        s.caller.is_connected()
    }));
    let (acc, hs_ts) = (accepted_at.unwrap(), hs_ts.get().unwrap());
    // libsrt's rule: base = arrival of the handshake - its timestamp
    let rule = |ts: u32| acc + Duration::from_micros(ts.wrapping_sub(hs_ts) as u64) + Duration::from_millis(120);
    let mut out = Vec::new();
    let mut msg = vec![0u8; 1316];
    let start = s.now;
    let mut next = start;
    s.run_until(dur + Duration::from_millis(600), |s| {
        if s.now - start < dur && s.now >= next {
            for _ in 0..10 {
                s.caller.send_message(s.now, &msg, None).unwrap();
            }
            msg[0] = msg[0].wrapping_add(1);
            next += Duration::from_millis(5);
        }
        let now = s.now;
        while let Some(m) = s.conn().recv_message(now) {
            let due = m.due.unwrap();
            let r = rule(m.timestamp);
            let d = if due >= r { (due - r).as_micros() as i64 } else { -((r - due).as_micros() as i64) };
            out.push(((now - start).as_micros() as i64, d));
        }
        false
    });
    let st = s.conn().stats().clone();
    (out, st)
}

/// Largest gap between consecutive deliveries in [from, to) µs after the start.
fn max_gap(d: &[(i64, i64)], from: i64, to: i64) -> (i64, i64) {
    d.windows(2)
        .filter(|w| w[1].0 >= from && w[1].0 < to)
        .map(|w| (w[1].0 - w[0].0, w[1].0))
        .max()
        .unwrap_or((0, 0))
}

/// Review A2: the receiver never plays a packet before libsrt's handshake
/// rule (base = arrival of the handshake packet - its timestamp) would:
/// by default (tsbpd_settle_ms 0) the due times are exactly that rule until
/// the drift tracer's first update; with the opt-in settle they are never
/// earlier (a fast handshake moves the base later, to the median data
/// offset; a slow one is left as libsrt leaves it).
#[test]
fn tsbpd_never_plays_before_the_handshake_rule() {
    for (settle, hs_ms, seed) in [(0, 0, 1u64), (0, 35, 2), (1000, 0, 3), (1000, 35, 4), (1000, 15, 5)] {
        let (d, st) = tsbpd_timing_run(settle, Duration::from_millis(hs_ms), Duration::from_secs(4), seed);
        assert!(d.len() >= 7990, "settle {settle} hs +{hs_ms} ms: {} delivered", d.len());
        let lo = d.iter().map(|x| x.1).min().unwrap();
        let hi = d.iter().map(|x| x.1).max().unwrap();
        eprintln!("settle {settle} hs +{hs_ms} ms: due - libsrt rule {lo}..{hi} us, settled {} us", st.us_tsbpd_settled);
        assert!(lo >= 0, "settle {settle} hs +{hs_ms} ms: plays {lo} us before libsrt's rule");
        if settle == 0 || hs_ms > 15 {
            assert_eq!((lo, hi, st.us_tsbpd_settled), (0, 0, 0), "settle {settle} hs +{hs_ms} ms");
        }
        if settle > 0 && hs_ms == 0 {
            // the median of the data offsets: ~15 ms later than a handshake 15 ms faster
            assert!((13_000..=17_000).contains(&(st.us_tsbpd_settled as i64)), "{}", st.us_tsbpd_settled);
        }
    }
}

/// Review A2: the old settle moved the base to the fastest packet and the
/// drift tracer moved it back ~10 s later, a playout stall of up to
/// latency / 8 (sim: 13.6 ms gap at t = 10 s). Now: by default nothing
/// moves before the drift tracer, and with the opt-in settle the drift
/// tracer starts from the settled base: no stall when it first applies,
/// and afterwards both play at the same time.
#[test]
fn drift_tracer_first_update_has_no_delivery_gap() {
    let dur = Duration::from_secs(14);
    // a typical handshake (at the mean delay): libsrt's rule, no settle
    let (d0, _) = tsbpd_timing_run(0, Duration::from_millis(15), dur, 11);
    let g0 = max_gap(&d0, 2_000_000, 14_000_000);
    // a fast handshake: the opt-in settle moves the base later at ~1 s
    let (d1, st1) = tsbpd_timing_run(1000, Duration::ZERO, dur, 11);
    let g1 = max_gap(&d1, 2_000_000, 14_000_000);
    let s1 = max_gap(&d1, 0, 2_000_000);
    // the same without the settle (libsrt): the drift tracer moves it at ~10 s
    let (d2, _) = tsbpd_timing_run(0, Duration::ZERO, dur, 11);
    let g2 = max_gap(&d2, 2_000_000, 14_000_000);
    let tail = |d: &[(i64, i64)]| d.iter().rev().take(100).map(|x| x.1).sum::<i64>() / 100;
    eprintln!(
        "typical hs, no settle: gap {g0:?}; fast hs, settle: settle gap {s1:?} (moved {} us), drift gap {g1:?}; fast hs, no settle: drift gap {g2:?}; \
         end offsets vs libsrt rule: {} / {} / {} us",
        st1.us_tsbpd_settled,
        tail(&d0),
        tail(&d1),
        tail(&d2)
    );
    let frame = 5_000;
    assert!(g0.0 <= frame + 2_000, "{g0:?}");
    assert!(g1.0 <= frame + 2_000, "{g1:?}");
    // (libsrt's own behaviour: a fast handshake costs a stall when its drift tracer applies)
    assert!(g2.0 > frame + 8_000, "{g2:?}");
    // after the drift update the settled and the unsettled receiver play alike
    assert!((tail(&d1) - tail(&d2)).abs() <= 2_000, "{} vs {}", tail(&d1), tail(&d2));
}

/// The same with FEC 10x5 staircase onreq: a group closes while its
/// "missing" packet is only late, and the filter releases it for a NAK at
/// once; with auto_reorder the released hole waits the observed reorder
/// lateness first.
#[test]
fn auto_reorder_with_fec_cuts_spurious_naks_under_jitter() {
    let f = "fec,cols:10,rows:5,layout:staircase,arq:onreq";
    for pct in [0.0, 1.0] {
        let (m0, c0, r0) = jitter_run_f(false, pct, 78, Some(f));
        let (m1, c1, r1) = jitter_run_f(true, pct, 78, Some(f));
        eprintln!("fec loss {pct}%: off: naks {} retrans {} | auto: naks {} retrans {} reordered {} supply {}",
            r0.nak_seqs_sent, c0.pkt_retrans, r1.nak_seqs_sent, c1.pkt_retrans, r1.pkt_rcv_reordered, r1.pkt_rcv_filter_supply);
        assert_eq!((m0, m1), (0, 0), "loss {pct}");
        assert!(c1.pkt_retrans * 4 < c0.pkt_retrans, "auto {} off {}", c1.pkt_retrans, c0.pkt_retrans);
    }
}

/// Send `n` messages caller -> listener over a lossless wire and let every
/// ACK come back (the caller's una then equals its next sequence).
fn connected_and_acked(isn: u32, n: usize) -> Sim {
    let mut s = Sim::new(cfg(120), cfg(120), 1, isn);
    s.connect();
    for i in 0..n {
        s.caller.send_message(s.now, &[i as u8; 1316], None).unwrap();
        s.run_until(Duration::from_micros(500), |_| false);
    }
    s.run_until(Duration::from_millis(100), |s| {
        let now = s.now;
        while s.conn().recv_message(now).is_some() {}
        false
    });
    assert_eq!(s.caller.send_buffer_len(), 0);
    s
}

/// Hand one crafted control packet to the caller (from the peer) and drain
/// its output; returns (datagrams, DROPREQ ranges seen, time spent).
fn feed_caller(s: &mut Sim, pkt: &[u8]) -> (usize, Vec<(u32, u32)>, Duration) {
    let (now, b) = (s.now, s.b);
    let t = Instant::now();
    s.caller.handle_datagram(now, b, pkt);
    let mut out = [0u8; 1500];
    let mut n = 0;
    let mut drops = Vec::new();
    while let Some(tx) = s.caller.poll_transmit(now, &mut out) {
        n += 1;
        assert!(n < 10_000, "poll_transmit does not end");
        if let Ok(Packet::Control { body: Control::DropReq { first, last }, .. }) = packet::decode(&out[..tx.len]) {
            drops.push((first, last));
        }
    }
    (n, drops, t.elapsed())
}

/// Review A2 PoC: a NAK range that straddles una (first after it, last
/// before it, yet first < last in modular order: the order is not
/// transitive) was inserted whole (~7.5e8 sequences) and popped one at a
/// time by poll_transmit (5.5 s of CPU). Ranges are now checked by offsets
/// from una: rejected, with bounded work.
#[test]
fn crafted_nak_ranges_are_rejected_with_bounded_work() {
    let mut s = connected_and_acked(0x1000, 200);
    let una = seq::seq_add(0x1000, 200);
    let mut b = [0u8; 64];
    let shapes = [
        // the fuzz's shape: first 877M ahead of una, last 518M behind it
        (seq::seq_add(una, 0x3445_51E4), seq::seq_add(una, -0x1EDD_CDD3)),
        // first = una + 2^30 - 1, last = una - 2
        (seq::seq_add(una, (1 << 30) - 1), seq::seq_add(una, -2)),
        // both before una but longer than the send buffer
        (seq::seq_add(una, -100_000), seq::seq_add(una, -1)),
        // reversed
        (seq::seq_add(una, -3), seq::seq_add(una, -5)),
    ];
    for (k, &(first, last)) in shapes.iter().enumerate() {
        let inv = s.caller.stats().nak_invalid;
        let loss = s.caller.stats().pkt_snd_loss;
        let n = packet::encode_nak([(first, last)], 0, 0x1234, 10, &mut b);
        let (sent, drops, dt) = feed_caller(&mut s, &b[..n]);
        assert_eq!(s.caller.stats().nak_invalid, inv + 1, "shape {k}");
        assert_eq!(s.caller.stats().pkt_snd_loss, loss, "shape {k}");
        assert!(drops.is_empty() && sent <= 1, "shape {k}: {sent} {drops:?}");
        let now = s.now;
        assert_eq!(s.caller.snapshot(now).snd_loss_runs, 0, "shape {k}");
        assert!(dt < Duration::from_millis(50), "shape {k}: {dt:?}");
        assert!(s.caller.is_connected());
    }
    // a valid range behind una: one DROPREQ, nothing retransmitted
    let n = packet::encode_nak([(seq::seq_add(una, -7), seq::seq_add(una, -3))], 0, 0x1234, 10, &mut b);
    let (_, drops, _) = feed_caller(&mut s, &b[..n]);
    assert_eq!(drops, vec![(seq::seq_add(una, -7), seq::seq_add(una, -3))]);
    // a range from behind una into what is in flight: DROPREQ for the part
    // behind it, retransmission of the rest
    s.caller.send_message(s.now, &[9u8; 100], None).unwrap();
    s.caller.send_message(s.now, &[9u8; 100], None).unwrap();
    let mut out = [0u8; 1500];
    let now = s.now;
    while s.caller.poll_transmit(now, &mut out).is_some() {} // sent, not yet acknowledged
    s.now += Duration::from_millis(50); // past the repair suppression
    let retrans = s.caller.stats().pkt_retrans;
    let n = packet::encode_nak([(seq::seq_add(una, -2), seq::seq_add(una, 1))], 0, 0x1234, 10, &mut b);
    let (_, drops, _) = feed_caller(&mut s, &b[..n]);
    assert_eq!(drops, vec![(seq::seq_add(una, -2), seq::seq_add(una, -1))]);
    assert_eq!(s.caller.stats().pkt_retrans, retrans + 2);
}

/// DROPREQ ranges are checked by offsets from the delivery point too: one
/// that straddles it (or reaches 2^29 away) is ignored and changes nothing.
#[test]
fn crafted_dropreq_ranges_are_rejected() {
    let mut s = Sim::new(cfg(500), cfg(500), 5, 50);
    s.connect();
    s.drop = Box::new(|side, d| side == "a" && matches!(data_seq(d), Some(52..=53)));
    for i in 0..6u8 {
        s.caller.send_message(s.now, &[i; 10], None).unwrap();
    }
    s.run_until(Duration::from_millis(30), |_| false);
    let now = s.now;
    assert_eq!(s.conn().snapshot(now).rcv_loss_seqs, 2);
    // the delivery point is 50 (TSBPD holds 50 and 51 for 500 ms)
    let mut b = [0u8; 64];
    let sid = s.conn().local_socket_id();
    let a = s.a;
    for (first, last) in [
        (seq::seq_add(50, (1 << 29) + 10), seq::seq_add(50, (1 << 30) - 5)),
        // first < last in modular order, but last is "before" the delivery point
        (seq::seq_add(50, 3), seq::seq_add(50, 3 + (1 << 30) - 1)),
        (54, 51),
    ] {
        let st = s.conn().stats().clone();
        let n = packet::encode_dropreq(0, first, last, 0, sid, &mut b);
        s.conn().handle_datagram(now, a, &b[..n]);
        let st2 = s.conn().stats().clone();
        assert_eq!(st2.dropreq_invalid, st.dropreq_invalid + 1, "{first:#x}..{last:#x}");
        assert_eq!((st2.pkt_rcv_dropreq_seqs, st2.pkt_rcv_drop), (st.pkt_rcv_dropreq_seqs, st.pkt_rcv_drop));
        assert_eq!(s.conn().snapshot(now).rcv_loss_seqs, 2);
    }
    // the holes are repaired, and a later loss is still detected (an
    // accepted straddling range would have moved the highest received to
    // the end of the window: no loss seen below it)
    let mut first58 = true;
    s.drop = Box::new(move |side, d| {
        if side == "a" && data_seq(d) == Some(58) && first58 {
            first58 = false;
            return true;
        }
        false
    });
    for i in 6..12u8 {
        s.caller.send_message(s.now, &[i; 10], None).unwrap();
    }
    let mut got = 0;
    s.run_until(Duration::from_millis(1000), |s| {
        let now = s.now;
        while s.conn().recv_message(now).is_some() {
            got += 1;
        }
        false
    });
    assert_eq!(got, 12);
}

/// A quick fuzz pass over crafted NAK, DROPREQ and ACK packets (seeded):
/// random ranges around una / the delivery point and anywhere in the
/// sequence space. Every packet must be handled with bounded work and the
/// connection must keep delivering.
#[test]
fn fuzz_control_ranges_bounded_work() {
    fuzz_control(0xF022_0001, 3000);
}

#[test]
#[ignore]
fn fuzz_control_ranges_bounded_work_long() {
    for seed in 0..20u64 {
        fuzz_control(0xF022_1000 + seed, 20_000);
    }
}

fn fuzz_control(seed: u64, n: usize) {
    let mut r = Rng(seed);
    let isn = (r.next() % 0x7FFF_FFF0) as u32;
    let mut s = Sim::new(cfg(120), cfg(120), 1, isn);
    s.connect();
    let mut b = [0u8; 64];
    let mut out = [0u8; 1500];
    let mut worst = Duration::ZERO;
    let mut msgs = 0u32;
    for k in 0..n {
        if k % 4 == 0 {
            let _ = s.caller.send_message(s.now, &[1u8; 200], None);
            msgs += 1;
        }
        s.run_until(Duration::from_micros(200), |s| {
            let now = s.now;
            while s.conn().recv_message(now).is_some() {}
            false
        });
        let una = seq::seq_add(isn, msgs as i32 - 5);
        let pick = |r: &mut Rng| -> u32 {
            match r.next() % 4 {
                0 => seq::seq_add(una, (r.next() % 64) as i32 - 32),
                1 => seq::seq_add(una, (r.next() % (1 << 31)) as i32),
                2 => seq::seq_add(una, ((r.next() % (1 << 21)) as i32) - (1 << 20)),
                _ => seq::seq_add(una, (1 << 30) + (r.next() % 64) as i32 - 32),
            }
        };
        let (first, last) = (pick(&mut r), pick(&mut r));
        let now = s.now;
        let t = Instant::now();
        match r.next() % 3 {
            0 => {
                let n = packet::encode_nak([(first, last)], 0, 0x1234, 10, &mut b);
                let bb = s.b;
                s.caller.handle_datagram(now, bb, &b[..n]);
                let mut c = 0;
                while s.caller.poll_transmit(now, &mut out).is_some() {
                    c += 1;
                    assert!(c < 10_000, "seed {seed:#x} step {k}: poll_transmit does not end");
                }
            }
            1 => {
                let sid = s.conn().local_socket_id();
                let n = packet::encode_dropreq(0, first, last, 0, sid, &mut b);
                let a = s.a;
                s.conn().handle_datagram(now, a, &b[..n]);
                let mut c = 0;
                while s.conn().poll_transmit(now, &mut out).is_some() {
                    c += 1;
                    assert!(c < 10_000);
                }
                while s.conn().recv_message(now).is_some() {}
            }
            _ => {
                let ack = srt_core::packet::Ack::light(first);
                let n = packet::encode_ack(&ack, 0, 0, 0x1234, &mut b);
                let bb = s.b;
                s.caller.handle_datagram(now, bb, &b[..n]);
                let mut c = 0;
                while s.caller.poll_transmit(now, &mut out).is_some() {
                    c += 1;
                    assert!(c < 10_000);
                }
            }
        }
        worst = worst.max(t.elapsed());
    }
    eprintln!("fuzz seed {seed:#x}: {n} packets, worst {worst:?}, caller {:?}", s.caller.state());
    assert!(worst < Duration::from_millis(200), "seed {seed:#x}: {worst:?}");
    assert!(s.caller.is_connected());
}
