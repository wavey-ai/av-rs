//! Caller and listener over a simulated network (fixed one-way delay,
//! scripted drops), with simulated time.

use srt_core::packet::{self, Control, Packet};
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
    assert_eq!((r.pkt_sent_nak, r.nak_seqs_sent), (2, 1), "one immediate NAK, sent twice");
    let c = s.caller.stats().clone();
    // both copies arrive; the second finds the request already queued
    assert_eq!((c.pkt_retrans, c.pkt_snd_loss, c.pkt_recv_nak), (1, 2, 2));
    assert_eq!(c.pkt_sent, 6);
}

#[test]
fn lost_retransmission_and_lost_nak_are_renaked() {
    // 1002 and 1004 lost; the first NAK (both copies) lost; then the first
    // retransmission of 1002 lost: three NAK rounds, the last repair of 1002
    // sent twice (its second retransmission)
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
    // the lost NAK pair is NAKed again; the lost repair of 1002 is sent
    // again by the receiver's re-NAK or the sender's head probe,
    // whichever comes first (the other is suppressed or not needed)
    assert!(r.pkt_sent_nak >= 4 && r.pkt_sent_nak % 2 == 0, "{r:?}");
    let c = s.caller.stats().clone();
    assert!(c.pkt_retrans >= 1 + 2 && c.pkt_retrans <= 1 + 3 + c.pkt_tail_probe + c.pkt_head_probe, "{c:?}");
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
    assert!(r.pkt_rcv_duplicate <= c.pkt_rexmit_copies + r.pkt_rcv_loss / 20, "dup {} loss {}\n{c:?}", r.pkt_rcv_duplicate, r.pkt_rcv_loss);
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
    s.delay = Box::new(|side, d| if side == "a" && data_seq(d) == Some(902) { Duration::from_micros(300) } else { Duration::ZERO });
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
