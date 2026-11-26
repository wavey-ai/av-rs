//! Test vectors captured from libsrt 1.5.7 (a libsrt caller and listener on
//! loopback with a logging UDP proxy between them; see
//! needletail-data/tbench-srt-rs-local-20261125/stage1/libsrt-capture).
//!
//! - every captured datagram decodes, and our encoders reproduce the
//!   handshakes byte for byte;
//! - our caller, fed libsrt listener's real answers, emits the same
//!   induction and conclusion libsrt's caller did and connects;
//! - our listener, fed libsrt caller's real requests, answers as libsrt's
//!   listener did and delivers the caller's data packets.

use srt_core::handshake::{flags, req, Handshake, SrtHsExt};
use srt_core::packet::{self, AckKind, Control, Packet};
use srt_core::{Config, Connection, Listener, ListenerAction, RejectReason};
use std::net::SocketAddr;
use std::time::{Duration, Instant};

struct Line {
    dir: &'static str,
    dropped: bool,
    bytes: Vec<u8>,
}

fn hex(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

fn load(text: &'static str) -> Vec<Line> {
    text.lines()
        .map(|l| {
            let mut p: Vec<&'static str> = l.split_whitespace().collect();
            let dropped = p[0] == "DROP";
            if dropped {
                p.remove(0);
            }
            Line {
                dir: if p[0] == "c2l" { "c2l" } else { "l2c" },
                dropped,
                bytes: hex(p[2]),
            }
        })
        .collect()
}

const FEC_SID: &str = include_str!("vectors/libsrt-1.5.7-cap-fec-sid.txt");
const LOSS: &str = include_str!("vectors/libsrt-1.5.7-cap-loss.txt");
const REJECT: &str = include_str!("vectors/libsrt-1.5.7-cap-reject.txt");

fn hs_of(b: &[u8]) -> (packet::ControlHeader, Handshake) {
    match packet::decode(b).unwrap() {
        Packet::Control {
            hdr,
            body: Control::Handshake(h),
        } => (hdr, *h),
        p => panic!("not a handshake: {p:?}"),
    }
}

#[test]
fn every_captured_datagram_decodes() {
    for text in [FEC_SID, LOSS, REJECT] {
        for l in load(text) {
            packet::decode(&l.bytes).unwrap_or_else(|e| panic!("{e}: {}", l.bytes.len()));
        }
    }
}

#[test]
fn handshakes_decode_and_reencode_byte_for_byte() {
    let v = load(FEC_SID);
    // (1) caller induction
    let (h, ind) = hs_of(&v[0].bytes);
    assert_eq!(h.dst, 0);
    assert_eq!((ind.version, ind.encryption, ind.ext_field, ind.req_type), (4, 0, 2, req::INDUCTION));
    assert_eq!(
        (ind.isn, ind.mss, ind.flow_window, ind.socket_id, ind.cookie),
        (0x51ca2477, 1500, 8192, 0x13c26e84, 0)
    );
    assert_eq!(srt_core::handshake::words_to_ip(&ind.peer_ip).to_string(), "127.0.0.1");
    // (2) listener induction response
    let (h, rsp) = hs_of(&v[1].bytes);
    assert_eq!(h.dst, 0x13c26e84);
    assert_eq!((rsp.version, rsp.ext_field, rsp.cookie), (5, 0x4A17, 0x20f88a0a));
    // (3) caller conclusion with HSREQ, SID, FILTER
    let (_, con) = hs_of(&v[2].bytes);
    assert_eq!((con.version, con.ext_field, con.req_type), (5, 5, req::CONCLUSION));
    assert_eq!(
        con.hsreq,
        Some(SrtHsExt {
            version: 0x010507,
            flags: 0xbf,
            recv_delay_ms: 120,
            send_delay_ms: 120
        })
    );
    assert_eq!(con.stream_id.as_deref(), Some("abcdefg"));
    assert_eq!(con.filter.as_deref(), Some("fec,cols:4,rows:2"));
    assert_eq!(con.conclusion_ext_flags(), con.ext_field);
    // (4) listener conclusion response with HSRSP and the merged FILTER
    let (h, cr) = hs_of(&v[3].bytes);
    assert_eq!(h.dst, 0x13c26e84);
    assert_eq!((cr.isn, cr.flow_window, cr.socket_id), (0x51ca2477, 25600, 0x2f06e599));
    assert_eq!(
        cr.hsrsp,
        Some(SrtHsExt {
            version: 0x010507,
            flags: 0xbf,
            recv_delay_ms: 120,
            send_delay_ms: 120
        })
    );
    assert_eq!(cr.filter.as_deref(), Some("fec,arq:onreq,cols:4,layout:staircase,rows:2"));
    // our encoder writes the same bytes
    for (i, l) in v.iter().take(4).enumerate() {
        let (h, hs) = hs_of(&l.bytes);
        let mut b = [0u8; 1500];
        let n = packet::encode_handshake(&hs, h.timestamp, h.dst, &mut b);
        assert_eq!(&b[..n], &l.bytes[..], "handshake {i}");
    }
    // rejection 1014 (filter cols:5 vs cols:4)
    let r = load(REJECT);
    let (_, rej) = hs_of(&r[3].bytes);
    assert_eq!(rej.reject_reason(), Some(RejectReason::Filter));
}

#[test]
fn control_and_data_packets_decode() {
    let v = load(FEC_SID);
    let (mut acks, mut ackacks, mut ka, mut shutdown, mut fec, mut data) = (0, 0, 0, 0, 0, 0);
    for l in &v {
        let mut b = [0u8; 1600];
        match packet::decode(&l.bytes).unwrap() {
            Packet::Control { hdr, body: Control::Ack(a) } => {
                acks += 1;
                assert_eq!(a.kind, AckKind::Full);
                assert!(hdr.info > 0);
                let n = packet::encode_ack(&a, hdr.info, hdr.timestamp, hdr.dst, &mut b);
                assert_eq!(&b[..n], &l.bytes[..]);
            }
            Packet::Control { hdr, body: Control::AckAck } => {
                ackacks += 1;
                let n = packet::encode_ackack(hdr.info, hdr.timestamp, hdr.dst, &mut b);
                assert_eq!(&b[..n], &l.bytes[..]);
            }
            Packet::Control { hdr, body: Control::KeepAlive } => {
                ka += 1;
                let n = packet::encode_keepalive(hdr.timestamp, hdr.dst, &mut b);
                assert_eq!(&b[..n], &l.bytes[..]);
            }
            Packet::Control { hdr, body: Control::Shutdown } => {
                shutdown += 1;
                let n = packet::encode_shutdown(hdr.timestamp, hdr.dst, &mut b);
                assert_eq!(&b[..n], &l.bytes[..]);
            }
            Packet::Data { hdr, payload } => {
                if hdr.msgno == 0 {
                    fec += 1;
                    // FEC payload: index, flags, length XOR, then P bytes
                    assert_eq!(payload.len(), 1316 + 4);
                } else {
                    data += 1;
                    assert_eq!(hdr.position, packet::Position::Solo);
                    assert_eq!(hdr.key, 0);
                }
                hdr.encode(&mut b);
                assert_eq!(&b[..16], &l.bytes[..16]);
            }
            _ => {}
        }
    }
    assert!(
        acks > 10 && ackacks > 10 && ka >= 2 && shutdown == 1 && fec > 0 && data > 0,
        "{acks} {ackacks} {ka} {shutdown} {fec} {data}"
    );
}

#[test]
fn nak_and_retransmission_from_capture() {
    let v = load(LOSS);
    let dropped: Vec<u32> = v.iter().filter(|l| l.dropped).map(|l| packet::DataHeader::decode(&l.bytes).seq).collect();
    assert!(!dropped.is_empty());
    let mut naked = Vec::new();
    let mut rexmit = Vec::new();
    for l in &v {
        match packet::decode(&l.bytes).unwrap() {
            Packet::Control { body: Control::Nak(list), .. } => {
                assert_eq!(l.dir, "l2c");
                for (a, b) in list.ranges() {
                    assert_eq!(a, b);
                    naked.push(a);
                }
                let mut b = [0u8; 64];
                let n = packet::encode_nak(list.ranges(), 0, 0, 100, &mut b);
                assert_eq!(&b[16..n], &l.bytes[16..]);
            }
            Packet::Data { hdr, .. } if hdr.rexmit => rexmit.push(hdr.seq),
            _ => {}
        }
    }
    // every dropped packet was NAKed and retransmitted with R = 1
    for s in &dropped {
        assert!(naked.contains(s), "{s} not NAKed");
        assert!(rexmit.contains(s), "{s} not retransmitted");
    }
}

fn addr(s: &str) -> SocketAddr {
    s.parse().unwrap()
}

/// Our caller, against libsrt listener's captured answers.
#[test]
fn our_caller_against_libsrt_listener_bytes() {
    let v = load(FEC_SID);
    let cfg = Config {
        stream_id: Some("abcdefg".into()),
        packet_filter: Some("fec,cols:4,rows:2".into()),
        flow_window: 8192,
        ..Config::default()
    }
    .with_latency_ms(120);
    let listener = addr("127.0.0.1:41001");
    let t0 = Instant::now();
    let mut c = Connection::connect(cfg, t0, listener, 0x13c26e84, 0x51ca2477);
    let mut b = [0u8; 1500];
    let t = c.poll_transmit(t0, &mut b).unwrap();
    // identical to libsrt's induction except the timestamp word
    assert_eq!(&b[..8], &v[0].bytes[..8]);
    assert_eq!(&b[12..t.len], &v[0].bytes[12..]);
    assert!(c.poll_transmit(t0, &mut b).is_none());
    // libsrt's induction response -> our conclusion (same as libsrt's caller)
    c.handle_datagram(t0, listener, &v[1].bytes);
    let t = c.poll_transmit(t0, &mut b).unwrap();
    assert_eq!(&b[..8], &v[2].bytes[..8]);
    assert_eq!(&b[12..t.len], &v[2].bytes[12..]);
    // conclusion response -> connected, merged filter adopted
    c.handle_datagram(t0, listener, &v[3].bytes);
    assert!(c.is_connected());
    assert_eq!(c.poll_event(), Some(srt_core::Event::Connected));
    let s = c.snapshot(t0);
    assert_eq!(s.peer_socket_id, 0x2f06e599);
    assert_eq!(s.packet_filter.as_deref(), Some("fec,arq:onreq,cols:4,layout:staircase,rows:2"));
    assert_eq!((s.rcv_tsbpd_delay_ms, s.snd_tsbpd_delay_ms), (120, 120));
    assert_eq!(s.flow_window, 25600);
    // a libsrt ACK from the capture is beyond what we sent: ignored, no ACKACK
    let ack = v.iter().find(|l| l.dir == "l2c" && l.bytes[..4] == [0x80, 2, 0, 0]).unwrap();
    c.handle_datagram(t0, listener, &ack.bytes);
    assert_eq!(c.stats().ack_invalid, 1);
    // send the first captured payload, then the ACK acknowledges it: ACKACK
    let first = v.iter().find(|l| l.dir == "c2l" && l.bytes[0] & 0x80 == 0).unwrap();
    let seq = c.send_message(t0, &first.bytes[16..], None).unwrap();
    assert_eq!(seq, 0x51ca2477);
    let t = c.poll_transmit(t0, &mut b).unwrap();
    let h = packet::DataHeader::decode(&b[..t.len]);
    assert_eq!((h.seq, h.msgno, h.dst, h.rexmit), (0x51ca2477, 1, 0x2f06e599, false));
    assert_eq!(&b[16..t.len], &first.bytes[16..]);
    c.handle_datagram(t0, listener, &ack.bytes);
    let t = c.poll_transmit(t0, &mut b).unwrap();
    match packet::decode(&b[..t.len]).unwrap() {
        Packet::Control { hdr, body: Control::AckAck } => {
            assert_eq!(hdr.info, 1);
            assert_eq!(hdr.dst, 0x2f06e599);
            assert_eq!(t.len, 20);
        }
        p => panic!("{p:?}"),
    }
    assert_eq!(c.send_buffer_len(), 0);
}

/// Our listener, against libsrt caller's captured requests.
#[test]
fn our_listener_against_libsrt_caller_bytes() {
    let v = load(FEC_SID);
    let caller = addr("127.0.0.1:50000");
    let t0 = Instant::now();
    let cfg = Config {
        packet_filter: Some("fec,cols:4,rows:2".into()),
        ..Config::default()
    }
    .with_latency_ms(120);
    let mut l = Listener::new(cfg, t0);
    let mut out = [0u8; 1500];
    // induction: echo of libsrt's 48 bytes with version 5, magic, our cookie
    let ListenerAction::Reply(n) = l.handle(t0, caller, &v[0].bytes, &mut out) else {
        panic!()
    };
    let (h, rsp) = hs_of(&out[..n]);
    let (_, ind) = hs_of(&v[0].bytes);
    assert_eq!(h.dst, ind.socket_id);
    assert_eq!((rsp.version, rsp.ext_field, rsp.encryption), (5, 0x4A17, 0));
    assert_eq!(
        (rsp.isn, rsp.mss, rsp.flow_window, rsp.socket_id, rsp.peer_ip),
        (ind.isn, ind.mss, ind.flow_window, ind.socket_id, ind.peer_ip)
    );
    // libsrt's conclusion with its cookie is silently ignored ...
    assert!(matches!(l.handle(t0, caller, &v[2].bytes, &mut out), ListenerAction::Ignore));
    // ... and accepted with ours
    let mut con = v[2].bytes.clone();
    con[16 + 28..16 + 32].copy_from_slice(&rsp.cookie.to_be_bytes());
    let ListenerAction::Accept(mut conn) = l.handle(t0, caller, &con, &mut out) else {
        panic!()
    };
    assert!(conn.is_connected());
    assert_eq!(conn.stream_id(), Some("abcdefg"));
    let mut b = [0u8; 1500];
    let t = conn.poll_transmit(t0, &mut b).unwrap();
    let (h, cr) = hs_of(&b[..t.len]);
    let (_, libsrt_cr) = hs_of(&v[3].bytes);
    assert_eq!(h.dst, 0x13c26e84);
    assert_eq!((cr.version, cr.req_type, cr.isn, cr.mss), (5, req::CONCLUSION, 0x51ca2477, 1500));
    assert_eq!(cr.ext_field, libsrt_cr.ext_field);
    assert_eq!(cr.hsrsp, libsrt_cr.hsrsp);
    assert_eq!(cr.filter, libsrt_cr.filter, "same merged filter string as libsrt");
    assert_eq!(cr.cookie, rsp.cookie);
    // a repeated conclusion is routed to the same connection, which answers again
    let ListenerAction::Existing(sid) = l.handle(t0, caller, &con, &mut out) else {
        panic!()
    };
    assert_eq!(sid, conn.local_socket_id());
    conn.handle_datagram(t0, caller, &con);
    let t = conn.poll_transmit(t0, &mut b).unwrap();
    assert_eq!(hs_of(&b[..t.len]).1.socket_id, sid);
    // libsrt's data packets (dst rewritten to our id) are delivered at
    // base + ts + 120 ms, base from the conclusion's timestamp
    let (conc_hdr, _) = hs_of(&v[2].bytes);
    let mut n_data = 0;
    for p in v.iter().filter(|l| l.dir == "c2l" && l.bytes[0] & 0x80 == 0) {
        let h = packet::DataHeader::decode(&p.bytes);
        if h.msgno == 0 {
            continue; // FEC
        }
        let mut d = p.bytes.clone();
        d[12..16].copy_from_slice(&sid.to_be_bytes());
        // each packet arrives at its own time (as sent, no extra delay); a
        // packet arriving earlier than the base predicts would move the base
        // (tsbpd_settle_ms)
        let sent = t0 + Duration::from_micros((h.timestamp - conc_hdr.timestamp) as u64);
        conn.handle_datagram(sent, caller, &d);
        let due = sent + Duration::from_micros(120_000);
        assert!(conn.recv_message(due - Duration::from_micros(1)).is_none());
        let m = conn.recv_message(due).expect("due");
        assert_eq!(m.payload, &p.bytes[16..]);
        assert_eq!(m.seq, h.seq);
        n_data += 1;
    }
    assert!(n_data >= 3);
    assert_eq!(conn.stats().pkt_rcv_filter_extra, 0);
}

#[test]
fn listener_rejections() {
    let t0 = Instant::now();
    let caller = addr("10.0.0.2:4000");
    let mk = |cfg: Config| {
        let mut c = Connection::connect(cfg, t0, addr("10.0.0.1:9000"), 77, 1000);
        let mut b = [0u8; 1500];
        let n = c.poll_transmit(t0, &mut b).unwrap().len;
        (c, b[..n].to_vec())
    };
    let run = |lcfg: Config, ccfg: Config, patch: &dyn Fn(&mut Vec<u8>)| -> Option<RejectReason> {
        let mut l = Listener::new(lcfg, t0);
        l.set_accept_callback(Some(Box::new(|r| {
            if r.stream_id == Some("forbidden") {
                Err(RejectReason::App(1403))
            } else {
                Ok(())
            }
        })));
        let (mut c, ind) = mk(ccfg);
        let mut out = [0u8; 1500];
        let ListenerAction::Reply(n) = l.handle(t0, caller, &ind, &mut out) else {
            panic!()
        };
        c.handle_datagram(t0, addr("10.0.0.1:9000"), &out[..n]);
        let mut b = [0u8; 1500];
        let t = c.poll_transmit(t0, &mut b).unwrap();
        let mut con = b[..t.len].to_vec();
        patch(&mut con);
        match l.handle(t0, caller, &con, &mut out) {
            ListenerAction::Reply(n) => {
                c.handle_datagram(t0, addr("10.0.0.1:9000"), &out[..n]);
                match c.state() {
                    srt_core::State::Closed(srt_core::CloseReason::Rejected(r)) => Some(*r),
                    s => panic!("{s:?}"),
                }
            }
            ListenerAction::Accept(_) => None,
            _ => panic!(),
        }
    };
    let none = |_: &mut Vec<u8>| {};
    assert_eq!(run(Config::default(), Config::default(), &none), None);
    let f = |s: &str| Config {
        packet_filter: Some(s.into()),
        ..Config::default()
    };
    assert_eq!(run(f("fec,cols:4,rows:2"), f("fec,cols:5,rows:2"), &none), Some(RejectReason::Filter));
    let sid = |s: &str| Config {
        stream_id: Some(s.into()),
        ..Config::default()
    };
    assert_eq!(run(Config::default(), sid("forbidden"), &none), Some(RejectReason::App(1403)));
    assert_eq!(run(Config::default(), sid("ok"), &none), None);
    // KMREQ block appended: UNSECURE
    let km = |c: &mut Vec<u8>| c.extend_from_slice(&[0, 3, 0, 0]);
    assert_eq!(run(Config::default(), Config::default(), &km), Some(RejectReason::Unsecure));
    // STREAM flag: MESSAGEAPI
    let stream = |c: &mut Vec<u8>| {
        let f = 16 + 48 + 8;
        c[f + 3] |= flags::STREAM as u8;
    };
    assert_eq!(run(Config::default(), Config::default(), &stream), Some(RejectReason::MessageApi));
    // HSREQ version 1.2.0: VERSION
    let old = |c: &mut Vec<u8>| c[16 + 48 + 4..16 + 48 + 8].copy_from_slice(&0x0001_0200u32.to_be_bytes());
    assert_eq!(run(Config::default(), Config::default(), &old), Some(RejectReason::Version));
    // backlog
    let mut l = Listener::new(Config::default(), t0);
    l.set_backlog_full(true);
    let (mut c, ind) = mk(Config::default());
    let mut out = [0u8; 1500];
    let ListenerAction::Reply(n) = l.handle(t0, caller, &ind, &mut out) else {
        panic!()
    };
    c.handle_datagram(t0, addr("10.0.0.1:9000"), &out[..n]);
    let mut b = [0u8; 1500];
    let t = c.poll_transmit(t0, &mut b).unwrap();
    let ListenerAction::Reply(n) = l.handle(t0, caller, &b[..t.len], &mut out) else {
        panic!()
    };
    assert_eq!(hs_of(&out[..n]).1.reject_reason(), Some(RejectReason::Backlog));
}
