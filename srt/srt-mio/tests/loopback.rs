//! Caller and listener on loopback sockets, one thread, one mio Poll.

use mio::{Events, Interest, Poll, Token};
use srt_mio::srt_core::Config;
use srt_mio::{SrtListener, SrtSocket, SrtTimer, UdpOptions};
use std::time::{Duration, Instant};

#[test]
fn connect_send_and_deliver_on_time() {
    let cfg = Config::default().with_latency_ms(80);
    let opts = UdpOptions::default();
    let mut l = SrtListener::bind("127.0.0.1:0".parse().unwrap(), cfg.clone(), &opts).unwrap();
    let laddr = l.local_addr().unwrap();
    let mut c = SrtSocket::connect("127.0.0.1:0".parse().unwrap(), laddr, cfg, &opts).unwrap();
    let mut poll = Poll::new().unwrap();
    let mut timer = SrtTimer::new().unwrap();
    poll.registry().register(&mut l, Token(0), Interest::READABLE | Interest::WRITABLE).unwrap();
    poll.registry().register(&mut c, Token(1), Interest::READABLE | Interest::WRITABLE).unwrap();
    poll.registry().register(&mut timer, Token(2), Interest::READABLE).unwrap();
    let mut ev = Events::with_capacity(16);
    let t0 = Instant::now();
    let mut id = None;
    let mut sent: Vec<Instant> = Vec::new();
    let mut lat = Vec::new();
    let total = 20_000u32;
    let mut msg = vec![0u8; 1316];
    let mut next_burst = t0;
    while lat.len() < total as usize && t0.elapsed() < Duration::from_secs(10) {
        let now = Instant::now();
        l.drive(now).unwrap();
        c.drive(now).unwrap();
        if id.is_none() {
            id = l.accept();
        }
        if c.is_connected() && sent.len() < total as usize && now >= next_burst {
            // 500-packet frames every 20 ms (~260 Mbit/s)
            for _ in 0..500 {
                if sent.len() == total as usize {
                    break;
                }
                msg[..4].copy_from_slice(&(sent.len() as u32).to_be_bytes());
                c.send(now, &msg).unwrap();
                sent.push(now);
            }
            c.flush(now).unwrap();
            next_burst = now + Duration::from_millis(20);
        }
        if let Some(id) = id {
            let now = Instant::now();
            l.recv_with(id, now, |m| {
                let i = u32::from_be_bytes(m.payload[..4].try_into().unwrap()) as usize;
                assert_eq!(i, lat.len(), "in order, no loss");
                lat.push(now - sent[i]);
            });
        }
        let mut wake = [c.poll_timeout(), l.poll_timeout(), Some(next_burst)].into_iter().flatten().min();
        if let Some(w) = wake {
            if w <= Instant::now() {
                continue;
            }
        } else {
            wake = Some(Instant::now() + Duration::from_millis(50));
        }
        timer.arm(wake, Instant::now()).unwrap();
        poll.poll(&mut ev, Some(Duration::from_millis(100))).unwrap();
        if ev.iter().any(|e| e.token() == Token(2)) {
            timer.clear();
        }
    }
    assert_eq!(lat.len(), total as usize);
    lat.sort();
    let p50 = lat[lat.len() / 2];
    let max = *lat.last().unwrap();
    // loopback one-way delay ~0: delivered at origin + 80 ms (+ the
    // handshake's processing delay, which TSBPD's base absorbs; loose bounds
    // for a debug build on a shared machine)
    assert!(p50 >= Duration::from_millis(80) && p50 < Duration::from_millis(82), "p50 {p50:?}");
    assert!(max < Duration::from_millis(90), "max {max:?}");
    let st = l.connection(id.unwrap()).unwrap().stats().clone();
    assert_eq!(st.pkt_rcv_loss, 0);
    assert_eq!(st.pkt_rcv_drop, 0);
    assert_eq!(c.connection().stats().ack_invalid, 0);
    // close: the listener's connection sees SHUTDOWN
    c.close(Instant::now()).unwrap();
    let t = Instant::now();
    while !l.connection(id.unwrap()).unwrap().is_closed() && t.elapsed() < Duration::from_secs(1) {
        l.drive(Instant::now()).unwrap();
        std::thread::sleep(Duration::from_millis(1));
    }
    assert!(l.connection(id.unwrap()).unwrap().is_closed());
}

#[test]
fn connect_blocking_and_rejection() {
    let lcfg = Config {
        packet_filter: Some("fec,cols:4,rows:2".into()),
        ..Config::default()
    };
    let opts = UdpOptions::default();
    let mut l = SrtListener::bind("127.0.0.1:0".parse().unwrap(), lcfg, &opts).unwrap();
    let laddr = l.local_addr().unwrap();
    let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let st = stop.clone();
    let h = std::thread::spawn(move || {
        while !st.load(std::sync::atomic::Ordering::Relaxed) {
            l.drive(Instant::now()).unwrap();
            std::thread::sleep(Duration::from_micros(200));
        }
        l.acceptor().stats().clone()
    });
    let ccfg = Config {
        packet_filter: Some("fec,cols:5,rows:2".into()),
        ..Config::default()
    };
    let e = SrtSocket::connect_blocking("127.0.0.1:0".parse().unwrap(), laddr, ccfg, &opts).err().unwrap();
    assert!(e.to_string().contains("Filter"), "{e}");
    let ccfg = Config {
        packet_filter: Some("fec,cols:4".into()),
        ..Config::default()
    };
    let s = SrtSocket::connect_blocking("127.0.0.1:0".parse().unwrap(), laddr, ccfg, &opts).unwrap();
    let snap = s.connection().snapshot(Instant::now());
    assert_eq!(snap.packet_filter.as_deref(), Some("fec,arq:onreq,cols:4,layout:staircase,rows:2"));
    stop.store(true, std::sync::atomic::Ordering::Relaxed);
    let ls = h.join().unwrap();
    assert_eq!((ls.accepted, ls.rejected), (1, 1));
}
