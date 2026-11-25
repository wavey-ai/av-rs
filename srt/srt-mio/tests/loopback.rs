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

/// Many callers on one listener: every connection's timers come from the
/// listener's heap (no scan of all connections per wake-up), every message
/// arrives in order, and the heap holds about one entry per connection.
#[test]
fn listener_timer_heap_many_callers() {
    // generous latency: the test checks the timer bookkeeping, not tight
    // delivery on a loaded machine
    let cfg = Config::default().with_latency_ms(500);
    let opts = UdpOptions { recv_buffer: Some(4 << 20), send_buffer: Some(1 << 20), reuse_address: true };
    let mut l = SrtListener::bind("127.0.0.1:0".parse().unwrap(), cfg.clone(), &opts).unwrap();
    let laddr = l.local_addr().unwrap();
    let n = 48usize;
    let mut cs: Vec<SrtSocket> = (0..n).map(|_| SrtSocket::connect("127.0.0.1:0".parse().unwrap(), laddr, cfg.clone(), &opts).unwrap()).collect();
    // callers bind port 0: every one must get its own port (SO_REUSEADDR
    // on an ephemeral bind let Linux hand out a port already in use)
    let ports: std::collections::HashSet<u16> = cs.iter().map(|c| c.local_addr().unwrap().port()).collect();
    assert_eq!(ports.len(), n, "two callers share a local port");
    let mut poll = Poll::new().unwrap();
    let mut timer = SrtTimer::new().unwrap();
    poll.registry().register(&mut l, Token(0), Interest::READABLE).unwrap();
    for (i, c) in cs.iter_mut().enumerate() {
        poll.registry().register(c, Token(1 + i), Interest::READABLE).unwrap();
    }
    poll.registry().register(&mut timer, Token(1000), Interest::READABLE).unwrap();
    let mut ev = Events::with_capacity(256);
    let t0 = Instant::now();
    let per = 300u32;
    let mut ids = Vec::new();
    let mut got: std::collections::HashMap<u32, u32> = std::collections::HashMap::new();
    let mut sent = vec![0u32; n];
    let mut next = t0;
    let mut max_heap = 0;
    while got.values().sum::<u32>() < per * n as u32 && t0.elapsed() < Duration::from_secs(30) {
        let now = Instant::now();
        l.drive_io(now).unwrap();
        for c in cs.iter_mut() {
            c.drive_io(now).unwrap();
        }
        while let Some(id) = l.accept() {
            ids.push(id);
        }
        if now >= next && cs.iter().all(|c| c.is_connected()) {
            for (i, c) in cs.iter_mut().enumerate() {
                for _ in 0..10 {
                    if sent[i] < per {
                        let mut m = [0u8; 188];
                        m[..4].copy_from_slice(&sent[i].to_be_bytes());
                        c.send(now, &m).unwrap();
                        sent[i] += 1;
                    }
                }
                c.flush(now).unwrap();
            }
            next = now + Duration::from_millis(5);
        }
        for &id in &ids {
            l.recv_with(id, Instant::now(), |m| {
                let k = u32::from_be_bytes(m.payload[..4].try_into().unwrap());
                let e = got.entry(id).or_insert(0);
                assert_eq!(k, *e, "in order, no loss");
                *e += 1;
            });
        }
        max_heap = max_heap.max(l.timer_entries());
        let sending = cs.iter().all(|c| c.is_connected()) && sent.iter().any(|&k| k < per);
        let wake = cs.iter().filter_map(|c| c.poll_timeout()).chain(l.poll_timeout()).chain(sending.then_some(next)).min().unwrap();
        let now = Instant::now();
        if wake <= now {
            continue;
        }
        timer.arm(Some(wake), now).unwrap();
        poll.poll(&mut ev, Some(Duration::from_millis(50))).unwrap();
        for e in ev.iter() {
            match e.token() {
                Token(0) => l.set_readable(),
                Token(1000) => timer.clear(),
                Token(i) => cs[i - 1].set_readable(),
            }
        }
    }
    if ids.len() != n {
        for c in &cs {
            if !c.is_connected() {
                eprintln!("caller not connected: {:?} stats hs {} recv calls {} datagrams {} local {:?} sid {:#x}", c.connection().state(), c.connection().stats().pkt_sent_handshake, c.recv_calls, c.recv_datagrams, c.local_addr(), c.connection().local_socket_id());
            }
        }
        eprintln!("acceptor {:?} sent {} calls {} wouldblock {} errors {} last {:?}", l.acceptor().stats(), l.send_batch().datagrams, l.send_batch().calls, l.send_batch().would_block, l.send_batch().errors, l.send_batch().last_error);
    }
    assert_eq!(ids.len(), n);
    assert_eq!(got.values().sum::<u32>(), per * n as u32, "every message delivered");
    assert!(max_heap <= 64 + 4 * n, "heap stays bounded: {max_heap}");
    for &id in &ids {
        let st = l.connection(id).unwrap().stats();
        assert_eq!((st.pkt_rcv_loss, st.pkt_rcv_drop), (0, 0));
    }
}

/// Read coalescing with a sender that sends one packet per wake-up: every
/// message still arrives in order and on time, and the listener paused.
#[test]
fn read_coalescing_with_a_packet_paced_sender() {
    let cfg = Config::default().with_latency_ms(60);
    let opts = UdpOptions::default();
    let mut l = SrtListener::bind("127.0.0.1:0".parse().unwrap(), cfg.clone(), &opts).unwrap();
    let laddr = l.local_addr().unwrap();
    let mut c = SrtSocket::connect("127.0.0.1:0".parse().unwrap(), laddr, cfg, &opts).unwrap();
    let t0 = Instant::now();
    let mut id = None;
    let total = 3000u32;
    let mut sent = 0u32;
    let mut got = 0u32;
    let mut late = 0u32;
    let mut sent_at = Vec::new();
    while got < total && t0.elapsed() < Duration::from_secs(10) {
        let now = Instant::now();
        c.drive(now).unwrap();
        l.drive(now).unwrap();
        if id.is_none() {
            id = l.accept();
        }
        if c.is_connected() && sent < total {
            let mut m = [0u8; 1316];
            m[..4].copy_from_slice(&sent.to_be_bytes());
            c.send(now, &m).unwrap();
            c.flush(now).unwrap();
            sent_at.push(now);
            sent += 1;
        }
        if let Some(id) = id {
            let now = Instant::now();
            l.recv_with(id, now, |m| {
                let k = u32::from_be_bytes(m.payload[..4].try_into().unwrap());
                assert_eq!(k, got, "in order, no loss");
                if now - sent_at[k as usize] > Duration::from_millis(70) {
                    late += 1;
                }
                got += 1;
            });
        }
        if let Some(d) = l.coalesce_delay(Instant::now(), 8, Duration::from_micros(300)) {
            std::thread::sleep(d);
        } else {
            std::thread::sleep(Duration::from_micros(20));
        }
    }
    assert_eq!(got, total);
    assert!(late <= total / 100, "late {late}");
    assert!(l.coalesce_pauses > 0);
}
