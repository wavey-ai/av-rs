//! Minimal SRT listener for interop checks:
//! `srt-listen ADDR [SECONDS] [FILTER] [FORBIDDEN_STREAM_ID]`
//! Accepts callers, prints each connection's stream ID, negotiated filter,
//! latency and how many messages it delivered; rejects
//! FORBIDDEN_STREAM_ID with 2403 (SRT_REJX_FORBIDDEN).

use mio::{Events, Interest, Poll, Token};
use srt_mio::srt_core::{Config, RejectReason};
use srt_mio::{SrtListener, SrtTimer, UdpOptions};
use std::collections::HashMap;
use std::time::{Duration, Instant};

fn main() -> std::io::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let addr = args.get(1).expect("ADDR").parse().expect("ADDR");
    let secs: u64 = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(10);
    let filter = args.get(3).filter(|s| !s.is_empty()).cloned();
    let forbidden = args.get(4).cloned();
    let cfg = Config {
        packet_filter: filter,
        ..Config::default()
    }
    .with_latency_ms(120);
    let mut l = SrtListener::bind(addr, cfg, &UdpOptions::default())?;
    l.set_accept_callback(Some(Box::new(move |r| {
        println!("accept request from {} stream id {:?}", r.peer, r.stream_id);
        match (&forbidden, r.stream_id) {
            (Some(f), Some(s)) if f == s => Err(RejectReason::App(1403)),
            _ => Ok(()),
        }
    })));
    let mut poll = Poll::new()?;
    let mut timer = SrtTimer::new()?;
    poll.registry().register(&mut l, Token(0), Interest::READABLE)?;
    poll.registry().register(&mut timer, Token(1), Interest::READABLE)?;
    let mut ev = Events::with_capacity(16);
    let end = Instant::now() + Duration::from_secs(secs);
    let mut got: HashMap<u32, u64> = HashMap::new();
    while Instant::now() < end {
        let now = Instant::now();
        l.drive_io(now)?;
        while let Some(id) = l.accept() {
            let c = l.connection(id).unwrap();
            let s = c.snapshot(now);
            println!(
                "connected id {id:#x} peer {} stream id {:?} filter {:?} latency rcv/snd {:?} peer version {:#x} flags {:#x}",
                c.peer_addr(),
                c.stream_id(),
                s.packet_filter,
                c.latencies_ms(),
                s.peer_srt_version,
                s.peer_flags
            );
            got.insert(id, 0);
        }
        let ids: Vec<u32> = got.keys().copied().collect();
        for id in ids {
            let n = l.recv_with(id, now, |_| {});
            *got.get_mut(&id).unwrap() += n as u64;
        }
        let wake = l.poll_timeout().unwrap_or(end).min(end).max(now + Duration::from_micros(50));
        timer.arm(Some(wake), now)?;
        poll.poll(&mut ev, Some(Duration::from_millis(100)))?;
        for e in ev.iter() {
            if e.token() == Token(1) {
                timer.clear();
            } else {
                l.set_readable();
            }
        }
    }
    for (id, n) in &got {
        let c = l.connection(*id).unwrap();
        println!(
            "connection {id:#x}: {n} messages delivered, state {:?}, loss {} drop {}",
            c.state(),
            c.stats().pkt_rcv_loss,
            c.stats().pkt_rcv_drop
        );
    }
    println!("listener {:?}", l.acceptor().stats());
    Ok(())
}
