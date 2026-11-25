//! SRT interop endpoint: caller or listener, sending a TS file or receiving
//! into one, for checks against libsrt tools (srt-live-transmit, ffmpeg).
//!
//! `srt-io MODE ADDR [key=value ...]`
//! - MODE: `call-send`, `call-recv`, `listen-send`, `listen-recv`
//! - keys: `latency` (ms, default 120), `filter` (SRTO_PACKETFILTER string),
//!   `streamid`, `secs` (run time, default 10), `in` (TS file to send),
//!   `out` (file the payloads go to), `rate` (Mbit/s the file is paced at,
//!   default 10), `payload` (default 1316)
//!
//! Prints one JSON line at the end: messages and bytes moved, TS sync
//! errors (a 0x47 every 188 bytes of every payload), loss/drop/
//! retransmission counters, negotiated filter, latencies, peer version.

use mio::{Events, Interest, Poll, Token};
use srt_mio::srt_core::{Config, Connection, State};
use srt_mio::{SrtListener, SrtSocket, SrtTimer, UdpOptions};
use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::SocketAddr;
use std::time::{Duration, Instant};

enum End {
    Call(SrtSocket),
    Listen(SrtListener, Option<u32>),
}

impl End {
    fn conn(&self) -> Option<&Connection> {
        match self {
            End::Call(s) => Some(s.connection()),
            End::Listen(l, Some(id)) => l.connection(*id),
            End::Listen(_, None) => None,
        }
    }
    fn drive(&mut self, now: Instant) -> std::io::Result<()> {
        match self {
            End::Call(s) => s.drive_io(now),
            End::Listen(l, id) => {
                l.drive_io(now)?;
                while let Some(n) = l.accept() {
                    if id.is_none() {
                        *id = Some(n);
                    }
                }
                Ok(())
            }
        }
    }
    fn set_readable(&mut self) {
        match self {
            End::Call(s) => s.set_readable(),
            End::Listen(l, _) => l.set_readable(),
        }
    }
    fn poll_timeout(&self) -> Option<Instant> {
        match self {
            End::Call(s) => s.poll_timeout(),
            End::Listen(l, _) => l.poll_timeout(),
        }
    }
    fn send(&mut self, now: Instant, m: &[u8]) -> bool {
        match self {
            End::Call(s) => s.send(now, m).is_ok(),
            End::Listen(l, Some(id)) => l.send(*id, now, m).is_ok(),
            End::Listen(_, None) => false,
        }
    }
    fn recv(&mut self, now: Instant, f: &mut dyn FnMut(&[u8])) {
        match self {
            End::Call(s) => {
                s.recv_with(now, |m| f(m.payload));
            }
            End::Listen(l, Some(id)) => {
                l.recv_with(*id, now, |m| f(m.payload));
            }
            End::Listen(_, None) => {}
        }
    }
    fn flush(&mut self, now: Instant) {
        let _ = match self {
            End::Call(s) => s.flush(now),
            End::Listen(l, _) => l.flush(now),
        };
    }
    fn close(&mut self, now: Instant) {
        let _ = match self {
            End::Call(s) => s.close(now),
            End::Listen(l, Some(id)) => l.close(*id, now),
            End::Listen(_, None) => Ok(()),
        };
    }
}

fn main() -> std::io::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let mode = args.get(1).expect("MODE").clone();
    let addr: SocketAddr = args.get(2).expect("ADDR").parse().expect("ADDR");
    let kv: HashMap<String, String> = args[3..].iter().filter_map(|a| a.split_once('=')).map(|(k, v)| (k.to_string(), v.to_string())).collect();
    let get = |k: &str| kv.get(k).cloned();
    let latency: u16 = get("latency").and_then(|v| v.parse().ok()).unwrap_or(120);
    let secs: f64 = get("secs").and_then(|v| v.parse().ok()).unwrap_or(10.0);
    let rate: f64 = get("rate").and_then(|v| v.parse().ok()).unwrap_or(10.0);
    let payload: usize = get("payload").and_then(|v| v.parse().ok()).unwrap_or(1316);
    let cfg = Config {
        packet_filter: get("filter").filter(|s| !s.is_empty()),
        stream_id: get("streamid"),
        payload_size: payload,
        ..Config::default()
    }
    .with_latency_ms(latency);
    let sending = mode.ends_with("send");
    let mut input = Vec::new();
    if sending {
        std::fs::File::open(get("in").expect("in=FILE"))?.read_to_end(&mut input)?;
    }
    let mut out = match get("out") {
        Some(p) => Some(std::fs::File::create(p)?),
        None => None,
    };
    let opts = UdpOptions::default();
    let t0 = Instant::now();
    let mut end = match mode.as_str() {
        "call-send" | "call-recv" => End::Call(SrtSocket::connect("0.0.0.0:0".parse().unwrap(), addr, cfg, &opts)?),
        "listen-send" | "listen-recv" => End::Listen(SrtListener::bind(addr, cfg, &opts)?, None),
        m => panic!("unknown mode {m}"),
    };
    let mut poll = Poll::new()?;
    let mut timer = SrtTimer::new()?;
    match &mut end {
        End::Call(s) => poll.registry().register(s, Token(0), Interest::READABLE)?,
        End::Listen(l, _) => poll.registry().register(l, Token(0), Interest::READABLE)?,
    }
    poll.registry().register(&mut timer, Token(1), Interest::READABLE)?;
    let mut ev = Events::with_capacity(64);
    let stop = t0 + Duration::from_secs_f64(secs);
    let mut connected_at: Option<Instant> = None;
    let mut sent = 0u64;
    let mut off = 0usize;
    let (mut msgs, mut bytes, mut sync_err) = (0u64, 0u64, 0u64);
    let mut closed_reason = None;
    let pace = Duration::from_secs_f64(payload as f64 * 8.0 / (rate * 1e6));
    let mut send_done_at: Option<Instant> = None;
    loop {
        let now = Instant::now();
        if now >= stop {
            break;
        }
        end.drive(now)?;
        let connected = end.conn().map_or(false, |c| c.is_connected());
        if connected && connected_at.is_none() {
            connected_at = Some(now);
        }
        if let Some(c) = end.conn() {
            if let State::Closed(r) = c.state() {
                if closed_reason.is_none() {
                    closed_reason = Some(format!("{r:?}"));
                }
                if c.poll_timeout().is_none() || matches!(mode.as_str(), "call-send" | "listen-send") {
                    break;
                }
            }
        }
        if sending && connected && send_done_at.is_none() {
            let start = connected_at.unwrap();
            while off < input.len() && start + pace * sent as u32 <= now {
                let n = payload.min(input.len() - off);
                if !end.send(now, &input[off..off + n]) {
                    break;
                }
                off += n;
                sent += 1;
            }
            end.flush(now);
            if off >= input.len() {
                send_done_at = Some(now);
            }
        }
        if let Some(t) = send_done_at {
            // linger for the receiver's latency and repairs, then close
            if now >= t + Duration::from_millis(latency as u64 * 2 + 1000) {
                end.close(now);
                break;
            }
        }
        if !sending {
            end.recv(now, &mut |p: &[u8]| {
                msgs += 1;
                bytes += p.len() as u64;
                sync_err += p.chunks(188).filter(|c| c[0] != 0x47).count() as u64;
                if let Some(f) = out.as_mut() {
                    let _ = f.write_all(p);
                }
            });
        }
        let mut wake = end.poll_timeout().unwrap_or(stop).min(stop);
        if sending && connected && send_done_at.is_none() {
            wake = wake.min(connected_at.unwrap() + pace * sent as u32);
        }
        let now = Instant::now();
        if wake > now {
            timer.arm(Some(wake), now)?;
            poll.poll(&mut ev, Some(Duration::from_millis(100)))?;
            for e in ev.iter() {
                if e.token() == Token(1) {
                    timer.clear();
                } else {
                    end.set_readable();
                }
            }
        }
    }
    let now = Instant::now();
    let summary = match end.conn() {
        Some(c) => {
            let st = c.stats();
            let sn = c.snapshot(now);
            format!(
                "{{\"mode\":\"{mode}\",\"connected\":{},\"connect_ms\":{},\"sent_msgs\":{sent},\"recv_msgs\":{msgs},\"recv_bytes\":{bytes},\"ts_sync_errors\":{sync_err},\"stream_id\":{:?},\"filter\":{:?},\"latency_rcv_snd\":{:?},\"peer_version\":\"{:#x}\",\"rcv_loss\":{},\"rcv_drop\":{},\"rcv_fec_supply\":{},\"snd_retrans\":{},\"snd_drop\":{},\"rtt_ms\":{:.2},\"closed\":{:?}}}",
                connected_at.is_some(),
                connected_at.map_or(-1.0, |t| (t - t0).as_secs_f64() * 1e3),
                c.stream_id(),
                sn.packet_filter,
                c.latencies_ms(),
                sn.peer_srt_version,
                st.pkt_rcv_loss,
                st.pkt_rcv_drop,
                st.pkt_rcv_filter_supply,
                st.pkt_retrans,
                st.pkt_snd_drop,
                sn.rtt_us as f64 / 1000.0,
                closed_reason
            )
        }
        None => format!("{{\"mode\":\"{mode}\",\"connected\":false}}"),
    };
    end.close(now);
    println!("{summary}");
    Ok(())
}
