//! Interop driver for wavey-srt (either backend), used by tests/interop.rs.
//!
//! ```text
//! srt-interop listen ADDR [--secs N] [--deny SID] [--write-back N] [--out FILE]
//! srt-interop call ADDR [--sid SID] [--count N] [--size B] [--interval-us U] [--read-back N]
//! ```
//!
//! `listen` accepts one connection through `AsyncListener` + callback,
//! reads until the peer closes (or `--secs`), and prints one JSON line:
//! the backend, stream id, messages, bytes, an FNV-1a hash of the bytes,
//! sequence check (for `call` payloads), MPEG-TS check (188-byte packets,
//! sync bytes), the error that ended the read, and (pure-rust) the
//! negotiated latency. `call` sends `--count` messages of `--size` bytes,
//! each starting with a big-endian u32 sequence number, then prints a JSON
//! line. `--write-back N --expect M` (listener: send N messages once M
//! arrived) and `--read-back N` (caller: read N before closing) exercise
//! the listener->caller direction.

use srt::{AsyncListener, AsyncStream, ConnectOptions, ListenerCallbackAction, ListenerOption};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn arg(args: &[String], name: &str) -> Option<String> {
    args.iter().position(|a| a == name).and_then(|i| args.get(i + 1).cloned())
}

fn fnv(h: &mut u64, b: &[u8]) {
    for &x in b {
        *h ^= x as u64;
        *h = h.wrapping_mul(0x100000001b3);
    }
}

fn json_str(s: &str) -> String {
    let mut o = String::from("\"");
    for c in s.chars() {
        match c {
            '"' => o.push_str("\\\""),
            '\\' => o.push_str("\\\\"),
            c if (c as u32) < 0x20 => o.push_str(&format!("\\u{:04x}", c as u32)),
            c => o.push(c),
        }
    }
    o.push('"');
    o
}

fn opt_str(s: &Option<String>) -> String {
    s.as_deref().map_or("null".into(), json_str)
}

#[cfg(feature = "pure-rust")]
fn latency(s: &AsyncStream) -> String {
    let (r, w) = s.latency_ms();
    format!("[{},{}]", r, w)
}

#[cfg(not(feature = "pure-rust"))]
fn latency(_s: &AsyncStream) -> String {
    "null".into()
}

/// MPEG-TS check over the received byte stream: 188-byte packets with
/// sync bytes, and the continuity counter of every PID (a lost or
/// reordered message shows as a CC error).
#[derive(Default)]
struct TsCheck {
    carry: Vec<u8>,
    packets: u64,
    resyncs: u64,
    cc_errors: u64,
    cc: std::collections::HashMap<u16, u8>,
}

impl TsCheck {
    fn feed(&mut self, m: &[u8]) {
        self.carry.extend_from_slice(m);
        let mut i = 0;
        while self.carry.len() - i >= 188 {
            if self.carry[i] != 0x47 {
                self.resyncs += 1;
                match self.carry[i + 1..].iter().position(|&b| b == 0x47) {
                    Some(o) => i += 1 + o,
                    None => {
                        i = self.carry.len();
                        break;
                    }
                }
                continue;
            }
            let p = &self.carry[i..i + 188];
            self.packets += 1;
            let pid = ((p[1] as u16 & 0x1f) << 8) | p[2] as u16;
            let afc = (p[3] >> 4) & 3;
            let cc = p[3] & 0xf;
            let discontinuity = (afc & 2) != 0 && p[4] > 0 && (p[5] & 0x80) != 0;
            if pid != 0x1fff && (afc & 1) != 0 {
                if let Some(&last) = self.cc.get(&pid) {
                    if !discontinuity && cc != (last + 1) & 0xf && cc != last {
                        self.cc_errors += 1;
                    }
                }
                self.cc.insert(pid, cc);
            }
            i += 188;
        }
        self.carry.drain(..i);
    }
}

async fn listen(args: &[String]) {
    let addr = args.get(2).expect("ADDR").clone();
    let secs: u64 = arg(args, "--secs").and_then(|s| s.parse().ok()).unwrap_or(30);
    let deny = arg(args, "--deny");
    let write_back: u32 = arg(args, "--write-back").and_then(|s| s.parse().ok()).unwrap_or(0);
    // write back once this many messages arrived
    let expect: u64 = arg(args, "--expect").and_then(|s| s.parse().ok()).unwrap_or(1);
    let out = arg(args, "--out");
    let mut opts = vec![
        ListenerOption::TimestampBasedPacketDeliveryMode(true),
        ListenerOption::TooLatePacketDrop(true),
        ListenerOption::ReceiveBufferSize(36_400_000),
    ];
    if let Some(l) = arg(args, "--peer-latency").and_then(|s| s.parse().ok()) {
        opts.push(ListenerOption::PeerLatency(l));
    }
    let seen: Arc<Mutex<Vec<Option<String>>>> = Arc::new(Mutex::new(Vec::new()));
    let seen2 = seen.clone();
    let listener = AsyncListener::bind_with_options(addr.as_str(), opts)
        .expect("bind")
        .with_callback(move |sid: Option<&str>| {
            seen2.lock().unwrap().push(sid.map(str::to_string));
            match (&deny, sid) {
                (Some(d), Some(s)) if d == s => ListenerCallbackAction::Deny,
                _ => ListenerCallbackAction::Allow { passphrase: None },
            }
        })
        .expect("callback");
    println!("{{\"listening\":{}}}", json_str(&addr));
    let deadline = Instant::now() + Duration::from_secs(secs);
    let accepted = loop {
        match tokio::time::timeout_at(deadline.into(), listener.accept()).await {
            Err(_) => break None,
            Ok(Ok(a)) => break Some(a),
            Ok(Err(e)) => eprintln!("accept error: {}", e),
        }
    };
    let callback_sids: Vec<String> = seen.lock().unwrap().iter().map(opt_str).collect();
    let Some((mut s, peer)) = accepted else {
        println!(
            "{{\"backend\":\"{}\",\"accepted\":false,\"callback_sids\":[{}]}}",
            srt::BACKEND,
            callback_sids.join(",")
        );
        return;
    };
    let t0 = Instant::now();
    let mut file = out.map(|p| std::fs::File::create(p).expect("out file"));
    let mut buf = vec![0u8; 1500];
    let (mut msgs, mut bytes, mut hash) = (0u64, 0u64, 0xcbf29ce484222325u64);
    let (mut seq_ok, mut next_seq, mut seq_gaps) = (true, 0u32, 0u64);
    let mut ts = TsCheck::default();
    let (mut first_at, mut last_at) = (None, None);
    let mut sizes = std::collections::BTreeMap::new();
    let mut wrote = 0u32;
    let end = loop {
        match tokio::time::timeout_at(deadline.into(), s.read(&mut buf)).await {
            Err(_) => break "timeout".to_string(),
            Ok(Ok(0)) => break "eof".to_string(),
            Ok(Ok(n)) => {
                let m = &buf[..n];
                msgs += 1;
                bytes += n as u64;
                fnv(&mut hash, m);
                *sizes.entry(n).or_insert(0u64) += 1;
                first_at.get_or_insert(t0.elapsed());
                last_at = Some(t0.elapsed());
                if let Some(f) = file.as_mut() {
                    use std::io::Write;
                    f.write_all(m).expect("write out");
                }
                if n >= 4 {
                    let q = u32::from_be_bytes([m[0], m[1], m[2], m[3]]);
                    if q != next_seq {
                        seq_ok = false;
                        seq_gaps += 1;
                    }
                    next_seq = q.wrapping_add(1);
                }
                if write_back > 0 && msgs == expect {
                    let mut m = vec![0u8; 1316];
                    for i in 0..write_back {
                        m[..4].copy_from_slice(&i.to_be_bytes());
                        if s.write_all(&m).await.is_err() {
                            break;
                        }
                        wrote += 1;
                    }
                }
                ts.feed(m);
            }
            Ok(Err(e)) => break e.to_string(),
        }
    };
    let sizes: Vec<String> = sizes.iter().map(|(k, v)| format!("\"{}\":{}", k, v)).collect();
    println!(
        "{{\"backend\":\"{}\",\"accepted\":true,\"peer\":\"{}\",\"stream_id\":{},\"callback_sids\":[{}],\"latency_ms\":{},\
\"messages\":{},\"bytes\":{},\"fnv\":\"{:016x}\",\"seq_in_order\":{},\"seq_gaps\":{},\"ts_packets\":{},\"ts_resyncs\":{},\"ts_cc_errors\":{},\
\"sizes\":{{{}}},\"first_ms\":{},\"last_ms\":{},\"end\":{},\"wrote_back\":{}}}",
        srt::BACKEND,
        peer,
        opt_str(&s.id().cloned()),
        callback_sids.join(","),
        latency(&s),
        msgs,
        bytes,
        hash,
        seq_ok,
        seq_gaps,
        ts.packets,
        ts.resyncs,
        ts.cc_errors,
        sizes.join(","),
        first_at.map_or(-1.0, |d| d.as_secs_f64() * 1000.0),
        last_at.map_or(-1.0, |d| d.as_secs_f64() * 1000.0),
        json_str(&end),
        wrote
    );
}

async fn call(args: &[String]) {
    let addr = args.get(2).expect("ADDR").clone();
    let count: u32 = arg(args, "--count").and_then(|s| s.parse().ok()).unwrap_or(1000);
    let size: usize = arg(args, "--size").and_then(|s| s.parse().ok()).unwrap_or(1316);
    let interval = Duration::from_micros(arg(args, "--interval-us").and_then(|s| s.parse().ok()).unwrap_or(1000));
    let read_back: u32 = arg(args, "--read-back").and_then(|s| s.parse().ok()).unwrap_or(0);
    let opts = ConnectOptions {
        stream_id: arg(args, "--sid"),
        max_send_payload_size: Some(1316),
        ..Default::default()
    };
    let t0 = Instant::now();
    let mut s = match AsyncStream::connect(addr.as_str(), &opts).await {
        Ok(s) => s,
        Err(e) => {
            println!(
                "{{\"backend\":\"{}\",\"connected\":false,\"error\":{},\"ms\":{}}}",
                srt::BACKEND,
                json_str(&e.to_string()),
                t0.elapsed().as_millis()
            );
            return;
        }
    };
    let connect_ms = t0.elapsed().as_secs_f64() * 1000.0;
    let mut m = vec![0u8; size];
    let mut hash = 0xcbf29ce484222325u64;
    let mut sent = 0u32;
    let start = Instant::now();
    for i in 0..count {
        m[..4].copy_from_slice(&i.to_be_bytes());
        for (j, b) in m[4..].iter_mut().enumerate() {
            *b = (i as usize + j) as u8;
        }
        let due = start + interval * i;
        tokio::time::sleep_until(due.into()).await;
        match s.write(&m).await {
            Ok(n) => {
                fnv(&mut hash, &m[..n]);
                sent += 1;
            }
            Err(e) => {
                eprintln!("write error: {}", e);
                break;
            }
        }
    }
    let (mut got, mut in_order) = (0u32, true);
    if read_back > 0 {
        let mut buf = [0u8; 1500];
        while got < read_back {
            match tokio::time::timeout(Duration::from_secs(10), s.read(&mut buf)).await {
                Ok(Ok(n)) if n >= 4 => {
                    if u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]) != got {
                        in_order = false;
                    }
                    got += 1;
                }
                _ => break,
            }
        }
    }
    // the process exits after this: give the last writes time to be
    // sent and acknowledged (libsrt drops unsent data on close)
    tokio::time::sleep(Duration::from_millis(500)).await;
    println!(
        "{{\"backend\":\"{}\",\"connected\":true,\"connect_ms\":{:.1},\"sent\":{},\"fnv\":\"{:016x}\",\"latency_ms\":{},\"read_back\":{},\"read_back_in_order\":{}}}",
        srt::BACKEND,
        connect_ms,
        sent,
        hash,
        latency(&s),
        got,
        in_order
    );
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("listen") => listen(&args).await,
        Some("call") => call(&args).await,
        _ => eprintln!("usage: srt-interop listen|call ADDR [options]"),
    }
}
