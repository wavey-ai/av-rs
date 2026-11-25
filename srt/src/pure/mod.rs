//! The pure Rust backend: `srt-core` (sans-IO live-mode SRT) on `srt-mio`
//! I/O threads (see `engine`), with the same API as the libsrt backend.
//!
//! Differences from the libsrt backend (see the crate's README section):
//! - no `sys` module and no `raw_stats` (libsrt's `SRT_TRACEBSTATS`):
//!   `stats()` returns `srt_core::Stats` instead;
//! - a passphrase (caller option or listener callback) is refused with a
//!   clear error unless AES is available: the connection never runs
//!   unencrypted;
//! - `set_log_handler` receives this backend's own warnings (refused
//!   connections, I/O errors), not libsrt's log lines.

mod engine;

#[cfg(feature = "async")]
mod async_impl;
#[cfg(feature = "async")]
pub use async_impl::*;

use crate::{ConnectOptions, Error, ListenerCallback, ListenerOption, LogLevel, MaxBandwidth, Result, SrtLogEvent};
use engine::{lock, srt_io_error, ConnHandle, ListenerHandle, Status, SRT_EINVPARAM, TX_LIMIT};
pub use srt_mio::srt_core;
use srt_mio::srt_core::Config;
use srt_mio::UdpOptions;
use std::{
    io::{self, Read, Write},
    marker::PhantomData,
    net::{SocketAddr, ToSocketAddrs},
    sync::{
        atomic::{AtomicI32, Ordering},
        Mutex,
    },
    time::Duration,
};

/// Connection counters of the pure Rust backend (libsrt's `srt_bistats` equivalent).
pub use srt_mio::srt_core::Stats;

/// libsrt sizes buffers in bytes of (MSS - 28) per packet.
const BYTES_PER_PKT: i32 = 1472;
/// libsrt's SRTO_CONNTIMEO default.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(3);

/// Whether this build can encrypt (AES). Without it a passphrase is refused.
pub const ENCRYPTION_SUPPORTED: bool = false;

// ------------------------------------------------------------------ logging

type LogHandlerBox = Box<dyn FnMut(&SrtLogEvent) + Send + Sync + 'static>;

static LOG_HANDLER: Mutex<Option<LogHandlerBox>> = Mutex::new(None);
static LOG_LEVEL: AtomicI32 = AtomicI32::new(libc::LOG_ERR);

/// Sets the handler for this backend's log events (warnings about refused
/// connections and I/O errors). They also go to the `log` crate.
pub fn set_log_handler<F>(handler: F)
where
    F: FnMut(&SrtLogEvent) + Send + Sync + 'static,
{
    *lock(&LOG_HANDLER) = Some(Box::new(handler));
}

/// Sets the minimum severity passed to the log handler.
pub fn set_log_level(level: LogLevel) {
    LOG_LEVEL.store(level as i32, Ordering::Relaxed);
}

pub(crate) fn log_warn(msg: &str) {
    log::warn!("{}", msg);
    // syslog order: a smaller number is more severe
    if LogLevel::Warning as i32 > LOG_LEVEL.load(Ordering::Relaxed) {
        return;
    }
    if let Some(h) = lock(&LOG_HANDLER).as_mut() {
        h(&SrtLogEvent {
            level: LogLevel::Warning,
            file: Some(file!()),
            line: line!() as _,
            area: Some("srt-rs"),
            message: Some(msg),
        });
    }
}

// ------------------------------------------------------------------ options

fn buf_pkts(bytes: i32) -> u32 {
    (bytes / BYTES_PER_PKT).max(32) as u32
}

fn latency_ms(v: i32) -> Result<u16> {
    std::convert::TryFrom::try_from(v).map_err(|_| invalid("srt_setsockopt"))
}

fn invalid(fn_name: &'static str) -> Error {
    Error::SRTError {
        fn_name,
        code: SRT_EINVPARAM,
        errno: 0,
    }
}

/// libsrt's defaults for a live socket.
fn base_config() -> Config {
    Config {
        connect_timeout: CONNECT_TIMEOUT,
        ..Config::default()
    }
}

pub(crate) fn listener_config(opts: impl IntoIterator<Item = ListenerOption>) -> Result<Config> {
    let mut cfg = base_config();
    for o in opts {
        match o {
            ListenerOption::TimestampBasedPacketDeliveryMode(v) => cfg.tsbpd = v,
            ListenerOption::PeerLatency(v) => cfg.peer_latency_ms = latency_ms(v)?,
            ListenerOption::TooLatePacketDrop(v) => cfg.tlpktdrop = v,
            ListenerOption::ReceiveBufferSize(v) => cfg.rcv_buf_pkts = buf_pkts(v),
            ListenerOption::SendBufferSize(v) => cfg.snd_buf_pkts = buf_pkts(v),
        }
    }
    cfg.validate().map_err(|_| invalid("srt_setsockopt"))?;
    Ok(cfg)
}

pub(crate) fn connect_config(o: &ConnectOptions) -> Result<Config> {
    let mut cfg = base_config();
    if let Some(p) = &o.passphrase {
        // libsrt accepts 10..=79 characters
        if p.len() < 10 || p.len() > 79 {
            return Err(invalid("srt_setsockopt"));
        }
        if !ENCRYPTION_SUPPORTED {
            return Err(Error::IOError(io::Error::new(
                io::ErrorKind::Unsupported,
                "srt_connect: a passphrase (AES encryption) was requested, which this wavey-srt pure-rust build does not support; \
                 refusing to connect unencrypted",
            )));
        }
    }
    if let Some(s) = &o.stream_id {
        if s.len() > 512 {
            return Err(invalid("srt_setsockopt"));
        }
        if !s.is_empty() {
            cfg.stream_id = Some(s.clone());
        }
    }
    if let Some(v) = o.too_late_packet_drop {
        cfg.tlpktdrop = v;
    }
    if let Some(v) = o.timestamp_based_packet_delivery_mode {
        cfg.tsbpd = v;
    }
    if let Some(v) = o.receive_buffer_size {
        cfg.rcv_buf_pkts = buf_pkts(v);
    }
    if let Some(v) = o.send_buffer_size {
        cfg.snd_buf_pkts = buf_pkts(v);
    }
    if let Some(bw) = &o.max_bandwidth {
        match bw {
            MaxBandwidth::Infinite => cfg.max_bw = -1,
            MaxBandwidth::Relative {
                input_bandwidth,
                overhead_bandwidth_percentage,
            } => {
                cfg.max_bw = 0;
                cfg.input_bw = *input_bandwidth as i64;
                cfg.overhead_bw_pct = *overhead_bandwidth_percentage;
            }
            MaxBandwidth::Absolute(n) => cfg.max_bw = *n as i64,
        }
    }
    if let Some(v) = o.max_send_payload_size {
        let max = cfg.mss as i32 - 44;
        if v < 0 || v > max {
            return Err(invalid("srt_setsockopt"));
        }
        // 0 is "no limit" in libsrt: one packet's worth here
        cfg.payload_size = if v == 0 { max as usize } else { v as usize };
    }
    cfg.validate().map_err(|_| invalid("srt_setsockopt"))?;
    Ok(cfg)
}

pub(crate) fn udp_options() -> UdpOptions {
    UdpOptions::default()
}

pub(crate) fn first_addr<A: ToSocketAddrs>(addr: A) -> Result<SocketAddr> {
    addr.to_socket_addrs()?.next().ok_or(Error::InvalidAddress)
}

// ------------------------------------------------------------------ blocking API

/// A listener whose `accept` blocks.
pub struct Listener<'c> {
    h: ListenerHandle,
    _cb: PhantomData<&'c ()>,
}

impl Listener<'static> {
    pub fn bind<A: ToSocketAddrs>(addr: A) -> Result<Self> {
        Self::bind_with_options(addr, vec![])
    }

    pub fn bind_with_options<A: ToSocketAddrs, O: IntoIterator<Item = ListenerOption>>(addr: A, opts: O) -> Result<Self> {
        let cfg = listener_config(opts)?;
        let h = engine::start_listener(first_addr(addr)?, cfg, udp_options())?;
        Ok(Listener { h, _cb: PhantomData })
    }
}

impl<'c> Listener<'c> {
    pub fn with_callback<F: ListenerCallback + 'c>(self, f: F) -> Result<Listener<'c>> {
        // SAFETY: the box lives until the handle's drop removes it
        unsafe { self.h.ls.set_callback(Some(Box::new(f))) };
        Ok(Listener { h: self.h, _cb: PhantomData })
    }

    pub fn accept(&self) -> Result<(Stream, SocketAddr)> {
        let (sh, addr) = self.h.ls.wait_accept()?;
        let id = sh.stream_id();
        Ok((Stream { h: ConnHandle { sh }, id }, addr))
    }

    /// The bound address.
    pub fn local_addr(&self) -> SocketAddr {
        self.h.ls.local
    }
}

/// A connection with blocking `Read` / `Write`, one SRT message per call.
pub struct Stream {
    h: ConnHandle,
    id: Option<String>,
}

impl Stream {
    pub fn connect<A: ToSocketAddrs>(addr: A, options: &ConnectOptions) -> Result<Self> {
        let cfg = connect_config(options)?;
        let mut last_err = Error::InvalidAddress;
        for addr in addr.to_socket_addrs()? {
            let h = engine::start_caller(addr, cfg.clone(), udp_options())?;
            match h.sh.wait(|s| s.poll_connected(None), |st| st.status != Status::Connecting) {
                Ok(()) => {
                    return Ok(Stream {
                        h,
                        id: options.stream_id.clone(),
                    })
                }
                Err(e) => last_err = e,
            }
        }
        Err(last_err)
    }

    pub fn id(&self) -> Option<&String> {
        self.id.as_ref()
    }

    pub fn peer_addr(&self) -> SocketAddr {
        self.h.sh.peer()
    }

    /// The connection's counters (refreshed every 100 ms and at close).
    pub fn stats(&self) -> Option<Stats> {
        self.h.sh.stats()
    }

    /// Why the connection closed, once it has.
    pub fn close_reason(&self) -> Option<srt_core::CloseReason> {
        self.h.sh.close_reason()
    }
}

impl Read for Stream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.h.sh.wait(|s| s.poll_read(buf, None), |st| !st.rx.is_empty() || matches!(st.status, Status::Closed(_)))
    }
}

impl Write for Stream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.h.sh.wait(|s| s.poll_write(buf, None), |st| st.tx.len() < TX_LIMIT || st.status != Status::Open)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[allow(dead_code)]
pub(crate) fn closed_error(fn_name: &'static str) -> io::Error {
    srt_io_error(fn_name, engine::SRT_ECONNLOST)
}

#[cfg(test)]
mod test;
