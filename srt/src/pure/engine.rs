//! The I/O thread of the pure Rust backend and the state it shares with
//! the application's handles.
//!
//! One thread per listener (all its connections share its UDP socket) and
//! one per caller connection run an `srt-mio` poll loop: socket readiness,
//! a `timerfd` armed at the protocol's next deadline, and a `mio::Waker`
//! the handles use to hand it work. Nothing spins: the thread sleeps until
//! a datagram, a deadline, or a handle's kick.
//!
//! Between the thread and a handle sit two bounded queues per connection
//! (`ConnState::rx` and `tx`) under one mutex. A reader takes whole
//! messages from `rx`; a writer appends messages to `tx` (each stamped with
//! its write time, which becomes its SRT origin time). The thread moves
//! `tx` into the connection while its send buffer has room (so a full send
//! buffer blocks writers: backpressure) and delivered messages into `rx`
//! until `RX_LIMIT` (beyond that they stay in the connection's receive
//! buffer and its flow window shrinks, as with libsrt).

use crate::{Error, ListenerCallback, ListenerCallbackAction, Result};
use mio::{Events, Interest, Poll, Token, Waker as MioWaker};
use srt_mio::srt_core::{AcceptRequest, CloseReason, Config, Connection, Event, RejectReason, SendError, State, Stats};
use srt_mio::{SrtListener, SrtSocket, SrtTimer, UdpOptions};
use std::collections::{HashMap, VecDeque};
use std::io;
use std::net::SocketAddr;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::task::Waker;
use std::thread;
use std::time::{Duration, Instant};

const SOCK: Token = Token(0);
const TIMER: Token = Token(1);
const WAKE: Token = Token(2);

/// Delivered messages held for the reader before the thread stops taking
/// them from the connection.
pub(crate) const RX_LIMIT: usize = 4096;
/// Messages a writer may queue ahead of the connection's send buffer.
pub(crate) const TX_LIMIT: usize = 256;
/// Recycled message buffers kept per connection.
const FREE_LIMIT: usize = 1024;
/// Retry a send the kernel refused (EAGAIN) after this long.
const SEND_RETRY: Duration = Duration::from_micros(200);
/// Longest sleep (the protocol always has a nearer deadline while connected).
const MAX_SLEEP: Duration = Duration::from_secs(1);
/// A connection whose reader is behind is looked at no more often than this.
const STALLED_POLL: Duration = Duration::from_millis(1);
/// Copy the connection's counters to its handle this often.
const STATS_EVERY: Duration = Duration::from_millis(100);
/// After its handle is dropped, a connection keeps sending until what was
/// written is acknowledged, at most this long, then closes (SHUTDOWN).
/// libsrt's live mode has no linger and drops what is still unsent.
pub(crate) const LINGER: Duration = Duration::from_secs(2);
/// Accepted connections queued for `accept()` (libsrt: `srt_listen(s, 10)`).
pub(crate) const BACKLOG: usize = 10;

// libsrt's SRT_ERRNO values (srt.h), so error texts match the C backend.
pub(crate) const SRT_ENOSERVER: i32 = 1001;
pub(crate) const SRT_ECONNREJ: i32 = 1002;
pub(crate) const SRT_ESOCKFAIL: i32 = 1003;
pub(crate) const SRT_ECONNLOST: i32 = 2001;
pub(crate) const SRT_EINVPARAM: i32 = 5003;

pub(crate) fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

pub(crate) fn srt_io_error(fn_name: &'static str, code: i32) -> io::Error {
    io::Error::new(io::ErrorKind::Other, Error::SRTError { fn_name, code, errno: 0 })
}

/// Commands from handles to the I/O thread.
pub(crate) enum Cmd {
    /// The handle of this connection was dropped: close it (one SHUTDOWN).
    Close(u32),
    /// The listener handle was dropped: stop accepting.
    StopListening,
}

/// How handles reach the I/O thread.
pub(crate) struct Ctl {
    waker: MioWaker,
    kicked: AtomicBool,
    cmds: Mutex<Vec<Cmd>>,
}

impl Ctl {
    /// Wake the thread (at most one wake-up syscall until it runs).
    pub fn kick(&self) {
        if !self.kicked.swap(true, Ordering::AcqRel) {
            let _ = self.waker.wake();
        }
    }

    pub fn command(&self, c: Cmd) {
        lock(&self.cmds).push(c);
        self.kicked.store(true, Ordering::Release);
        let _ = self.waker.wake();
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Status {
    Connecting,
    Open,
    /// Closed or failed, with the libsrt error code reads/writes/connect report.
    Closed(i32),
}

pub(crate) struct ConnState {
    pub status: Status,
    pub close_reason: Option<CloseReason>,
    pub rx: VecDeque<Vec<u8>>,
    /// The thread stopped taking messages because `rx` was full.
    pub rx_stalled: bool,
    pub tx: VecDeque<(Instant, Vec<u8>)>,
    /// The connection refused a message (send buffer full) since `tx` was last empty.
    tx_blocked: bool,
    free: Vec<Vec<u8>>,
    pub rx_waker: Option<Waker>,
    pub tx_waker: Option<Waker>,
    pub max_message: usize,
    pub stream_id: Option<String>,
    pub peer: SocketAddr,
    pub stats: Option<Stats>,
    stats_at: Option<Instant>,
}

/// One connection as seen by its handle and by the I/O thread.
pub(crate) struct ConnShared {
    pub ctl: Arc<Ctl>,
    pub id: u32,
    pub st: Mutex<ConnState>,
    pub cv: Condvar,
}

fn set_waker(slot: &mut Option<Waker>, w: &Waker) {
    if !slot.as_ref().map_or(false, |o| o.will_wake(w)) {
        *slot = Some(w.clone());
    }
}

impl ConnShared {
    fn new(ctl: Arc<Ctl>, id: u32, status: Status, peer: SocketAddr, stream_id: Option<String>, max_message: usize) -> Arc<ConnShared> {
        Arc::new(ConnShared {
            ctl,
            id,
            st: Mutex::new(ConnState {
                status,
                close_reason: None,
                rx: VecDeque::new(),
                rx_stalled: false,
                tx: VecDeque::new(),
                tx_blocked: false,
                free: Vec::new(),
                rx_waker: None,
                tx_waker: None,
                max_message,
                stream_id: stream_id.filter(|s| !s.is_empty()),
                peer,
                stats: None,
                stats_at: None,
            }),
            cv: Condvar::new(),
        })
    }

    /// One message into `buf` (truncated if longer, as libsrt live mode).
    /// `None`: nothing yet (the waker, if any, is registered).
    pub fn poll_read(&self, buf: &mut [u8], waker: Option<&Waker>) -> Option<io::Result<usize>> {
        let mut st = lock(&self.st);
        if let Some(m) = st.rx.pop_front() {
            let n = m.len().min(buf.len());
            buf[..n].copy_from_slice(&m[..n]);
            if st.free.len() < FREE_LIMIT {
                st.free.push(m);
            }
            let kick = st.rx_stalled && st.rx.len() <= RX_LIMIT / 2;
            if kick {
                st.rx_stalled = false;
            }
            drop(st);
            if kick {
                self.ctl.kick();
            }
            return Some(Ok(n));
        }
        match st.status {
            Status::Closed(code) => Some(Err(srt_io_error("srt_recv", code))),
            _ => {
                if let Some(w) = waker {
                    set_waker(&mut st.rx_waker, w);
                }
                None
            }
        }
    }

    /// Queue one message (at most `max_message` bytes of `src`).
    pub fn poll_write(&self, src: &[u8], waker: Option<&Waker>) -> Option<io::Result<usize>> {
        let mut st = lock(&self.st);
        match st.status {
            Status::Closed(code) => return Some(Err(srt_io_error("srt_send", code))),
            Status::Connecting => return Some(Err(srt_io_error("srt_send", 2002))),
            Status::Open => {}
        }
        if src.is_empty() {
            return Some(Ok(0));
        }
        if st.tx.len() >= TX_LIMIT {
            if let Some(w) = waker {
                set_waker(&mut st.tx_waker, w);
            }
            return None;
        }
        let n = src.len().min(st.max_message);
        let mut b = st.free.pop().unwrap_or_default();
        b.clear();
        b.extend_from_slice(&src[..n]);
        st.tx.push_back((Instant::now(), b));
        let first = st.tx.len() == 1;
        drop(st);
        if first {
            self.ctl.kick();
        }
        Some(Ok(n))
    }

    /// `None` while connecting.
    pub fn poll_connected(&self, waker: Option<&Waker>) -> Option<Result<()>> {
        let mut st = lock(&self.st);
        match st.status {
            Status::Open => Some(Ok(())),
            Status::Closed(code) => Some(Err(Error::SRTError {
                fn_name: "srt_connect",
                code,
                errno: 0,
            })),
            Status::Connecting => {
                if let Some(w) = waker {
                    set_waker(&mut st.rx_waker, w);
                }
                None
            }
        }
    }

    /// Block until `f` returns `Some`; `ready` says (under the lock) when
    /// `f` may have something, so a wake-up between the two is not lost.
    pub fn wait<T>(&self, mut f: impl FnMut(&Self) -> Option<T>, ready: impl Fn(&ConnState) -> bool) -> T {
        loop {
            if let Some(v) = f(self) {
                return v;
            }
            let st = lock(&self.st);
            if !ready(&st) {
                let _st = self.cv.wait_timeout(st, Duration::from_millis(500)).unwrap_or_else(|e| e.into_inner());
            }
        }
    }

    pub fn stream_id(&self) -> Option<String> {
        lock(&self.st).stream_id.clone()
    }

    pub fn peer(&self) -> SocketAddr {
        lock(&self.st).peer
    }

    pub fn stats(&self) -> Option<Stats> {
        lock(&self.st).stats.clone()
    }

    pub fn close_reason(&self) -> Option<CloseReason> {
        lock(&self.st).close_reason.clone()
    }
}

/// Whether a lingering connection is done: all written data acknowledged.
fn drained(conn: &Connection, sh: &ConnShared) -> bool {
    conn.is_closed() || (lock(&sh.st).tx.is_empty() && conn.send_buffer_len() == 0)
}

/// The handle side of a connection: closes it on drop.
pub(crate) struct ConnHandle {
    pub sh: Arc<ConnShared>,
}

impl Drop for ConnHandle {
    fn drop(&mut self) {
        self.sh.ctl.command(Cmd::Close(self.sh.id));
    }
}

fn close_code(r: &CloseReason, was_open: bool) -> i32 {
    match r {
        _ if was_open => SRT_ECONNLOST,
        CloseReason::ConnectTimeout => SRT_ENOSERVER,
        CloseReason::Rejected(_) | CloseReason::Encrypted => SRT_ECONNREJ,
        _ => SRT_ECONNLOST,
    }
}

/// Move messages between a connection and its handle; true if it closed now.
/// With `lingering` (the handle is gone) received messages are discarded.
fn service(conn: &mut Connection, sh: &ConnShared, now: Instant, lingering: bool) -> bool {
    let mut guard = lock(&sh.st);
    let st = &mut *guard;
    let (mut wake_rx, mut wake_tx) = (false, false);
    while let Some(ev) = conn.poll_event() {
        if ev == Event::Connected && st.status == Status::Connecting {
            st.status = Status::Open;
            st.max_message = conn.max_message();
            wake_rx = true;
            wake_tx = true;
        }
    }
    if conn.is_connected() {
        let mut moved = false;
        while let Some((t, m)) = st.tx.front() {
            let origin = if st.tx_blocked { now } else { *t };
            match conn.send_message(now, m, Some(origin)) {
                Ok(_) | Err(SendError::TooLarge) => {
                    let (_, b) = st.tx.pop_front().expect("front");
                    if st.free.len() < FREE_LIMIT {
                        st.free.push(b);
                    }
                    moved = true;
                }
                Err(_) => {
                    st.tx_blocked = true;
                    break;
                }
            }
        }
        if st.tx.is_empty() {
            st.tx_blocked = false;
        }
        wake_tx |= moved;
    }
    if st.rx.len() < RX_LIMIT {
        st.rx_stalled = false;
        while let Some(m) = conn.recv_message(now) {
            let mut b = st.free.pop().unwrap_or_default();
            b.clear();
            b.extend_from_slice(m.payload);
            st.rx.push_back(b);
            wake_rx = true;
            if st.rx.len() >= RX_LIMIT {
                st.rx_stalled = true;
                break;
            }
        }
    } else {
        st.rx_stalled = true;
    }
    if lingering {
        st.rx.clear();
        st.rx_stalled = false;
        if !conn.is_closed() {
            while conn.recv_message(now).is_some() {}
        }
    }
    let mut closed_now = false;
    if let State::Closed(r) = conn.state().clone() {
        if !matches!(st.status, Status::Closed(_)) {
            // hand over what is buffered, TSBPD-held messages included
            let later = now + Duration::from_secs(3600);
            while let Some(m) = conn.recv_message(later) {
                st.rx.push_back(m.payload.to_vec());
            }
            let code = close_code(&r, st.status == Status::Open);
            st.status = Status::Closed(code);
            st.close_reason = Some(r);
            wake_rx = true;
            wake_tx = true;
            closed_now = true;
        }
    }
    if closed_now || st.stats_at.map_or(true, |t| now.saturating_duration_since(t) >= STATS_EVERY) {
        st.stats = Some(conn.stats().clone());
        st.stats_at = Some(now);
    }
    let rw = if wake_rx { st.rx_waker.take() } else { None };
    let tw = if wake_tx { st.tx_waker.take() } else { None };
    drop(guard);
    if wake_rx || wake_tx {
        sh.cv.notify_all();
    }
    if let Some(w) = rw {
        w.wake();
    }
    if let Some(w) = tw {
        w.wake();
    }
    closed_now
}

fn mark_closed(sh: &ConnShared, r: CloseReason) {
    let mut st = lock(&sh.st);
    if !matches!(st.status, Status::Closed(_)) {
        st.status = Status::Closed(close_code(&r, st.status == Status::Open));
        st.close_reason = Some(r);
    }
    let (rw, tw) = (st.rx_waker.take(), st.tx_waker.take());
    drop(st);
    sh.cv.notify_all();
    if let Some(w) = rw {
        w.wake();
    }
    if let Some(w) = tw {
        w.wake();
    }
}

struct Io {
    poll: Poll,
    events: Events,
    timer: SrtTimer,
    ctl: Arc<Ctl>,
    zero_waits: u32,
}

impl Io {
    fn new() -> io::Result<(Io, Arc<Ctl>)> {
        let poll = Poll::new()?;
        let waker = MioWaker::new(poll.registry(), WAKE)?;
        let mut timer = SrtTimer::new()?;
        poll.registry().register(&mut timer, TIMER, Interest::READABLE)?;
        let ctl = Arc::new(Ctl {
            waker,
            kicked: AtomicBool::new(false),
            cmds: Mutex::new(Vec::new()),
        });
        Ok((
            Io {
                poll,
                events: Events::with_capacity(16),
                timer,
                ctl: ctl.clone(),
                zero_waits: 0,
            },
            ctl,
        ))
    }

    fn take_cmds(&self) -> Vec<Cmd> {
        self.ctl.kicked.store(false, Ordering::Release);
        std::mem::take(&mut *lock(&self.ctl.cmds))
    }

    /// Sleep until `wake` (or a datagram / kick). Returns whether the socket is readable.
    fn wait(&mut self, now: Instant, mut wake: Instant) -> io::Result<bool> {
        if wake <= now {
            // something is due already; never loop hot for long
            self.zero_waits += 1;
            if self.zero_waits < 1000 {
                return Ok(true);
            }
            wake = now + Duration::from_micros(100);
        }
        self.zero_waits = 0;
        self.timer.arm(Some(wake), now)?;
        match self.poll.poll(&mut self.events, Some(wake - now + Duration::from_millis(1))) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::Interrupted => return Ok(true),
            Err(e) => return Err(e),
        }
        let mut readable = false;
        for e in self.events.iter() {
            match e.token() {
                TIMER => self.timer.clear(),
                SOCK => readable = true,
                _ => {}
            }
        }
        Ok(readable)
    }
}

fn soft_io_error(e: &io::Error) -> bool {
    // ICMP errors surface on the next recv of a connected UDP socket
    matches!(
        e.kind(),
        io::ErrorKind::ConnectionRefused | io::ErrorKind::ConnectionReset | io::ErrorKind::Interrupted | io::ErrorKind::WouldBlock
    )
}

// ------------------------------------------------------------------ caller

/// Start a caller connection on its own I/O thread.
pub(crate) fn start_caller(remote: SocketAddr, cfg: Config, opts: UdpOptions) -> Result<ConnHandle> {
    let local: SocketAddr = if remote.is_ipv4() { "0.0.0.0:0".parse().unwrap() } else { "[::]:0".parse().unwrap() };
    let stream_id = cfg.stream_id.clone();
    let max_message = cfg.payload_size;
    let (io, ctl) = Io::new()?;
    let mut sock = SrtSocket::connect(local, remote, cfg, &opts).map_err(|e| Error::SRTError {
        fn_name: "srt_connect",
        code: SRT_ESOCKFAIL,
        errno: e.raw_os_error().unwrap_or(0),
    })?;
    io.poll.registry().register(&mut sock, SOCK, Interest::READABLE)?;
    let sh = ConnShared::new(ctl, sock.connection().local_socket_id(), Status::Connecting, remote, stream_id, max_message);
    let tsh = sh.clone();
    thread::Builder::new()
        .name("srt-rs-caller".into())
        .spawn(move || run_caller(io, sock, tsh))?;
    Ok(ConnHandle { sh })
}

fn run_caller(mut io: Io, mut sock: SrtSocket, sh: Arc<ConnShared>) {
    let mut linger: Option<Instant> = None;
    loop {
        let now = Instant::now();
        for c in io.take_cmds() {
            if let Cmd::Close(_) = c {
                linger.get_or_insert(now + LINGER);
            }
        }
        if let Err(e) = sock.drive_io(now) {
            if !soft_io_error(&e) {
                crate::pure::log_warn(&format!("srt caller I/O error: {e}"));
            }
        }
        service(sock.connection_mut(), &sh, now, linger.is_some());
        if let Err(e) = sock.flush(now) {
            if !soft_io_error(&e) {
                crate::pure::log_warn(&format!("srt caller send error: {e}"));
            }
        }
        if let Some(d) = linger {
            if now >= d || drained(sock.connection(), &sh) {
                let _ = sock.close(now);
                mark_closed(&sh, CloseReason::Local);
                return;
            }
        }
        if sock.connection().is_closed() && sock.pending_datagrams() == 0 {
            // the status (and what was buffered) is with the handle; a
            // later Close command has nothing left to do
            service(sock.connection_mut(), &sh, now, linger.is_some());
            return;
        }
        let mut wake = linger.unwrap_or(now + MAX_SLEEP).min(now + MAX_SLEEP);
        if let Some(t) = sock.poll_timeout() {
            wake = wake.min(if lock(&sh.st).rx_stalled { t.max(now + STALLED_POLL) } else { t });
        }
        if sock.pending_datagrams() > 0 {
            wake = wake.min(now + SEND_RETRY);
        }
        match io.wait(now, wake) {
            Ok(true) => sock.set_readable(),
            Ok(false) => {}
            Err(e) => {
                crate::pure::log_warn(&format!("srt caller poll error: {e}"));
                thread::sleep(Duration::from_millis(1));
            }
        }
    }
}

// ------------------------------------------------------------------ listener

type CallbackSlot = Mutex<Option<Box<dyn ListenerCallback + 'static>>>;

pub(crate) struct ListenerState {
    pub q: VecDeque<(Arc<ConnShared>, SocketAddr)>,
    /// Connections refused for a reason the application should see.
    pub errors: VecDeque<String>,
    pub waker: Option<Waker>,
    /// The I/O thread ended (with why).
    pub dead: Option<String>,
}

pub(crate) struct ListenerShared {
    pub ctl: Arc<Ctl>,
    pub st: Mutex<ListenerState>,
    pub cv: Condvar,
    pub callback: CallbackSlot,
    pub stopped: AtomicBool,
    pub local: SocketAddr,
}

impl ListenerShared {
    /// The next accepted connection, an error to report, or `None` (waker registered).
    pub fn poll_accept(&self, waker: Option<&Waker>) -> Option<Result<(Arc<ConnShared>, SocketAddr)>> {
        let mut st = lock(&self.st);
        if let Some(c) = st.q.pop_front() {
            drop(st);
            self.ctl.kick(); // room in the backlog
            return Some(Ok(c));
        }
        if let Some(e) = st.errors.pop_front() {
            return Some(Err(Error::IOError(io::Error::new(io::ErrorKind::PermissionDenied, e))));
        }
        if st.dead.is_some() {
            return Some(Err(Error::SRTError {
                fn_name: "srt_accept",
                code: SRT_ESOCKFAIL,
                errno: 0,
            }));
        }
        if let Some(w) = waker {
            set_waker(&mut st.waker, w);
        }
        None
    }

    pub fn wait_accept(&self) -> Result<(Arc<ConnShared>, SocketAddr)> {
        loop {
            if let Some(r) = self.poll_accept(None) {
                return r;
            }
            let st = lock(&self.st);
            if st.q.is_empty() && st.errors.is_empty() && st.dead.is_none() {
                let _ = self.cv.wait_timeout(st, Duration::from_millis(50));
            }
        }
    }

    /// Install (or with `None` remove) the application's callback.
    ///
    /// # Safety
    /// The callback must stay valid until it is removed with
    /// `set_callback(None)` (which waits for a call in progress).
    pub unsafe fn set_callback<'c>(&self, cb: Option<Box<dyn ListenerCallback + 'c>>) {
        // SAFETY: (caller) the box is removed before 'c ends; every call
        // runs under this mutex, so after `take` no call is in progress.
        let cb: Option<Box<dyn ListenerCallback + 'static>> = std::mem::transmute(cb);
        let old = std::mem::replace(&mut *lock(&self.callback), cb);
        drop(old);
    }

    fn push_error(&self, e: String) {
        crate::pure::log_warn(&e);
        let mut st = lock(&self.st);
        if st.errors.len() < 64 {
            st.errors.push_back(e);
        }
        let w = st.waker.take();
        drop(st);
        self.cv.notify_all();
        if let Some(w) = w {
            w.wake();
        }
    }
}

/// The listener handle side: stops accepting (and drops the callback) on drop.
pub(crate) struct ListenerHandle {
    pub ls: Arc<ListenerShared>,
}

impl Drop for ListenerHandle {
    fn drop(&mut self) {
        self.ls.stopped.store(true, Ordering::Release);
        // SAFETY: removing is always allowed
        unsafe { self.ls.set_callback(None) };
        self.ls.ctl.command(Cmd::StopListening);
    }
}

/// What the listener's handshake acceptor asks the application's callback.
fn decide(ls: &ListenerShared, rq: &AcceptRequest<'_>) -> std::result::Result<(), RejectReason> {
    if ls.stopped.load(Ordering::Acquire) {
        return Err(RejectReason::Close);
    }
    let guard = lock(&ls.callback);
    let Some(cb) = guard.as_ref() else { return Ok(()) };
    let action = match catch_unwind(AssertUnwindSafe(|| cb.callback(rq.stream_id))) {
        Ok(a) => a,
        Err(_) => {
            drop(guard);
            ls.push_error(format!("srt listener callback panicked for {} (stream id {:?}): rejected", rq.peer, rq.stream_id));
            return Err(RejectReason::Unknown);
        }
    };
    drop(guard);
    match action {
        ListenerCallbackAction::Deny => Err(RejectReason::Unknown),
        ListenerCallbackAction::Allow { passphrase: None } => Ok(()),
        ListenerCallbackAction::Allow { passphrase: Some(_) } => {
            ls.push_error(format!(
                "srt connection from {} (stream id {:?}) refused: the listener callback requires a passphrase (AES encryption), \
                 which this wavey-srt pure-rust build does not support; it is never run unencrypted",
                rq.peer, rq.stream_id
            ));
            Err(RejectReason::Unsecure)
        }
    }
}

pub(crate) fn start_listener(addr: SocketAddr, cfg: Config, opts: UdpOptions) -> Result<ListenerHandle> {
    let (io, ctl) = Io::new()?;
    let mut l = SrtListener::bind(addr, cfg, &opts).map_err(|e| Error::SRTError {
        fn_name: "srt_bind",
        code: SRT_ESOCKFAIL,
        errno: e.raw_os_error().unwrap_or(0),
    })?;
    l.set_backlog(BACKLOG);
    io.poll.registry().register(&mut l, SOCK, Interest::READABLE)?;
    let local = l.local_addr()?;
    let ls = Arc::new(ListenerShared {
        ctl,
        st: Mutex::new(ListenerState {
            q: VecDeque::new(),
            errors: VecDeque::new(),
            waker: None,
            dead: None,
        }),
        cv: Condvar::new(),
        callback: Mutex::new(None),
        stopped: AtomicBool::new(false),
        local,
    });
    let cb_ls = ls.clone();
    l.set_accept_callback(Some(Box::new(move |rq: &AcceptRequest<'_>| decide(&cb_ls, rq))));
    let tls = ls.clone();
    let mut io = io;
    thread::Builder::new().name("srt-rs-listener".into()).spawn(move || {
        let r = catch_unwind(AssertUnwindSafe(|| run_listener(&mut io, &mut l, &tls)));
        let why = match r {
            Ok(()) => "stopped".to_string(),
            Err(_) => "panicked".to_string(),
        };
        // the callback closure (in `l`) holds the shared state: break the cycle
        l.set_accept_callback(None);
        let mut st = lock(&tls.st);
        st.dead = Some(why);
        let w = st.waker.take();
        drop(st);
        tls.cv.notify_all();
        if let Some(w) = w {
            w.wake();
        }
    })?;
    Ok(ListenerHandle { ls })
}

fn run_listener(io: &mut Io, l: &mut SrtListener, ls: &Arc<ListenerShared>) {
    // connections handed to the application (or queued for accept())
    let mut conns: HashMap<u32, Arc<ConnShared>> = HashMap::new();
    // dropped handles whose connection still sends: id -> deadline
    let mut lingering: HashMap<u32, Instant> = HashMap::new();
    let mut stopped = false;
    loop {
        let now = Instant::now();
        for c in io.take_cmds() {
            match c {
                Cmd::Close(id) => {
                    if l.connection(id).is_some() {
                        lingering.entry(id).or_insert(now + LINGER);
                    } else if let Some(sh) = conns.remove(&id) {
                        mark_closed(&sh, CloseReason::Local);
                    }
                }
                Cmd::StopListening => stopped = true,
            }
        }
        if stopped {
            // close what was accepted but never taken
            let queued: Vec<_> = lock(&ls.st).q.drain(..).collect();
            for (sh, _) in queued {
                conns.remove(&sh.id);
                let _ = l.close(sh.id, now);
                l.remove(sh.id);
                mark_closed(&sh, CloseReason::Local);
            }
            while let Some(id) = l.accept() {
                let _ = l.close(id, now);
                l.remove(id);
            }
        }
        if let Err(e) = l.drive_io(now) {
            if !soft_io_error(&e) {
                crate::pure::log_warn(&format!("srt listener I/O error: {e}"));
            }
        }
        if !stopped {
            let mut new = Vec::new();
            {
                let st = lock(&ls.st);
                let mut room = BACKLOG.saturating_sub(st.q.len());
                drop(st);
                while room > 0 {
                    let Some(id) = l.accept() else { break };
                    let Some(c) = l.connection(id) else { continue };
                    let sh = ConnShared::new(
                        io.ctl.clone(),
                        id,
                        Status::Open,
                        c.peer_addr(),
                        c.stream_id().map(str::to_string),
                        c.max_message(),
                    );
                    conns.insert(id, sh.clone());
                    new.push((sh, c.peer_addr()));
                    room -= 1;
                }
            }
            if !new.is_empty() {
                let mut st = lock(&ls.st);
                st.q.extend(new);
                let w = st.waker.take();
                drop(st);
                ls.cv.notify_all();
                if let Some(w) = w {
                    w.wake();
                }
            }
        }
        let mut gone = Vec::new();
        for (id, sh) in &conns {
            if let Some(c) = l.connection_mut(*id) {
                if service(c, sh, now, lingering.contains_key(id)) {
                    gone.push(*id);
                }
            }
        }
        for id in gone {
            // closed by the peer (or idle): free it now; the handle keeps
            // the status and buffered messages until it is dropped
            l.remove(id);
        }
        let done: Vec<u32> = lingering
            .iter()
            .filter(|(id, d)| {
                now >= **d
                    || match (l.connection(**id), conns.get(*id)) {
                        (Some(c), Some(sh)) => drained(c, sh),
                        _ => true,
                    }
            })
            .map(|(id, _)| *id)
            .collect();
        for id in done {
            lingering.remove(&id);
            let _ = l.close(id, now);
            l.remove(id);
            if let Some(sh) = conns.remove(&id) {
                mark_closed(&sh, CloseReason::Local);
            }
        }
        if let Err(e) = l.flush(now) {
            if !soft_io_error(&e) {
                crate::pure::log_warn(&format!("srt listener send error: {e}"));
            }
        }
        if stopped && conns.is_empty() && l.pending_datagrams() == 0 {
            return;
        }
        // next deadline: a connection whose reader is behind (or one not
        // yet accepted) may have a delivery due that nobody takes
        let mut wake = now + MAX_SLEEP;
        for d in lingering.values() {
            wake = wake.min(*d);
        }
        for &id in l.connection_ids() {
            let Some(c) = l.connection(id) else { continue };
            let Some(t) = c.poll_timeout() else { continue };
            let held = match conns.get(&id) {
                Some(sh) => lock(&sh.st).rx_stalled,
                None => true,
            };
            wake = wake.min(if held { t.max(now + STALLED_POLL) } else { t });
        }
        if l.pending_datagrams() > 0 {
            wake = wake.min(now + SEND_RETRY);
        }
        match io.wait(now, wake) {
            Ok(true) => l.set_readable(),
            Ok(false) => {}
            Err(e) => {
                crate::pure::log_warn(&format!("srt listener poll error: {e}"));
                thread::sleep(Duration::from_millis(1));
            }
        }
    }
}
