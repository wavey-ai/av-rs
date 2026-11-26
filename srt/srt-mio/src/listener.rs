//! SRT listener: one UDP socket, connections demultiplexed by destination
//! socket ID (0 goes to the handshake acceptor).
//!
//! Timers: each connection's `poll_timeout` is cached in a min-heap (lazy
//! deletion: an entry counts only while it equals the connection's cached
//! deadline). A connection is *dirty* once anything may have changed its
//! deadline or given it something to send (a datagram for it, its timer,
//! a call through `send`, `recv_with`, `close`, `connection_mut`); `drive_io`
//! runs the due timers from the heap, flushes only dirty connections and
//! re-files their deadlines. A wake-up costs O(dirty + due x log n), not
//! O(connections).

use crate::batch::{RecvBatch, SendBatch};
use crate::socket::udp_socket;
use crate::UdpOptions;
use mio::event::Source;
use mio::{Interest, Registry, Token};
use srt_core::packet::dst_socket_id;
use srt_core::{AcceptCallback, Config, Connection, Delivered, Listener, ListenerAction, SendError};
use std::cmp::Reverse;
use std::collections::{BinaryHeap, HashMap, VecDeque};
use std::io;
use std::net::SocketAddr;
use std::os::unix::io::AsRawFd;
use std::time::Instant;

const MAX_RECV_PER_DRIVE: usize = 1024;

struct Slot {
    conn: Connection,
    /// The deadline filed in the heap (None: no timer).
    due: Option<Instant>,
    dirty: bool,
}

pub struct SrtListener {
    sock: mio::net::UdpSocket,
    acceptor: Listener,
    conns: HashMap<u32, Slot>,
    /// (deadline, connection id), earliest first; stale entries are skipped.
    timers: BinaryHeap<Reverse<(Instant, u32)>>,
    /// Connections whose deadline or output may have changed since `drive_io`.
    dirty: Vec<u32>,
    order: Vec<u32>,
    accept_q: VecDeque<u32>,
    backlog: usize,
    rx: RecvBatch,
    tx: SendBatch,
    scratch: Vec<u8>,
    pub udp_buffers: (usize, usize),
    /// Datagrams for unknown socket IDs.
    pub unknown_dst: u64,
    pub recv_calls: u64,
    pub recv_datagrams: u64,
    /// Datagrams read by the last `drive_io` that read the socket.
    pub last_read: usize,
    /// Coalescing pauses taken (`coalesce_delay` returned Some).
    pub coalesce_pauses: u64,
    may_read: bool,
    /// The last read stopped at MAX_RECV_PER_DRIVE with datagrams left:
    /// `poll_timeout` returns this (past) time so the next drive comes at
    /// once (no new readiness edge will come for them).
    read_backlog: Option<Instant>,
}

impl SrtListener {
    pub fn bind(addr: SocketAddr, cfg: Config, opts: &UdpOptions) -> io::Result<SrtListener> {
        cfg.validate().map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
        let (s, udp_buffers) = udp_socket(addr, opts)?;
        Ok(SrtListener {
            sock: mio::net::UdpSocket::from_std(s),
            acceptor: Listener::new(cfg, Instant::now()),
            conns: HashMap::new(),
            timers: BinaryHeap::new(),
            dirty: Vec::new(),
            order: Vec::new(),
            accept_q: VecDeque::new(),
            backlog: 64,
            rx: RecvBatch::new(),
            tx: SendBatch::new(),
            scratch: vec![0u8; crate::batch::SEND_SLOT],
            udp_buffers,
            unknown_dst: 0,
            recv_calls: 0,
            recv_datagrams: 0,
            last_read: 0,
            coalesce_pauses: 0,
            may_read: true,
            read_backlog: None,
        })
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.sock.local_addr()
    }

    pub fn set_accept_callback(&mut self, cb: Option<AcceptCallback>) {
        self.acceptor.set_accept_callback(cb);
    }

    /// Accepted-but-not-yet-`accept()`ed connections allowed before BACKLOG rejections.
    pub fn set_backlog(&mut self, n: usize) {
        self.backlog = n.max(1);
    }

    pub fn acceptor(&self) -> &Listener {
        &self.acceptor
    }

    /// The next newly connected connection's id.
    pub fn accept(&mut self) -> Option<u32> {
        let id = self.accept_q.pop_front();
        self.acceptor.set_backlog_full(self.accept_q.len() >= self.backlog);
        id
    }

    pub fn connection(&self, id: u32) -> Option<&Connection> {
        self.conns.get(&id).map(|s| &s.conn)
    }

    /// Mutable access marks the connection dirty (its timers are re-read
    /// and its output flushed on the next `drive_io`/`flush`).
    pub fn connection_mut(&mut self, id: u32) -> Option<&mut Connection> {
        let s = self.conns.get_mut(&id)?;
        mark(&mut self.dirty, id, s);
        Some(&mut s.conn)
    }

    pub fn connection_ids(&self) -> &[u32] {
        &self.order
    }

    /// Forget a connection (after reading its final stats).
    pub fn remove(&mut self, id: u32) -> Option<Connection> {
        self.acceptor.remove(id);
        self.order.retain(|&x| x != id);
        self.accept_q.retain(|&x| x != id);
        self.dirty.retain(|&x| x != id);
        self.conns.remove(&id).map(|s| s.conn)
    }

    pub fn send(&mut self, id: u32, now: Instant, msg: &[u8]) -> Result<u32, SendError> {
        let s = self.conns.get_mut(&id).ok_or(SendError::NotConnected)?;
        mark(&mut self.dirty, id, s);
        s.conn.send_message(now, msg, None)
    }

    pub fn recv_with<F: FnMut(&Delivered<'_>)>(&mut self, id: u32, now: Instant, mut f: F) -> usize {
        let Some(s) = self.conns.get_mut(&id) else { return 0 };
        // reading may drop too-late packets and so move the deadline even
        // when nothing is delivered
        mark(&mut self.dirty, id, s);
        let mut n = 0;
        while let Some(m) = s.conn.recv_message(now) {
            f(&m);
            n += 1;
        }
        n
    }

    pub fn close(&mut self, id: u32, now: Instant) -> io::Result<()> {
        if let Some(s) = self.conns.get_mut(&id) {
            mark(&mut self.dirty, id, s);
            s.conn.close(now);
        }
        self.flush(now)
    }

    /// Read what the socket has, run due timers, send what is due.
    pub fn drive(&mut self, now: Instant) -> io::Result<()> {
        self.may_read = true;
        self.drive_io(now)
    }

    /// Mark the socket readable (its mio token fired).
    pub fn set_readable(&mut self) {
        self.may_read = true;
    }

    /// As `drive`, but reads the socket only if it was marked readable
    /// since it was last drained.
    pub fn drive_io(&mut self, now: Instant) -> io::Result<()> {
        if self.may_read {
            self.recv(now)?;
        }
        while let Some(&Reverse((t, id))) = self.timers.peek() {
            if t > now {
                break;
            }
            self.timers.pop();
            let Some(s) = self.conns.get_mut(&id) else { continue };
            if s.due != Some(t) {
                continue; // stale: re-filed since
            }
            s.due = None;
            mark(&mut self.dirty, id, s);
        }
        // every dirty connection: its timers if due, then (in flush) its output
        for &id in &self.dirty {
            if let Some(s) = self.conns.get_mut(&id) {
                if s.conn.poll_timeout().map_or(false, |t| t <= now) {
                    s.conn.handle_timeout(now);
                }
            }
        }
        self.flush(now)
    }

    fn recv(&mut self, now: Instant) -> io::Result<()> {
        let fd = self.sock.as_raw_fd();
        let mut total = 0;
        while total < MAX_RECV_PER_DRIVE {
            let n = self.rx.recv(fd)?;
            self.recv_calls += 1;
            if n == 0 {
                self.may_read = false;
                break;
            }
            for i in 0..n {
                let (d, from) = self.rx.get(i);
                let (Some(from), Some(dst)) = (from, dst_socket_id(d)) else { continue };
                if dst == 0 {
                    match self.acceptor.handle(now, from, d, &mut self.scratch) {
                        ListenerAction::Reply(len) => {
                            if self.tx.is_full() {
                                self.tx.flush(fd)?;
                            }
                            if let Some(slot) = self.tx.slot() {
                                slot[..len].copy_from_slice(&self.scratch[..len]);
                                self.tx.commit(len, Some(&from));
                            }
                        }
                        ListenerAction::Accept(c) => {
                            let id = c.local_socket_id();
                            self.conns.insert(id, Slot { conn: *c, due: None, dirty: true });
                            self.dirty.push(id);
                            self.order.push(id);
                            self.accept_q.push_back(id);
                            self.acceptor.set_backlog_full(self.accept_q.len() >= self.backlog);
                        }
                        ListenerAction::Existing(id) => {
                            if let Some(s) = self.conns.get_mut(&id) {
                                mark(&mut self.dirty, id, s);
                                s.conn.handle_datagram(now, from, d);
                            }
                        }
                        ListenerAction::Ignore => {}
                    }
                } else if let Some(s) = self.conns.get_mut(&dst) {
                    mark(&mut self.dirty, dst, s);
                    s.conn.handle_datagram(now, from, d);
                } else {
                    self.unknown_dst += 1;
                }
            }
            total += n;
            self.recv_datagrams += n as u64;
            if n < crate::batch::BATCH {
                self.may_read = false;
                break;
            }
        }
        self.last_read = total;
        self.read_backlog = self.may_read.then_some(now);
        Ok(())
    }

    /// Read coalescing for a peer that paces packet by packet (libsrt
    /// sends each packet on its own): after a small read (< `min_batch`
    /// datagrams), wait `delay` before the next poll, so the next
    /// `recvmmsg` takes a batch instead of one wake-up per 1-3 packets.
    /// `delay` = min(SRTT / 16, `max`), SRTT the smallest of the
    /// connections with an RTT sample (deterministic, and the pause stays
    /// short for the tightest one); None when that is zero, when a timer is
    /// due before it ends, when datagrams are queued to send, or when the
    /// last read left datagrams in the socket. The pause delays only
    /// reading (ACKs and NAKs by <= SRTT / 16); TSBPD delivery and timers
    /// keep their times. Call after `drive_io`, before polling; sleep the
    /// returned duration.
    pub fn coalesce_delay(&mut self, now: Instant, min_batch: usize, max: std::time::Duration) -> Option<std::time::Duration> {
        if self.last_read == 0 || self.last_read >= min_batch || self.tx.pending() > 0 || self.read_backlog.is_some() {
            return None;
        }
        let rtt = self.conns.values().map(|s| s.conn.rtt_us()).filter(|r| r.1).map(|r| r.0).min()?;
        let d = std::time::Duration::from_micros(rtt as u64 / 16).min(max);
        if d.is_zero() || self.poll_timeout().map_or(false, |t| t <= now + d) {
            return None;
        }
        self.last_read = 0;
        self.coalesce_pauses += 1;
        Some(d)
    }

    /// Send what the dirty connections have due (a connection whose pacer
    /// holds data back has that in its deadline), then re-file their
    /// deadlines. On EAGAIN the rest stay dirty for the next call.
    pub fn flush(&mut self, now: Instant) -> io::Result<()> {
        let fd = self.sock.as_raw_fd();
        let mut done = 0;
        let mut blocked = false;
        'conns: for &id in &self.dirty {
            if let Some(s) = self.conns.get_mut(&id) {
                let dst = s.conn.peer_addr();
                loop {
                    if self.tx.is_full() && !self.tx.flush(fd)? {
                        blocked = true; // would block: this one and the rest stay dirty
                        break 'conns;
                    }
                    let Some(slot) = self.tx.slot() else { break };
                    match s.conn.poll_transmit(now, slot) {
                        Some(t) => self.tx.commit(t.len, Some(&dst)),
                        None => break,
                    }
                }
                s.dirty = false;
                let due = s.conn.poll_timeout();
                if due != s.due {
                    s.due = due;
                    if let Some(t) = due {
                        self.timers.push(Reverse((t, id)));
                    }
                }
            }
            done += 1;
        }
        self.dirty.drain(..done);
        if !blocked {
            self.tx.flush(fd)?;
        }
        // drop stale heap tops so `poll_timeout` can peek
        while let Some(&Reverse((t, id))) = self.timers.peek() {
            match self.conns.get(&id) {
                Some(s) if s.due == Some(t) => break,
                _ => {
                    self.timers.pop();
                }
            }
        }
        // a heap of mostly stale entries keeps only the live deadlines (in
        // place: no allocation)
        if self.timers.len() > 64 + 4 * self.conns.len() {
            let conns = &self.conns;
            self.timers.retain(|Reverse((t, id))| conns.get(id).map_or(false, |s| s.due == Some(*t)));
        }
        Ok(())
    }

    pub fn pending_datagrams(&self) -> usize {
        self.tx.pending()
    }

    pub fn send_batch(&self) -> &SendBatch {
        &self.tx
    }

    pub fn recv_batch(&self) -> &RecvBatch {
        &self.rx
    }

    /// Earliest timer of any connection: the heap's top (valid after
    /// `drive_io`/`flush`), or now-ish for a connection touched since (dirty
    /// ones are read directly); the last drive's time when its read left
    /// datagrams in the socket.
    pub fn poll_timeout(&self) -> Option<Instant> {
        let mut t = self.timers.peek().map(|r| r.0 .0);
        if let Some(b) = self.read_backlog {
            t = Some(t.map_or(b, |x| x.min(b)));
        }
        for id in &self.dirty {
            if let Some(d) = self.conns.get(id).and_then(|s| s.conn.poll_timeout()) {
                t = Some(t.map_or(d, |x| x.min(d)));
            }
        }
        t
    }

    /// Connections with a filed timer (for tests and stats).
    pub fn timer_entries(&self) -> usize {
        self.timers.len()
    }
}

#[inline]
fn mark(dirty: &mut Vec<u32>, id: u32, s: &mut Slot) {
    if !s.dirty {
        s.dirty = true;
        dirty.push(id);
    }
}

impl Source for SrtListener {
    fn register(&mut self, r: &Registry, t: Token, i: Interest) -> io::Result<()> {
        self.sock.register(r, t, i)
    }
    fn reregister(&mut self, r: &Registry, t: Token, i: Interest) -> io::Result<()> {
        self.sock.reregister(r, t, i)
    }
    fn deregister(&mut self, r: &Registry) -> io::Result<()> {
        self.sock.deregister(r)
    }
}
