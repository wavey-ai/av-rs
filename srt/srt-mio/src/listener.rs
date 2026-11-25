//! SRT listener: one UDP socket, connections demultiplexed by destination
//! socket ID (0 goes to the handshake acceptor).

use crate::batch::{RecvBatch, SendBatch};
use crate::socket::udp_socket;
use crate::UdpOptions;
use mio::event::Source;
use mio::{Interest, Registry, Token};
use srt_core::packet::dst_socket_id;
use srt_core::{AcceptCallback, Config, Connection, Delivered, Listener, ListenerAction, SendError};
use std::collections::{HashMap, VecDeque};
use std::io;
use std::net::SocketAddr;
use std::os::unix::io::AsRawFd;
use std::time::Instant;

const MAX_RECV_PER_DRIVE: usize = 1024;

pub struct SrtListener {
    sock: mio::net::UdpSocket,
    acceptor: Listener,
    conns: HashMap<u32, Connection>,
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
    may_read: bool,
}

impl SrtListener {
    pub fn bind(addr: SocketAddr, cfg: Config, opts: &UdpOptions) -> io::Result<SrtListener> {
        cfg.validate().map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
        let (s, udp_buffers) = udp_socket(addr, opts)?;
        Ok(SrtListener {
            sock: mio::net::UdpSocket::from_std(s),
            acceptor: Listener::new(cfg, Instant::now()),
            conns: HashMap::new(),
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
            may_read: true,
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
        self.conns.get(&id)
    }

    pub fn connection_mut(&mut self, id: u32) -> Option<&mut Connection> {
        self.conns.get_mut(&id)
    }

    pub fn connection_ids(&self) -> &[u32] {
        &self.order
    }

    /// Forget a connection (after reading its final stats).
    pub fn remove(&mut self, id: u32) -> Option<Connection> {
        self.acceptor.remove(id);
        self.order.retain(|&x| x != id);
        self.accept_q.retain(|&x| x != id);
        self.conns.remove(&id)
    }

    pub fn send(&mut self, id: u32, now: Instant, msg: &[u8]) -> Result<u32, SendError> {
        self.conns.get_mut(&id).ok_or(SendError::NotConnected)?.send_message(now, msg, None)
    }

    pub fn recv_with<F: FnMut(&Delivered<'_>)>(&mut self, id: u32, now: Instant, mut f: F) -> usize {
        let Some(c) = self.conns.get_mut(&id) else { return 0 };
        let mut n = 0;
        while let Some(m) = c.recv_message(now) {
            f(&m);
            n += 1;
        }
        n
    }

    pub fn close(&mut self, id: u32, now: Instant) -> io::Result<()> {
        if let Some(c) = self.conns.get_mut(&id) {
            c.close(now);
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
        for c in self.conns.values_mut() {
            if c.poll_timeout().map_or(false, |t| t <= now) {
                c.handle_timeout(now);
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
                            self.conns.insert(id, *c);
                            self.order.push(id);
                            self.accept_q.push_back(id);
                            self.acceptor.set_backlog_full(self.accept_q.len() >= self.backlog);
                        }
                        ListenerAction::Existing(id) => {
                            if let Some(c) = self.conns.get_mut(&id) {
                                c.handle_datagram(now, from, d);
                            }
                        }
                        ListenerAction::Ignore => {}
                    }
                } else if let Some(c) = self.conns.get_mut(&dst) {
                    c.handle_datagram(now, from, d);
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
        Ok(())
    }

    /// Send what every connection has due.
    pub fn flush(&mut self, now: Instant) -> io::Result<()> {
        let fd = self.sock.as_raw_fd();
        for id in &self.order {
            let Some(c) = self.conns.get_mut(id) else { continue };
            let dst = c.peer_addr();
            loop {
                if self.tx.is_full() && !self.tx.flush(fd)? {
                    return Ok(()); // would block
                }
                let Some(slot) = self.tx.slot() else { break };
                match c.poll_transmit(now, slot) {
                    Some(t) => self.tx.commit(t.len, Some(&dst)),
                    None => break,
                }
            }
        }
        self.tx.flush(fd)?;
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

    /// Earliest timer of any connection.
    pub fn poll_timeout(&self) -> Option<Instant> {
        self.conns.values().filter_map(|c| c.poll_timeout()).min()
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
