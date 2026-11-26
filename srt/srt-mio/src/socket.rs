//! SRT caller on one connected UDP socket.

use crate::batch::{RecvBatch, SendBatch};
use crate::UdpOptions;
use mio::event::Source;
use mio::{Interest, Registry, Token};
use srt_core::{Config, Connection, Delivered, SendError};
use std::io;
use std::net::SocketAddr;
use std::os::unix::io::AsRawFd;
use std::time::{Duration, Instant};

/// Datagrams read per `drive` before returning (so sends are not starved).
const MAX_RECV_PER_DRIVE: usize = 1024;

pub struct SrtSocket {
    sock: mio::net::UdpSocket,
    conn: Connection,
    rx: RecvBatch,
    tx: SendBatch,
    remote: SocketAddr,
    /// Effective SO_RCVBUF / SO_SNDBUF.
    pub udp_buffers: (usize, usize),
    /// recvmmsg calls and datagrams.
    pub recv_calls: u64,
    pub recv_datagrams: u64,
    /// The socket may hold unread datagrams (edge-triggered readiness).
    may_read: bool,
}

pub(crate) fn udp_socket(bind: SocketAddr, opts: &UdpOptions) -> io::Result<(std::net::UdpSocket, (usize, usize))> {
    use socket2::{Domain, Protocol, Socket, Type};
    let s = Socket::new(Domain::for_address(bind), Type::DGRAM, Some(Protocol::UDP))?;
    if let Some(n) = opts.recv_buffer {
        let _ = s.set_recv_buffer_size(n);
    }
    if let Some(n) = opts.send_buffer {
        let _ = s.set_send_buffer_size(n);
    }
    // only for a fixed port: with SO_REUSEADDR on an ephemeral bind (port
    // 0) Linux may hand out a UDP port another SO_REUSEADDR socket already
    // has; two callers to the same listener from one port then get each
    // other's datagrams (one never connects)
    if opts.reuse_address && bind.port() != 0 {
        s.set_reuse_address(true)?;
    }
    s.set_nonblocking(true)?;
    s.bind(&bind.into())?;
    let bufs = (s.recv_buffer_size().unwrap_or(0), s.send_buffer_size().unwrap_or(0));
    Ok((s.into(), bufs))
}

impl SrtSocket {
    /// Start a caller handshake from `local` to `remote` (non-blocking;
    /// it completes as `drive` is called). Use `0.0.0.0:0` for any local.
    pub fn connect(local: SocketAddr, remote: SocketAddr, cfg: Config, opts: &UdpOptions) -> io::Result<SrtSocket> {
        cfg.validate().map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
        let (s, udp_buffers) = udp_socket(local, opts)?;
        s.connect(remote)?;
        let now = Instant::now();
        let conn = Connection::connect(cfg, now, remote, srt_core::random_socket_id(), srt_core::random_isn());
        let mut me = SrtSocket {
            sock: mio::net::UdpSocket::from_std(s),
            conn,
            rx: RecvBatch::new(),
            tx: SendBatch::new(),
            remote,
            udp_buffers,
            recv_calls: 0,
            recv_datagrams: 0,
            may_read: true,
        };
        me.flush(now)?;
        Ok(me)
    }

    /// Connect and wait (own poll loop) until connected, rejected or timed out.
    pub fn connect_blocking(local: SocketAddr, remote: SocketAddr, cfg: Config, opts: &UdpOptions) -> io::Result<SrtSocket> {
        let mut s = SrtSocket::connect(local, remote, cfg, opts)?;
        let mut poll = mio::Poll::new()?;
        let mut ev = mio::Events::with_capacity(8);
        poll.registry().register(&mut s, Token(0), Interest::READABLE)?;
        loop {
            let now = Instant::now();
            s.drive(now)?;
            if s.conn.is_connected() {
                break;
            }
            if let srt_core::State::Closed(r) = s.conn.state() {
                return Err(io::Error::new(io::ErrorKind::ConnectionRefused, format!("srt connect {remote}: {r:?}")));
            }
            let wait = s.poll_timeout().map(|t| t.saturating_duration_since(now) + Duration::from_micros(100));
            poll.poll(&mut ev, wait)?;
        }
        poll.registry().deregister(&mut s)?;
        Ok(s)
    }

    pub fn connection(&self) -> &Connection {
        &self.conn
    }

    pub fn connection_mut(&mut self) -> &mut Connection {
        &mut self.conn
    }

    pub fn remote_addr(&self) -> SocketAddr {
        self.remote
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.sock.local_addr()
    }

    pub fn is_connected(&self) -> bool {
        self.conn.is_connected()
    }

    pub fn send_batch(&self) -> &SendBatch {
        &self.tx
    }

    pub fn recv_batch(&self) -> &RecvBatch {
        &self.rx
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
    /// since it was last drained (saves a recvmmsg per timer wake-up).
    pub fn drive_io(&mut self, now: Instant) -> io::Result<()> {
        if self.may_read {
            self.recv(now)?;
        }
        if self.conn.poll_timeout().map_or(false, |t| t <= now) {
            self.conn.handle_timeout(now);
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
                if let Some(from) = from {
                    self.conn.handle_datagram(now, from, d);
                }
            }
            total += n;
            self.recv_datagrams += n as u64;
            if n < crate::batch::BATCH {
                // drained: the next datagram raises a new readiness edge
                self.may_read = false;
                break;
            }
        }
        if total == 0 {
            self.may_read = false;
        }
        Ok(())
    }

    /// Move what the connection wants to send into the batch and send it.
    /// Returns with data still queued if the socket would block.
    pub fn flush(&mut self, now: Instant) -> io::Result<()> {
        let fd = self.sock.as_raw_fd();
        loop {
            while let Some(slot) = self.tx.slot() {
                match self.conn.poll_transmit(now, slot) {
                    Some(t) => self.tx.commit(t.len, None),
                    None => break,
                }
            }
            let full = self.tx.is_full();
            if !self.tx.flush(fd)? {
                return Ok(()); // would block: wait for WRITABLE
            }
            if !full {
                return Ok(());
            }
        }
    }

    /// Queue one message; call `flush` (or `drive`) to send it.
    pub fn send(&mut self, now: Instant, msg: &[u8]) -> Result<u32, SendError> {
        self.conn.send_message(now, msg, None)
    }

    /// Hand every message due by `now` to `f`; returns how many.
    pub fn recv_with<F: FnMut(&Delivered<'_>)>(&mut self, now: Instant, mut f: F) -> usize {
        let mut n = 0;
        while let Some(m) = self.conn.recv_message(now) {
            f(&m);
            n += 1;
        }
        n
    }

    /// When the next `drive` is needed (timers, pacing, delivery).
    pub fn poll_timeout(&self) -> Option<Instant> {
        self.conn.poll_timeout()
    }

    /// Datagrams queued in the batch because the socket would block.
    pub fn pending_datagrams(&self) -> usize {
        self.tx.pending()
    }

    /// Close (one SHUTDOWN if connected) and flush.
    pub fn close(&mut self, now: Instant) -> io::Result<()> {
        self.conn.close(now);
        self.flush(now)
    }
}

impl Source for SrtSocket {
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
