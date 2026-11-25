//! `recvmmsg` / `sendmmsg` batches with preallocated buffers.

use std::io;
use std::mem;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::os::unix::io::RawFd;

/// A zero-initialised plain C struct (sockaddr_storage, iovec, mmsghdr,
/// itimerspec): all-zero is a valid value for each of them.
pub(crate) fn zeroed_c<T: Copy>() -> T {
    unsafe { mem::MaybeUninit::<T>::zeroed().assume_init() }
}

/// Datagrams per system call.
pub const BATCH: usize = 64;
/// Receive slot: larger than any SRT datagram, so truncation is detectable.
const RECV_SLOT: usize = 2048;
/// Send slot: one SRT datagram.
pub const SEND_SLOT: usize = 1500;

pub(crate) fn to_sockaddr(a: &SocketAddr) -> (libc::sockaddr_storage, libc::socklen_t) {
    let mut ss: libc::sockaddr_storage = zeroed_c();
    let len = match a {
        SocketAddr::V4(v4) => {
            let sin = libc::sockaddr_in {
                sin_family: libc::AF_INET as libc::sa_family_t,
                sin_port: v4.port().to_be(),
                sin_addr: libc::in_addr {
                    s_addr: u32::from_ne_bytes(v4.ip().octets()),
                },
                sin_zero: [0; 8],
            };
            unsafe { std::ptr::write(&mut ss as *mut _ as *mut libc::sockaddr_in, sin) };
            mem::size_of::<libc::sockaddr_in>()
        }
        SocketAddr::V6(v6) => {
            let sin6 = libc::sockaddr_in6 {
                sin6_family: libc::AF_INET6 as libc::sa_family_t,
                sin6_port: v6.port().to_be(),
                sin6_flowinfo: v6.flowinfo(),
                sin6_addr: libc::in6_addr { s6_addr: v6.ip().octets() },
                sin6_scope_id: v6.scope_id(),
            };
            unsafe { std::ptr::write(&mut ss as *mut _ as *mut libc::sockaddr_in6, sin6) };
            mem::size_of::<libc::sockaddr_in6>()
        }
    };
    (ss, len as libc::socklen_t)
}

pub(crate) fn from_sockaddr(ss: &libc::sockaddr_storage) -> Option<SocketAddr> {
    match ss.ss_family as libc::c_int {
        libc::AF_INET => {
            let sin = unsafe { &*(ss as *const _ as *const libc::sockaddr_in) };
            let ip = Ipv4Addr::from(sin.sin_addr.s_addr.to_ne_bytes());
            Some(SocketAddr::V4(SocketAddrV4::new(ip, u16::from_be(sin.sin_port))))
        }
        libc::AF_INET6 => {
            let sin6 = unsafe { &*(ss as *const _ as *const libc::sockaddr_in6) };
            let ip = Ipv6Addr::from(sin6.sin6_addr.s6_addr);
            Some(SocketAddr::V6(SocketAddrV6::new(
                ip,
                u16::from_be(sin6.sin6_port),
                sin6.sin6_flowinfo,
                sin6.sin6_scope_id,
            )))
        }
        _ => None,
    }
}

/// A batch of received datagrams.
pub struct RecvBatch {
    bufs: Vec<u8>,
    addrs: Vec<libc::sockaddr_storage>,
    iovs: Vec<libc::iovec>,
    hdrs: Vec<libc::mmsghdr>,
    lens: Vec<usize>,
    from: Vec<Option<SocketAddr>>,
    count: usize,
    /// Datagrams dropped because they were larger than a slot.
    pub truncated: u64,
}

// The raw pointers in `iovs`/`hdrs` only ever point into the batch's own
// heap buffers (re-set before each call), so moving a batch between threads
// is sound.
unsafe impl Send for RecvBatch {}

impl Default for RecvBatch {
    fn default() -> Self {
        Self::new()
    }
}

impl RecvBatch {
    pub fn new() -> RecvBatch {
        RecvBatch {
            bufs: vec![0u8; BATCH * RECV_SLOT],
            addrs: vec![zeroed_c(); BATCH],
            iovs: vec![
                libc::iovec {
                    iov_base: std::ptr::null_mut(),
                    iov_len: 0
                };
                BATCH
            ],
            hdrs: vec![zeroed_c(); BATCH],
            lens: vec![0; BATCH],
            from: vec![None; BATCH],
            count: 0,
            truncated: 0,
        }
    }

    /// Receive up to `BATCH` datagrams; `Ok(0)` when the socket is empty.
    pub fn recv(&mut self, fd: RawFd) -> io::Result<usize> {
        self.count = 0;
        let base = self.bufs.as_mut_ptr();
        for i in 0..BATCH {
            self.iovs[i] = libc::iovec {
                iov_base: unsafe { base.add(i * RECV_SLOT) } as *mut libc::c_void,
                iov_len: RECV_SLOT,
            };
            let h = &mut self.hdrs[i].msg_hdr;
            h.msg_name = &mut self.addrs[i] as *mut _ as *mut libc::c_void;
            h.msg_namelen = mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
            h.msg_iov = &mut self.iovs[i];
            h.msg_iovlen = 1;
            h.msg_control = std::ptr::null_mut();
            h.msg_controllen = 0;
            h.msg_flags = 0;
            self.hdrs[i].msg_len = 0;
        }
        let r = unsafe { libc::recvmmsg(fd, self.hdrs.as_mut_ptr(), BATCH as libc::c_uint, libc::MSG_DONTWAIT, std::ptr::null_mut()) };
        if r < 0 {
            let e = io::Error::last_os_error();
            return match e.kind() {
                io::ErrorKind::WouldBlock => Ok(0),
                // a pending ICMP error on a connected socket: not data
                io::ErrorKind::ConnectionRefused => Ok(0),
                _ if e.raw_os_error() == Some(libc::EINTR) => Ok(0),
                _ => Err(e),
            };
        }
        let r = r as usize;
        for i in 0..r {
            let trunc = self.hdrs[i].msg_hdr.msg_flags & libc::MSG_TRUNC != 0;
            if trunc {
                self.truncated += 1;
            }
            self.lens[i] = if trunc { 0 } else { self.hdrs[i].msg_len as usize };
            self.from[i] = from_sockaddr(&self.addrs[i]);
        }
        self.count = r;
        Ok(r)
    }

    pub fn len(&self) -> usize {
        self.count
    }

    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Datagram `i` of the last `recv` (empty if truncated) and its source.
    pub fn get(&self, i: usize) -> (&[u8], Option<SocketAddr>) {
        let o = i * RECV_SLOT;
        (&self.bufs[o..o + self.lens[i]], self.from[i])
    }
}

/// A batch of datagrams to send. Fill with `slot()` + `commit()`, then
/// `flush()`; a partial send keeps the rest for the next `flush()`.
pub struct SendBatch {
    bufs: Vec<u8>,
    lens: Vec<usize>,
    addrs: Vec<(libc::sockaddr_storage, libc::socklen_t)>,
    has_addr: Vec<bool>,
    iovs: Vec<libc::iovec>,
    hdrs: Vec<libc::mmsghdr>,
    count: usize,
    sent: usize,
    /// Datagrams the kernel refused with an error other than EAGAIN.
    pub errors: u64,
    pub last_error: Option<io::Error>,
    /// sendmmsg calls / datagrams sent.
    pub calls: u64,
    pub datagrams: u64,
    pub would_block: u64,
}

// See RecvBatch.
unsafe impl Send for SendBatch {}

impl Default for SendBatch {
    fn default() -> Self {
        Self::new()
    }
}

impl SendBatch {
    pub fn new() -> SendBatch {
        SendBatch {
            bufs: vec![0u8; BATCH * SEND_SLOT],
            lens: vec![0; BATCH],
            addrs: vec![(zeroed_c(), 0); BATCH],
            has_addr: vec![false; BATCH],
            iovs: vec![
                libc::iovec {
                    iov_base: std::ptr::null_mut(),
                    iov_len: 0
                };
                BATCH
            ],
            hdrs: vec![zeroed_c(); BATCH],
            count: 0,
            sent: 0,
            errors: 0,
            last_error: None,
            calls: 0,
            datagrams: 0,
            would_block: 0,
        }
    }

    pub fn is_full(&self) -> bool {
        self.count == BATCH
    }

    /// Datagrams queued and not yet sent.
    pub fn pending(&self) -> usize {
        self.count - self.sent
    }

    /// The next free buffer (`None` when full).
    pub fn slot(&mut self) -> Option<&mut [u8]> {
        if self.count == BATCH {
            return None;
        }
        let o = self.count * SEND_SLOT;
        Some(&mut self.bufs[o..o + SEND_SLOT])
    }

    /// Queue the datagram written into `slot()`; `dst` None on a connected socket.
    pub fn commit(&mut self, len: usize, dst: Option<&SocketAddr>) {
        let i = self.count;
        self.lens[i] = len;
        match dst {
            Some(a) => {
                self.addrs[i] = to_sockaddr(a);
                self.has_addr[i] = true;
            }
            None => self.has_addr[i] = false,
        }
        self.count += 1;
    }

    /// Send what is queued. `Ok(true)` when everything went out, `Ok(false)`
    /// when the socket would block (the rest stays queued).
    pub fn flush(&mut self, fd: RawFd) -> io::Result<bool> {
        while self.sent < self.count {
            let base = self.bufs.as_mut_ptr();
            for i in self.sent..self.count {
                self.iovs[i] = libc::iovec {
                    iov_base: unsafe { base.add(i * SEND_SLOT) } as *mut libc::c_void,
                    iov_len: self.lens[i],
                };
                let h = &mut self.hdrs[i].msg_hdr;
                if self.has_addr[i] {
                    h.msg_name = &mut self.addrs[i].0 as *mut _ as *mut libc::c_void;
                    h.msg_namelen = self.addrs[i].1;
                } else {
                    h.msg_name = std::ptr::null_mut();
                    h.msg_namelen = 0;
                }
                h.msg_iov = &mut self.iovs[i];
                h.msg_iovlen = 1;
                h.msg_control = std::ptr::null_mut();
                h.msg_controllen = 0;
                h.msg_flags = 0;
            }
            let n = (self.count - self.sent) as libc::c_uint;
            let r = unsafe { libc::sendmmsg(fd, self.hdrs.as_mut_ptr().add(self.sent), n, 0) };
            self.calls += 1;
            if r < 0 {
                let e = io::Error::last_os_error();
                match e.kind() {
                    io::ErrorKind::WouldBlock => {
                        self.would_block += 1;
                        return Ok(false);
                    }
                    _ if e.raw_os_error() == Some(libc::EINTR) => continue,
                    _ => {
                        // this datagram cannot go (e.g. ECONNREFUSED from an
                        // earlier ICMP): skip it and carry on
                        self.errors += 1;
                        self.last_error = Some(e);
                        self.sent += 1;
                        continue;
                    }
                }
            }
            self.sent += r as usize;
            self.datagrams += r as u64;
        }
        self.count = 0;
        self.sent = 0;
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::UdpSocket;
    use std::os::unix::io::AsRawFd;

    #[test]
    fn sockaddr_round_trip() {
        for s in ["10.1.2.3:4567", "[2001:db8::1]:9", "[::1]:65535"] {
            let a: SocketAddr = s.parse().unwrap();
            let (ss, _) = to_sockaddr(&a);
            assert_eq!(from_sockaddr(&ss), Some(a));
        }
    }

    #[test]
    fn mmsg_loopback() {
        let a = UdpSocket::bind("127.0.0.1:0").unwrap();
        let b = UdpSocket::bind("127.0.0.1:0").unwrap();
        b.set_nonblocking(true).unwrap();
        let bdst = b.local_addr().unwrap();
        let mut tx = SendBatch::new();
        for i in 0..100u32 {
            if tx.is_full() {
                assert!(tx.flush(a.as_raw_fd()).unwrap());
            }
            let s = tx.slot().unwrap();
            s[..4].copy_from_slice(&i.to_be_bytes());
            tx.commit(4 + (i as usize % 7), Some(&bdst));
        }
        assert!(tx.flush(a.as_raw_fd()).unwrap());
        assert_eq!(tx.datagrams, 100);
        let mut rx = RecvBatch::new();
        let mut got = Vec::new();
        while got.len() < 100 {
            let n = rx.recv(b.as_raw_fd()).unwrap();
            for i in 0..n {
                let (d, from) = rx.get(i);
                assert_eq!(from, Some(a.local_addr().unwrap()));
                got.push((u32::from_be_bytes(d[..4].try_into().unwrap()), d.len()));
            }
        }
        for (i, (v, len)) in got.iter().enumerate() {
            assert_eq!((*v as usize, *len), (i, 4 + i % 7));
        }
        assert_eq!(rx.recv(b.as_raw_fd()).unwrap(), 0);
    }
}
