//! UDP I/O for `srt-core` on mio: a caller (`SrtSocket`, one connected UDP
//! socket), a listener (`SrtListener`, one UDP socket, connections
//! demultiplexed by destination socket ID), `recvmmsg`/`sendmmsg` batches
//! and a `timerfd` source (`SrtTimer`) for sub-millisecond wake-ups.
//!
//! Everything runs on the caller's thread: register the socket (and a
//! timer) in a `mio::Poll` with `Interest::READABLE` only, call
//! `set_readable()` when its token fires and `drive_io(now)` on every
//! wake-up, arm the timer at `poll_timeout()`, and read messages with
//! `recv_with`. Do not register WRITABLE: on UDP every packet the kernel
//! frees raises a new EPOLLOUT edge, i.e. one wake-up per packet sent; if
//! `pending_datagrams() > 0` (EAGAIN) retry on a short timer instead.
//! `SrtSocketSet` drives many callers (a fan-out sender) from one timer
//! heap. See srt-core's DESIGN.md.

pub mod batch;
mod listener;
mod set;
mod socket;
mod timer;

pub use listener::SrtListener;
pub use set::SrtSocketSet;
pub use socket::SrtSocket;
pub use srt_core;
pub use timer::SrtTimer;

/// UDP socket options.
#[derive(Clone, Debug)]
pub struct UdpOptions {
    /// SO_RCVBUF request (the kernel caps it at net.core.rmem_max).
    pub recv_buffer: Option<usize>,
    /// SO_SNDBUF request.
    pub send_buffer: Option<usize>,
    pub reuse_address: bool,
}

impl Default for UdpOptions {
    fn default() -> Self {
        UdpOptions {
            recv_buffer: Some(32 << 20),
            send_buffer: Some(32 << 20),
            reuse_address: true,
        }
    }
}
