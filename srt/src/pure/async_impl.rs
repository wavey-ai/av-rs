//! tokio API of the pure Rust backend: the same types and methods as the
//! libsrt backend's `async` feature. The I/O runs on the backend's own
//! threads; these futures only wait on its queues (no `spawn_blocking`).

use super::engine::{self, ConnHandle, ListenerHandle};
use super::{connect_config, first_addr, listener_config, udp_options, Stats};
use crate::{ConnectOptions, Error, ListenerCallback, ListenerOption, Result};
use std::{
    future::Future,
    io,
    marker::PhantomData,
    net::{SocketAddr, ToSocketAddrs},
    pin::Pin,
    task::{Context, Poll},
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

pub struct AsyncListener<'c> {
    pub(super) h: ListenerHandle,
    _cb: PhantomData<&'c ()>,
}

impl AsyncListener<'static> {
    pub fn bind<A: ToSocketAddrs>(addr: A) -> Result<Self> {
        Self::bind_with_options(addr, vec![])
    }

    pub fn bind_with_options<A: ToSocketAddrs, O: IntoIterator<Item = ListenerOption>>(addr: A, opts: O) -> Result<Self> {
        let cfg = listener_config(opts)?;
        let h = engine::start_listener(first_addr(addr)?, cfg, udp_options())?;
        Ok(Self { h, _cb: PhantomData })
    }
}

impl<'c> AsyncListener<'c> {
    /// Access control: called on the listener's I/O thread for each
    /// caller's conclusion handshake, with its stream ID.
    pub fn with_callback<F: ListenerCallback + 'c>(self, f: F) -> Result<AsyncListener<'c>> {
        // SAFETY: the box lives until the handle's drop removes it, which
        // happens before 'c ends
        unsafe { self.h.ls.set_callback(Some(Box::new(f))) };
        Ok(AsyncListener { h: self.h, _cb: PhantomData })
    }

    /// The next connection. Cancel-safe: dropping the future loses nothing.
    pub async fn accept(&self) -> Result<(AsyncStream, SocketAddr)> {
        let (sh, addr) = Accept { l: self }.await?;
        let id = sh.stream_id();
        Ok((AsyncStream { h: ConnHandle { sh }, id }, addr))
    }

    /// The bound address.
    pub fn local_addr(&self) -> SocketAddr {
        self.h.ls.local
    }
}

struct Accept<'a, 'c> {
    l: &'a AsyncListener<'c>,
}

impl<'a, 'c> Future for Accept<'a, 'c> {
    type Output = Result<(std::sync::Arc<engine::ConnShared>, SocketAddr)>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context) -> Poll<Self::Output> {
        match self.l.h.ls.poll_accept(Some(cx.waker())) {
            Some(r) => Poll::Ready(r),
            None => Poll::Pending,
        }
    }
}

pub struct AsyncStream {
    h: ConnHandle,
    id: Option<String>,
}

struct Connected<'a> {
    h: &'a ConnHandle,
}

impl<'a> Future for Connected<'a> {
    type Output = Result<()>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context) -> Poll<Self::Output> {
        match self.h.sh.poll_connected(Some(cx.waker())) {
            Some(r) => Poll::Ready(r),
            None => Poll::Pending,
        }
    }
}

impl AsyncStream {
    pub async fn connect<A: ToSocketAddrs>(addr: A, options: &ConnectOptions) -> Result<Self> {
        let cfg = connect_config(options)?;
        let mut last_err = Error::InvalidAddress;
        for addr in addr.to_socket_addrs()? {
            let h = engine::start_caller(addr, cfg.clone(), udp_options())?;
            match (Connected { h: &h }).await {
                Ok(()) => {
                    return Ok(Self {
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
    pub fn close_reason(&self) -> Option<super::srt_core::CloseReason> {
        self.h.sh.close_reason()
    }

    /// Negotiated TSBPD latency (receive, send), ms: each side uses the
    /// larger of its own and the peer's proposal.
    pub fn latency_ms(&self) -> (u16, u16) {
        self.h.sh.latency_ms()
    }

    /// AES key length of the connection's encryption, bytes (None: clear).
    pub fn encryption_key_len(&self) -> Option<usize> {
        self.h.sh.key_len()
    }
}

impl AsyncRead for AsyncStream {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context, buf: &mut ReadBuf) -> Poll<io::Result<()>> {
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        let dst = buf.initialize_unfilled();
        match self.h.sh.poll_read(dst, Some(cx.waker())) {
            Some(Ok(n)) => {
                buf.advance(n);
                Poll::Ready(Ok(()))
            }
            Some(Err(e)) => Poll::Ready(Err(e)),
            None => Poll::Pending,
        }
    }
}

impl AsyncWrite for AsyncStream {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, src: &[u8]) -> Poll<io::Result<usize>> {
        match self.h.sh.poll_write(src, Some(cx.waker())) {
            Some(r) => Poll::Ready(r),
            None => Poll::Pending,
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}
