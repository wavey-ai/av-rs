//! A `timerfd` as a mio source: wakes the poll loop at a precise
//! `Instant` (epoll's own timeout has 1 ms resolution).

use mio::event::Source;
use mio::unix::SourceFd;
use mio::{Interest, Registry, Token};
use std::io;
use std::os::unix::io::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::time::Instant;

pub struct SrtTimer {
    fd: OwnedFd,
    armed: Option<Instant>,
}

impl SrtTimer {
    pub fn new() -> io::Result<SrtTimer> {
        let fd = unsafe { libc::timerfd_create(libc::CLOCK_MONOTONIC, libc::TFD_NONBLOCK | libc::TFD_CLOEXEC) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(SrtTimer {
            fd: unsafe { OwnedFd::from_raw_fd(fd) },
            armed: None,
        })
    }

    /// Clear a fired expiration (call when the timer's token is ready).
    pub fn clear(&mut self) {
        let mut b = [0u8; 8];
        unsafe { libc::read(self.fd.as_raw_fd(), b.as_mut_ptr() as *mut libc::c_void, 8) };
        self.armed = None;
    }

    /// Fire at `at` (or disarm with None). A deadline in the past fires at once.
    pub fn arm(&mut self, at: Option<Instant>, now: Instant) -> io::Result<()> {
        if at == self.armed {
            return Ok(());
        }
        self.clear();
        let mut spec: libc::itimerspec = crate::batch::zeroed_c();
        if let Some(t) = at {
            let d = t.saturating_duration_since(now);
            let (s, ns) = if d.is_zero() {
                (0, 1)
            } else {
                (d.as_secs() as libc::time_t, d.subsec_nanos() as libc::c_long)
            };
            spec.it_value.tv_sec = s;
            spec.it_value.tv_nsec = ns;
        }
        if unsafe { libc::timerfd_settime(self.fd.as_raw_fd(), 0, &spec, std::ptr::null_mut()) } < 0 {
            return Err(io::Error::last_os_error());
        }
        self.armed = at;
        Ok(())
    }
}

impl AsRawFd for SrtTimer {
    fn as_raw_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }
}

impl Source for SrtTimer {
    fn register(&mut self, r: &Registry, t: Token, i: Interest) -> io::Result<()> {
        SourceFd(&self.fd.as_raw_fd()).register(r, t, i)
    }
    fn reregister(&mut self, r: &Registry, t: Token, i: Interest) -> io::Result<()> {
        SourceFd(&self.fd.as_raw_fd()).reregister(r, t, i)
    }
    fn deregister(&mut self, r: &Registry) -> io::Result<()> {
        SourceFd(&self.fd.as_raw_fd()).deregister(r)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn fires_precisely() {
        let mut poll = mio::Poll::new().unwrap();
        let mut ev = mio::Events::with_capacity(4);
        let mut t = SrtTimer::new().unwrap();
        poll.registry().register(&mut t, Token(1), Interest::READABLE).unwrap();
        for _ in 0..3 {
            let now = Instant::now();
            let at = now + Duration::from_micros(700);
            t.arm(Some(at), now).unwrap();
            loop {
                poll.poll(&mut ev, Some(Duration::from_millis(50))).unwrap();
                if ev.iter().any(|e| e.token() == Token(1)) {
                    break;
                }
            }
            let late = Instant::now().saturating_duration_since(at);
            assert!(Instant::now() >= at);
            assert!(late < Duration::from_millis(5), "{late:?}");
            t.clear();
        }
    }
}
