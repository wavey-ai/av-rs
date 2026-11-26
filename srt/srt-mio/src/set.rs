//! A set of callers driven together (one sender fanning out to many
//! receivers, each on its own socket): their timers in one min-heap, so a
//! wake-up drives only the sockets that are readable, due, or were handed
//! something (`get_mut`, `send`), not all of them.

use crate::SrtSocket;
use srt_core::SendError;
use std::cmp::Reverse;
use std::collections::BinaryHeap;
use std::io;
use std::time::Instant;

struct Entry {
    sock: SrtSocket,
    /// The deadline filed in the heap.
    due: Option<Instant>,
    dirty: bool,
}

#[derive(Default)]
pub struct SrtSocketSet {
    socks: Vec<Entry>,
    timers: BinaryHeap<Reverse<(Instant, usize)>>,
    dirty: Vec<usize>,
    /// Sockets driven, over all `drive` calls (for stats).
    pub driven: u64,
}

impl SrtSocketSet {
    pub fn new() -> SrtSocketSet {
        SrtSocketSet::default()
    }

    /// Add a socket; returns its index (use it as its mio token).
    pub fn push(&mut self, sock: SrtSocket) -> usize {
        let i = self.socks.len();
        self.socks.push(Entry { sock, due: None, dirty: true });
        self.dirty.push(i);
        i
    }

    pub fn len(&self) -> usize {
        self.socks.len()
    }

    pub fn is_empty(&self) -> bool {
        self.socks.is_empty()
    }

    pub fn get(&self, i: usize) -> &SrtSocket {
        &self.socks[i].sock
    }

    /// Mutable access marks the socket for the next `drive`.
    pub fn get_mut(&mut self, i: usize) -> &mut SrtSocket {
        self.mark(i);
        &mut self.socks[i].sock
    }

    pub fn iter(&self) -> impl Iterator<Item = &SrtSocket> {
        self.socks.iter().map(|e| &e.sock)
    }

    /// Every socket marked (e.g. before closing all).
    pub fn iter_mut(&mut self) -> impl Iterator<Item = &mut SrtSocket> {
        for i in 0..self.socks.len() {
            self.mark(i);
        }
        self.socks.iter_mut().map(|e| &mut e.sock)
    }

    /// Queue a message on socket `i` (sent by the next `drive`).
    pub fn send(&mut self, i: usize, now: Instant, msg: &[u8]) -> Result<u32, SendError> {
        self.mark(i);
        self.socks[i].sock.send(now, msg)
    }

    /// Socket `i`'s mio token fired.
    pub fn set_readable(&mut self, i: usize) {
        if i < self.socks.len() {
            self.socks[i].sock.set_readable();
            self.mark(i);
        }
    }

    #[inline]
    fn mark(&mut self, i: usize) {
        let e = &mut self.socks[i];
        if !e.dirty {
            e.dirty = true;
            self.dirty.push(i);
        }
    }

    /// Drive the readable, due and marked sockets; `on_err(i, e)` gets
    /// socket errors (the socket stays in the set).
    pub fn drive(&mut self, now: Instant, mut on_err: impl FnMut(usize, io::Error)) {
        while let Some(&Reverse((t, i))) = self.timers.peek() {
            if t > now {
                break;
            }
            self.timers.pop();
            if self.socks[i].due == Some(t) {
                self.socks[i].due = None;
                self.mark(i);
            }
        }
        let mut keep = 0;
        for k in 0..self.dirty.len() {
            let i = self.dirty[k];
            let e = &mut self.socks[i];
            self.driven += 1;
            if let Err(err) = e.sock.drive_io(now) {
                on_err(i, err);
            }
            if e.sock.pending_datagrams() > 0 {
                // EAGAIN: stays marked, retried on the caller's short timer
                self.dirty[keep] = i;
                keep += 1;
                continue;
            }
            e.dirty = false;
            let due = e.sock.poll_timeout();
            if due != e.due {
                e.due = due;
                if let Some(t) = due {
                    self.timers.push(Reverse((t, i)));
                }
            }
        }
        self.dirty.truncate(keep);
        while let Some(&Reverse((t, i))) = self.timers.peek() {
            if self.socks[i].due == Some(t) {
                break;
            }
            self.timers.pop();
        }
        if self.timers.len() > 64 + 4 * self.socks.len() {
            self.timers = self.socks.iter().enumerate().filter_map(|(i, e)| e.due.map(|t| Reverse((t, i)))).collect();
        }
    }

    /// The earliest deadline: the heap's top, or that of a socket marked
    /// since the last `drive`.
    pub fn poll_timeout(&self) -> Option<Instant> {
        let mut t = self.timers.peek().map(|r| r.0 .0);
        for &i in &self.dirty {
            if let Some(d) = self.socks[i].sock.poll_timeout() {
                t = Some(t.map_or(d, |x| x.min(d)));
            }
        }
        t
    }

    /// Datagrams queued on any socket because it would block.
    pub fn pending_datagrams(&self) -> usize {
        self.dirty.iter().map(|&i| self.socks[i].sock.pending_datagrams()).sum()
    }

    /// Filed timers (tests, stats).
    pub fn timer_entries(&self) -> usize {
        self.timers.len()
    }
}
