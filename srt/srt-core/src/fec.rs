//! The libsrt `fec` packet filter (spec 8): XOR parity over row groups
//! (C consecutive packets) and column groups (R packets C apart), wire
//! compatible with libsrt 1.5.7.
//!
//! - `FecConfig`: the negotiated `fec,...` string.
//! - `Geometry`: which groups a packet belongs to (even and staircase
//!   layouts), from its offset `k` from the ISN of the direction.
//! - `FecTx`: the sender's accumulators; a FEC packet is emitted right after
//!   the data packet that completes its group (column first, then row), as
//!   libsrt does.
//! - `FecRx`: the receiver's groups in rings indexed by group number (no
//!   per-group allocation, no linear search), rebuild of a group's one
//!   missing packet (iterative across rows and columns), and the decision
//!   of when a missing packet can no longer be rebuilt (its groups are
//!   closed: the FEC packet came, or new data past the group's end did).
//!   The connection uses that decision to send the first NAK under
//!   `arq:onreq`/`always`; the NAK schedule (re-NAKs) stays the
//!   connection's, so unlike libsrt a lost NAK or repair is not final, and
//!   no reset drops a loss without a report (spec 8.7, 8.8, 12 #9).
//!
//! XOR runs over the bytes a packet really has (an accumulator remembers
//! how far it is non-zero, so groups are never cleared byte by byte), in
//! 32-byte blocks the compiler vectorises.

use crate::filter::FilterConfig;
use crate::rcvbuf::RcvBuf;
use crate::seq::{seq_add, seq_off};

/// `arq` level (spec 8.7).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ArqLevel {
    Never,
    OnReq,
    Always,
}

/// A parsed `fec` filter.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FecConfig {
    /// C: packets per row group.
    pub cols: u32,
    /// |rows|: packets per column group (1 = rows only).
    pub rows: u32,
    /// Row FEC packets are sent (false with `rows` <= -2: columns only).
    pub row_fec: bool,
    /// Column FEC packets are sent (`rows` >= 2 or <= -2).
    pub col_fec: bool,
    pub staircase: bool,
    pub arq: ArqLevel,
}

impl FecConfig {
    /// Parse a (negotiated) filter string; None unless it is a valid `fec`.
    pub fn parse(s: &str) -> Option<FecConfig> {
        let c = FilterConfig::parse(s)?;
        if c.kind != "fec" {
            return None;
        }
        let cols: i64 = c.params.get("cols")?.parse().ok()?;
        let rows: i64 = c.params.get("rows").map_or(Some(1), |v| v.parse().ok())?;
        let staircase = c.params.get("layout").map_or(true, |v| v != "even");
        let arq = match c.params.get("arq").map(String::as_str) {
            Some("never") => ArqLevel::Never,
            Some("always") => ArqLevel::Always,
            _ => ArqLevel::OnReq,
        };
        if cols < 2 || rows == 0 || rows == -1 {
            return None;
        }
        Some(FecConfig {
            cols: cols as u32,
            rows: rows.unsigned_abs() as u32,
            row_fec: rows > 0,
            col_fec: rows.abs() >= 2,
            staircase,
            arq,
        })
    }
}

/// Group membership for a packet at offset `k` (>= 0) from the ISN.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Geometry {
    c: i64,
    r: i64,
    staircase: bool,
    pub row_fec: bool,
    pub col_fec: bool,
}

impl Geometry {
    pub fn new(f: &FecConfig) -> Geometry {
        Geometry {
            c: f.cols as i64,
            r: f.rows.max(1) as i64,
            staircase: f.staircase,
            row_fec: f.row_fec,
            col_fec: f.col_fec,
        }
    }

    #[cfg(test)]
    pub fn cols(&self) -> i64 {
        self.c
    }

    #[cfg(test)]
    pub fn rows(&self) -> i64 {
        self.r
    }

    /// Rows column `j` starts below row 0 (staircase: `j mod R`; libsrt's
    /// "add C + 1, restart every R columns").
    #[inline]
    fn shift(&self, j: i64) -> i64 {
        if self.staircase {
            j % self.r
        } else {
            0
        }
    }

    /// Column group of `k`: (group id = series x C + column, index in the
    /// group), or None if `k` lies above its column's first group
    /// (staircase head: row protection only).
    #[inline]
    pub fn col_of(&self, k: i64) -> Option<(i64, i64)> {
        let (q, j) = (k / self.c, k % self.c);
        let d = q - self.shift(j);
        if d < 0 {
            return None;
        }
        Some(((d / self.r) * self.c + j, d % self.r))
    }

    /// Offset of member `i` of column group `id`.
    #[inline]
    pub fn col_member(&self, id: i64, i: i64) -> i64 {
        let (s, j) = (id / self.c, id % self.c);
        (self.shift(j) + s * self.r + i) * self.c + j
    }

    /// Offset of the first packet of column `j`'s first group (libsrt
    /// ConfigureColumns).
    #[cfg(test)]
    pub fn col_base(&self, j: i64) -> i64 {
        self.col_member(j, 0)
    }
}

/// `dst ^= src` over the common length.
#[inline]
pub(crate) fn xor_into(dst: &mut [u8], src: &[u8]) {
    let n = dst.len().min(src.len());
    let (d, s) = (&mut dst[..n], &src[..n]);
    let mut dc = d.chunks_exact_mut(32);
    let mut sc = s.chunks_exact(32);
    for (a, b) in (&mut dc).zip(&mut sc) {
        for i in 0..32 {
            a[i] ^= b[i];
        }
    }
    for (a, b) in dc.into_remainder().iter_mut().zip(sc.remainder()) {
        *a ^= *b;
    }
}

/// XOR `data` into an accumulator whose bytes from `*len` on are zero.
#[inline]
fn clip(acc: &mut [u8], len: &mut u16, data: &[u8]) {
    let n = data.len().min(acc.len());
    let a = *len as usize;
    if n <= a {
        xor_into(&mut acc[..n], &data[..n]);
    } else {
        xor_into(&mut acc[..a], &data[..a]);
        acc[a..n].copy_from_slice(&data[a..n]);
        *len = n as u16;
    }
}

/// XOR of 0..n (n >= 1): the index sum trick finds a group's one missing
/// member without scanning.
#[inline]
fn xor_upto(n: u32) -> u32 {
    let m = n - 1;
    match m % 4 {
        0 => m,
        1 => 1,
        2 => m + 1,
        _ => 0,
    }
}

/// Group state shared by sender and receiver (the payload accumulator lives
/// in a separate byte area).
#[derive(Clone, Copy, Debug)]
struct Group {
    id: i64,
    collected: u32,
    /// Receiver: the FEC packet has been clipped in.
    fec: bool,
    /// Receiver: rebuilt (or found unrebuildable); nothing more to do.
    done: bool,
    idx_xor: u32,
    len_x: u16,
    flags_x: u8,
    ts_x: u32,
    acc_len: u16,
    /// Sender: sequence of the group's last packet (the FEC packet's).
    seq_last: u32,
}

const NO_GROUP: Group = Group {
    id: -1,
    collected: 0,
    fec: false,
    done: false,
    idx_xor: 0,
    len_x: 0,
    flags_x: 0,
    ts_x: 0,
    acc_len: 0,
    seq_last: 0,
};

impl Group {
    #[inline]
    fn reset(&mut self, id: i64) {
        *self = Group { id, ..NO_GROUP };
    }

    #[inline]
    fn clip_data(&mut self, acc: &mut [u8], idx: u32, payload: &[u8], ts: u32, flags: u8) {
        self.len_x ^= payload.len() as u16;
        self.flags_x ^= flags;
        self.ts_x ^= ts;
        self.idx_xor ^= idx;
        self.collected += 1;
        clip(acc, &mut self.acc_len, payload);
    }
}

/// Map 31-bit sequences to a monotonic 64-bit offset from the ISN.
#[derive(Clone, Copy, Debug)]
struct SeqMap {
    seq: u32,
    k: i64,
}

impl SeqMap {
    fn new(isn: u32) -> SeqMap {
        SeqMap { seq: isn, k: 0 }
    }

    #[inline]
    fn k(&self, seq: u32) -> i64 {
        self.k + seq_off(self.seq, seq) as i64
    }

    #[inline]
    fn seq(&self, k: i64) -> u32 {
        seq_add(self.seq, (k - self.k) as i32)
    }

    /// Re-anchor at `seq` when it is ahead (keeps offsets within 2^30).
    #[inline]
    fn advance(&mut self, seq: u32) {
        let d = seq_off(self.seq, seq);
        if d > 0 {
            self.seq = seq;
            self.k += d as i64;
        }
    }
}

/// Which FEC packet the sender has ready.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Pending {
    Col(usize),
    Row,
}

/// Sender side: one row accumulator and one per column.
pub(crate) struct FecTx {
    geo: Geometry,
    /// FEC payload clip size P (the sender's SRTO_PAYLOADSIZE).
    p: usize,
    row: Group,
    cols: Vec<Group>,
    /// Row accumulator at 0, column j at (1 + j) * p.
    acc: Vec<u8>,
    pending: [Option<Pending>; 2],
    map: SeqMap,
}

impl FecTx {
    pub fn new(f: &FecConfig, p: usize, isn: u32) -> FecTx {
        let geo = Geometry::new(f);
        let ncols = if geo.col_fec { geo.c as usize } else { 0 };
        FecTx {
            geo,
            p,
            row: NO_GROUP,
            cols: vec![NO_GROUP; ncols],
            acc: vec![0; (1 + ncols) * p],
            pending: [None, None],
            map: SeqMap::new(isn),
        }
    }

    /// FEC packets wait to be sent (before the next new data packet).
    #[inline]
    pub fn has_pending(&self) -> bool {
        self.pending[0].is_some()
    }

    /// Clip a data packet sent for the first time (in sequence order).
    pub fn on_new(&mut self, seq: u32, payload: &[u8], ts: u32, flags: u8) {
        debug_assert!(!self.has_pending());
        self.map.advance(seq);
        let k = self.map.k(seq);
        if k < 0 {
            return;
        }
        let (c, p) = (self.geo.c, self.p);
        let mut n = 0;
        if self.geo.col_fec {
            if let Some((id, i)) = self.geo.col_of(k) {
                let j = (k % c) as usize;
                let g = &mut self.cols[j];
                if g.id != id {
                    g.reset(id);
                }
                let a = (1 + j) * p;
                g.clip_data(&mut self.acc[a..a + p], i as u32, payload, ts, flags);
                if g.collected as i64 == self.geo.r {
                    g.seq_last = seq;
                    self.pending[n] = Some(Pending::Col(j));
                    n += 1;
                }
            }
        }
        if !self.geo.row_fec {
            return; // columns only
        }
        let row = k / c;
        if self.row.id != row {
            self.row.reset(row);
        }
        self.row.clip_data(&mut self.acc[..p], (k % c) as u32, payload, ts, flags);
        if self.row.collected as i64 == c {
            self.row.seq_last = seq;
            self.pending[n] = Some(Pending::Row);
        }
    }

    /// Write the next pending FEC packet (header + payload) into `buf`.
    pub fn write_next(&mut self, dst_sid: u32, buf: &mut [u8]) -> Option<usize> {
        let which = self.pending[0]?;
        self.pending[0] = self.pending[1].take();
        let p = self.p;
        let (g, a, index) = match which {
            Pending::Row => (&mut self.row, 0, 0xFFu8),
            Pending::Col(j) => (&mut self.cols[j], (1 + j) * p, j as u8),
        };
        // data packet, PP = 11 (solo), message number 0
        crate::packet::wr32(buf, 0, g.seq_last & 0x7FFF_FFFF);
        crate::packet::wr32(buf, 4, 0xC000_0000);
        crate::packet::wr32(buf, 8, g.ts_x);
        crate::packet::wr32(buf, 12, dst_sid);
        let h = crate::packet::HDR_LEN;
        buf[h] = index;
        buf[h + 1] = g.flags_x;
        buf[h + 2..h + 4].copy_from_slice(&g.len_x.to_be_bytes());
        let al = (g.acc_len as usize).min(p);
        buf[h + 4..h + 4 + al].copy_from_slice(&self.acc[a..a + al]);
        buf[h + 4 + al..h + 4 + p].fill(0);
        // spent: the next packet of this row/column starts a new group
        g.reset(-1);
        Some(h + 4 + p)
    }
}

/// Which dimension a receiver group is in.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Dim {
    Row,
    Col,
}

/// A packet the receiver rebuilt; its payload is `FecRx::rebuilt()`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Rebuilt {
    pub seq: u32,
    pub k: i64,
    pub len: usize,
    pub timestamp: u32,
    pub flags: u8,
    pub from: Dim,
}

/// A group a FEC packet went into (to close it).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct GroupRef {
    pub dim: Dim,
    pub id: i64,
}

/// Receiver side.
pub(crate) struct FecRx {
    pub cfg: FecConfig,
    geo: Geometry,
    map: SeqMap,
    /// Highest offset of new (not retransmitted) data received: every group
    /// ending before it is closed (its FEC packet went out before it).
    pass_k: i64,
    /// Groups older than this many packets behind `pass_k` are forgotten.
    window: i64,
    rows: Vec<Group>,
    row_mask: usize,
    cols: Vec<Group>,
    col_mask: usize,
    /// Accumulators: rows first, then columns; `accsz` bytes each.
    acc: Vec<u8>,
    accsz: usize,
    /// Groups that may have become rebuildable.
    cand: Vec<GroupRef>,
    /// The last rebuilt payload.
    scratch: Vec<u8>,
}

impl FecRx {
    /// `accsz`: largest payload accepted (FEC payload - 4 is clipped to it);
    /// `window`: packets of group history (at most the receive buffer).
    pub fn new(cfg: &FecConfig, accsz: usize, isn: u32, window: u32) -> FecRx {
        let geo = Geometry::new(cfg);
        let w = window.max(64) as i64;
        let nrows = if geo.row_fec { ((w / geo.c + 4) as usize).next_power_of_two() } else { 0 };
        let ncols = if geo.col_fec {
            (((w / (geo.c * geo.r) + 4) * geo.c) as usize).next_power_of_two()
        } else {
            0
        };
        FecRx {
            cfg: *cfg,
            geo,
            map: SeqMap::new(isn),
            pass_k: 0,
            window: w,
            rows: vec![NO_GROUP; nrows],
            row_mask: nrows.saturating_sub(1),
            cols: vec![NO_GROUP; ncols],
            col_mask: ncols.saturating_sub(1),
            acc: vec![0; (nrows + ncols) * accsz],
            accsz,
            cand: Vec::with_capacity(16),
            scratch: vec![0; accsz],
        }
    }

    #[inline]
    pub fn seq_of(&self, k: i64) -> u32 {
        self.map.seq(k)
    }

    /// Payload of the last `Rebuilt`.
    pub fn rebuilt(&self, r: &Rebuilt) -> &[u8] {
        &self.scratch[..r.len]
    }

    /// The group slot for `id`, reset if it held an older group; None if
    /// the slot already holds a newer one (the group is too old).
    #[inline]
    fn slot(&mut self, dim: Dim, id: i64) -> Option<usize> {
        let (v, mask) = match dim {
            Dim::Row => (&mut self.rows, self.row_mask),
            Dim::Col => (&mut self.cols, self.col_mask),
        };
        if v.is_empty() || id < 0 {
            return None;
        }
        let i = id as usize & mask;
        let g = &mut v[i];
        match g.id.cmp(&id) {
            std::cmp::Ordering::Equal => Some(i),
            std::cmp::Ordering::Less => {
                g.reset(id);
                Some(i)
            }
            std::cmp::Ordering::Greater => None,
        }
    }

    /// The slot holding `id`, if any (no reset).
    #[inline]
    fn find(&self, dim: Dim, id: i64) -> Option<&Group> {
        let (v, mask) = match dim {
            Dim::Row => (&self.rows, self.row_mask),
            Dim::Col => (&self.cols, self.col_mask),
        };
        if v.is_empty() || id < 0 {
            return None;
        }
        let g = &v[id as usize & mask];
        (g.id == id).then_some(g)
    }

    #[inline]
    fn acc_off(&self, dim: Dim, slot: usize) -> usize {
        match dim {
            Dim::Row => slot * self.accsz,
            Dim::Col => (self.rows.len() + slot) * self.accsz,
        }
    }

    #[inline]
    fn size(&self, dim: Dim) -> u32 {
        match dim {
            Dim::Row => self.geo.c as u32,
            Dim::Col => self.geo.r as u32,
        }
    }

    fn clip_into(&mut self, dim: Dim, id: i64, idx: u32, payload: &[u8], ts: u32, flags: u8) {
        let Some(s) = self.slot(dim, id) else { return };
        let off = self.acc_off(dim, s);
        let sz = self.accsz;
        let size = self.size(dim);
        let g = match dim {
            Dim::Row => &mut self.rows[s],
            Dim::Col => &mut self.cols[s],
        };
        if g.done {
            return;
        }
        g.clip_data(&mut self.acc[off..off + sz], idx, payload, ts, flags);
        if g.fec && g.collected + 1 == size {
            self.cand.push(GroupRef { dim, id });
        }
    }

    /// A data packet stored for the first time (received, or rebuilt from
    /// the other dimension `skip`): clip it into its groups.
    pub fn feed(&mut self, seq: u32, payload: &[u8], ts: u32, flags: u8, skip: Option<Dim>) {
        self.map.advance(seq);
        let k = self.map.k(seq);
        if k < 0 || k + self.window < self.pass_k {
            return;
        }
        let c = self.geo.c;
        if self.geo.row_fec && skip != Some(Dim::Row) {
            self.clip_into(Dim::Row, k / c, (k % c) as u32, payload, ts, flags);
        }
        if self.geo.col_fec && skip != Some(Dim::Col) {
            if let Some((id, i)) = self.geo.col_of(k) {
                self.clip_into(Dim::Col, id, i as u32, payload, ts, flags);
            }
        }
    }

    /// Feed the last rebuilt packet into its other group.
    pub fn feed_rebuilt(&mut self, r: &Rebuilt) {
        let other = match r.from {
            Dim::Row => Dim::Col,
            Dim::Col => Dim::Row,
        };
        let scratch = std::mem::take(&mut self.scratch);
        let c = self.geo.c;
        match other {
            Dim::Row if self.geo.row_fec => self.clip_into(Dim::Row, r.k / c, (r.k % c) as u32, &scratch[..r.len], r.timestamp, r.flags),
            Dim::Col if self.geo.col_fec => {
                if let Some((id, i)) = self.geo.col_of(r.k) {
                    self.clip_into(Dim::Col, id, i as u32, &scratch[..r.len], r.timestamp, r.flags);
                }
            }
            _ => {}
        }
        self.scratch = scratch;
    }

    /// A FEC packet (msgno 0): `payload` is its whole payload (4-byte FEC
    /// header + clip). Returns the group it completed, if valid.
    pub fn on_fec(&mut self, seq: u32, payload: &[u8], ts: u32) -> Option<GroupRef> {
        if payload.len() < 4 {
            return None;
        }
        let k = self.map.k(seq);
        if k < 0 || k + self.window < self.pass_k || k > self.pass_k + 4 * self.window {
            return None;
        }
        self.map.advance(seq);
        let c = self.geo.c;
        let (dim, id) = if payload[0] == 0xFF {
            if !self.geo.row_fec || k % c != c - 1 {
                return None;
            }
            (Dim::Row, k / c)
        } else {
            if !self.geo.col_fec || (k % c) as u8 != payload[0] {
                return None;
            }
            let (id, i) = self.geo.col_of(k)?;
            if i != self.geo.r - 1 {
                return None;
            }
            (Dim::Col, id)
        };
        let s = self.slot(dim, id)?;
        let off = self.acc_off(dim, s);
        let sz = self.accsz;
        let size = self.size(dim);
        let g = match dim {
            Dim::Row => &mut self.rows[s],
            Dim::Col => &mut self.cols[s],
        };
        if g.fec {
            return None; // duplicate
        }
        g.fec = true;
        g.flags_x ^= payload[1];
        g.len_x ^= u16::from_be_bytes([payload[2], payload[3]]);
        g.ts_x ^= ts;
        clip(&mut self.acc[off..off + sz], &mut g.acc_len, &payload[4..]);
        if !g.done && g.collected + 1 == size {
            self.cand.push(GroupRef { dim, id });
        }
        Some(GroupRef { dim, id })
    }

    /// Rebuild the next candidate group's missing packet (payload in
    /// `rebuilt()`), or None when no candidate is left.
    pub fn next_rebuild(&mut self) -> Option<Rebuilt> {
        while let Some(gr) = self.cand.pop() {
            let size = self.size(gr.dim);
            if self.find(gr.dim, gr.id).is_none() {
                continue;
            }
            let s = gr.id as usize & if gr.dim == Dim::Row { self.row_mask } else { self.col_mask };
            let off = self.acc_off(gr.dim, s);
            let accsz = self.accsz;
            let g = match gr.dim {
                Dim::Row => &mut self.rows[s],
                Dim::Col => &mut self.cols[s],
            };
            if g.done || !g.fec || g.collected + 1 != size {
                continue;
            }
            g.done = true;
            g.collected = size;
            let idx = (xor_upto(size) ^ g.idx_xor) as i64;
            let len = g.len_x as usize;
            if idx >= size as i64 || len == 0 || len > accsz {
                continue; // inconsistent (a stale group or a foreign payload size)
            }
            let (ts, flags, al) = (g.ts_x, g.flags_x, g.acc_len as usize);
            let k = match gr.dim {
                Dim::Row => gr.id * self.geo.c + idx,
                Dim::Col => self.geo.col_member(gr.id, idx),
            };
            let n = al.min(len);
            self.scratch[..n].copy_from_slice(&self.acc[off..off + n]);
            self.scratch[n..len].fill(0);
            return Some(Rebuilt {
                seq: self.map.seq(k),
                k,
                len,
                timestamp: ts,
                flags,
                from: gr.dim,
            });
        }
        None
    }

    fn row_closed(&self, q: i64) -> bool {
        (q + 1) * self.geo.c - 1 < self.pass_k || self.find(Dim::Row, q).map_or(false, |g| g.fec || g.done)
    }

    fn col_closed(&self, id: i64) -> bool {
        self.geo.col_member(id, self.geo.r - 1) < self.pass_k || self.find(Dim::Col, id).map_or(false, |g| g.fec || g.done)
    }

    /// `k` can no longer be rebuilt: every group protecting it is closed.
    fn unrebuildable(&self, k: i64) -> bool {
        if self.geo.row_fec && !self.row_closed(k / self.geo.c) {
            return false;
        }
        if self.geo.col_fec {
            if let Some((id, _)) = self.geo.col_of(k) {
                if !self.col_closed(id) {
                    return false;
                }
            }
        }
        true
    }

    /// Missing members of a closed group that no group can rebuild now go
    /// to `out` (offsets).
    fn scan(&self, dim: Dim, id: i64, rcv: &RcvBuf, out: &mut Vec<i64>) {
        let size = self.size(dim);
        if self.find(dim, id).map_or(false, |g| g.collected >= size) {
            return; // complete (received or rebuilt)
        }
        for i in 0..size as i64 {
            let k = match dim {
                Dim::Row => id * self.geo.c + i,
                Dim::Col => self.geo.col_member(id, i),
            };
            if rcv.is_missing(self.map.seq(k)) && self.unrebuildable(k) {
                out.push(k);
            }
        }
    }

    /// A FEC packet closed `g` (after any rebuild): its missing members
    /// that cannot be rebuilt go to `out`.
    pub fn close(&self, g: GroupRef, rcv: &RcvBuf, out: &mut Vec<i64>) {
        self.scan(g.dim, g.id, rcv, out);
    }

    /// New data (not a retransmission) at `seq`: every group ending before
    /// it is closed (its FEC packet was sent before this one). Missing
    /// packets no group can rebuild any more go to `out`. Returns true when
    /// the jump is beyond the group history: everything missing before
    /// `seq` is then unrebuildable (the caller releases the range).
    pub fn advance(&mut self, seq: u32, rcv: &RcvBuf, out: &mut Vec<i64>) -> bool {
        let k = self.map.k(seq);
        if k <= self.pass_k {
            return false;
        }
        let old = self.pass_k;
        self.pass_k = k;
        if k - old > self.window {
            return true;
        }
        let (c, r) = (self.geo.c, self.geo.r);
        for q in old / c..=(k - 1) / c {
            let row_last = q * c + c - 1;
            if row_last >= old && row_last < k {
                // rows close in columns-only mode too: unprotected packets
                self.scan(Dim::Row, q, rcv, out);
            }
            if !self.geo.col_fec {
                continue;
            }
            // column groups whose last packet is in row q
            let (j0, step) = if self.geo.staircase {
                ((q + 1) % r, r)
            } else if (q + 1) % r == 0 {
                (0, 1)
            } else {
                continue;
            };
            let mut j = j0;
            while j < c {
                let kl = q * c + j;
                let d = q - self.shift_of(j) - (r - 1);
                if d >= 0 && kl >= old && kl < k {
                    self.scan(Dim::Col, (d / r) * c + j, rcv, out);
                }
                j += step;
            }
        }
        false
    }

    #[inline]
    fn shift_of(&self, j: i64) -> i64 {
        self.geo.shift(j)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::{rd32, HDR_LEN};

    fn cfg(s: &str) -> FecConfig {
        FecConfig::parse(s).unwrap()
    }

    #[test]
    fn parse_config() {
        let c = cfg("fec,cols:10,rows:5,layout:staircase,arq:onreq");
        assert_eq!(
            (c.cols, c.rows, c.row_fec, c.col_fec, c.staircase, c.arq),
            (10, 5, true, true, true, ArqLevel::OnReq)
        );
        let c = cfg("fec,arq:never,cols:20,layout:staircase,rows:1");
        assert_eq!((c.cols, c.rows, c.row_fec, c.col_fec, c.arq), (20, 1, true, false, ArqLevel::Never));
        let c = cfg("fec,cols:4,rows:-3,layout:even,arq:always");
        assert_eq!((c.rows, c.row_fec, c.col_fec, c.staircase, c.arq), (3, false, true, false, ArqLevel::Always));
        let c = cfg("fec,cols:8");
        assert_eq!((c.rows, c.row_fec, c.col_fec, c.staircase, c.arq), (1, true, false, true, ArqLevel::OnReq));
        assert!(FecConfig::parse("fec,rows:2").is_none());
        assert!(FecConfig::parse("other,cols:2").is_none());
    }

    #[test]
    fn staircase_geometry_matches_libsrt() {
        // spec 8.4: C = 4, R = 3 -> column bases 0, 5, 10, 3, each +12
        let g = Geometry::new(&cfg("fec,cols:4,rows:3"));
        assert_eq!((0..4).map(|j| g.col_base(j)).collect::<Vec<_>>(), vec![0, 5, 10, 3]);
        assert_eq!(g.col_of(5), Some((1, 0)));
        assert_eq!(g.col_of(9), Some((1, 1)));
        assert_eq!(g.col_of(13), Some((1, 2)));
        assert_eq!(g.col_of(17), Some((4 + 1, 0)));
        // packets above their column's first group: row protection only
        assert_eq!((g.col_of(1), g.col_of(2), g.col_of(6)), (None, None, None));
        // even: every column starts at row 0
        let e = Geometry::new(&cfg("fec,cols:4,rows:3,layout:even"));
        assert_eq!((0..4).map(|j| e.col_base(j)).collect::<Vec<_>>(), vec![0, 1, 2, 3]);
        assert_eq!(e.col_of(13), Some((4 + 1, 0)));
        assert_eq!(e.col_member(4 + 1, 2), 21);
    }

    /// A test packet: length and contents from the sequence.
    fn payload(k: i64) -> Vec<u8> {
        let len = 100 + (k as usize * 37) % 1200;
        (0..len).map(|i| (k as usize * 7 + i * 13) as u8).collect()
    }

    fn ts(k: i64) -> u32 {
        1_000_000 + k as u32 * 333
    }

    /// Run `n` packets through a sender; return the FEC packets as
    /// (position in the stream: after data packet index, bytes).
    fn encode(f: &str, isn: u32, n: i64) -> Vec<(i64, Vec<u8>)> {
        let mut tx = FecTx::new(&cfg(f), 1316, isn);
        let mut out = Vec::new();
        let mut buf = [0u8; 1500];
        for k in 0..n {
            assert!(!tx.has_pending());
            tx.on_new(seq_add(isn, k as i32), &payload(k), ts(k), 0);
            while let Some(len) = tx.write_next(0x55, &mut buf) {
                out.push((k, buf[..len].to_vec()));
            }
        }
        out
    }

    #[test]
    fn sender_emits_libsrt_packets_and_order() {
        let isn = 0x7FFF_FFF0; // across the wrap
        let fec = encode("fec,cols:4,rows:3,layout:staircase", isn, 48);
        for (k, p) in &fec {
            assert_eq!(p.len(), HDR_LEN + 4 + 1316);
            // sequence of the group's last packet = the packet just sent
            assert_eq!(rd32(p, 0), seq_add(isn, *k as i32));
            assert_eq!(rd32(p, 4), 0xC000_0000, "PP=11, msgno 0");
            assert_eq!(rd32(p, 12), 0x55);
        }
        // rows: after k = 3, 7, 11, ...; columns after each group's last
        // member; column first when both end at one packet
        let rows: Vec<i64> = fec.iter().filter(|(_, p)| p[HDR_LEN] == 0xFF).map(|(k, _)| *k).collect();
        assert_eq!(rows, (0..12).map(|r| r * 4 + 3).collect::<Vec<_>>());
        let g = Geometry::new(&cfg("fec,cols:4,rows:3"));
        let mut cols: Vec<(i64, u8)> = fec.iter().filter(|(_, p)| p[HDR_LEN] != 0xFF).map(|(k, p)| (*k, p[HDR_LEN])).collect();
        cols.sort();
        let mut want = Vec::new();
        for id in 0..12 * 4 {
            let last = g.col_member(id, 2);
            if last < 48 {
                want.push((last, (id % 4) as u8));
            }
        }
        want.sort();
        assert_eq!(cols, want);
        // a packet ending both groups: column FEC first
        let both: Vec<&(i64, Vec<u8>)> = fec.iter().filter(|(k, _)| *k == 11).collect();
        assert_eq!(both.len(), 2);
        assert_eq!((both[0].1[HDR_LEN], both[1].1[HDR_LEN]), (3, 0xFF));
        // the row FEC is the XOR of its packets (length, timestamp, payload)
        let (_, r0) = &fec.iter().find(|(k, p)| *k == 3 && p[HDR_LEN] == 0xFF).unwrap();
        let mut acc = vec![0u8; 1316];
        let (mut l, mut t) = (0u16, 0u32);
        for k in 0..4 {
            let p = payload(k);
            xor_into(&mut acc, &p);
            l ^= p.len() as u16;
            t ^= ts(k);
        }
        assert_eq!(&r0[HDR_LEN + 2..HDR_LEN + 4], &l.to_be_bytes());
        assert_eq!(rd32(r0, 8), t);
        assert_eq!(&r0[HDR_LEN + 4..], &acc[..]);
    }

    /// Receive `n` packets minus `lost` with all FEC packets (minus
    /// `fec_lost` by emission index), rebuild, and return the rebuilt offsets.
    fn decode(f: &str, isn: u32, n: i64, lost: &[i64], fec_lost: &[usize]) -> Vec<i64> {
        let fec = encode(f, isn, n);
        let mut rx = FecRx::new(&cfg(f), 1456, isn, 4096);
        let mut got = Vec::new();
        let mut have = std::collections::HashSet::new();
        let mut fi = 0;
        let drain = |rx: &mut FecRx, got: &mut Vec<i64>, have: &mut std::collections::HashSet<i64>| {
            while let Some(r) = rx.next_rebuild() {
                assert!(!have.contains(&r.k), "rebuilt a packet we have: {}", r.k);
                assert_eq!(rx.rebuilt(&r), &payload(r.k)[..], "payload of {}", r.k);
                assert_eq!((r.timestamp, r.len, r.seq), (ts(r.k), payload(r.k).len(), seq_add(isn, r.k as i32)));
                have.insert(r.k);
                got.push(r.k);
                rx.feed_rebuilt(&r);
            }
        };
        for k in 0..n {
            if !lost.contains(&k) {
                have.insert(k);
                rx.feed(seq_add(isn, k as i32), &payload(k), ts(k), 0, None);
                drain(&mut rx, &mut got, &mut have);
            }
            while fi < fec.len() && fec[fi].0 == k {
                if !fec_lost.contains(&fi) {
                    let p = &fec[fi].1;
                    rx.on_fec(rd32(p, 0), &p[HDR_LEN..], rd32(p, 8));
                    drain(&mut rx, &mut got, &mut have);
                }
                fi += 1;
            }
        }
        got.sort();
        got
    }

    /// Brute-force peeling decoder: repeat "a group whose FEC arrived and
    /// that misses exactly one packet gets it back" until nothing changes.
    fn reference(f: &str, isn: u32, n: i64, lost: &[i64], fec_lost: &[usize]) -> Vec<i64> {
        let g = Geometry::new(&cfg(f));
        let fec = encode(f, isn, n);
        let mut groups: Vec<Vec<i64>> = Vec::new();
        for (i, (_, p)) in fec.iter().enumerate() {
            if fec_lost.contains(&i) {
                continue;
            }
            let k = seq_off(isn, rd32(p, 0)) as i64;
            if p[HDR_LEN] == 0xFF {
                let r = k / g.cols();
                groups.push((0..g.cols()).map(|x| r * g.cols() + x).collect());
            } else {
                let (id, _) = g.col_of(k).unwrap();
                groups.push((0..g.rows()).map(|x| g.col_member(id, x)).collect());
            }
        }
        let mut missing: std::collections::BTreeSet<i64> = lost.iter().copied().collect();
        let mut out = Vec::new();
        loop {
            let mut changed = false;
            for m in &groups {
                let miss: Vec<i64> = m.iter().filter(|k| missing.contains(k)).copied().collect();
                if miss.len() == 1 {
                    missing.remove(&miss[0]);
                    out.push(miss[0]);
                    changed = true;
                }
            }
            if !changed {
                break;
            }
        }
        out.sort();
        out
    }

    fn check(f: &str, isn: u32, n: i64, lost: &[i64], fec_lost: &[usize]) -> Vec<i64> {
        let got = decode(f, isn, n, lost, fec_lost);
        assert_eq!(got, reference(f, isn, n, lost, fec_lost), "{f} lost {lost:?} fec_lost {fec_lost:?}");
        got
    }

    #[test]
    fn row_only_rebuilds_one_per_row() {
        let f = "fec,cols:10,rows:1";
        // one loss in rows 0, 2 (its last packet), 3; two in row 1: no rebuild
        assert_eq!(check(f, 5, 50, &[3, 11, 12, 29, 30], &[]), vec![3, 29, 30]);
        // the FEC of row 0 lost: no rebuild there
        assert_eq!(check(f, 5, 50, &[3, 29], &[0]), vec![29]);
    }

    #[test]
    fn staircase_2d_rebuilds_iteratively() {
        let f = "fec,cols:4,rows:3,layout:staircase";
        // 22 and 23 are alone in their columns; 16/20 and 17/21 share
        // columns and rows: stuck
        assert_eq!(check(f, 0x7FFF_FFFE, 96, &[16, 17, 20, 21, 22, 23], &[]), vec![22, 23]);
        // iterative: 40 and 41 in one row, 41 and 45 in one column (rebuilt
        // after 45's row gives it back), then 40 by its row
        let got = check(f, 1, 96, &[40, 41, 45, 49], &[]);
        assert_eq!(got, vec![40, 41, 45, 49]);
        // a packet above its column's first group (k = 1) is row-only
        assert_eq!(check(f, 1, 96, &[1, 2], &[]), Vec::<i64>::new());
    }

    #[test]
    fn even_2d_rebuilds_columns_and_rows() {
        let f = "fec,cols:5,rows:4,layout:even";
        // a burst of a whole row and a single loss in another row
        assert_eq!(check(f, 100, 60, &[5, 6, 7, 8, 9, 33], &[]), vec![5, 6, 7, 8, 9, 33]);
        // 0 and 5 in column 0, 5 and 6 in row 1: row 0 gives 0, column 0
        // then 5, row 1 then 6
        assert_eq!(check(f, 100, 60, &[0, 5, 6], &[]), vec![0, 5, 6]);
        // columns only: 5 and 10 share column 0
        assert_eq!(check("fec,cols:5,rows:-4,layout:even", 100, 60, &[5, 6, 7, 8, 9, 10], &[]), vec![6, 7, 8, 9]);
    }

    #[test]
    fn random_losses_match_the_reference_decoder() {
        let mut x = 0x2545_F491_4F6C_DD1Du64;
        let mut rnd = move || {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x
        };
        for f in [
            "fec,cols:10,rows:5,layout:staircase",
            "fec,cols:10,rows:5,layout:even",
            "fec,cols:20,rows:1",
            "fec,cols:6,rows:-3,layout:staircase",
            "fec,cols:3,rows:7,layout:even",
        ] {
            for pct in [2u64, 5, 10, 20] {
                for _ in 0..6 {
                    let n = 400;
                    let lost: Vec<i64> = (0..n).filter(|_| rnd() % 100 < pct).collect();
                    let nfec = encode(f, 77, n).len();
                    let fec_lost: Vec<usize> = (0..nfec).filter(|_| rnd() % 100 < pct).collect();
                    check(f, 77, n, &lost, &fec_lost);
                }
            }
        }
    }

    #[test]
    fn xor_helpers() {
        let mut a = vec![0u8; 100];
        let mut l = 0u16;
        clip(&mut a, &mut l, &[1, 2, 3]);
        clip(&mut a, &mut l, &[1, 0, 0, 4, 5]);
        assert_eq!((&a[..6], l), (&[0, 2, 3, 4, 5, 0][..], 5));
        for n in 1..40u32 {
            assert_eq!(xor_upto(n), (0..n).fold(0, |x, y| x ^ y));
        }
        let mut d: Vec<u8> = (0..77).collect();
        let s: Vec<u8> = (0..77).map(|x| x * 3).collect();
        xor_into(&mut d, &s);
        assert!(d.iter().enumerate().all(|(i, x)| *x == (i as u8) ^ (i as u8 * 3)));
    }
}
