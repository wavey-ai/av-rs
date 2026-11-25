//! Fixed-size packet slots, allocated in chunks and recycled LIFO, so the
//! hot path never allocates and memory follows the packets in flight (not
//! the configured buffer size).

const CHUNK: u32 = 256;

pub(crate) const NONE: u32 = u32::MAX;

pub(crate) struct Pool {
    slot: usize,
    max: u32,
    chunks: Vec<Box<[u8]>>,
    free: Vec<u32>,
    allocated: u32,
}

impl Pool {
    pub fn new(slot: usize, max: u32) -> Pool {
        Pool {
            slot,
            max,
            chunks: Vec::new(),
            free: Vec::new(),
            allocated: 0,
        }
    }

    pub fn alloc(&mut self) -> Option<u32> {
        if let Some(i) = self.free.pop() {
            return Some(i);
        }
        if self.allocated >= self.max {
            return None;
        }
        let n = CHUNK.min(self.max - self.allocated);
        self.chunks.push(vec![0u8; CHUNK as usize * self.slot].into_boxed_slice());
        self.free.reserve(n as usize);
        for i in (self.allocated..self.allocated + n).rev() {
            self.free.push(i);
        }
        self.allocated += n;
        self.free.pop()
    }

    #[inline]
    pub fn free(&mut self, i: u32) {
        self.free.push(i);
    }

    #[inline]
    pub fn get(&self, i: u32) -> &[u8] {
        let (c, o) = ((i / CHUNK) as usize, (i % CHUNK) as usize * self.slot);
        &self.chunks[c][o..o + self.slot]
    }

    #[inline]
    pub fn get_mut(&mut self, i: u32) -> &mut [u8] {
        let (c, o) = ((i / CHUNK) as usize, (i % CHUNK) as usize * self.slot);
        &mut self.chunks[c][o..o + self.slot]
    }

    /// Slots allocated so far (memory footprint / slot size).
    pub fn allocated(&self) -> u32 {
        self.allocated
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alloc_free_reuse_and_limit() {
        let mut p = Pool::new(8, 300);
        let a = p.alloc().unwrap();
        assert_eq!(a, 0);
        p.get_mut(a)[0] = 7;
        p.free(a);
        assert_eq!(p.alloc(), Some(a), "LIFO reuse");
        assert_eq!(p.get(a)[0], 7);
        let mut got = vec![a];
        while let Some(i) = p.alloc() {
            got.push(i);
        }
        assert_eq!(got.len(), 300);
        assert_eq!(p.allocated(), 300);
        p.get_mut(299)[7] = 1;
    }
}
