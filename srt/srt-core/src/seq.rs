//! 31-bit sequence numbers, 26-bit message numbers and ACK numbers
//! (spec section 1).

/// Largest sequence number (sequences are 31-bit).
pub const SEQ_MAX: u32 = 0x7FFF_FFFF;
/// Half-range threshold for modular comparison.
pub const SEQ_THRESHOLD: u32 = 0x3FFF_FFFF;
/// Largest message number (26-bit); message numbers run 1..=MSGNO_MAX.
pub const MSGNO_MAX: u32 = 0x03FF_FFFF;

/// `a + n` modulo 2^31.
#[inline]
pub fn seq_add(a: u32, n: i32) -> u32 {
    a.wrapping_add(n as u32) & SEQ_MAX
}

/// `a + 1` modulo 2^31.
#[inline]
pub fn seq_inc(a: u32) -> u32 {
    a.wrapping_add(1) & SEQ_MAX
}

/// `a - 1` modulo 2^31.
#[inline]
pub fn seq_dec(a: u32) -> u32 {
    a.wrapping_sub(1) & SEQ_MAX
}

/// Signed distance from `a` to `b` (`b - a`), using the half-range rule.
#[inline]
pub fn seq_off(a: u32, b: u32) -> i32 {
    let d = b.wrapping_sub(a) & SEQ_MAX;
    if d > SEQ_THRESHOLD {
        (d as i64 - (1i64 << 31)) as i32
    } else {
        d as i32
    }
}

/// Modular comparison: negative if `a` is before `b`, 0 if equal, positive
/// if after.
#[inline]
pub fn seq_cmp(a: u32, b: u32) -> i32 {
    seq_off(b, a)
}

/// `a < b` in modular order.
#[inline]
pub fn seq_lt(a: u32, b: u32) -> bool {
    seq_cmp(a, b) < 0
}

/// `a <= b` in modular order.
#[inline]
pub fn seq_le(a: u32, b: u32) -> bool {
    seq_cmp(a, b) <= 0
}

/// The later of two sequences.
#[inline]
pub fn seq_max(a: u32, b: u32) -> u32 {
    if seq_lt(a, b) {
        b
    } else {
        a
    }
}

/// Next message number: 1 ..= MSGNO_MAX, never 0 (0 is reserved for FEC).
#[inline]
pub fn msgno_inc(m: u32) -> u32 {
    if m >= MSGNO_MAX {
        1
    } else {
        m + 1
    }
}

/// Next ACK number (journal counter): 1 ..= SEQ_MAX, then 1 again (0 is a
/// light ACK).
#[inline]
pub fn ackno_inc(a: u32) -> u32 {
    if a >= SEQ_MAX {
        1
    } else {
        a + 1
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn offsets_and_wrap() {
        assert_eq!(seq_off(10, 15), 5);
        assert_eq!(seq_off(15, 10), -5);
        assert_eq!(seq_off(SEQ_MAX, 0), 1);
        assert_eq!(seq_off(0, SEQ_MAX), -1);
        assert_eq!(seq_off(SEQ_MAX - 2, 3), 6);
        assert_eq!(seq_add(SEQ_MAX, 1), 0);
        assert_eq!(seq_add(0, -1), SEQ_MAX);
        assert_eq!(seq_inc(SEQ_MAX), 0);
        assert_eq!(seq_dec(0), SEQ_MAX);
        assert!(seq_lt(SEQ_MAX, 0));
        assert!(seq_lt(SEQ_MAX - 100, 50));
        assert!(!seq_lt(50, SEQ_MAX - 100));
        assert_eq!(seq_max(SEQ_MAX, 2), 2);
        // threshold: exactly 2^30 - 1 ahead is "after"
        assert_eq!(seq_off(0, SEQ_THRESHOLD), SEQ_THRESHOLD as i32);
        assert_eq!(seq_off(0, SEQ_THRESHOLD + 1), -(1 << 30));
    }

    #[test]
    fn msgno_and_ackno() {
        assert_eq!(msgno_inc(1), 2);
        assert_eq!(msgno_inc(MSGNO_MAX), 1);
        assert_eq!(ackno_inc(0), 1);
        assert_eq!(ackno_inc(SEQ_MAX), 1);
    }
}
