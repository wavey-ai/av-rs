//! SRT packet codec: the 16-byte header, data packets and every control
//! type (spec sections 2 and 3). Decoding borrows the datagram; encoding
//! writes into a caller-supplied buffer and returns the length.

use crate::handshake::Handshake;
use std::fmt;

/// SRT header length.
pub const HDR_LEN: usize = 16;
/// IPv4 + UDP + SRT header bytes per packet (libsrt's byte counters convention).
pub const PKT_OVERHEAD: usize = 44;
/// libsrt's receive unit: larger datagrams are dropped by it.
pub const MAX_DATAGRAM: usize = 1500;

/// Control packet types (spec 2.2).
pub mod ctrl {
    pub const HANDSHAKE: u16 = 0;
    pub const KEEPALIVE: u16 = 1;
    pub const ACK: u16 = 2;
    pub const NAK: u16 = 3;
    pub const CGWARNING: u16 = 4;
    pub const SHUTDOWN: u16 = 5;
    pub const ACKACK: u16 = 6;
    pub const DROPREQ: u16 = 7;
    pub const PEERERROR: u16 = 8;
    pub const EXT: u16 = 0x7FFF;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DecodeError {
    /// Shorter than the 16-byte header.
    TooShort,
    /// A control CIF that is malformed for its type.
    BadControl(u16),
    /// A handshake CIF shorter than 48 bytes.
    BadHandshake,
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DecodeError::TooShort => write!(f, "datagram shorter than the SRT header"),
            DecodeError::BadControl(t) => write!(f, "malformed control packet type {t}"),
            DecodeError::BadHandshake => write!(f, "malformed handshake"),
        }
    }
}

impl std::error::Error for DecodeError {}

#[inline]
pub(crate) fn rd32(b: &[u8], off: usize) -> u32 {
    u32::from_be_bytes([b[off], b[off + 1], b[off + 2], b[off + 3]])
}

#[inline]
pub(crate) fn wr32(b: &mut [u8], off: usize, v: u32) {
    b[off..off + 4].copy_from_slice(&v.to_be_bytes());
}

/// Is this datagram a control packet? (bit 31 of word 0)
#[inline]
pub fn is_control(b: &[u8]) -> bool {
    !b.is_empty() && b[0] & 0x80 != 0
}

/// Destination socket ID of a datagram (word 3), if it has a header.
#[inline]
pub fn dst_socket_id(b: &[u8]) -> Option<u32> {
    (b.len() >= HDR_LEN).then(|| rd32(b, 12))
}

/// Packet position flag (PP) of a data packet.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Position {
    Middle = 0,
    Last = 1,
    First = 2,
    Solo = 3,
}

impl Position {
    fn from_bits(b: u32) -> Position {
        match b & 3 {
            0 => Position::Middle,
            1 => Position::Last,
            2 => Position::First,
            _ => Position::Solo,
        }
    }
}

/// Header of a data packet (spec 2.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DataHeader {
    pub seq: u32,
    pub position: Position,
    pub in_order: bool,
    /// KK: 0 clear, 1 even key, 2 odd key.
    pub key: u8,
    pub rexmit: bool,
    pub msgno: u32,
    pub timestamp: u32,
    pub dst: u32,
}

impl DataHeader {
    /// Word 1 (position, order, key, R, message number).
    #[inline]
    pub fn word1(&self) -> u32 {
        ((self.position as u32) << 30)
            | ((self.in_order as u32) << 29)
            | (((self.key & 3) as u32) << 27)
            | ((self.rexmit as u32) << 26)
            | (self.msgno & 0x03FF_FFFF)
    }

    #[inline]
    pub fn encode(&self, b: &mut [u8]) {
        wr32(b, 0, self.seq & 0x7FFF_FFFF);
        wr32(b, 4, self.word1());
        wr32(b, 8, self.timestamp);
        wr32(b, 12, self.dst);
    }

    #[inline]
    pub fn decode(b: &[u8]) -> DataHeader {
        let w1 = rd32(b, 4);
        DataHeader {
            seq: rd32(b, 0) & 0x7FFF_FFFF,
            position: Position::from_bits(w1 >> 30),
            in_order: w1 & (1 << 29) != 0,
            key: ((w1 >> 27) & 3) as u8,
            rexmit: w1 & (1 << 26) != 0,
            msgno: w1 & 0x03FF_FFFF,
            timestamp: rd32(b, 8),
            dst: rd32(b, 12),
        }
    }

    /// Set the R (retransmitted) bit of an encoded data header in place.
    #[inline]
    pub fn set_rexmit_in_place(b: &mut [u8]) {
        b[4] |= 0x04;
    }
}

/// Header of a control packet (spec 2.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ControlHeader {
    pub ctype: u16,
    pub subtype: u16,
    /// Type-specific information (ACK number, message number, error code...).
    pub info: u32,
    pub timestamp: u32,
    pub dst: u32,
}

impl ControlHeader {
    pub fn new(ctype: u16, info: u32, timestamp: u32, dst: u32) -> Self {
        ControlHeader {
            ctype,
            subtype: 0,
            info,
            timestamp,
            dst,
        }
    }

    #[inline]
    pub fn encode(&self, b: &mut [u8]) {
        wr32(b, 0, 0x8000_0000 | ((self.ctype as u32 & 0x7FFF) << 16) | self.subtype as u32);
        wr32(b, 4, self.info);
        wr32(b, 8, self.timestamp);
        wr32(b, 12, self.dst);
    }

    #[inline]
    pub fn decode(b: &[u8]) -> ControlHeader {
        let w0 = rd32(b, 0);
        ControlHeader {
            ctype: ((w0 >> 16) & 0x7FFF) as u16,
            subtype: (w0 & 0xFFFF) as u16,
            info: rd32(b, 4),
            timestamp: rd32(b, 8),
            dst: rd32(b, 12),
        }
    }
}

/// ACK size class (spec 3.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AckKind {
    /// 4 bytes, ACK number 0, no ACKACK expected.
    Light,
    /// 16 bytes.
    Small,
    /// 28 bytes.
    Full,
}

/// ACK control information.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ack {
    pub kind: AckKind,
    /// First sequence not received contiguously.
    pub seq: u32,
    pub rtt_us: u32,
    pub rtt_var_us: u32,
    /// Available receive buffer, packets.
    pub avail_buf: u32,
    /// Packet receive rate, packets/s (full ACK only).
    pub pkt_rate: u32,
    /// Estimated link capacity, packets/s (full ACK only).
    pub bandwidth: u32,
    /// Receive rate, bytes/s (full ACK only).
    pub byte_rate: u32,
}

impl Ack {
    pub fn light(seq: u32) -> Ack {
        Ack {
            kind: AckKind::Light,
            seq,
            rtt_us: 0,
            rtt_var_us: 0,
            avail_buf: 0,
            pkt_rate: 0,
            bandwidth: 0,
            byte_rate: 0,
        }
    }

    fn cif_len(&self) -> usize {
        match self.kind {
            AckKind::Light => 4,
            AckKind::Small => 16,
            AckKind::Full => 28,
        }
    }
}

/// A NAK loss list, borrowed from the datagram; validated at decode.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LossList<'a> {
    raw: &'a [u8],
}

impl<'a> LossList<'a> {
    fn parse(raw: &'a [u8]) -> Option<LossList<'a>> {
        if raw.len() % 4 != 0 {
            return None;
        }
        let l = LossList { raw };
        // a range start must be followed by an end word with bit 31 clear
        let n = raw.len() / 4;
        let mut i = 0;
        while i < n {
            let w = rd32(raw, i * 4);
            if w & 0x8000_0000 != 0 {
                if i + 1 >= n || rd32(raw, (i + 1) * 4) & 0x8000_0000 != 0 {
                    return None;
                }
                i += 2;
            } else {
                i += 1;
            }
        }
        Some(l)
    }

    /// Ranges `(first, last)` inclusive; a single loss is `(s, s)`.
    pub fn ranges(&self) -> LossRanges<'a> {
        LossRanges { raw: self.raw, pos: 0 }
    }

    pub fn raw(&self) -> &'a [u8] {
        self.raw
    }
}

pub struct LossRanges<'a> {
    raw: &'a [u8],
    pos: usize,
}

impl<'a> Iterator for LossRanges<'a> {
    type Item = (u32, u32);
    fn next(&mut self) -> Option<(u32, u32)> {
        if self.pos + 4 > self.raw.len() {
            return None;
        }
        let w = rd32(self.raw, self.pos);
        self.pos += 4;
        if w & 0x8000_0000 != 0 {
            let last = rd32(self.raw, self.pos);
            self.pos += 4;
            Some((w & 0x7FFF_FFFF, last & 0x7FFF_FFFF))
        } else {
            Some((w, w))
        }
    }
}

/// Body of a control packet.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Control<'a> {
    Handshake(Box<Handshake>),
    KeepAlive,
    /// ACK number is `ControlHeader::info` (0 for a light ACK).
    Ack(Ack),
    Nak(LossList<'a>),
    CongestionWarning,
    Shutdown,
    /// ACK number being confirmed is `ControlHeader::info`.
    AckAck,
    /// Message number is `ControlHeader::info`.
    DropReq {
        first: u32,
        last: u32,
    },
    /// Error code is `ControlHeader::info`.
    PeerError,
    /// EXT (0x7FFF) or an unknown type: carried raw.
    Other {
        cif: &'a [u8],
    },
}

/// A decoded packet.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Packet<'a> {
    Data { hdr: DataHeader, payload: &'a [u8] },
    Control { hdr: ControlHeader, body: Control<'a> },
}

/// Decode one datagram.
pub fn decode(b: &[u8]) -> Result<Packet<'_>, DecodeError> {
    if b.len() < HDR_LEN {
        return Err(DecodeError::TooShort);
    }
    if !is_control(b) {
        return Ok(Packet::Data {
            hdr: DataHeader::decode(b),
            payload: &b[HDR_LEN..],
        });
    }
    let hdr = ControlHeader::decode(b);
    let cif = &b[HDR_LEN..];
    let bad = DecodeError::BadControl(hdr.ctype);
    let body = match hdr.ctype {
        ctrl::HANDSHAKE => Control::Handshake(Box::new(Handshake::decode(cif).ok_or(DecodeError::BadHandshake)?)),
        ctrl::KEEPALIVE => Control::KeepAlive,
        ctrl::ACK => {
            let n = cif.len();
            if n < 4 {
                return Err(bad);
            }
            let seq = rd32(cif, 0) & 0x7FFF_FFFF;
            if n < 16 {
                if n != 4 {
                    return Err(bad);
                }
                Control::Ack(Ack::light(seq))
            } else {
                let full = n >= 28;
                Control::Ack(Ack {
                    kind: if full { AckKind::Full } else { AckKind::Small },
                    seq,
                    rtt_us: rd32(cif, 4),
                    rtt_var_us: rd32(cif, 8),
                    avail_buf: rd32(cif, 12),
                    pkt_rate: if full { rd32(cif, 16) } else { 0 },
                    bandwidth: if full { rd32(cif, 20) } else { 0 },
                    byte_rate: if full { rd32(cif, 24) } else { 0 },
                })
            }
        }
        ctrl::NAK => Control::Nak(LossList::parse(cif).ok_or(bad)?),
        ctrl::CGWARNING => Control::CongestionWarning,
        ctrl::SHUTDOWN => Control::Shutdown,
        ctrl::ACKACK => Control::AckAck,
        ctrl::DROPREQ => {
            if cif.len() < 8 {
                return Err(bad);
            }
            Control::DropReq {
                first: rd32(cif, 0) & 0x7FFF_FFFF,
                last: rd32(cif, 4) & 0x7FFF_FFFF,
            }
        }
        ctrl::PEERERROR => Control::PeerError,
        _ => Control::Other { cif },
    };
    Ok(Packet::Control { hdr, body })
}

// ---------------------------------------------------------------- encoders

/// A control packet with a 4-byte zero CIF (KEEPALIVE, SHUTDOWN, ACKACK,
/// CGWARNING, PEERERROR): libsrt drops control packets with an empty CIF.
pub fn encode_simple(ctype: u16, info: u32, timestamp: u32, dst: u32, b: &mut [u8]) -> usize {
    ControlHeader::new(ctype, info, timestamp, dst).encode(b);
    wr32(b, HDR_LEN, 0);
    HDR_LEN + 4
}

pub fn encode_keepalive(timestamp: u32, dst: u32, b: &mut [u8]) -> usize {
    encode_simple(ctrl::KEEPALIVE, 0, timestamp, dst, b)
}

pub fn encode_shutdown(timestamp: u32, dst: u32, b: &mut [u8]) -> usize {
    encode_simple(ctrl::SHUTDOWN, 0, timestamp, dst, b)
}

pub fn encode_ackack(ackno: u32, timestamp: u32, dst: u32, b: &mut [u8]) -> usize {
    encode_simple(ctrl::ACKACK, ackno, timestamp, dst, b)
}

/// ACK; `ackno` must be 0 for a light ACK.
pub fn encode_ack(ack: &Ack, ackno: u32, timestamp: u32, dst: u32, b: &mut [u8]) -> usize {
    ControlHeader::new(ctrl::ACK, ackno, timestamp, dst).encode(b);
    let words = [
        ack.seq & 0x7FFF_FFFF,
        ack.rtt_us,
        ack.rtt_var_us,
        ack.avail_buf,
        ack.pkt_rate,
        ack.bandwidth,
        ack.byte_rate,
    ];
    let n = ack.cif_len() / 4;
    for (i, w) in words.iter().take(n).enumerate() {
        wr32(b, HDR_LEN + i * 4, *w);
    }
    HDR_LEN + n * 4
}

/// NAK from inclusive ranges; at most `max_words` loss words (libsrt limits a
/// NAK to maxPayload/4). Returns the length (0 if there was nothing to send).
pub fn encode_nak<I: IntoIterator<Item = (u32, u32)>>(ranges: I, timestamp: u32, dst: u32, max_words: usize, b: &mut [u8]) -> usize {
    ControlHeader::new(ctrl::NAK, 0, timestamp, dst).encode(b);
    let mut off = HDR_LEN;
    let mut words = 0;
    for (first, last) in ranges {
        if first == last {
            if words + 1 > max_words {
                break;
            }
            wr32(b, off, first & 0x7FFF_FFFF);
            off += 4;
            words += 1;
        } else {
            if words + 2 > max_words {
                break;
            }
            wr32(b, off, 0x8000_0000 | (first & 0x7FFF_FFFF));
            wr32(b, off + 4, last & 0x7FFF_FFFF);
            off += 8;
            words += 2;
        }
    }
    if words == 0 {
        0
    } else {
        off
    }
}

pub fn encode_dropreq(msgno: u32, first: u32, last: u32, timestamp: u32, dst: u32, b: &mut [u8]) -> usize {
    ControlHeader::new(ctrl::DROPREQ, msgno, timestamp, dst).encode(b);
    wr32(b, HDR_LEN, first & 0x7FFF_FFFF);
    wr32(b, HDR_LEN + 4, last & 0x7FFF_FFFF);
    HDR_LEN + 8
}

/// HANDSHAKE control packet; returns the length.
pub fn encode_handshake(hs: &Handshake, timestamp: u32, dst: u32, b: &mut [u8]) -> usize {
    ControlHeader::new(ctrl::HANDSHAKE, 0, timestamp, dst).encode(b);
    HDR_LEN + hs.encode(&mut b[HDR_LEN..])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn data_header_round_trip() {
        let h = DataHeader {
            seq: 0x51ca_2477,
            position: Position::Solo,
            in_order: false,
            key: 0,
            rexmit: true,
            msgno: 3,
            timestamp: 0xa99c,
            dst: 0x19f0_1a4b,
        };
        let mut b = [0u8; 16];
        h.encode(&mut b);
        assert_eq!(DataHeader::decode(&b), h);
        assert_eq!(&b[4..8], &[0xc4, 0, 0, 3]);
        let mut h2 = h;
        h2.rexmit = false;
        h2.encode(&mut b);
        DataHeader::set_rexmit_in_place(&mut b);
        assert_eq!(DataHeader::decode(&b), h);
    }

    #[test]
    fn simple_controls_have_4_byte_cif() {
        let mut b = [0u8; 64];
        let n = encode_keepalive(7, 9, &mut b);
        assert_eq!(n, 20);
        assert_eq!(&b[..4], &[0x80, 0x01, 0, 0]);
        let n = encode_ackack(5, 7, 9, &mut b);
        assert_eq!(n, 20);
        match decode(&b[..n]).unwrap() {
            Packet::Control { hdr, body: Control::AckAck } => assert_eq!(hdr.info, 5),
            p => panic!("{p:?}"),
        }
        let n = encode_shutdown(7, 9, &mut b);
        assert!(matches!(decode(&b[..n]).unwrap(), Packet::Control { body: Control::Shutdown, .. }));
    }

    #[test]
    fn ack_round_trip_all_sizes() {
        let mut b = [0u8; 64];
        for kind in [AckKind::Light, AckKind::Small, AckKind::Full] {
            let mut a = Ack {
                kind,
                seq: 77,
                rtt_us: 1000,
                rtt_var_us: 500,
                avail_buf: 8000,
                pkt_rate: 10,
                bandwidth: 20,
                byte_rate: 30,
            };
            if kind == AckKind::Light {
                a = Ack::light(77);
            }
            if kind != AckKind::Full {
                a.pkt_rate = 0;
                a.bandwidth = 0;
                a.byte_rate = 0;
            }
            let ackno = if kind == AckKind::Light { 0 } else { 12 };
            let n = encode_ack(&a, ackno, 1, 2, &mut b);
            assert_eq!(n, HDR_LEN + a.cif_len());
            match decode(&b[..n]).unwrap() {
                Packet::Control { hdr, body: Control::Ack(d) } => {
                    assert_eq!(hdr.info, ackno);
                    assert_eq!(d, a);
                }
                p => panic!("{p:?}"),
            }
        }
        // 8 bytes is neither light nor small: malformed
        let n = encode_ack(&Ack::light(1), 0, 1, 2, &mut b);
        assert!(decode(&b[..n + 4]).is_err());
    }

    #[test]
    fn nak_round_trip_and_limits() {
        let mut b = [0u8; 128];
        let ranges = [(5u32, 5u32), (10, 20), (0x7FFF_FFFE, 0x7FFF_FFFF)];
        let n = encode_nak(ranges, 1, 2, 100, &mut b);
        assert_eq!(n, HDR_LEN + 4 * 5);
        match decode(&b[..n]).unwrap() {
            Packet::Control { body: Control::Nak(l), .. } => {
                assert_eq!(l.ranges().collect::<Vec<_>>(), ranges.to_vec());
            }
            p => panic!("{p:?}"),
        }
        // limited to 2 words: the single and nothing else (range needs 2 more)
        let n = encode_nak(ranges, 1, 2, 2, &mut b);
        assert_eq!(n, HDR_LEN + 4);
        assert_eq!(encode_nak(std::iter::empty(), 1, 2, 10, &mut b), 0);
        // a dangling range start is malformed
        ControlHeader::new(ctrl::NAK, 0, 0, 0).encode(&mut b);
        wr32(&mut b, 16, 0x8000_0005);
        assert!(decode(&b[..20]).is_err());
    }

    #[test]
    fn dropreq_round_trip() {
        let mut b = [0u8; 32];
        let n = encode_dropreq(9, 100, 200, 1, 2, &mut b);
        match decode(&b[..n]).unwrap() {
            Packet::Control {
                hdr,
                body: Control::DropReq { first, last },
            } => {
                assert_eq!((hdr.info, first, last), (9, 100, 200));
            }
            p => panic!("{p:?}"),
        }
    }

    #[test]
    fn short_datagram_rejected() {
        assert_eq!(decode(&[0u8; 15]), Err(DecodeError::TooShort));
        assert_eq!(dst_socket_id(&[0u8; 15]), None);
    }
}
