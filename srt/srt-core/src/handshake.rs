//! The HSv5 handshake CIF and its extension blocks (spec section 4).

use crate::packet::{rd32, wr32};
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Handshake CIF length without extensions.
pub const HS_CIF_LEN: usize = 48;
/// Extension field magic in the listener's induction response.
pub const HS_MAGIC: u16 = 0x4A17;
/// Our SRT version in HSREQ/HSRSP (as libsrt 1.5.7).
pub const SRT_VERSION: u32 = 0x0001_0507;
/// Lowest peer SRT version accepted for HSv5.
pub const SRT_MIN_VERSION: u32 = 0x0001_0300;
/// `UDT_DGRAM`, the caller induction's type word.
pub const UDT_DGRAM: u32 = 2;

/// HSREQ/HSRSP flags (spec 4.3).
pub mod flags {
    pub const TSBPDSND: u32 = 0x01;
    pub const TSBPDRCV: u32 = 0x02;
    pub const HAICRYPT: u32 = 0x04;
    pub const TLPKTDROP: u32 = 0x08;
    pub const NAKREPORT: u32 = 0x10;
    pub const REXMITFLG: u32 = 0x20;
    pub const STREAM: u32 = 0x40;
    pub const FILTERCAP: u32 = 0x80;
    /// What libsrt live-mode sockets send: everything but STREAM.
    pub const LIVE: u32 = TSBPDSND | TSBPDRCV | HAICRYPT | TLPKTDROP | NAKREPORT | REXMITFLG | FILTERCAP;
}

/// Extension field flags of a conclusion (spec 4.1).
pub mod ext {
    pub const HSREQ: u16 = 0x1;
    pub const KMREQ: u16 = 0x2;
    pub const CONFIG: u16 = 0x4;
}

/// Extension block commands (spec 4.2).
pub mod cmd {
    pub const HSREQ: u16 = 1;
    pub const HSRSP: u16 = 2;
    pub const KMREQ: u16 = 3;
    pub const KMRSP: u16 = 4;
    pub const SID: u16 = 5;
    pub const CONGESTION: u16 = 6;
    pub const FILTER: u16 = 7;
    pub const GROUP: u16 = 8;
}

/// Request types (word 5).
pub mod req {
    pub const INDUCTION: u32 = 1;
    pub const WAVEAHAND: u32 = 0;
    pub const CONCLUSION: u32 = 0xFFFF_FFFF;
    pub const AGREEMENT: u32 = 0xFFFF_FFFE;
    /// Rejections are 1000 + reason.
    pub const REJECT_BASE: u32 = 1000;
}

/// Maximum stream ID length (bytes).
pub const MAX_SID_LEN: usize = 512;
/// Maximum packet filter config length (bytes).
pub const MAX_FILTER_LEN: usize = 64;

/// Rejection reasons (spec 4.6). `App(n)` is an application reason
/// (`SRT_REJX_*`, n >= 1000): the wire value is 1000 + n, so "forbidden"
/// is `App(1403)`, 2403 on the wire.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum RejectReason {
    Unknown,
    System,
    Peer,
    Resource,
    Rogue,
    Backlog,
    Ipe,
    Close,
    Version,
    RdvCookie,
    BadSecret,
    Unsecure,
    MessageApi,
    Congestion,
    Filter,
    Group,
    /// Local only: the handshake did not complete in time.
    Timeout,
    /// Application code (`SRT_REJX_*`): wire value is 1000 + this (>= 1000).
    App(u32),
}

impl RejectReason {
    /// The reason number (`SRT_REJ_*`, or >= 1000 for application codes).
    pub fn code(self) -> u32 {
        use RejectReason::*;
        match self {
            Unknown => 0,
            System => 1,
            Peer => 2,
            Resource => 3,
            Rogue => 4,
            Backlog => 5,
            Ipe => 6,
            Close => 7,
            Version => 8,
            RdvCookie => 9,
            BadSecret => 10,
            Unsecure => 11,
            MessageApi => 12,
            Congestion => 13,
            Filter => 14,
            Group => 15,
            Timeout => 16,
            App(n) => n,
        }
    }

    pub fn from_code(c: u32) -> RejectReason {
        use RejectReason::*;
        match c {
            1 => System,
            2 => Peer,
            3 => Resource,
            4 => Rogue,
            5 => Backlog,
            6 => Ipe,
            7 => Close,
            8 => Version,
            9 => RdvCookie,
            10 => BadSecret,
            11 => Unsecure,
            12 => MessageApi,
            13 => Congestion,
            14 => Filter,
            15 => Group,
            16 => Timeout,
            n if n >= 1000 => App(n),
            _ => Unknown,
        }
    }

    /// Request type value on the wire (1000 + code).
    pub fn to_wire(self) -> u32 {
        req::REJECT_BASE + self.code()
    }

    /// Parse a request type; `None` if it is not a rejection.
    pub fn from_wire(req_type: u32) -> Option<RejectReason> {
        if (req::REJECT_BASE..req::AGREEMENT).contains(&req_type) {
            Some(RejectReason::from_code(req_type - req::REJECT_BASE))
        } else {
            None
        }
    }
}

impl fmt::Display for RejectReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?} ({})", self, self.to_wire())
    }
}

/// HSREQ / HSRSP body.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SrtHsExt {
    pub version: u32,
    pub flags: u32,
    /// High half of word 2: the receiver TSBPD delay (ms).
    pub recv_delay_ms: u16,
    /// Low half of word 2: the sender TSBPD delay (ms).
    pub send_delay_ms: u16,
}

/// A handshake CIF with its extension blocks.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct Handshake {
    pub version: u32,
    /// Bits 31-16 of word 1: PBKEYLEN/8 (0 = no encryption).
    pub encryption: u16,
    /// Bits 15-0 of word 1: magic, extension flags or (induction) part of UDT_DGRAM.
    pub ext_field: u16,
    pub isn: u32,
    pub mss: u32,
    pub flow_window: u32,
    pub req_type: u32,
    pub socket_id: u32,
    pub cookie: u32,
    /// Words 8-11 as read from the wire (big-endian words).
    pub peer_ip: [u32; 4],
    pub hsreq: Option<SrtHsExt>,
    pub hsrsp: Option<SrtHsExt>,
    pub stream_id: Option<String>,
    pub congestion: Option<String>,
    pub filter: Option<String>,
    /// A KMREQ block was present (encryption requested).
    pub kmreq: bool,
    /// A KMRSP block was present.
    pub kmrsp: bool,
    pub group: bool,
}

/// Encode an IP address as handshake words 8-11 (spec section 1: each
/// 4-byte group reversed on the wire).
pub fn ip_to_words(ip: IpAddr) -> [u32; 4] {
    match ip {
        IpAddr::V4(a) => [u32::from_le_bytes(a.octets()), 0, 0, 0],
        IpAddr::V6(a) => {
            let o = a.octets();
            let mut w = [0u32; 4];
            for (i, x) in w.iter_mut().enumerate() {
                *x = u32::from_le_bytes([o[4 * i], o[4 * i + 1], o[4 * i + 2], o[4 * i + 3]]);
            }
            w
        }
    }
}

/// Decode handshake words 8-11 (IPv4 when words 9-11 are zero).
pub fn words_to_ip(w: &[u32; 4]) -> IpAddr {
    if w[1] == 0 && w[2] == 0 && w[3] == 0 {
        IpAddr::V4(Ipv4Addr::from(w[0].to_le_bytes()))
    } else {
        let mut o = [0u8; 16];
        for i in 0..4 {
            o[4 * i..4 * i + 4].copy_from_slice(&w[i].to_le_bytes());
        }
        IpAddr::V6(Ipv6Addr::from(o))
    }
}

/// Write a config string as libsrt does: zero-padded to whole words, each
/// 4-byte group reversed. Returns the number of words.
fn put_string(s: &str, b: &mut [u8]) -> usize {
    let bytes = s.as_bytes();
    let words = (bytes.len() + 3) / 4;
    for w in 0..words {
        let mut chunk = [0u8; 4];
        for (i, c) in chunk.iter_mut().enumerate() {
            if let Some(&x) = bytes.get(w * 4 + i) {
                *c = x;
            }
        }
        chunk.reverse();
        b[w * 4..w * 4 + 4].copy_from_slice(&chunk);
    }
    words
}

/// Read a word-swapped config string, trimming trailing NULs.
fn get_string(b: &[u8]) -> String {
    let mut out = Vec::with_capacity(b.len());
    for chunk in b.chunks_exact(4) {
        out.extend([chunk[3], chunk[2], chunk[1], chunk[0]]);
    }
    while out.last() == Some(&0) {
        out.pop();
    }
    String::from_utf8_lossy(&out).into_owned()
}

impl Handshake {
    /// Is this a rejection?
    pub fn reject_reason(&self) -> Option<RejectReason> {
        RejectReason::from_wire(self.req_type)
    }

    /// Extension flags a conclusion carrying these blocks must advertise.
    pub fn conclusion_ext_flags(&self) -> u16 {
        let mut f = 0;
        if self.hsreq.is_some() || self.hsrsp.is_some() {
            f |= ext::HSREQ;
        }
        if self.kmreq || self.kmrsp {
            f |= ext::KMREQ;
        }
        if self.stream_id.is_some() || self.congestion.is_some() || self.filter.is_some() || self.group {
            f |= ext::CONFIG;
        }
        f
    }

    /// Bytes `encode` will write.
    pub fn encoded_len(&self) -> usize {
        let mut n = HS_CIF_LEN;
        if self.hsreq.is_some() {
            n += 16;
        }
        if self.hsrsp.is_some() {
            n += 16;
        }
        for s in [&self.stream_id, &self.congestion, &self.filter].into_iter().flatten() {
            n += 4 + (s.len() + 3) / 4 * 4;
        }
        n
    }

    /// Encode the CIF (48 bytes + blocks in libsrt's order: HSREQ/HSRSP, SID,
    /// CONGESTION, FILTER). KMREQ/GROUP are never emitted. Returns the length.
    pub fn encode(&self, b: &mut [u8]) -> usize {
        wr32(b, 0, self.version);
        wr32(b, 4, ((self.encryption as u32) << 16) | self.ext_field as u32);
        wr32(b, 8, self.isn);
        wr32(b, 12, self.mss);
        wr32(b, 16, self.flow_window);
        wr32(b, 20, self.req_type);
        wr32(b, 24, self.socket_id);
        wr32(b, 28, self.cookie);
        for i in 0..4 {
            wr32(b, 32 + 4 * i, self.peer_ip[i]);
        }
        let mut off = HS_CIF_LEN;
        for (c, e) in [(cmd::HSREQ, &self.hsreq), (cmd::HSRSP, &self.hsrsp)] {
            if let Some(e) = e {
                wr32(b, off, (c as u32) << 16 | 3);
                wr32(b, off + 4, e.version);
                wr32(b, off + 8, e.flags);
                wr32(b, off + 12, (e.recv_delay_ms as u32) << 16 | e.send_delay_ms as u32);
                off += 16;
            }
        }
        for (c, s) in [(cmd::SID, &self.stream_id), (cmd::CONGESTION, &self.congestion), (cmd::FILTER, &self.filter)] {
            if let Some(s) = s {
                let words = put_string(s, &mut b[off + 4..]);
                wr32(b, off, (c as u32) << 16 | words as u32);
                off += 4 + words * 4;
            }
        }
        off
    }

    /// Decode a handshake CIF; `None` if shorter than 48 bytes. Blocks
    /// whose length overruns the packet end parsing; unknown ones are skipped.
    pub fn decode(b: &[u8]) -> Option<Handshake> {
        if b.len() < HS_CIF_LEN {
            return None;
        }
        let w1 = rd32(b, 4);
        let mut hs = Handshake {
            version: rd32(b, 0),
            encryption: (w1 >> 16) as u16,
            ext_field: w1 as u16,
            isn: rd32(b, 8),
            mss: rd32(b, 12),
            flow_window: rd32(b, 16),
            req_type: rd32(b, 20),
            socket_id: rd32(b, 24),
            cookie: rd32(b, 28),
            peer_ip: [rd32(b, 32), rd32(b, 36), rd32(b, 40), rd32(b, 44)],
            ..Default::default()
        };
        let mut off = HS_CIF_LEN;
        while off + 4 <= b.len() {
            let w = rd32(b, off);
            let c = (w >> 16) as u16;
            let len = (w & 0xFFFF) as usize * 4;
            let body_at = off + 4;
            if body_at + len > b.len() {
                break;
            }
            let body = &b[body_at..body_at + len];
            match c {
                cmd::HSREQ | cmd::HSRSP => {
                    if body.len() >= 8 {
                        let delays = if body.len() >= 12 { rd32(body, 8) } else { 0 };
                        let e = SrtHsExt {
                            version: rd32(body, 0),
                            flags: rd32(body, 4),
                            recv_delay_ms: (delays >> 16) as u16,
                            send_delay_ms: delays as u16,
                        };
                        if c == cmd::HSREQ {
                            hs.hsreq = Some(e);
                        } else {
                            hs.hsrsp = Some(e);
                        }
                    }
                }
                cmd::KMREQ => hs.kmreq = true,
                cmd::KMRSP => hs.kmrsp = true,
                cmd::SID => hs.stream_id = Some(get_string(body)),
                cmd::CONGESTION => hs.congestion = Some(get_string(body)),
                cmd::FILTER => hs.filter = Some(get_string(body)),
                cmd::GROUP => hs.group = true,
                _ => {}
            }
            off = body_at + len;
        }
        Some(hs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn string_word_swap_matches_spec_example() {
        let mut b = [0u8; 8];
        assert_eq!(put_string("abcdefg", &mut b), 2);
        assert_eq!(b, [0x64, 0x63, 0x62, 0x61, 0x00, 0x67, 0x66, 0x65]);
        assert_eq!(get_string(&b), "abcdefg");
    }

    #[test]
    fn ip_words() {
        let ip: IpAddr = "10.78.1.20".parse().unwrap();
        let w = ip_to_words(ip);
        let mut b = [0u8; 4];
        wr32(&mut b, 0, w[0]);
        assert_eq!(b, [0x14, 0x01, 0x4e, 0x0a]);
        assert_eq!(words_to_ip(&w), ip);
        let ip6: IpAddr = "2001:db8::1".parse().unwrap();
        assert_eq!(words_to_ip(&ip_to_words(ip6)), ip6);
    }

    #[test]
    fn reject_codes() {
        assert_eq!(RejectReason::Filter.to_wire(), 1014);
        assert_eq!(RejectReason::from_wire(1011), Some(RejectReason::Unsecure));
        assert_eq!(RejectReason::from_wire(2403), Some(RejectReason::App(1403)));
        assert_eq!(RejectReason::App(1403).to_wire(), 2403);
        assert_eq!(RejectReason::from_wire(req::CONCLUSION), None);
        assert_eq!(RejectReason::from_wire(req::INDUCTION), None);
    }

    #[test]
    fn round_trip_with_blocks() {
        let hs = Handshake {
            version: 5,
            encryption: 0,
            ext_field: ext::HSREQ | ext::CONFIG,
            isn: 0x51ca_2477,
            mss: 1500,
            flow_window: 8192,
            req_type: req::CONCLUSION,
            socket_id: 0x13c2_6e84,
            cookie: 0x20f8_8a0a,
            peer_ip: ip_to_words("127.0.0.1".parse().unwrap()),
            hsreq: Some(SrtHsExt {
                version: SRT_VERSION,
                flags: flags::LIVE,
                recv_delay_ms: 120,
                send_delay_ms: 120,
            }),
            stream_id: Some("abcdefg".into()),
            filter: Some("fec,cols:4,rows:2".into()),
            ..Default::default()
        };
        assert_eq!(hs.conclusion_ext_flags(), 5);
        let mut b = [0u8; 256];
        let n = hs.encode(&mut b);
        assert_eq!(n, hs.encoded_len());
        assert_eq!(Handshake::decode(&b[..n]).unwrap(), hs);
        // truncated block: parsing stops, the 48 bytes still decode
        let d = Handshake::decode(&b[..n - 4]).unwrap();
        assert!(d.filter.is_none());
        assert!(d.hsreq.is_some());
        assert!(Handshake::decode(&b[..47]).is_none());
    }
}
