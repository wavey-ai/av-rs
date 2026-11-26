//! SRT payload encryption (feature `aes`): the HaiCrypt keying material
//! (KM) message carried in KMREQ/KMRSP, key derivation and AES-CTR, as
//! libsrt does it without AEAD (SRT spec, "Encryption"):
//!
//! - KEK = PBKDF2-HMAC-SHA1(passphrase, last 8 bytes of the 16-byte salt,
//!   2048 iterations, key length);
//! - the stream encrypting keys (SEK, even and/or odd) travel wrapped with
//!   the KEK by AES key wrap (RFC 3394);
//! - each data payload is AES-CTR with IV = (0^80 || seq as 4 bytes BE ||
//!   0^16) XOR (first 14 bytes of the salt || 0^16): the low 16 bits count
//!   blocks; the packet's KK bits (msgno bits 27-28) say which key (1 even,
//!   2 odd).
//!
//! Written from the protocol description and libsrt's observable
//! behaviour; no libsrt code.

use aes::cipher::{KeyInit, StreamCipher};
use std::fmt;

/// KM message header length (before the salt).
const KM_HDR: usize = 16;
pub const SALT_LEN: usize = 16;
const PBKDF2_SALT_LEN: usize = 8;
const PBKDF2_ITER: u32 = 2048;
/// "HAI" PnP vendor id.
const KM_SIGN: u16 = (((b'H' - b'@') as u16) << 10) | (((b'A' - b'@') as u16) << 5) | (b'I' - b'@') as u16;
const KM_VERSION: u8 = 1;
const KM_PT_KM: u8 = 2;
const CIPHER_AES_CTR: u8 = 2;
const SE_TSSRT: u8 = 2;
/// AES key wrap adds one 8-byte block.
const WRAP_OVERHEAD: usize = 8;

/// KM states (libsrt `SRT_KM_S_*`), also the one-word KMRSP error payload.
pub mod km_state {
    pub const UNSECURED: u32 = 0;
    pub const SECURING: u32 = 1;
    pub const SECURED: u32 = 2;
    pub const NOSECRET: u32 = 3;
    pub const BADSECRET: u32 = 4;
}

/// Key flags in a KM message and in a data packet's KK bits.
pub mod kk {
    pub const EVEN: u8 = 1;
    pub const ODD: u8 = 2;
    pub const BOTH: u8 = 3;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KmError {
    /// Not a KM message we understand (version, type, cipher, lengths).
    Malformed,
    /// The key unwrap failed: the passphrase differs.
    BadSecret,
    /// We have no passphrase for an encrypted peer.
    NoSecret,
}

impl KmError {
    /// The KM state reported in a one-word KMRSP.
    pub fn state(self) -> u32 {
        match self {
            KmError::Malformed | KmError::BadSecret => km_state::BADSECRET,
            KmError::NoSecret => km_state::NOSECRET,
        }
    }
}

impl fmt::Display for KmError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

#[derive(Clone)]
enum Aes {
    A128(aes::Aes128),
    A192(aes::Aes192),
    A256(aes::Aes256),
}

impl Aes {
    fn new(key: &[u8]) -> Option<Aes> {
        Some(match key.len() {
            16 => Aes::A128(aes::Aes128::new_from_slice(key).ok()?),
            24 => Aes::A192(aes::Aes192::new_from_slice(key).ok()?),
            32 => Aes::A256(aes::Aes256::new_from_slice(key).ok()?),
            _ => return None,
        })
    }

    fn ctr(&self, iv: &[u8; 16], data: &mut [u8]) {
        use ctr::cipher::StreamCipherCoreWrapper;
        use ctr::flavors::Ctr128BE;
        use ctr::CtrCore;
        let iv = (*iv).into();
        // the expanded key is reused: only the counter block is new per packet
        match self {
            Aes::A128(c) => StreamCipherCoreWrapper::from_core(<CtrCore<aes::Aes128, Ctr128BE> as ctr::cipher::InnerIvInit>::inner_iv_init(c.clone(), &iv)).apply_keystream(data),
            Aes::A192(c) => StreamCipherCoreWrapper::from_core(<CtrCore<aes::Aes192, Ctr128BE> as ctr::cipher::InnerIvInit>::inner_iv_init(c.clone(), &iv)).apply_keystream(data),
            Aes::A256(c) => StreamCipherCoreWrapper::from_core(<CtrCore<aes::Aes256, Ctr128BE> as ctr::cipher::InnerIvInit>::inner_iv_init(c.clone(), &iv)).apply_keystream(data),
        }
    }
}

/// Overwrite secret bytes with zeros (volatile: not optimised away).
fn wipe(b: &mut [u8]) {
    for x in b.iter_mut() {
        // SAFETY: `x` is a valid, aligned, exclusive reference
        unsafe { std::ptr::write_volatile(x, 0) };
    }
    std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
}

fn kek(passphrase: &[u8], salt: &[u8; SALT_LEN], klen: usize) -> Vec<u8> {
    let mut k = vec![0u8; klen];
    pbkdf2::pbkdf2_hmac::<sha1::Sha1>(passphrase, &salt[SALT_LEN - PBKDF2_SALT_LEN..], PBKDF2_ITER, &mut k);
    k
}

fn wrap(kek: &[u8], data: &[u8]) -> Option<Vec<u8>> {
    let mut out = vec![0u8; data.len() + WRAP_OVERHEAD];
    let r = match kek.len() {
        16 => aes_kw::KekAes128::new(kek.into()).wrap(data, &mut out),
        24 => aes_kw::KekAes192::new(kek.into()).wrap(data, &mut out),
        32 => aes_kw::KekAes256::new(kek.into()).wrap(data, &mut out),
        _ => return None,
    };
    r.ok().map(|_| out)
}

fn unwrap(kek: &[u8], data: &[u8]) -> Option<Vec<u8>> {
    if data.len() < WRAP_OVERHEAD + 16 {
        return None;
    }
    let mut out = vec![0u8; data.len() - WRAP_OVERHEAD];
    let r = match kek.len() {
        16 => aes_kw::KekAes128::new(kek.into()).unwrap(data, &mut out),
        24 => aes_kw::KekAes192::new(kek.into()).unwrap(data, &mut out),
        32 => aes_kw::KekAes256::new(kek.into()).unwrap(data, &mut out),
        _ => return None,
    };
    r.ok().map(|_| out)
}

/// Fill `b` from the OS CSPRNG.
pub fn random_bytes(b: &mut [u8]) {
    getrandom::getrandom(b).expect("OS random source");
}

/// The keys of one direction-independent SRT crypto context (HSv5 uses the
/// caller's KM for both directions).
#[derive(Clone)]
pub struct Crypto {
    salt: [u8; SALT_LEN],
    klen: usize,
    /// [even, odd]
    keys: [Option<Aes>; 2],
    /// The KM message that established the current keys (sent in KMREQ,
    /// echoed in KMRSP).
    km: Vec<u8>,
    /// Key our sender uses (kk::EVEN or kk::ODD).
    tx_kk: u8,
    /// For key refreshes (KMREQ while connected).
    passphrase: String,
}

impl Drop for Crypto {
    fn drop(&mut self) {
        // SAFETY: zero bytes are valid UTF-8
        wipe(unsafe { self.passphrase.as_bytes_mut() });
        wipe(&mut self.km);
    }
}

impl fmt::Debug for Crypto {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Crypto").field("klen", &self.klen).field("tx_kk", &self.tx_kk).finish_non_exhaustive()
    }
}

/// A parsed KM message (keys unwrapped).
struct Km {
    kflags: u8,
    salt: [u8; SALT_LEN],
    klen: usize,
    even: Option<Vec<u8>>,
    odd: Option<Vec<u8>>,
}

impl Drop for Km {
    fn drop(&mut self) {
        for k in [&mut self.even, &mut self.odd].into_iter().flatten() {
            wipe(k);
        }
    }
}

/// Length of a KM message with `nkeys` keys of `klen` bytes (libsrt
/// accepts exactly this length, nothing shorter or longer).
fn km_len(klen: usize, nkeys: usize) -> usize {
    KM_HDR + SALT_LEN + klen * nkeys + WRAP_OVERHEAD
}

fn parse_km(passphrase: &[u8], m: &[u8]) -> Result<Km, KmError> {
    if m.len() < KM_HDR + SALT_LEN {
        return Err(KmError::Malformed);
    }
    let version = m[0] >> 4;
    let pt = m[0] & 0xF;
    let sign = u16::from_be_bytes([m[1], m[2]]);
    let kflags = m[3] & kk::BOTH;
    if version != KM_VERSION || pt != KM_PT_KM || sign != KM_SIGN || kflags == 0 {
        return Err(KmError::Malformed);
    }
    // KEKI (word 1) must be 0: preshared passphrase
    if m[4..8] != [0, 0, 0, 0] || m[8] != CIPHER_AES_CTR || m[9] != 0 {
        return Err(KmError::Malformed);
    }
    let slen = m[14] as usize * 4;
    let klen = m[15] as usize * 4;
    if slen != SALT_LEN || !matches!(klen, 16 | 24 | 32) {
        return Err(KmError::Malformed);
    }
    let nkeys = if kflags == kk::BOTH { 2 } else { 1 };
    let wrapped_at = KM_HDR + SALT_LEN;
    // exactly one message: trailing bytes would be echoed in KMRSP
    if m.len() != km_len(klen, nkeys) {
        return Err(KmError::Malformed);
    }
    let mut salt = [0u8; SALT_LEN];
    salt.copy_from_slice(&m[KM_HDR..KM_HDR + SALT_LEN]);
    let mut k = kek(passphrase, &salt, klen);
    let keys = unwrap(&k, &m[wrapped_at..]);
    wipe(&mut k);
    let mut keys = keys.ok_or(KmError::BadSecret)?;
    let (even, odd) = match kflags {
        kk::EVEN => (Some(keys), None),
        kk::ODD => (None, Some(keys)),
        _ => {
            let pair = (Some(keys[..klen].to_vec()), Some(keys[klen..].to_vec()));
            wipe(&mut keys);
            pair
        }
    };
    Ok(Km { kflags, salt, klen, even, odd })
}

fn build_km(passphrase: &[u8], salt: &[u8; SALT_LEN], kflags: u8, even: Option<&[u8]>, odd: Option<&[u8]>, klen: usize) -> Vec<u8> {
    let mut plain = Vec::with_capacity(2 * klen);
    if let Some(e) = even {
        plain.extend_from_slice(e);
    }
    if let Some(o) = odd {
        plain.extend_from_slice(o);
    }
    let mut k = kek(passphrase, salt, klen);
    let wrapped = wrap(&k, &plain).expect("valid key length");
    wipe(&mut k);
    wipe(&mut plain);
    let mut m = Vec::with_capacity(KM_HDR + SALT_LEN + wrapped.len());
    m.push((KM_VERSION << 4) | KM_PT_KM);
    m.extend_from_slice(&KM_SIGN.to_be_bytes());
    m.push(kflags);
    m.extend_from_slice(&[0, 0, 0, 0]); // KEKI
    m.extend_from_slice(&[CIPHER_AES_CTR, 0, SE_TSSRT, 0, 0, 0]);
    m.push((SALT_LEN / 4) as u8);
    m.push((klen / 4) as u8);
    m.extend_from_slice(salt);
    m.extend_from_slice(&wrapped);
    m
}

impl Crypto {
    /// Caller (sender of KMREQ): a fresh salt and even key of `klen`
    /// bytes (16, 24 or 32).
    pub fn generate(passphrase: &str, klen: usize) -> Crypto {
        assert!(matches!(klen, 16 | 24 | 32));
        let mut salt = [0u8; SALT_LEN];
        random_bytes(&mut salt);
        let mut sek = vec![0u8; klen];
        random_bytes(&mut sek);
        let km = build_km(passphrase.as_bytes(), &salt, kk::EVEN, Some(&sek), None, klen);
        let keys = [Aes::new(&sek), None];
        wipe(&mut sek);
        Crypto {
            salt,
            klen,
            keys,
            km,
            tx_kk: kk::EVEN,
            passphrase: passphrase.to_string(),
        }
    }

    /// Listener (receiver of KMREQ): the keys of the caller's KM message.
    pub fn from_km(passphrase: &str, km: &[u8]) -> Result<Crypto, KmError> {
        let k = parse_km(passphrase.as_bytes(), km)?;
        let tx_kk = if k.even.is_some() { kk::EVEN } else { kk::ODD };
        Ok(Crypto {
            salt: k.salt,
            klen: k.klen,
            keys: [k.even.as_deref().and_then(Aes::new), k.odd.as_deref().and_then(Aes::new)],
            km: km.to_vec(),
            tx_kk,
            passphrase: passphrase.to_string(),
        })
    }

    /// A KMREQ received while connected (key refresh): take the keys it
    /// announces. Returns the message to echo in KMRSP.
    pub fn refresh(&mut self, km: &[u8]) -> Result<(), KmError> {
        let k = parse_km(self.passphrase.as_bytes(), km)?;
        if k.klen != self.klen {
            return Err(KmError::Malformed);
        }
        self.salt = k.salt;
        if let Some(e) = k.even.as_deref() {
            self.keys[0] = Aes::new(e);
        }
        if let Some(o) = k.odd.as_deref() {
            self.keys[1] = Aes::new(o);
        }
        let _ = k.kflags;
        wipe(&mut self.km);
        self.km = km.to_vec();
        Ok(())
    }

    /// The KM message (KMREQ payload / KMRSP echo).
    pub fn km_msg(&self) -> &[u8] {
        &self.km
    }

    /// Key length from a handshake's encryption field (PBKEYLEN / 8: 2, 3
    /// or 4), if valid.
    pub fn klen_from_hs_field(f: u16) -> Option<usize> {
        match f {
            2 => Some(16),
            3 => Some(24),
            4 => Some(32),
            _ => None,
        }
    }

    /// The handshake encryption field for our key length.
    pub fn hs_field(&self) -> u16 {
        (self.klen / 8) as u16
    }

    /// Key length, bytes.
    pub fn key_len(&self) -> usize {
        self.klen
    }

    /// Does this KMRSP confirm our KMREQ? (libsrt echoes the message.)
    pub fn km_matches(&self, rsp: &[u8]) -> bool {
        rsp.len() >= self.km.len() && rsp[..self.km.len()] == self.km[..]
    }

    fn iv(&self, seq: u32) -> [u8; 16] {
        let mut iv = [0u8; 16];
        iv[10..14].copy_from_slice(&seq.to_be_bytes());
        for (b, s) in iv.iter_mut().zip(&self.salt[..14]) {
            *b ^= s;
        }
        iv
    }

    /// Encrypt a data payload in place with our sending key; returns the KK bits.
    pub fn encrypt(&self, seq: u32, data: &mut [u8]) -> u8 {
        let idx = (self.tx_kk - 1) as usize;
        if let Some(k) = &self.keys[idx] {
            k.ctr(&self.iv(seq), data);
        }
        self.tx_kk
    }

    /// Decrypt a data payload in place; false if its key is unknown.
    pub fn decrypt(&self, key: u8, seq: u32, data: &mut [u8]) -> bool {
        let k = match key {
            kk::EVEN => &self.keys[0],
            kk::ODD => &self.keys[1],
            _ => return false,
        };
        match k {
            Some(k) => {
                k.ctr(&self.iv(seq), data);
                true
            }
            None => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc3394_vector() {
        // RFC 3394 4.1: 128-bit key data with a 128-bit KEK
        let kek: Vec<u8> = (0u8..16).collect();
        let data = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
        let w = wrap(&kek, &data).unwrap();
        assert_eq!(
            w,
            [
                0x1F, 0xA6, 0x8B, 0x0A, 0x81, 0x12, 0xB4, 0x47, 0xAE, 0xF3, 0x4B, 0xD8, 0xFB, 0x5A, 0x7B, 0x82, 0x9D, 0x3E, 0x86, 0x23, 0x71, 0xD2,
                0xCF, 0xE5
            ]
        );
        assert_eq!(unwrap(&kek, &w).unwrap(), data);
    }

    #[test]
    fn pbkdf2_sha1_vector() {
        // RFC 6070 test 2 (c = 2): P = "password", S = "salt"
        let mut k = [0u8; 20];
        pbkdf2::pbkdf2_hmac::<sha1::Sha1>(b"password", b"salt", 2, &mut k);
        assert_eq!(
            k,
            [0xea, 0x6c, 0x01, 0x4d, 0xc7, 0x2d, 0x6f, 0x8c, 0xcd, 0x1e, 0xd9, 0x2a, 0xce, 0x1d, 0x41, 0xf0, 0xd8, 0xde, 0x89, 0x57]
        );
    }

    #[test]
    fn km_round_trip_and_bad_secret() {
        for klen in [16, 24, 32] {
            let tx = Crypto::generate("correct horse battery", klen);
            let m = tx.km_msg().to_vec();
            assert_eq!(m.len(), 16 + 16 + klen + 8);
            assert_eq!(&m[..4], &[0x12, 0x20, 0x29, 0x01]);
            let rx = Crypto::from_km("correct horse battery", &m).unwrap();
            assert_eq!(rx.key_len(), klen);
            assert_eq!(Crypto::from_km("wrong horse battery!", &m).err(), Some(KmError::BadSecret));
            let mut data = b"0123456789abcdef-some-ts-payload-of-odd-length".to_vec();
            let orig = data.clone();
            let key = tx.encrypt(0x1234_5678, &mut data);
            assert_eq!(key, kk::EVEN);
            assert_ne!(data, orig);
            assert!(rx.decrypt(key, 0x1234_5678, &mut data));
            assert_eq!(data, orig);
            assert!(!rx.decrypt(kk::ODD, 1, &mut data));
        }
    }

    #[test]
    fn refresh_takes_both_keys() {
        let tx = Crypto::generate("0123456789", 16);
        let mut rx = Crypto::from_km("0123456789", tx.km_msg()).unwrap();
        let mut odd = vec![7u8; 16];
        random_bytes(&mut odd);
        let even = vec![1u8; 16];
        let m = build_km(b"0123456789", &tx.salt, kk::BOTH, Some(&even), Some(&odd), 16);
        rx.refresh(&m).unwrap();
        let mut a = Crypto::from_km("0123456789", &m).unwrap();
        a.tx_kk = kk::ODD;
        let mut d = b"payload".to_vec();
        let key = a.encrypt(5, &mut d);
        assert_eq!(key, kk::ODD);
        assert!(rx.decrypt(key, 5, &mut d));
        assert_eq!(&d, b"payload");
        assert_eq!(Crypto::klen_from_hs_field(4), Some(32));
        assert_eq!(tx.hs_field(), 2);
    }

    #[test]
    fn km_must_have_its_exact_length() {
        for klen in [16, 24, 32] {
            let tx = Crypto::generate("0123456789", klen);
            let m = tx.km_msg().to_vec();
            // trailing junk (would be echoed in KMRSP) and truncation
            for extra in [1usize, 4, 400, 1600] {
                let mut long = m.clone();
                long.extend(std::iter::repeat(0xAA).take(extra));
                assert_eq!(Crypto::from_km("0123456789", &long).err(), Some(KmError::Malformed), "klen {klen} +{extra}");
            }
            for cut in [1usize, 4, 8] {
                assert_eq!(Crypto::from_km("0123456789", &m[..m.len() - cut]).err(), Some(KmError::Malformed));
            }
            // a refresh with junk is refused and changes nothing
            let mut rx = Crypto::from_km("0123456789", &m).unwrap();
            let fresh = Crypto::generate("0123456789", klen);
            let mut long = fresh.km_msg().to_vec();
            long.extend_from_slice(&[0x55; 12]);
            assert_eq!(rx.refresh(&long), Err(KmError::Malformed));
            assert_eq!(rx.km_msg(), &m[..]);
            rx.refresh(fresh.km_msg()).unwrap();
            assert_eq!(rx.km_msg(), fresh.km_msg());
            assert_eq!(rx.km_msg().len(), km_len(klen, 1));
        }
    }

    #[test]
    fn wipe_zeroes() {
        let mut b = vec![0xA5u8; 33];
        wipe(&mut b);
        assert!(b.iter().all(|x| *x == 0));
    }

    #[test]
    fn iv_layout() {
        let mut c = Crypto::generate("0123456789", 16);
        c.salt = [0xFF; 16];
        let iv = c.iv(0x0102_0304);
        assert_eq!(iv, [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE, 0xFD, 0xFC, 0xFB, 0, 0]);
    }
}
