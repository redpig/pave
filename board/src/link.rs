//! In-person links: a QR code opens the channel, the exchange runs over a
//! radio, and a QR-only fallback carries it in frames.
//!
//! - **The invite.** One phone shows a QR code holding a fresh 32-byte
//!   session key, an 8-byte token, the radios it is listening on (a Wi-Fi
//!   Aware service, a Bluetooth LE service) and an expiry. The other scans
//!   it and connects over one of them; the token is what it looks for in
//!   the advertisement.
//! - **The session.** Every message is sealed with XChaCha20-Poly1305 under
//!   the session key, the same construction the wallet's vault uses: no
//!   key agreement and nothing new. Only someone who scanned the code can
//!   read or inject on the radio; someone filming the screen could, which
//!   is why what crosses is signed and checked anyway. Each sealed message
//!   carries its direction and a sequence number in its associated data,
//!   so a message can't be replayed, reordered or reflected back.
//! - **QR-only.** With no radio, sealed messages are cut into frames, each
//!   a QR code shown in a loop; the other phone collects them in any order.
//!
//! Codes are base45 ([RFC 9285]), which QR's alphanumeric mode packs
//! tightly.
//!
//! [RFC 9285]: https://www.rfc-editor.org/rfc/rfc9285

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// What every invite code starts with.
pub const INVITE_PREFIX: &str = "PAVE1:";
/// What every frame code starts with.
pub const FRAME_PREFIX: &str = "PAVF1:";
/// Bytes of sealed message per frame: about a version 20 QR code in
/// alphanumeric mode, which phones read reliably off another screen.
pub const FRAME_BYTES: usize = 600;

/// A radio an inviting phone is listening on.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Radio {
    /// A Wi-Fi Aware service name.
    WifiAware(String),
    /// A Bluetooth LE service UUID.
    Ble([u8; 16]),
}

/// What the QR code carries.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Invite {
    #[serde(with = "serde_bytes")]
    pub key: [u8; 32],
    pub token: [u8; 8],
    pub radios: Vec<Radio>,
    /// Seconds since 1970 after which the code is stale.
    pub expires: u64,
}

impl Invite {
    /// A fresh invite, good for `ttl` seconds.
    pub fn new(radios: Vec<Radio>, ttl: u64) -> Invite {
        Invite {
            key: rand::random(),
            token: rand::random(),
            radios,
            expires: crate::bulletin::now() + ttl,
        }
    }

    /// The text to put in the QR code.
    pub fn to_qr(&self) -> String {
        format!(
            "{INVITE_PREFIX}{}",
            base45::encode(&pave_kernel::hash::encode(self))
        )
    }

    /// Read a scanned invite, refusing a stale one.
    pub fn from_qr(s: &str) -> Result<Invite, String> {
        let body = s.strip_prefix(INVITE_PREFIX).ok_or("not a pave invite")?;
        let inv: Invite =
            ciborium::from_reader(base45::decode(body)?.as_slice()).map_err(|e| e.to_string())?;
        if crate::bulletin::now() > inv.expires {
            return Err("this invite has expired: ask for a new code".into());
        }
        Ok(inv)
    }
}

/// Which side of the link this phone is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Side {
    /// Showed the invite.
    Shower,
    /// Scanned it.
    Scanner,
}

/// One end of a link.
pub struct Link {
    key: [u8; 32],
    token: [u8; 8],
    side: Side,
    sent: u64,
    /// The next sequence number expected from the other side.
    next: u64,
}

/// A sealed message: nonce, sequence, then ciphertext.
const HEADER: usize = 24 + 8;

impl Link {
    pub fn new(inv: &Invite, side: Side) -> Link {
        Link {
            key: inv.key,
            token: inv.token,
            side,
            sent: 0,
            next: 0,
        }
    }

    pub fn token(&self) -> [u8; 8] {
        self.token
    }

    fn aad(&self, from: Side, seq: u64, kind: &str) -> Vec<u8> {
        let mut a = b"pave/link/v1".to_vec();
        a.extend_from_slice(&self.token);
        a.push(from as u8);
        a.extend_from_slice(&seq.to_be_bytes());
        a.extend_from_slice(kind.as_bytes());
        a
    }

    /// Seal a message of `kind` for the other side.
    pub fn seal(&mut self, kind: &str, body: &[u8]) -> Vec<u8> {
        let (seq, nonce) = (self.sent, rand::random::<[u8; 24]>());
        self.sent += 1;
        let plain = pave_kernel::hash::encode(&(kind, serde_bytes::Bytes::new(body)));
        let aad = self.aad(self.side, seq, kind);
        let ct = XChaCha20Poly1305::new(Key::from_slice(&self.key))
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: &plain,
                    aad: &aad,
                },
            )
            .expect("sealing doesn't fail");
        let mut out = nonce.to_vec();
        out.extend_from_slice(&seq.to_be_bytes());
        out.push(u8::try_from(kind.len()).expect("a kind is a short name"));
        out.extend_from_slice(kind.as_bytes());
        out.extend_from_slice(&ct);
        out
    }

    /// Open a message from the other side: its kind and body. Refuses one
    /// sealed by this side, out of order, replayed, or altered.
    pub fn open(&mut self, sealed: &[u8]) -> Result<(String, Vec<u8>), String> {
        // Everything refused before the seal is checked gets one answer, so
        // an outsider learns nothing from it.
        const NOT_OURS: &str = "not from the other side of this link";
        if sealed.len() < HEADER + 1 {
            return Err(NOT_OURS.into());
        }
        let seq = u64::from_be_bytes(sealed[24..32].try_into().unwrap());
        let klen = sealed[32] as usize;
        let kind = sealed
            .get(33..33 + klen)
            .and_then(|k| std::str::from_utf8(k).ok())
            .ok_or(NOT_OURS)?
            .to_string();
        let from = match self.side {
            Side::Shower => Side::Scanner,
            Side::Scanner => Side::Shower,
        };
        let aad = self.aad(from, seq, &kind);
        let plain = XChaCha20Poly1305::new(Key::from_slice(&self.key))
            .decrypt(
                XNonce::from_slice(&sealed[..24]),
                Payload {
                    msg: &sealed[33 + klen..],
                    aad: &aad,
                },
            )
            .map_err(|_| NOT_OURS)?;
        // Only now, authenticated: is it the next one?
        if seq != self.next {
            return Err(format!("out of order: expected {}, got {seq}", self.next));
        }
        let (k, body): (String, serde_bytes::ByteBuf) =
            ciborium::from_reader(plain.as_slice()).map_err(|e| e.to_string())?;
        if k != kind {
            return Err("kind mismatch".into());
        }
        self.next += 1;
        Ok((kind, body.into_vec()))
    }
}

/// An open link and the QR frames collected on it.
pub struct Session {
    pub link: Link,
    pub frames: Frames,
}

/// One QR frame of a sealed message.
#[derive(Serialize, Deserialize)]
struct Frame {
    token: [u8; 8],
    /// Which message, by its sequence number on this link.
    msg: u64,
    index: u32,
    count: u32,
    #[serde(with = "serde_bytes")]
    data: Vec<u8>,
}

/// Cut a sealed message into QR frame codes, to show in a loop.
pub fn frames(token: [u8; 8], sealed: &[u8], size: usize) -> Vec<String> {
    let msg = u64::from_be_bytes(sealed[24..32].try_into().unwrap_or([0; 8]));
    let chunks: Vec<&[u8]> = sealed.chunks(size.max(1)).collect();
    let count = chunks.len() as u32;
    chunks
        .iter()
        .enumerate()
        .map(|(i, c)| {
            format!(
                "{FRAME_PREFIX}{}",
                base45::encode(&pave_kernel::hash::encode(&Frame {
                    token,
                    msg,
                    index: i as u32,
                    count,
                    data: c.to_vec()
                }))
            )
        })
        .collect()
}

/// Collects scanned frames for one link, in any order and with repeats,
/// into whole sealed messages.
pub struct Frames {
    token: [u8; 8],
    parts: BTreeMap<u64, (u32, BTreeMap<u32, Vec<u8>>)>,
}

impl Frames {
    pub fn new(token: [u8; 8]) -> Frames {
        Frames {
            token,
            parts: BTreeMap::new(),
        }
    }

    /// Add a scanned code. Returns a sealed message once all its frames are
    /// in; ignores frames from another link.
    pub fn add(&mut self, code: &str) -> Result<Option<Vec<u8>>, String> {
        let body = code.strip_prefix(FRAME_PREFIX).ok_or("not a pave frame")?;
        let f: Frame =
            ciborium::from_reader(base45::decode(body)?.as_slice()).map_err(|e| e.to_string())?;
        if f.token != self.token || f.count == 0 || f.index >= f.count {
            return Ok(None);
        }
        let (count, got) = self
            .parts
            .entry(f.msg)
            .or_insert((f.count, BTreeMap::new()));
        if *count != f.count {
            return Err("frames disagree on their count".into());
        }
        got.insert(f.index, f.data);
        if got.len() as u32 == *count {
            let (_, got) = self.parts.remove(&f.msg).unwrap();
            return Ok(Some(got.into_values().flatten().collect()));
        }
        Ok(None)
    }

    /// How many of the current messages' frames are still missing.
    pub fn missing(&self) -> u32 {
        self.parts
            .values()
            .map(|(n, got)| n - got.len() as u32)
            .sum()
    }
}

/// Base45, RFC 9285.
pub mod base45 {
    const ALPHABET: &[u8; 45] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:";

    pub fn encode(data: &[u8]) -> String {
        let mut out = String::with_capacity(data.len() * 3 / 2 + 1);
        for c in data.chunks(2) {
            let (n, digits) = match c {
                [a, b] => ((*a as u32) * 256 + *b as u32, 3),
                [a] => (*a as u32, 2),
                _ => unreachable!(),
            };
            let mut n = n;
            for _ in 0..digits {
                out.push(ALPHABET[(n % 45) as usize] as char);
                n /= 45;
            }
        }
        out
    }

    pub fn decode(s: &str) -> Result<Vec<u8>, String> {
        let vals: Vec<u32> = s
            .bytes()
            .map(|b| {
                ALPHABET
                    .iter()
                    .position(|&a| a == b)
                    .map(|p| p as u32)
                    .ok_or("not base45")
            })
            .collect::<Result<_, _>>()?;
        let mut out = Vec::with_capacity(vals.len() * 2 / 3);
        for c in vals.chunks(3) {
            match c {
                [a, b, c] => {
                    let n = a + b * 45 + c * 45 * 45;
                    if n > 0xffff {
                        return Err("not base45".into());
                    }
                    out.extend_from_slice(&[(n >> 8) as u8, n as u8]);
                }
                [a, b] => {
                    let n = a + b * 45;
                    if n > 0xff {
                        return Err("not base45".into());
                    }
                    out.push(n as u8);
                }
                _ => return Err("not base45".into()),
            }
        }
        Ok(out)
    }

    #[cfg(test)]
    mod tests {
        // RFC 9285, section 4.
        #[test]
        fn rfc_vectors() {
            for (plain, coded) in [
                ("AB", "BB8"),
                ("Hello!!", "%69 VD92EX0"),
                ("base-45", "UJCLQE7W581"),
                ("ietf!", "QED8WEX0"),
            ] {
                assert_eq!(super::encode(plain.as_bytes()), coded);
                assert_eq!(super::decode(coded).unwrap(), plain.as_bytes());
            }
            assert!(super::decode("GGW").is_err(), "65535 < value");
            assert!(super::decode("a").is_err());
        }
    }
}
