//! Standard security handler (ISO 32000-2 §7.6.4): opening encrypted files that need no password.
//!
//! Only the empty user password is tried: such files open in a viewer without a prompt, so their
//! content must be scanned. Anything else (a password, another handler) cannot be opened here.

use aes::cipher::{BlockCipherDecrypt, BlockCipherEncrypt, KeyInit};
use aes::{Aes128, Aes256, Block};
use md5::Md5;
use sha2::{Digest, Sha256, Sha384, Sha512};

/// Object number and generation: RC4 and AES-128 keys are derived per object.
pub type ObjId = (u32, u16);

/// Crypt filter method (`/CFM`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Method {
    Identity,
    Rc4,
    Aes128,
    Aes256,
    Unsupported,
}

/// Values of the encryption dictionary.
pub struct Params<'a> {
    pub v: f64,
    pub r: f64,
    /// Key length: `/Length` (bits) for V 1–2, `/Length` of the stream crypt filter for V 4.
    pub length: Option<f64>,
    pub o: &'a [u8],
    pub u: &'a [u8],
    pub ue: &'a [u8],
    pub p: f64,
    pub encrypt_metadata: bool,
    /// The first element of the trailer `/ID`.
    pub id0: &'a [u8],
    /// Default methods for streams (`/StmF`) and strings (`/StrF`), V 4–5 only.
    pub stm: Method,
    pub strf: Method,
    /// All crypt filters of `/CF`, for streams with a `/Crypt` filter.
    pub named: Vec<(Box<[u8]>, Method)>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Decryptor {
    key: Vec<u8>,
    pub stm: Method,
    strf: Method,
    named: Vec<(Box<[u8]>, Method)>,
}

/// Padding of passwords (Algorithm 2, step a).
const PAD: [u8; 32] = [
    0x28, 0xBF, 0x4E, 0x5E, 0x4E, 0x75, 0x8A, 0x41, 0x64, 0x00, 0x4E, 0x56, 0xFF, 0xFA, 0x01, 0x08, 0x2E, 0x2E, 0x00,
    0xB6, 0xD0, 0x68, 0x3E, 0x80, 0x2F, 0x0C, 0xA9, 0xFE, 0x64, 0x53, 0x69, 0x7A,
];

impl Decryptor {
    /// Authenticates the empty user password. `None`: a password is required or the parameters
    /// are not supported.
    pub fn open(p: &Params) -> Option<Decryptor> {
        let (stm, strf, len) = match p.v {
            1.0 => (Method::Rc4, Method::Rc4, Some(5)),
            2.0 => (Method::Rc4, Method::Rc4, key_bytes(p.length.unwrap_or(40.0))),
            // some writers give the crypt filter length in bytes
            4.0 => (p.stm, p.strf, key_bytes(p.length.map_or(128.0, |l| if l < 40.0 { l * 8.0 } else { l }))),
            5.0 => (p.stm, p.strf, Some(32)),
            _ => return None,
        };
        if stm == Method::Unsupported || strf == Method::Unsupported {
            return None;
        }
        let key = match (p.r, len?) {
            (2.0 | 3.0 | 4.0, n) if n <= 16 => md5_key(p, n)?,
            (5.0 | 6.0, 32) => sha_key(p)?,
            _ => return None,
        };
        Some(Decryptor { key, stm, strf, named: p.named.clone() })
    }

    /// Method of a named crypt filter (`/Crypt` filter of a stream).
    pub fn named(&self, name: &[u8]) -> Method {
        match name {
            b"Identity" => Method::Identity,
            _ => self.named.iter().find(|(n, _)| &**n == name).map_or(Method::Unsupported, |(_, m)| *m),
        }
    }

    /// `None` if strings are not encrypted (or the method is unsupported).
    pub fn string(&self, id: ObjId, data: &[u8]) -> Option<Vec<u8>> {
        self.decrypt(self.strf, id, data)
    }

    /// `None` if the method does not encrypt (Identity) or is unsupported.
    pub fn decrypt(&self, m: Method, (num, gen): ObjId, data: &[u8]) -> Option<Vec<u8>> {
        let key = match m {
            Method::Identity | Method::Unsupported => return None,
            Method::Aes256 => self.key.clone(),
            Method::Rc4 | Method::Aes128 => {
                // Algorithm 1: the object key
                let mut h = Md5::new();
                h.update(&self.key);
                h.update(&num.to_le_bytes()[..3]);
                h.update(gen.to_le_bytes());
                if m == Method::Aes128 {
                    h.update(b"sAlT");
                }
                h.finalize()[..(self.key.len() + 5).min(16)].to_vec()
            }
        };
        match m {
            Method::Rc4 => Some(rc4(&key, data)),
            Method::Aes128 => Aes128::new_from_slice(&key).ok().map(|c| aes_decrypt(|b| c.decrypt_block(b), data)),
            _ => Aes256::new_from_slice(&key).ok().map(|c| aes_decrypt(|b| c.decrypt_block(b), data)),
        }
    }
}

/// Key length in bytes from bits (40–128, a multiple of 8).
fn key_bytes(bits: f64) -> Option<usize> {
    ((40.0..=128.0).contains(&bits) && bits % 8.0 == 0.0).then(|| bits as usize / 8)
}

/// R 2–4: Algorithm 2 for the empty password, checked against /U (Algorithms 4, 5).
fn md5_key(p: &Params, n: usize) -> Option<Vec<u8>> {
    if p.o.len() < 32 || p.u.len() < 32 {
        return None;
    }
    let mut h = Md5::new();
    h.update(PAD);
    h.update(&p.o[..32]);
    // /P is a signed 32-bit value, some writers store it unsigned
    h.update(((p.p as i64) as u32).to_le_bytes());
    h.update(p.id0);
    if p.r >= 4.0 && !p.encrypt_metadata {
        h.update([0xff; 4]);
    }
    let mut key = h.finalize()[..n].to_vec();
    if p.r >= 3.0 {
        for _ in 0..50 {
            key = Md5::digest(&key)[..n].to_vec();
        }
    }
    let ok = if p.r == 2.0 {
        rc4(&key, &PAD) == p.u[..32]
    } else {
        let mut h = Md5::new();
        h.update(PAD);
        h.update(p.id0);
        let mut x = rc4(&key, &h.finalize());
        for i in 1..=19u8 {
            let k: Vec<u8> = key.iter().map(|b| b ^ i).collect();
            x = rc4(&k, &x);
        }
        x[..] == p.u[..16]
    };
    ok.then_some(key)
}

/// R 5–6: the empty password is checked against /U, the file key is decrypted from /UE.
fn sha_key(p: &Params) -> Option<Vec<u8>> {
    if p.u.len() < 48 || p.ue.len() < 32 {
        return None;
    }
    let (hash, salt, key_salt) = (&p.u[..32], &p.u[32..40], &p.u[40..48]);
    let (check, ik) = if p.r == 5.0 { (Sha256::digest(salt).to_vec(), Sha256::digest(key_salt).to_vec()) } else { (hash_2b(salt), hash_2b(key_salt)) };
    if check != hash {
        return None;
    }
    // /UE is the file key encrypted with AES-256-CBC, zero IV, no padding
    let c = Aes256::new_from_slice(&ik).ok()?;
    let mut key = p.ue[..32].to_vec();
    cbc(|b| c.decrypt_block(b), &[0; 16], &mut key);
    Some(key)
}

/// Algorithm 2.B (R 6) for the empty password and no user data.
fn hash_2b(salt: &[u8]) -> Vec<u8> {
    let mut k = Sha256::digest(salt).to_vec();
    let mut round = 0u32;
    loop {
        let mut e = k.repeat(64);
        let Ok(c) = Aes128::new_from_slice(&k[..16]) else { return vec![] };
        let mut iv = [0u8; 16];
        iv.copy_from_slice(&k[16..32]);
        for chunk in e.chunks_exact_mut(16) {
            for (b, v) in chunk.iter_mut().zip(iv) {
                *b ^= v;
            }
            if let Ok(block) = <&mut Block>::try_from(&mut *chunk) {
                c.encrypt_block(block);
            }
            iv.copy_from_slice(chunk);
        }
        // the first 16 bytes as a big-endian number mod 3 (256 ≡ 1 mod 3)
        k = match e[..16].iter().map(|&b| b as u32).sum::<u32>() % 3 {
            0 => Sha256::digest(&e).to_vec(),
            1 => Sha384::digest(&e).to_vec(),
            _ => Sha512::digest(&e).to_vec(),
        };
        round += 1;
        if round >= 64 && e.last().map_or(true, |&l| l as u32 + 32 <= round) {
            return k[..32].to_vec();
        }
    }
}

fn rc4(key: &[u8], data: &[u8]) -> Vec<u8> {
    if key.is_empty() {
        return data.to_vec();
    }
    let mut s: [u8; 256] = std::array::from_fn(|i| i as u8);
    let mut j = 0u8;
    for i in 0..256 {
        j = j.wrapping_add(s[i]).wrapping_add(key[i % key.len()]);
        s.swap(i, j as usize);
    }
    let (mut i, mut j) = (0u8, 0u8);
    data.iter()
        .map(|&b| {
            i = i.wrapping_add(1);
            j = j.wrapping_add(s[i as usize]);
            s.swap(i as usize, j as usize);
            b ^ s[s[i as usize].wrapping_add(s[j as usize]) as usize]
        })
        .collect()
}

fn cbc(decrypt: impl Fn(&mut Block), iv: &[u8; 16], data: &mut [u8]) {
    let mut prev = *iv;
    for chunk in data.chunks_exact_mut(16) {
        let mut cur = [0u8; 16];
        cur.copy_from_slice(chunk);
        if let Ok(block) = <&mut Block>::try_from(&mut *chunk) {
            decrypt(block);
        }
        for (b, p) in chunk.iter_mut().zip(prev) {
            *b ^= p;
        }
        prev = cur;
    }
}

/// AES-CBC with the IV in the first 16 bytes. Lenient like viewers: an incomplete last block is
/// dropped, the padding is removed only if it looks valid.
fn aes_decrypt(decrypt: impl Fn(&mut Block), data: &[u8]) -> Vec<u8> {
    if data.len() < 16 {
        return vec![];
    }
    let mut iv = [0u8; 16];
    iv.copy_from_slice(&data[..16]);
    let body = &data[16..];
    let mut out = body[..body.len() / 16 * 16].to_vec();
    cbc(decrypt, &iv, &mut out);
    if let Some(&pad) = out.last() {
        if (1..=16).contains(&pad) && out[out.len() - pad as usize..].iter().all(|&b| b == pad) {
            out.truncate(out.len() - pad as usize);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rc4_vectors() {
        assert_eq!(rc4(b"Key", b"Plaintext"), [0xBB, 0xF3, 0x16, 0xE8, 0xD9, 0x40, 0xAF, 0x0A, 0xD3]);
        assert_eq!(rc4(b"Secret", b"Attack at dawn"), [0x45, 0xA0, 0x1F, 0x64, 0x5F, 0xC3, 0x5B, 0x38, 0x35, 0x52, 0x54, 0x4B, 0x9B, 0xF5]);
    }

    #[test]
    fn aes_padding_and_short_input() {
        let c = Aes128::new_from_slice(&[7; 16]).unwrap();
        let enc = |plain: &[u8]| {
            let mut v = plain.to_vec();
            let pad = 16 - v.len() % 16;
            v.extend(std::iter::repeat(pad as u8).take(pad));
            let mut iv = [3u8; 16];
            let mut out = iv.to_vec();
            for chunk in v.chunks_exact_mut(16) {
                for (b, p) in chunk.iter_mut().zip(iv) {
                    *b ^= p;
                }
                c.encrypt_block(<&mut Block>::try_from(&mut *chunk).unwrap());
                iv.copy_from_slice(chunk);
                out.extend_from_slice(chunk);
            }
            out
        };
        for plain in [&b""[..], b"x", b"exactly16bytes!!", b"javascript:app.alert(1)"] {
            assert_eq!(aes_decrypt(|b| c.decrypt_block(b), &enc(plain)), plain);
        }
        assert!(aes_decrypt(|b| c.decrypt_block(b), b"short").is_empty());
        // an incomplete last block is dropped
        let mut e = enc(b"0123456789abcdef0123");
        e.extend_from_slice(b"xyz");
        assert_eq!(aes_decrypt(|b| c.decrypt_block(b), &e), b"0123456789abcdef0123");
    }
}
