//! Transparent compression: the `com.apple.decmpfs` extended attribute. Readable types hold
//! the data inside the attribute: 1 (stored), 3 (zlib, decoded by a small inflate written from
//! RFC 1950/1951, or stored after a 0x?f marker byte) and 9 when its payload is stored after a
//! 0xcc marker byte. Every other type (resource-fork types 4, 8, 10, 12; LZVN 7; LZFSE 11;
//! type 9 with compressed payload) is reported as unsupported. The type semantics were checked
//! against the macOS kernel, which decompresses hand-built attributes of types 1, 3 and 9 on read.

use crate::{adler32, be32, Error, Result};

pub(crate) const XATTR: &[u8] = b"com.apple.decmpfs";
/// `bsd_flags` bit set on compressed files.
pub(crate) const UF_COMPRESSED: u32 = 0x20;

const HEADER: usize = 16;
/// Data held inside the attribute is at most a few KiB; allow a generous inflate ratio.
const INLINE_MAX: u64 = 16 << 20;

/// (compression type, uncompressed size) from the `cmpf` header.
pub(crate) fn header(x: &[u8]) -> Option<(u32, u64)> {
    if x.get(..4)? != b"fpmc" {
        return None;
    }
    Some((u32::from_le_bytes(x.get(4..8)?.try_into().ok()?), u64::from_le_bytes(x.get(8..16)?.try_into().ok()?)))
}

/// Reads uncompressed bytes at `offset` from the attribute `x`.
pub(crate) fn read(x: &[u8], offset: u64, buf: &mut [u8]) -> Result<usize> {
    let (kind, size) = header(x).ok_or_else(|| Error::corrupt("bad decmpfs header"))?;
    let payload = &x[HEADER..];
    let unsupported = || Error::unsupported(format!("decmpfs compression type {kind}"));
    let data = match kind {
        1 => payload.get(..usize::try_from(size).unwrap_or(usize::MAX)).map(<[u8]>::to_vec),
        3 if size > INLINE_MAX => None,
        3 => match payload.first() {
            Some(b) if b & 0x0f == 0x0f => payload.get(1..).map(<[u8]>::to_vec),
            _ => zlib(payload, size as usize),
        },
        9 if payload.first() == Some(&0xcc) => Some(payload[1..].to_vec()),
        _ => return Err(unsupported()),
    };
    let data = data.filter(|d| d.len() as u64 == size).ok_or_else(|| Error::corrupt("bad decmpfs data"))?;
    let start = usize::try_from(offset).unwrap_or(usize::MAX).min(data.len());
    let n = buf.len().min(data.len() - start);
    buf[..n].copy_from_slice(&data[start..start + n]);
    Ok(n)
}

/// Decompresses a zlib stream (RFC 1950) into at most `max` bytes, checking its Adler-32.
pub(crate) fn zlib(data: &[u8], max: usize) -> Option<Vec<u8>> {
    let (cmf, flg) = (*data.first()?, *data.get(1)?);
    if cmf & 0x0f != 8 || (u16::from(cmf) << 8 | u16::from(flg)) % 31 != 0 || flg & 0x20 != 0 {
        return None;
    }
    let mut out = Vec::with_capacity(max.min(1 << 20));
    let mut bits = Bits { data: &data[2..], pos: 0, buf: 0, count: 0 };
    inflate(&mut bits, &mut out, max)?;
    let trailer = bits.align();
    (trailer.len() >= 4 && be32(trailer, 0) == adler32(&out)).then_some(out)
}

struct Bits<'a> {
    data: &'a [u8],
    pos: usize,
    buf: u32,
    count: u32,
}

impl Bits<'_> {
    /// The next `n` (at most 16) bits, least significant first.
    fn get(&mut self, n: u32) -> Option<u32> {
        while self.count < n {
            self.buf |= u32::from(*self.data.get(self.pos)?) << self.count;
            self.pos += 1;
            self.count += 8;
        }
        let v = self.buf & ((1u32 << n) - 1);
        self.buf >>= n;
        self.count -= n;
        Some(v)
    }

    /// Drops to the next byte boundary and returns the unread bytes.
    fn align(&mut self) -> &[u8] {
        self.pos -= (self.count / 8) as usize;
        self.buf = 0;
        self.count = 0;
        &self.data[self.pos..]
    }
}

/// A canonical Huffman code: how many codes have each length, and the symbols in code order.
struct Huffman {
    counts: [u16; 16],
    symbols: Vec<u16>,
}

impl Huffman {
    fn new(lengths: &[u8]) -> Option<Huffman> {
        let mut counts = [0u16; 16];
        for &l in lengths {
            counts[usize::from(l)] += 1;
        }
        counts[0] = 0;
        let mut left = 1i32;
        for &c in &counts[1..] {
            left = (left << 1) - i32::from(c);
            if left < 0 {
                return None; // more codes than the lengths allow
            }
        }
        let mut offsets = [0u16; 16];
        for len in 1..15 {
            offsets[len + 1] = offsets[len] + counts[len];
        }
        let mut symbols = vec![0u16; lengths.len()];
        for (sym, &l) in lengths.iter().enumerate() {
            if l != 0 {
                symbols[usize::from(offsets[usize::from(l)])] = sym as u16;
                offsets[usize::from(l)] += 1;
            }
        }
        Some(Huffman { counts, symbols })
    }

    fn decode(&self, bits: &mut Bits) -> Option<u16> {
        let (mut code, mut first, mut index) = (0i32, 0i32, 0i32);
        for &count in &self.counts[1..] {
            code |= bits.get(1)? as i32;
            let count = i32::from(count);
            if code - first < count {
                return self.symbols.get((index + code - first) as usize).copied();
            }
            index += count;
            first = (first + count) << 1;
            code <<= 1;
        }
        None
    }
}

const LEN_BASE: [u16; 29] =
    [3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99, 115, 131, 163, 195, 227, 258];
const LEN_EXTRA: [u8; 29] = [0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0];
const DIST_BASE: [u16; 30] = [
    1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025, 1537, 2049, 3073, 4097, 6145,
    8193, 12289, 16385, 24577,
];
const DIST_EXTRA: [u8; 30] =
    [0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13];
const CLEN_ORDER: [usize; 19] = [16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15];

/// RFC 1951 deflate.
fn inflate(bits: &mut Bits, out: &mut Vec<u8>, max: usize) -> Option<()> {
    loop {
        let last = bits.get(1)? == 1;
        match bits.get(2)? {
            0 => {
                let rest = bits.align();
                let len = usize::from(u16::from_le_bytes([*rest.first()?, *rest.get(1)?]));
                let nlen = u16::from_le_bytes([*rest.get(2)?, *rest.get(3)?]);
                if len as u16 != !nlen || out.len() + len > max {
                    return None;
                }
                out.extend_from_slice(rest.get(4..4 + len)?);
                bits.pos += 4 + len;
            }
            1 => {
                let mut lengths = [8u8; 288];
                lengths[144..256].fill(9);
                lengths[256..280].fill(7);
                codes(bits, out, max, &Huffman::new(&lengths)?, &Huffman::new(&[5; 30])?)?;
            }
            2 => {
                let nlit = bits.get(5)? as usize + 257;
                if nlit > 286 {
                    return None; // RFC 1951 3.2.7: 257 to 286 literal/length codes
                }
                let ndist = bits.get(5)? as usize + 1;
                let nclen = bits.get(4)? as usize + 4;
                let mut clen = [0u8; 19];
                for &i in &CLEN_ORDER[..nclen] {
                    clen[i] = bits.get(3)? as u8;
                }
                let clen = Huffman::new(&clen)?;
                let mut lengths = [0u8; 320];
                let mut i = 0;
                while i < nlit + ndist {
                    let (value, repeat) = match clen.decode(bits)? {
                        sym @ 0..=15 => (sym as u8, 1),
                        16 => (*lengths.get(i.checked_sub(1)?)?, 3 + bits.get(2)? as usize),
                        17 => (0, 3 + bits.get(3)? as usize),
                        _ => (0, 11 + bits.get(7)? as usize),
                    };
                    lengths.get_mut(i..i + repeat).filter(|_| i + repeat <= nlit + ndist)?.fill(value);
                    i += repeat;
                }
                let lit = Huffman::new(&lengths[..nlit])?;
                let dist = Huffman::new(&lengths[nlit..nlit + ndist])?;
                codes(bits, out, max, &lit, &dist)?;
            }
            _ => return None,
        }
        if last {
            return Some(());
        }
    }
}

fn codes(bits: &mut Bits, out: &mut Vec<u8>, max: usize, lit: &Huffman, dist: &Huffman) -> Option<()> {
    loop {
        let sym = usize::from(lit.decode(bits)?);
        if sym < 256 {
            if out.len() >= max {
                return None;
            }
            out.push(sym as u8);
            continue;
        }
        if sym == 256 {
            return Some(());
        }
        let l = sym - 257;
        let len = usize::from(*LEN_BASE.get(l)?) + bits.get(u32::from(LEN_EXTRA[l]))? as usize;
        let d = usize::from(dist.decode(bits)?);
        let distance = usize::from(*DIST_BASE.get(d)?) + bits.get(u32::from(DIST_EXTRA[d]))? as usize;
        if distance > out.len() || out.len() + len > max {
            return None;
        }
        let from = out.len() - distance;
        for k in 0..len {
            out.push(out[from + k]);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
    }

    /// Streams made with Python's `zlib.compress` at levels 0 (stored), 9 on a short string
    /// (fixed codes) and 9 on a longer text (dynamic codes).
    #[test]
    fn inflate_stored_fixed_and_dynamic() {
        assert_eq!(zlib(&unhex("7801010500faff68656c6c6f062c0215"), 100).unwrap(), b"hello");
        assert_eq!(zlib(&unhex("78dacb48cdc9c95728cf2fca4901001a0b045d"), 100).unwrap(), b"hello world");
        let text: Vec<u8> = (0..200).flat_map(|i| format!("line {} of {}\n", i % 17, i % 5).into_bytes()).collect();
        let packed = unhex(DYNAMIC);
        assert_eq!(zlib(&packed, 1 << 20).unwrap(), text);
        assert!(zlib(&packed, 100).is_none(), "output limit");
        for cut in 0..packed.len() - 4 {
            let _ = zlib(&packed[..cut], 1 << 20);
        }
    }

    #[test]
    fn adler32_trailer_is_verified() {
        let good = unhex("7801010500faff68656c6c6f062c0215");
        let mut bad = good.clone();
        *bad.last_mut().unwrap() ^= 0xff;
        assert!(zlib(&bad, 100).is_none(), "wrong checksum");
        assert!(zlib(&good[..good.len() - 4], 100).is_none(), "no checksum");
    }

    /// A zlib stream holding one empty dynamic block that declares `nlit` literal/length
    /// codes, all 9 bits long, and one distance code.
    fn dynamic_empty(nlit: u32) -> Vec<u8> {
        let (mut out, mut acc, mut n) = (vec![0x78, 0x01], 0u32, 0u32);
        let mut put = |value: u32, bits: u32| {
            for i in 0..bits {
                acc |= (value >> i & 1) << n;
                n += 1;
                if n == 8 {
                    out.push(acc as u8);
                    (acc, n) = (0, 0);
                }
            }
        };
        let code =
            |put: &mut dyn FnMut(u32, u32), code: u32, len: u32| (0..len).rev().for_each(|i| put(code >> i & 1, 1));
        put(1, 1); // last block
        put(2, 2); // dynamic codes
        put(nlit - 257, 5);
        put(0, 5); // one distance code
        put(14, 4); // 18 code-length codes, enough to reach symbol 1
        for &symbol in &CLEN_ORDER[..18] {
            put(u32::from(symbol == 1 || symbol == 9), 3);
        }
        // Code-length symbols 1 and 9 are both one bit long: 1 is `0`, 9 is `1`.
        (0..nlit).for_each(|_| code(&mut put, 1, 1));
        code(&mut put, 0, 1);
        code(&mut put, 256, 9); // end of block
        put(0, 7);
        out.extend_from_slice(&1u32.to_be_bytes()); // Adler-32 of nothing
        out
    }

    #[test]
    fn more_than_286_literal_codes_are_refused() {
        assert_eq!(zlib(&dynamic_empty(286), 100), Some(Vec::new()));
        assert_eq!(zlib(&dynamic_empty(288), 100), None, "HLIT above 286");
    }

    const DYNAMIC: &str = "78daedd4bb6dc4401044415f513084edfd71199004083848f97b07824e318273e8b5537863cdebf7ef7b2bdbffcf56be5ee7ceb973ed7aee7aed76ee76ed7eee7eed819dd81dbbb00736b7b0e5988eed188ff5982f7a78453770c70eecc4eed8853d3cfc16b61cd3b11de3b11ef3450fafe806eed8819dd81dbbb08787dfc296633ab6633cd663bee8e115ddc01d3bb013bb6317f6f0f05bd8724cc7768cc77acc173dbca21bb86307766277ecc21e1e7e0b5b8ee9d88ef1588ff9e73d3cefe1790fcf7b78dec3e7dfc31bf658a37d";

    #[test]
    fn inline_types() {
        let mut x = b"fpmc".to_vec();
        x.extend_from_slice(&3u32.to_le_bytes());
        x.extend_from_slice(&5u64.to_le_bytes());
        x.extend_from_slice(b"\xffhello");
        let mut buf = [0u8; 8];
        assert_eq!(read(&x, 1, &mut buf).unwrap(), 4);
        assert_eq!(&buf[..4], b"ello");
        assert_eq!(read(&x, 5, &mut buf).unwrap(), 0);
        x[16] = 0xcc;
        assert!(matches!(read(&x, 0, &mut buf), Err(Error::Corrupt(_))), "not a zlib stream");
        x[4] = 9;
        assert_eq!(read(&x, 0, &mut buf).unwrap(), 5);
        x[16] = 0x06;
        assert!(matches!(read(&x, 0, &mut buf), Err(Error::Unsupported(m)) if m == "decmpfs compression type 9"));
        x[4] = 11;
        assert!(matches!(read(&x, 0, &mut buf), Err(Error::Unsupported(m)) if m == "decmpfs compression type 11"));
    }
}
