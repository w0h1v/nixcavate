//! LZO1X decompression and the framing Btrfs wraps it in, written from the kernel's
//! `lib/lzo/lzo1x_decompress_safe.c` (the reference bitstream description is in its
//! `Documentation/staging/lzo.rst`) and `fs/btrfs/lzo.c`.
//!
//! A Btrfs LZO extent is a 4-byte little-endian total length (itself included), then
//! segments: a 4-byte length and that many bytes of LZO1X data, which decompress to at most
//! one sector. A segment header never straddles a sector boundary: when fewer than 4 bytes are
//! left in the sector, they are padding. Each segment decompresses on its own, so a match can
//! only reach back into the output of its own segment.

use crate::{le16, le32, Error, Result};

/// `lzo1x_worst_compress(PAGE_SIZE)` for 64 KiB pages: no real segment is longer.
const MAX_SEGMENT: usize = 65536 + 65536 / 16 + 64 + 3;
/// Most zero bytes a length run may hold before the count would overflow (the kernel's
/// `MAX_255_COUNT` for a 64-bit `size_t`, cut to what any real stream needs).
const MAX_ZERO_RUN: usize = 1 << 16;

/// Decompresses a Btrfs LZO extent, appending at most `limit` bytes to `out` (a segment that
/// decompresses to more than a sector is an error).
pub(crate) fn decompress(input: &[u8], sector: usize, out: &mut Vec<u8>, limit: usize) -> Result<()> {
    let bad = |what: &str| Error::corrupt(format!("LZO extent: {what}"));
    let total = le32(input, 0) as usize;
    if total < 4 || total > input.len() {
        return Err(bad("total length out of range"));
    }
    let sector = sector.max(1);
    let start = out.len();
    let mut at = 4usize;
    while at < total && out.len() - start < limit {
        if at + 4 > total {
            return Err(bad("segment header past the end"));
        }
        let len = le32(input, at) as usize;
        at += 4;
        let end = at.checked_add(len).filter(|&e| e <= total && len <= MAX_SEGMENT);
        let Some(end) = end else { return Err(bad("segment length out of range")) };
        // Like the kernel, decompress the whole segment and keep what the extent needs.
        lzo1x(&input[at..end], out, sector)?;
        out.truncate(start + limit.min(out.len() - start));
        at = end;
        let left = at.next_multiple_of(sector) - at;
        if left < 4 {
            at += left;
        }
    }
    Ok(())
}

/// Decompresses one LZO1X stream, appending to `out`. More than `limit` bytes of output, a
/// match reaching before this stream's output, or input that ends early is an error.
pub(crate) fn lzo1x(input: &[u8], out: &mut Vec<u8>, limit: usize) -> Result<()> {
    let base = out.len();
    let bad = |what: &str| Error::corrupt(format!("LZO stream: {what}"));
    let mut ip = 0usize;
    let byte = |ip: usize| input.get(ip).copied().map(usize::from).ok_or_else(|| bad("input ends early"));
    // Copies `n` literal bytes from the input.
    let literals = |out: &mut Vec<u8>, ip: &mut usize, n: usize| -> Result<()> {
        let src = input.get(*ip..ip.saturating_add(n)).ok_or_else(|| bad("input ends early"))?;
        if out.len() - base + n > limit {
            return Err(bad("output larger than a sector"));
        }
        out.extend_from_slice(src);
        *ip += n;
        Ok(())
    };
    // Copies a match of `len` bytes from `dist` bytes back (overlapping copies repeat).
    let copy = |out: &mut Vec<u8>, dist: usize, len: usize| -> Result<()> {
        if dist == 0 || dist > out.len() - base {
            return Err(bad("match reaches before the start of the output"));
        }
        if out.len() - base + len > limit {
            return Err(bad("output larger than a sector"));
        }
        let from = out.len() - dist;
        for i in 0..len {
            let b = out[from + i];
            out.push(b);
        }
        Ok(())
    };
    // A length extended by zero bytes (each worth 255) and a final byte.
    let run = |ip: &mut usize, add: usize| -> Result<usize> {
        let first = *ip;
        while byte(*ip)? == 0 {
            *ip += 1;
            if *ip - first > MAX_ZERO_RUN {
                return Err(bad("length run too long"));
            }
        }
        let n = (*ip - first) * 255 + add + byte(*ip)?;
        *ip += 1;
        Ok(n)
    };

    if input.len() < 3 {
        return Err(bad("too short"));
    }
    if input.len() >= 5 && input[0] == 17 {
        // LZO-RLE marker (bitstream version), written by zram, never by Btrfs.
        if input[1] != 0 {
            return Err(Error::unsupported("LZO-RLE stream"));
        }
        ip = 2;
    }
    // `state`: literals copied after the last match (0 to 3), or 4 after a literal run.
    let mut state;
    let first = byte(ip)?;
    if first > 17 {
        ip += 1;
        let t = first - 17;
        literals(out, &mut ip, t)?;
        state = if t < 4 { t } else { 4 };
    } else {
        state = 0;
    }
    loop {
        let t = byte(ip)?;
        ip += 1;
        let (dist, len, next);
        if t < 16 {
            if state == 0 {
                // A run of literals.
                let n = if t == 0 { run(&mut ip, 15)? } else { t } + 3;
                literals(out, &mut ip, n)?;
                state = 4;
                continue;
            }
            let b = byte(ip)?;
            ip += 1;
            next = t & 3;
            if state == 4 {
                // A 3-byte match 2049 to 3072 bytes back.
                dist = 1 + 0x800 + (t >> 2) + (b << 2);
                len = 3;
            } else {
                // A 2-byte match at most 1024 bytes back.
                dist = 1 + (t >> 2) + (b << 2);
                len = 2;
            }
        } else if t >= 64 {
            let b = byte(ip)?;
            ip += 1;
            next = t & 3;
            dist = 1 + ((t >> 2) & 7) + (b << 3);
            len = (t >> 5) + 1;
        } else if t >= 32 {
            let n = t & 31;
            len = if n == 0 { run(&mut ip, 31)? } else { n } + 2;
            let d = usize::from(le16(input.get(ip..ip + 2).ok_or_else(|| bad("input ends early"))?, 0));
            ip += 2;
            next = d & 3;
            dist = 1 + (d >> 2);
        } else {
            let n = t & 7;
            len = if n == 0 { run(&mut ip, 7)? } else { n } + 2;
            let d = usize::from(le16(input.get(ip..ip + 2).ok_or_else(|| bad("input ends early"))?, 0));
            ip += 2;
            next = d & 3;
            let far = ((t & 8) << 11) + (d >> 2);
            if far == 0 {
                // End of stream: 0x11 0x00 0x00.
                if len != 3 {
                    return Err(bad("malformed end marker"));
                }
                return Ok(());
            }
            dist = far + 0x4000;
        }
        copy(out, dist, len)?;
        literals(out, &mut ip, next)?;
        state = next;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// "abcabcabcabc" + end: 3 literals, then a 9-byte match 3 bytes back.
    const SMALL: &[u8] = &[17 + 3, b'a', b'b', b'c', 0x20 | 7, 2 << 2, 0, 0x11, 0, 0];

    #[test]
    fn decodes_literals_and_overlapping_matches() {
        let mut out = Vec::new();
        lzo1x(SMALL, &mut out, 4096).unwrap();
        assert_eq!(out, b"abcabcabcabc");
    }

    #[test]
    fn refuses_bad_streams() {
        let mut out = Vec::new();
        // A match reaching before the start of the output.
        let back = [17 + 3, b'a', b'b', b'c', 0x20 | 7, 9 << 2, 0, 0x11, 0, 0];
        assert!(lzo1x(&back, &mut out, 4096).is_err());
        // Earlier output in `out` (another segment) is not reachable either.
        let mut out = b"0123456789".to_vec();
        assert!(lzo1x(&back, &mut out, 4096).is_err());
        // More output than the limit, and every truncation of a valid stream.
        assert!(lzo1x(SMALL, &mut Vec::new(), 8).is_err());
        for n in 0..SMALL.len() {
            assert!(lzo1x(&SMALL[..n], &mut Vec::new(), 4096).is_err(), "{n}");
        }
        // A long run of zero length bytes ends.
        let mut zeros = vec![0u8; 1 << 20];
        zeros.push(1);
        assert!(lzo1x(&zeros, &mut Vec::new(), 4096).is_err());
    }

    #[test]
    fn btrfs_framing() {
        // Total length, one segment, then padding to the sector end and a second segment.
        let mut ext = Vec::new();
        ext.extend_from_slice(&0u32.to_le_bytes());
        ext.extend_from_slice(&(SMALL.len() as u32).to_le_bytes());
        ext.extend_from_slice(SMALL);
        let total = ext.len() as u32;
        ext[..4].copy_from_slice(&total.to_le_bytes());
        let mut out = Vec::new();
        decompress(&ext, 4096, &mut out, 1 << 17).unwrap();
        assert_eq!(out, b"abcabcabcabc");
        // The limit cuts the output short.
        let mut out = Vec::new();
        decompress(&ext, 4096, &mut out, 5).unwrap();
        assert_eq!(out, b"abcab");
        // A total length larger than the input, or a segment past the total.
        let mut lie = ext.clone();
        lie[..4].copy_from_slice(&1000u32.to_le_bytes());
        assert!(decompress(&lie, 4096, &mut Vec::new(), 1 << 17).is_err());
        let mut lie = ext.clone();
        lie[4..8].copy_from_slice(&100u32.to_le_bytes());
        assert!(decompress(&lie, 4096, &mut Vec::new(), 1 << 17).is_err());
    }
}
