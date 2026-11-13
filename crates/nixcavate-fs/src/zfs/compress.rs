//! The decompressors ZFS needs that have no workspace dependency, written from OpenZFS
//! `module/zfs/lz4_zfs.c` (with the LZ4 block format description, `lz4_Block_format.md`),
//! `lzjb.c` and `zle.c`. Each fills exactly the logical size of a block or fails: a stream
//! that would write past it, reach before its start or read past its input is damage.

use crate::{be32, Error, Result};

fn bad(what: &str, why: &str) -> Error {
    Error::corrupt(format!("{what} block: {why}"))
}

/// A ZFS LZ4 block: a 4-byte big-endian length of the LZ4 data, then one LZ4 block.
/// Output the block does not fill is left as zeros, as the kernel leaves it.
pub(crate) fn lz4_zfs(input: &[u8], out: &mut [u8]) -> Result<()> {
    let len = be32(input, 0) as usize;
    let data = input.get(4..).and_then(|d| d.get(..len)).ok_or_else(|| bad("LZ4", "length past the input"))?;
    lz4_block(data, out).map(|_| ())
}

/// One raw LZ4 block into `out`; returns the bytes written.
pub(crate) fn lz4_block(input: &[u8], out: &mut [u8]) -> Result<usize> {
    let (mut ip, mut op) = (0usize, 0usize);
    let max = out.len();
    let byte = |ip: usize| input.get(ip).copied().ok_or_else(|| bad("LZ4", "input ends early"));
    // A length nibble of 15 continues in bytes of 255 until a smaller one.
    let length = |ip: &mut usize, mut n: usize| -> Result<usize> {
        if n == 15 {
            loop {
                let b = byte(*ip)?;
                *ip += 1;
                n = n.checked_add(usize::from(b)).filter(|&n| n <= max).ok_or_else(|| bad("LZ4", "length too long"))?;
                if b != 255 {
                    break;
                }
            }
        }
        Ok(n)
    };
    loop {
        let token = byte(ip)?;
        ip += 1;
        let lits = length(&mut ip, usize::from(token >> 4))?;
        let src = input.get(ip..ip + lits).ok_or_else(|| bad("LZ4", "literals past the input"))?;
        let dst = out.get_mut(op..op + lits).ok_or_else(|| bad("LZ4", "output past the block size"))?;
        dst.copy_from_slice(src);
        ip += lits;
        op += lits;
        if ip == input.len() {
            return Ok(op);
        }
        let offset = usize::from(byte(ip)?) | usize::from(byte(ip + 1)?) << 8;
        ip += 2;
        let len = length(&mut ip, usize::from(token & 15))? + 4;
        if offset == 0 || offset > op {
            return Err(bad("LZ4", "match reaches before the start of the output"));
        }
        if len > out.len() - op {
            return Err(bad("LZ4", "output past the block size"));
        }
        // An overlapping match repeats the last `offset` bytes: copy what is already there,
        // doubling each time (every copy starts a whole number of periods after `from`).
        let from = op - offset;
        let mut done = 0;
        while done < len {
            let n = (offset + done).min(len - done);
            out.copy_within(from..from + n, op + done);
            done += n;
        }
        op += len;
    }
}

/// LZJB: a copy-map byte announces eight items, each a literal byte or a 2-byte match (6 bits
/// of length less 3, 10 bits of distance). Fills `out` exactly.
pub(crate) fn lzjb(input: &[u8], out: &mut [u8]) -> Result<()> {
    let (mut ip, mut op) = (0usize, 0usize);
    let byte = |ip: usize| input.get(ip).copied().ok_or_else(|| bad("LZJB", "input ends early"));
    let (mut map, mut mask) = (0u8, 0x80u16);
    while op < out.len() {
        mask <<= 1;
        if mask == 0x100 {
            mask = 1;
            map = byte(ip)?;
            ip += 1;
        }
        if u16::from(map) & mask != 0 {
            let (a, b) = (usize::from(byte(ip)?), usize::from(byte(ip + 1)?));
            ip += 2;
            let len = (a >> 2) + 3;
            let offset = (a << 8 | b) & 0x3ff;
            if offset == 0 || offset > op {
                return Err(bad("LZJB", "match reaches before the start of the output"));
            }
            let len = len.min(out.len() - op);
            for _ in 0..len {
                out[op] = out[op - offset];
                op += 1;
            }
        } else {
            out[op] = byte(ip)?;
            ip += 1;
            op += 1;
        }
    }
    Ok(())
}

/// ZLE (zero-length encoding, level 64): a byte `n` below 64 is followed by `n + 1` literal
/// bytes, a larger one stands for `n - 63` zeros. The output must come out exactly full.
pub(crate) fn zle(input: &[u8], out: &mut [u8]) -> Result<()> {
    const N: usize = 64;
    let (mut ip, mut op) = (0usize, 0usize);
    while ip < input.len() && op < out.len() {
        let len = 1 + usize::from(input[ip]);
        ip += 1;
        if len <= N {
            let src = input.get(ip..ip + len).ok_or_else(|| bad("ZLE", "literals past the input"))?;
            out.get_mut(op..op + len).ok_or_else(|| bad("ZLE", "output past the block size"))?.copy_from_slice(src);
            ip += len;
            op += len;
        } else {
            let len = len - N;
            out.get_mut(op..op + len).ok_or_else(|| bad("ZLE", "output past the block size"))?.fill(0);
            op += len;
        }
    }
    if op != out.len() {
        return Err(bad("ZLE", "output shorter than the block size"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lz4_literals_and_overlapping_matches() {
        // "abc" then a 9-byte match 3 back, then the last literals "xyz".
        let block = [0x35, b'a', b'b', b'c', 3, 0, 0x30, b'x', b'y', b'z'];
        let mut out = [0u8; 15];
        assert_eq!(lz4_block(&block, &mut out).unwrap(), 15);
        assert_eq!(&out, b"abcabcabcabcxyz");
        let mut framed = (block.len() as u32).to_be_bytes().to_vec();
        framed.extend_from_slice(&block);
        framed.extend_from_slice(&[0xff; 9]); // padding to the sector after the data
        let mut out = [0u8; 20];
        lz4_zfs(&framed, &mut out).unwrap();
        assert_eq!(&out[..15], b"abcabcabcabcxyz");
        assert_eq!(&out[15..], &[0; 5]);
    }

    #[test]
    fn lz4_refuses_bad_streams() {
        let mut out = [0u8; 15];
        // A match 4 back after 3 bytes, a zero offset, output past the block, every truncation.
        assert!(lz4_block(&[0x35, b'a', b'b', b'c', 4, 0, 0x30, b'x', b'y', b'z'], &mut out).is_err());
        assert!(lz4_block(&[0x35, b'a', b'b', b'c', 0, 0, 0x30, b'x', b'y', b'z'], &mut out).is_err());
        assert!(lz4_block(&[0x35, b'a', b'b', b'c', 3, 0, 0x30, b'x', b'y', b'z'], &mut [0u8; 14]).is_err());
        let good = [0x35, b'a', b'b', b'c', 3, 0, 0x30, b'x', b'y', b'z'];
        for n in 0..good.len() {
            let _ = lz4_block(&good[..n], &mut out);
        }
        // A literal length of 15 + 255 * many cannot pass the output size.
        let mut long = vec![0xf0];
        long.extend(std::iter::repeat_n(255u8, 1 << 16));
        assert!(lz4_block(&long, &mut [0u8; 4096]).is_err());
        // The framed length cannot pass the input.
        assert!(lz4_zfs(&[0, 0, 1, 0, 0x10, b'a'], &mut out).is_err());
    }

    #[test]
    fn lzjb_round_trip() {
        // Map 0b10: literal 'a', then a match of 3 + 2 = 5 bytes 1 back.
        let input = [0b10, b'a', 2 << 2, 1];
        let mut out = [0u8; 6];
        lzjb(&input, &mut out).unwrap();
        assert_eq!(&out, b"aaaaaa");
        // A match before the start, and input that ends early.
        assert!(lzjb(&[0b1, 2 << 2, 1], &mut [0u8; 4]).is_err());
        assert!(lzjb(&[0b10, b'a', 2 << 2, 0], &mut [0u8; 4]).is_err());
        assert!(lzjb(&[0, b'a'], &mut [0u8; 4]).is_err());
    }

    #[test]
    fn zle_runs() {
        // Two literals, then 70 zeros (70 + 63 = 133), then one literal.
        let input = [1, b'x', b'y', 133, 0, b'z'];
        let mut out = [0u8; 73];
        zle(&input, &mut out).unwrap();
        assert_eq!(&out[..2], b"xy");
        assert!(out[2..72].iter().all(|&b| b == 0));
        assert_eq!(out[72], b'z');
        assert!(zle(&input, &mut [0u8; 74]).is_err());
        assert!(zle(&input, &mut [0u8; 71]).is_err());
        assert!(zle(&[5, b'a'], &mut [0u8; 6]).is_err());
    }
}
