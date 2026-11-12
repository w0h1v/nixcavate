//! Reading inputs as lines or whole buffers, with compressed rotations (`.gz`, `.bz2`, `.zst`, `.xz`)
//! decompressed on the way. Compression is detected from the content, not the file name.

use crate::Input;
use nixcavate_core::{Error, Result};
use std::borrow::Cow;
use std::io::{BufRead, BufReader, Read};

/// Lines of a compressed stream longer than this are cut; plain inputs are never cut.
const MAX_STREAMED_LINE: usize = 1 << 20;
/// The most a whole-buffer decompression may hold in memory.
const MAX_BUFFERED: u64 = 1 << 30;

/// How many decompressed bytes one input may produce: the expansion limit times its size,
/// at least 16 MiB. A file that expands far more than real logs do is cut there, so a few
/// kilobytes of evidence cannot fill the analyst's disk or memory.
fn output_limit(compressed: usize) -> u64 {
    nixcavate_source::expansion_budget(compressed as u64, 16 << 20)
}

/// The task fails with this, keeping what was read. The message says how to get the rest.
fn too_large(compressed: usize, limit: u64) -> Error {
    Error::format(format!(
        "stopped after {} MiB of decompressed data: {} KiB of input expanded more than the --max-expansion limit allows; \
         rerun with a higher limit (or 0 for none) if this evidence is trusted",
        limit >> 20,
        compressed >> 10
    ))
}

/// One line of text, without its line ending.
pub struct Line<'a> {
    /// 1-based. Meaningful only for artifacts that are not split (`Artifact::split_lines`).
    pub number: u64,
    /// Byte offset of the line in the decompressed file.
    pub offset: u64,
    pub bytes: &'a [u8],
}

/// A streaming decoder when `data` is compressed, `None` when it is plain.
fn decoder(data: &[u8]) -> Result<Option<Box<dyn Read + '_>>> {
    Ok(if data.starts_with(&[0x1f, 0x8b]) {
        Some(Box::new(flate2::read::MultiGzDecoder::new(data)))
    } else if data.starts_with(&[0x28, 0xb5, 0x2f, 0xfd]) {
        Some(Box::new(zstd::stream::read::Decoder::new(data)?))
    } else if data.starts_with(&[0xfd, b'7', b'z', b'X', b'Z', 0]) {
        // The memory limit stops a stream that declares a huge dictionary.
        let stream = xz2::stream::Stream::new_stream_decoder(256 << 20, xz2::stream::CONCATENATED)
            .map_err(|e| Error::format(format!("xz: {e}")))?;
        Some(Box::new(xz2::read::XzDecoder::new_stream(data, stream)))
    } else if data.starts_with(b"BZh") && data.get(4..10) == Some(&[0x31, 0x41, 0x59, 0x26, 0x53, 0x59]) {
        Some(Box::new(bzip2::read::MultiBzDecoder::new(data)))
    } else {
        None
    })
}

/// True when `data` starts with a gzip, bzip2, zstd or xz header.
pub fn is_compressed(data: &[u8]) -> bool {
    !matches!(decoder(data), Ok(None))
}

/// The input's bytes, decompressed if needed. For binary formats that may be rotated and
/// compressed; text parsers should use [`for_each_line`], which streams.
pub fn decompressed<'a>(data: &'a [u8]) -> Result<Cow<'a, [u8]>> {
    let Some(reader) = decoder(data)? else { return Ok(Cow::Borrowed(data)) };
    let limit = output_limit(data.len()).min(MAX_BUFFERED);
    let mut out = Vec::new();
    reader.take(limit + 1).read_to_end(&mut out)?;
    if out.len() as u64 > limit {
        return Err(too_large(data.len(), limit));
    }
    Ok(Cow::Owned(out))
}

/// Calls `f` for every line of the input. A trailing `\r` is removed; a final line with no
/// newline is still delivered.
pub fn for_each_line(input: &Input, mut f: impl FnMut(Line) -> Result<()>) -> Result<()> {
    let strip = |line: &[u8]| -> usize { line.len() - usize::from(line.last() == Some(&b'\r')) };
    // A chunk from the middle of a split file is plain text by construction. Its first bytes
    // are attacker-chosen log content and must not be mistaken for a compression header.
    let reader = if input.offset > 0 { None } else { decoder(input.data)? };
    let Some(reader) = reader else {
        let data = input.data;
        let (mut start, mut number) = (0, 0);
        while start < data.len() {
            let end = memchr::memchr(b'\n', &data[start..]).map_or(data.len(), |i| start + i);
            let line = &data[start..end];
            number += 1;
            f(Line { number, offset: input.offset + start as u64, bytes: &line[..strip(line)] })?;
            start = end + 1;
        }
        return Ok(());
    };

    let limit = output_limit(input.data.len());
    let mut reader = BufReader::with_capacity(1 << 20, reader.take(limit + 1));
    let mut line = Vec::new();
    let (mut offset, mut number) = (0u64, 0u64);
    loop {
        line.clear();
        let line_start = offset;
        let mut ended = false;
        while !ended {
            let buf = reader.fill_buf()?;
            if buf.is_empty() {
                break;
            }
            let (take, used) = match memchr::memchr(b'\n', buf) {
                Some(i) => {
                    ended = true;
                    (i, i + 1)
                }
                None => (buf.len(), buf.len()),
            };
            let room = MAX_STREAMED_LINE.saturating_sub(line.len());
            line.extend_from_slice(&buf[..take.min(room)]);
            reader.consume(used);
            offset += used as u64;
        }
        if !ended && offset == line_start {
            return Ok(());
        }
        if offset > limit {
            // Everything up to here was delivered; the task fails so the cut is visible.
            return Err(too_large(input.data.len(), limit));
        }
        number += 1;
        f(Line { number, offset: line_start, bytes: &line[..strip(&line)] })?;
    }
}

/// Text for output: valid UTF-8 is borrowed, anything else has its bad bytes replaced.
pub fn lossy(bytes: &[u8]) -> Cow<'_, str> {
    String::from_utf8_lossy(bytes)
}

/// Splits `line` at the first `separator` into the part before and the part after.
pub fn split_once(line: &[u8], separator: u8) -> Option<(&[u8], &[u8])> {
    memchr::memchr(separator, line).map(|i| (&line[..i], &line[i + 1..]))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::with_input;
    use std::io::Write;

    fn lines_of(data: &[u8]) -> Vec<(u64, u64, String)> {
        with_input("x.log", data, 0, |input| {
            let mut seen = Vec::new();
            for_each_line(input, |l| {
                seen.push((l.number, l.offset, lossy(l.bytes).into_owned()));
                Ok(())
            })
            .unwrap();
            seen
        })
    }

    #[test]
    fn plain_lines_with_and_without_trailing_newline() {
        let expected =
            vec![(1, 0, "one".to_string()), (2, 4, "two".into()), (3, 9, String::new()), (4, 10, "four".into())];
        assert_eq!(lines_of(b"one\ntwo\r\n\nfour"), expected);
        assert_eq!(lines_of(b"one\ntwo\r\n\nfour\n"), expected);
        assert!(lines_of(b"").is_empty());
    }

    #[test]
    fn compressed_lines_match_plain_lines() {
        let plain = b"alpha\nbeta\r\n\ngamma";
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        gz.write_all(plain).unwrap();
        let zst = zstd::encode_all(&plain[..], 1).unwrap();
        let mut xz = xz2::write::XzEncoder::new(Vec::new(), 1);
        xz.write_all(plain).unwrap();
        let mut bz = bzip2::write::BzEncoder::new(Vec::new(), bzip2::Compression::fast());
        bz.write_all(plain).unwrap();
        for packed in [gz.finish().unwrap(), zst, xz.finish().unwrap(), bz.finish().unwrap()] {
            assert_eq!(lines_of(&packed), lines_of(plain));
            assert_eq!(&*decompressed(&packed).unwrap(), plain);
        }
    }

    #[test]
    fn overlong_compressed_lines_are_cut_not_buffered() {
        let mut plain = vec![b'a'; MAX_STREAMED_LINE + 500];
        plain.extend_from_slice(b"\nnext\n");
        let packed = zstd::encode_all(&plain[..], 1).unwrap();
        let lines = lines_of(&packed);
        assert_eq!(lines.len(), 2);
        assert_eq!(lines[0].2.len(), MAX_STREAMED_LINE);
        assert_eq!((lines[1].1, lines[1].2.as_str()), (MAX_STREAMED_LINE as u64 + 501, "next"));
    }

    #[test]
    fn a_chunk_that_starts_like_a_compressed_file_is_still_text() {
        let data = b"\x1f\x8b not gzip, just a log line\nBZh91AY&SY next\n";
        let lines = with_input("x.log", data, 0, |input| {
            let chunk = crate::Input { offset: 4096, ..*input };
            let mut seen = Vec::new();
            for_each_line(&chunk, |l| {
                seen.push(l.offset);
                Ok(())
            })
            .unwrap();
            seen
        });
        assert_eq!(lines, [4096, 4096 + 29]);
    }

    #[test]
    fn decompression_bombs_are_cut() {
        // 40 lines of 1 MiB compress to a few kilobytes: past both the ratio and the floor.
        let mut plain = vec![b'a'; (1 << 20) - 1];
        plain.push(b'\n');
        let bomb = zstd::encode_all(&plain.repeat(40)[..], 3).unwrap();
        assert!(bomb.len() < 64 << 10);
        assert!(matches!(decompressed(&bomb), Err(Error::Format(_))));
        let (lines, result) = with_input("x.log.zst", &bomb, 0, |input| {
            let mut lines = 0u64;
            let result = for_each_line(input, |_| {
                lines += 1;
                Ok(())
            });
            (lines, result)
        });
        assert!(matches!(result, Err(Error::Format(_))));
        assert!((16..=18).contains(&lines), "cut near the 16 MiB limit, got {lines} lines");
    }
}
