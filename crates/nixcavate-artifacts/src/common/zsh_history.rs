//! zsh history: `.zsh_history`, `.zhistory` and macOS per-session files. Format: zshoptions(1)
//! `EXTENDED_HISTORY` (`: <epoch>:<duration>;command`), zshparam(1) `HISTFILE`. Multi-line
//! commands end each line but the last with a backslash. Bytes zsh treats as special
//! (0x83..=0x9f and NUL) are stored "metafied": a 0x83 marker, then the byte XOR 0x20.

use super::home::user_from_path;
use crate::text::{for_each_line, lossy};
use crate::{Artifact, Category, Input, ANY_OS};
use nixcavate_core::time::parse_uint;
use nixcavate_core::{Basis, Event, Loc, Record, Result, Sink, Timestamp};
use serde::Serialize;
use std::borrow::Cow;

pub const ARTIFACT: Artifact = Artifact::new(
    "zsh-history",
    "Zsh command history",
    Category::Execution,
    ANY_OS,
    &[
        "home/*/.zsh_history",
        "home/*/.zhistory",
        "root/.zsh_history",
        "root/.zhistory",
        "Users/*/.zsh_history",
        "Users/*/.zhistory",
        "Users/*/.zsh_sessions/*.history",
        "Users/*/.zsh_sessions/*.historynew",
        "private/var/root/.zsh_history",
        "private/var/root/.zhistory",
        "private/var/root/.zsh_sessions/*.history",
        "private/var/root/.zsh_sessions/*.historynew",
        "var/root/.zsh_history",
        "var/root/.zhistory",
        "var/root/.zsh_sessions/*.history",
        "var/root/.zsh_sessions/*.historynew",
    ],
    parse,
);

const META: u8 = 0x83;

#[derive(Serialize)]
struct Entry<'a> {
    user: &'a str,
    /// Present only with `EXTENDED_HISTORY`.
    time: Option<Timestamp>,
    duration_secs: Option<u64>,
    command: &'a str,
}

impl Record for Entry<'_> {
    fn events(&self) -> impl Iterator<Item = Event<'_>> {
        self.time.map(|ts| Event::new(ts, "executed", format!("{} ran {}", self.user, self.command))).into_iter()
    }
}

/// Splits `: <epoch>:<duration>;` off the front of a line.
fn extended_header(line: &[u8]) -> Option<(i64, u64, &[u8])> {
    let rest = line.strip_prefix(b": ")?;
    let colon = memchr::memchr(b':', rest)?;
    let semi = colon + memchr::memchr(b';', &rest[colon..])?;
    let epoch = i64::try_from(parse_uint(&rest[..colon])?).ok()?;
    let duration = parse_uint(&rest[colon + 1..semi])?;
    Some((epoch, duration, &rest[semi + 1..]))
}

fn unmetafy(bytes: &[u8]) -> Cow<'_, [u8]> {
    if !bytes.contains(&META) {
        return Cow::Borrowed(bytes);
    }
    let mut out = Vec::with_capacity(bytes.len());
    let mut iter = bytes.iter();
    while let Some(&b) = iter.next() {
        match (b == META, b) {
            (true, _) => out.extend(iter.next().map(|n| n ^ 0x20)),
            _ => out.push(b),
        }
    }
    Cow::Owned(out)
}

fn parse(input: &Input, sink: &mut Sink) -> Result<()> {
    let user = user_from_path(input.path);
    // The command being assembled: raw bytes, its first line, and its header fields.
    let mut buf: Vec<u8> = Vec::new();
    let mut open: Option<(u64, Option<(i64, u64)>)> = None;

    let flush = |buf: &mut Vec<u8>, open: &mut Option<(u64, Option<(i64, u64)>)>, sink: &mut Sink| -> Result<()> {
        let Some((number, header)) = open.take() else { return Ok(()) };
        let command = unmetafy(buf);
        let (time, duration_secs) = match header {
            Some((epoch, duration)) => (Some(Timestamp::from_secs(epoch, Basis::Recorded)), Some(duration)),
            None => (None, None),
        };
        let result = sink.emit(Loc::Line(number), &Entry { user, time, duration_secs, command: &lossy(&command) });
        buf.clear();
        result
    };

    for_each_line(input, |line| {
        if open.is_none() {
            if line.bytes.is_empty() {
                return Ok(());
            }
            let (header, body) = match extended_header(line.bytes) {
                Some((epoch, duration, body)) => (Some((epoch, duration)), body),
                None => (None, line.bytes),
            };
            open = Some((line.number, header));
            buf.extend_from_slice(body);
        } else {
            buf.push(b'\n');
            buf.extend_from_slice(line.bytes);
        }
        if buf.last() == Some(&b'\\') {
            buf.pop();
            return Ok(());
        }
        flush(&mut buf, &mut open, sink)
    })?;
    // A file that ends mid-continuation still holds a command.
    flush(&mut buf, &mut open, sink)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{fixture, run};

    #[test]
    fn extended_history_from_zsh() {
        insta::assert_snapshot!(run(&ARTIFACT, "Users/sam/.zsh_history", &fixture("zsh-history/.zsh_history"), 0));
    }

    #[test]
    fn plain_continued_and_crlf_lines() {
        let data = b"ls\r\n: 1700000000:3;echo a \\\r\nb\r\n\r\n: 1700000001:0;tail \\\r\n";
        insta::assert_snapshot!(run(&ARTIFACT, "private/var/root/.zsh_sessions/A.historynew", data, 0));
    }

    #[test]
    fn metafied_bytes_are_restored() {
        assert_eq!(&*unmetafy(&[b'a', META, 0x20, b'b', META]), b"a\x00b");
        assert_eq!(&*unmetafy(&[0xe6, META, 0xb7, 0xa5]), &[0xe6, 0x97, 0xa5]);
    }

    #[test]
    fn empty_and_garbage_do_not_panic() {
        assert_eq!(run(&ARTIFACT, "root/.zsh_history", b"", 0), "");
        let garbage: Vec<u8> = (0..=255u8).cycle().take(2000).collect();
        run(&ARTIFACT, "root/.zsh_history", &garbage, 0);
        run(&ARTIFACT, "root/.zsh_history", b"\x83", 0);
    }
}
