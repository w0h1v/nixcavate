//! UAC's `bodyfile/bodyfile.txt`: one line per file in the Sleuth Kit body file 3.x format,
//! `MD5|name|inode|mode_as_string|UID|GID|size|atime|mtime|ctime|crtime`, times in epoch seconds.
//! Reference: the Sleuth Kit wiki, "Body file".

use crate::text::{for_each_line, lossy};
use crate::{Artifact, Category, Input, ANY_OS};
use nixcavate_core::time::parse_uint;
use nixcavate_core::{Basis, Error, Event, Loc, Record, Result, Sink, Timestamp};
use serde::Serialize;
use std::borrow::Cow;

pub const ARTIFACT: Artifact = Artifact::new(
    "bodyfile",
    "File listing with timestamps (Sleuth Kit body file)",
    Category::Filesystem,
    ANY_OS,
    &["../bodyfile/bodyfile.txt"],
    parse,
)
.split_lines();

/// Timeline kind for each non-empty set of the four times, indexed by `mask - 1` where
/// M=1, A=2, C=4, B=8 (the conventional `macb` column order).
const MACB: [&str; 15] = [
    "m...", ".a..", "ma..", "..c.", "m.c.", ".ac.", "mac.", "...b", "m..b", ".a.b", "ma.b", "..cb", "m.cb", ".acb",
    "macb",
];

#[derive(Serialize)]
struct Entry<'a> {
    path: Cow<'a, str>,
    link_target: Option<Cow<'a, str>>,
    inode: Cow<'a, str>,
    mode: Cow<'a, str>,
    uid: Option<u32>,
    gid: Option<u32>,
    size: Option<u64>,
    accessed: Option<Timestamp>,
    modified: Option<Timestamp>,
    changed: Option<Timestamp>,
    created: Option<Timestamp>,
    suid: bool,
    sgid: bool,
    world_writable: bool,
}

impl Record for Entry<'_> {
    fn events(&self) -> impl Iterator<Item = Event<'_>> {
        let times = [self.modified, self.accessed, self.changed, self.created];
        let mut events: [Option<Event>; 4] = [None, None, None, None];
        for (i, time) in times.iter().enumerate() {
            let Some(time) = time else { continue };
            if times[..i].iter().flatten().any(|earlier| earlier.utc == time.utc) {
                continue; // already reported with the first column holding this value
            }
            let mask = times[i..]
                .iter()
                .enumerate()
                .filter(|(_, other)| other.is_some_and(|o| o.utc == time.utc))
                .fold(0, |mask, (offset, _)| mask | 1 << (i + offset));
            events[i] = Some(Event::new(*time, MACB[mask - 1], &*self.path));
        }
        events.into_iter().flatten()
    }
}

/// A time of 0 or -1 means the file system did not record it.
fn time(bytes: &[u8]) -> Option<Timestamp> {
    let secs = match bytes.strip_prefix(b"-") {
        Some(digits) => i64::try_from(parse_uint(digits)?).ok()?.checked_neg()?,
        None => i64::try_from(parse_uint(bytes)?).ok()?,
    };
    (secs != 0 && secs != -1).then(|| Timestamp::from_secs(secs, Basis::Recorded))
}

fn number<T: TryFrom<u64>>(bytes: &[u8]) -> Option<T> {
    parse_uint(bytes).and_then(|n| T::try_from(n).ok())
}

fn parse_line<'a>(line: &'a [u8]) -> Option<Entry<'a>> {
    // The name may contain `|`, so the nine fixed fields are cut from the right. A line with
    // eight has no creation time: UAC writes it for a file system that records none.
    let rest = &line[memchr::memchr(b'|', line)? + 1..];
    let cut_from_right = |count: usize| {
        let mut cuts = [rest.len(); 9];
        let mut end = rest.len();
        for cut in cuts[..count].iter_mut().rev() {
            end = memchr::memrchr(b'|', &rest[..end])?;
            *cut = end;
        }
        Some(cuts)
    };
    // The short form is accepted only with a mode where the mode belongs: the second half of a
    // name that holds a newline has as many separators, and must stay a line of its own.
    let is_mode = |cuts: &[usize; 9]| {
        let mode = &rest[cuts[1] + 1..cuts[2]];
        mode.len() == 10 && b"-dlcbps".contains(&mode[0])
    };
    let cuts = cut_from_right(9).or_else(|| cut_from_right(8).filter(is_mode))?;
    let field = |n: usize| match cuts.get(n + 1) {
        _ if cuts[n] == rest.len() => &rest[rest.len()..],
        Some(&next) => &rest[cuts[n] + 1..next],
        None => &rest[cuts[n] + 1..],
    };

    let name = &rest[..cuts[0]];
    let mode_bytes = field(1);
    let split = if mode_bytes.starts_with(b"l") { memchr::memmem::find(name, b" -> ") } else { None };
    let (path, link_target) = match split {
        Some(at) => (lossy(&name[..at]), Some(lossy(&name[at + 4..]))),
        None => (lossy(name), None),
    };
    let mode = lossy(mode_bytes);
    let flag = |index: usize, set: &[u8]| mode.as_bytes().get(index).is_some_and(|b| set.contains(b));
    Some(Entry {
        suid: flag(3, b"sS"),
        sgid: flag(6, b"sS"),
        world_writable: flag(8, b"w"),
        path,
        link_target,
        inode: lossy(field(0)),
        mode,
        uid: number(field(2)),
        gid: number(field(3)),
        size: number(field(4)),
        accessed: time(field(5)),
        modified: time(field(6)),
        changed: time(field(7)),
        created: time(field(8)),
    })
}

/// What stands in for a line that is not a body file line (a file name holding a newline
/// splits its line in two): the raw text as the path, so no file name silently disappears.
fn unparsed(line: &[u8]) -> Entry<'_> {
    Entry {
        path: lossy(line),
        link_target: None,
        inode: Cow::Borrowed(""),
        mode: Cow::Borrowed(""),
        uid: None,
        gid: None,
        size: None,
        accessed: None,
        modified: None,
        changed: None,
        created: None,
        suid: false,
        sgid: false,
        world_writable: false,
    }
}

fn parse(input: &Input, sink: &mut Sink) -> Result<()> {
    if input.data.is_empty() {
        return Err(Error::skipped("empty file"));
    }
    let mut unparsed_lines = 0u64;
    for_each_line(input, |line| {
        if line.bytes.is_empty() {
            return Ok(());
        }
        let entry = parse_line(line.bytes).unwrap_or_else(|| {
            unparsed_lines += 1;
            unparsed(line.bytes)
        });
        sink.emit(Loc::Offset(line.offset), &entry)
    })?;
    if unparsed_lines > 0 {
        sink.warn(format!(
            "{unparsed_lines} lines are not body file lines; each is output with its raw text as the path"
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    // The test host has no parent directory, so paths are given without the `../` the real
    // patterns have; the parsers only look at the file name.
    use super::*;
    use crate::testing::{fixture, run};

    /// UAC writes ten fields, with no creation time, for a file system that has none (the
    /// FAT partition at `/boot/efi`).
    #[test]
    fn a_line_without_a_creation_time_is_a_body_file_line() {
        let entry = parse_line(b"0|/boot/efi|1|drwx------|0|0|512|1700000000|1700000001|1700000002").unwrap();
        assert_eq!((entry.path.as_ref(), entry.size, entry.created.is_none()), ("/boot/efi", Some(512), true));
        assert_eq!(entry.changed.map(|t| t.utc), Some(1_700_000_002_000_000_000));
        assert!(parse_line(b"0|/x|1|drwx------|0|0|512|1|2").is_none());
    }

    #[test]
    fn parses_uac_bodyfile() {
        insta::assert_snapshot!(run(&ARTIFACT, "../bodyfile/bodyfile.txt", &fixture("bodyfile/bodyfile.txt"), 0));
    }

    #[test]
    fn edge_cases() {
        insta::assert_snapshot!(run(&ARTIFACT, "../bodyfile/bodyfile.txt", &fixture("bodyfile/edge.txt"), 0));
    }

    #[test]
    fn a_name_with_a_newline_keeps_both_halves_as_records() {
        let data = b"0|/tmp/a|1|-rw-r--r--|0|0|1|1|1|1|1\n0|/tmp/evil\nname|2|-rwxr-xr-x|0|0|5|1|1|1|1\n";
        let out = run(&ARTIFACT, "../bodyfile/bodyfile.txt", data, 0);
        assert!(
            out.contains("\"path\":\"0|/tmp/evil\"") && out.contains("\"path\":\"name|2|-rwxr-xr-x|0|0|5|1|1|1|1\""),
            "{out}"
        );
        assert_eq!(out.matches("warning").count(), 1, "{out}");
        assert!(out.contains("2 lines are not body file lines"), "{out}");
    }

    #[test]
    fn empty_file_is_skipped() {
        insta::assert_snapshot!(run(&ARTIFACT, "../bodyfile/bodyfile.txt", b"", 0));
    }

    #[test]
    fn macb_table_matches_masks() {
        for (i, kind) in MACB.iter().enumerate() {
            let mask = i + 1;
            let expected: String =
                "macb".chars().enumerate().map(|(bit, c)| if mask >> bit & 1 == 1 { c } else { '.' }).collect();
            assert_eq!(*kind, expected);
        }
    }

    #[test]
    fn truncated_and_flipped_input_does_not_panic() {
        let data = fixture("bodyfile/edge.txt");
        for len in 0..data.len() {
            run(&ARTIFACT, "../bodyfile/bodyfile.txt", &data[..len], 0);
        }
        for i in (0..data.len()).step_by(3) {
            let mut flipped = data.clone();
            flipped[i] ^= 0xa5;
            run(&ARTIFACT, "../bodyfile/bodyfile.txt", &flipped, 0);
        }
    }
}
