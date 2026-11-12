//! FSEvents logs (`.fseventsd/*`): the file system change journal kept per volume. The files are
//! gzip-compressed streams of pages. A page starts with a 12-byte header (`1SLD`, `2SLD` or
//! `3SLD`, 4 unknown bytes, u32 page size including the header), then little-endian records:
//! NUL-terminated path, u64 event id, u32 flags, and from version 2 on a u64 node id (version 3
//! adds one more u32, which is not decoded). Layout: libyal dtformats, "MacOS File System Events
//! Disk Log Stream format" (versions 1 and 2).
//!
//! Flag bits follow the table used by the community FSEvents tools (FSEventsParser, and the
//! mac4n6 write-ups). The libyal document lists different values for the high bits (it derives
//! them from kernel constants), so the two disagree; this table could not be checked against a
//! live journal. The raw value is always output next to the names.
//!
//! Records carry no time of their own, only a monotonically increasing event id, so there are no
//! timeline events and the file's mtime is not used as a record time. A journal can be hundreds
//! of MiB decompressed: records borrow the path from the buffer and the flag names are written
//! into one reusable `|`-joined string.

use crate::text::{decompressed, lossy};
use crate::{Artifact, Category, Input, MACOS};
use nixcavate_core::{Error, Loc, Record, Result, Sink};
use serde::Serialize;
use std::borrow::Cow;

pub const ARTIFACT: Artifact = Artifact::new(
    "fsevents",
    "File system event journal (.fseventsd)",
    Category::Filesystem,
    MACOS,
    &[".fseventsd/*", "System/Volumes/Data/.fseventsd/*"],
    parse,
);

const PAGE_HEADER: usize = 12;

const FLAGS: [(u32, &str); 21] = [
    (0x0000_0001, "FolderEvent"),
    (0x0000_0002, "Mount"),
    (0x0000_0004, "Unmount"),
    (0x0000_0020, "EndOfTransaction"),
    (0x0000_0800, "LastHardLinkRemoved"),
    (0x0000_1000, "HardLink"),
    (0x0000_4000, "SymbolicLink"),
    (0x0000_8000, "FileEvent"),
    (0x0001_0000, "PermissionChange"),
    (0x0002_0000, "ExtendedAttrModified"),
    (0x0004_0000, "ExtendedAttrRemoved"),
    (0x0010_0000, "DocumentRevisioning"),
    (0x0040_0000, "ItemCloned"),
    (0x0100_0000, "Created"),
    (0x0200_0000, "Removed"),
    (0x0400_0000, "InodeMetaMod"),
    (0x0800_0000, "Renamed"),
    (0x1000_0000, "Modified"),
    (0x2000_0000, "Exchange"),
    (0x4000_0000, "FinderInfoMod"),
    (0x8000_0000, "FolderCreated"),
];

#[derive(Serialize)]
struct Event<'a> {
    path: Cow<'a, str>,
    event_id: u64,
    /// Names of the set flags joined with `|`; bits without a name appear only in `flags_raw`.
    flags: &'a str,
    flags_raw: u32,
    node_id: Option<u64>,
}

impl Record for Event<'_> {}

fn le<const N: usize>(bytes: &[u8]) -> Option<[u8; N]> {
    bytes.get(..N)?.try_into().ok()
}

fn parse(input: &Input, sink: &mut Sink) -> Result<()> {
    if input.path.ends_with("fseventsd-uuid") {
        return Err(Error::skipped("volume identifier, not a journal"));
    }
    let data = decompressed(input.data)?;
    if data.is_empty() {
        return Err(Error::skipped("empty file"));
    }
    if !matches!(data.get(..4), Some(b"1SLD" | b"2SLD" | b"3SLD")) {
        return Err(Error::format("not an FSEvents page stream"));
    }
    let mut names = String::new();
    let mut page = 0usize;
    while page < data.len() {
        let magic = data.get(page..page + 4);
        let version = match magic {
            Some(b"1SLD") => 1,
            Some(b"2SLD") => 2,
            Some(b"3SLD") => 3,
            _ => {
                sink.warn(format!("offset {page}: no page header; the rest of the file is skipped"));
                break;
            }
        };
        let size = data.get(page + 8..).and_then(le::<4>).map_or(0, |b| u32::from_le_bytes(b) as usize);
        if size < PAGE_HEADER {
            sink.warn(format!("offset {page}: page size {size} is too small; the rest of the file is skipped"));
            break;
        }
        let end = page.saturating_add(size).min(data.len());
        let mut pos = page + PAGE_HEADER;
        while pos < end {
            let rest = &data[pos..end];
            let Some(nul) = memchr::memchr(0, rest) else {
                sink.warn(format!("offset {pos}: path is not terminated; page ends here"));
                break;
            };
            let tail = &rest[nul + 1..];
            let id_flags = le::<8>(tail).zip(tail.get(8..).and_then(le::<4>));
            let node = if version >= 2 { tail.get(12..).and_then(le::<8>) } else { None };
            let fixed = 12 + if version >= 2 { 8 } else { 0 } + if version >= 3 { 4 } else { 0 };
            let (Some((id, flags)), true) = (id_flags, tail.len() >= fixed) else {
                sink.warn(format!("offset {pos}: record is cut off; page ends here"));
                break;
            };
            let flags_raw = u32::from_le_bytes(flags);
            names.clear();
            for (bit, name) in FLAGS {
                if flags_raw & bit != 0 {
                    if !names.is_empty() {
                        names.push('|');
                    }
                    names.push_str(name);
                }
            }
            sink.emit(
                Loc::Offset(pos as u64),
                &Event {
                    path: lossy(&rest[..nul]),
                    event_id: u64::from_le_bytes(id),
                    flags: &names,
                    flags_raw,
                    node_id: node.map(u64::from_le_bytes),
                },
            )?;
            pos += nul + 1 + fixed;
        }
        page = end;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{fixture, run};

    const PATH: &str = ".fseventsd/0000000000a1b2c3";

    #[test]
    fn version_1_pages() {
        insta::assert_snapshot!(run(&ARTIFACT, PATH, &fixture("fsevents/v1.gz"), 0));
    }

    #[test]
    fn version_2_pages_with_a_truncated_last_record() {
        insta::assert_snapshot!(run(&ARTIFACT, PATH, &fixture("fsevents/v2.gz"), 0));
    }

    #[test]
    fn mtime_is_never_a_record_time() {
        let out = run(&ARTIFACT, PATH, &fixture("fsevents/v2.gz"), 1_710_000_000);
        assert!(!out.contains("--- timeline ---") && !out.contains("\"time\""));
    }

    #[test]
    fn uuid_empty_and_foreign_files_are_not_journals() {
        assert!(run(&ARTIFACT, ".fseventsd/fseventsd-uuid", b"0123-4567", 0).contains("skipped"));
        assert!(run(&ARTIFACT, PATH, b"", 0).contains("skipped: empty file"));
        assert!(run(&ARTIFACT, PATH, b"hello, not a journal", 0).contains("failed: not an FSEvents"));
    }

    #[test]
    fn plain_pages_are_accepted_too() {
        let plain = decompressed(&fixture("fsevents/v1.gz")).unwrap().into_owned();
        assert_eq!(run(&ARTIFACT, PATH, &plain, 0), run(&ARTIFACT, PATH, &fixture("fsevents/v1.gz"), 0));
    }

    #[test]
    fn truncated_and_corrupted_input_never_panics() {
        for name in ["fsevents/v1.gz", "fsevents/v2.gz"] {
            let plain = decompressed(&fixture(name)).unwrap().into_owned();
            for len in 0..plain.len() {
                run(&ARTIFACT, PATH, &plain[..len], 0);
            }
            for i in 0..plain.len() {
                for mask in [0xff, 0x80, 0x01] {
                    let mut flipped = plain.clone();
                    flipped[i] ^= mask;
                    run(&ARTIFACT, PATH, &flipped, 0);
                }
            }
            // Cut compressed streams must fail cleanly, not panic.
            let packed = fixture(name);
            for len in (0..packed.len()).step_by(7) {
                run(&ARTIFACT, PATH, &packed[..len], 0);
            }
        }
    }
}
