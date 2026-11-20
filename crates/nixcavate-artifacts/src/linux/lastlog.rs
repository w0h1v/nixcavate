//! `/var/log/lastlog`: last login per UID. Format: lastlog(8) and glibc `struct lastlog`:
//! records indexed by UID holding a time, a 32-byte line and a 256-byte host. The time is
//! 32-bit on x86-64 (292-byte records) and 64-bit on aarch64 (296-byte records), and
//! big-endian on s390x. The file says none of this, so the layout is chosen by the file
//! length and, when that does not decide, by which one makes the records plausible; the byte
//! order is the one that gives plausible login times.

use super::utmp::field;
use crate::{Artifact, Category, Input, LINUX};
use nixcavate_core::{Basis, Error, Event, Loc, Record, Result, Sink, Timestamp};
use serde::Serialize;
use std::borrow::Cow;
use std::collections::{BTreeMap, HashMap};

pub const ARTIFACT: Artifact =
    Artifact::new("lastlog", "Last login per user", Category::Accounts, LINUX, &["var/log/lastlog"], parse)
        .companions(&["etc/passwd"])
        .sparse();

/// Record sizes: x86-64 (4-byte time), then aarch64 (8-byte time).
const RECORD_SIZES: [usize; 2] = [292, 296];
static ZEROS: [u8; 296] = [0; 296];

#[derive(Serialize)]
struct LastLogin<'a> {
    uid: u64,
    /// From `etc/passwd`; empty when the UID is not listed there.
    user: &'a str,
    /// None when the stored time is 0 although the record is not empty.
    time: Option<Timestamp>,
    line: Cow<'a, str>,
    remote_host: Cow<'a, str>,
}

impl Record for LastLogin<'_> {
    fn events(&self) -> impl Iterator<Item = Event<'_>> {
        let who = if self.user.is_empty() { format!("uid {}", self.uid) } else { self.user.to_string() };
        let from = if self.remote_host.is_empty() { "local" } else { &self.remote_host };
        let message = format!("{who} last logged in on {} from {from}", self.line);
        self.time.map(|ts| Event::new(ts, "last_login", message)).into_iter()
    }
}

/// Maps UID to the first account that has it, the one `getpwuid` would return.
fn users(passwd: &str) -> HashMap<u64, &str> {
    let mut map = HashMap::new();
    for line in passwd.lines().filter(|l| !l.starts_with('#')) {
        let mut fields = line.split(':');
        if let (Some(name), Some(uid)) = (fields.next(), fields.nth(1).and_then(|f| f.parse().ok())) {
            map.entry(uid).or_insert(name);
        }
    }
    map
}

/// The records that are not all zeros, with their index (the UID), under record size `size`:
/// the whole records of `input.data`, or, for a sparse file read as its pieces, every record a
/// piece touches, its bytes outside the pieces being the zeros of the holes.
fn used<'d>(input: &Input<'d>, size: usize) -> Vec<(u64, Cow<'d, [u8]>)> {
    if input.pieces.is_empty() {
        let records = input.data.chunks_exact(size).enumerate();
        return records.filter(|(_, r)| *r != &ZEROS[..size]).map(|(i, r)| (i as u64, Cow::Borrowed(r))).collect();
    }
    let size64 = size as u64;
    // Keyed by index: a record that two pieces both reach is put together from both.
    let mut records: BTreeMap<u64, Vec<u8>> = BTreeMap::new();
    for &(offset, bytes) in input.pieces {
        let end = offset.saturating_add(bytes.len() as u64).min(input.size);
        if offset >= end {
            continue;
        }
        // Every record the piece touches: one that runs on past the piece has zeros there (a
        // hole). Whole records of the file only, as for a whole file: one cut by its end is dropped.
        let (first, last) = (offset / size64, end.div_ceil(size64).min(input.size / size64));
        for index in first..last {
            let start = index * size64;
            let record = records.entry(index).or_insert_with(|| vec![0u8; size]);
            let from = start.max(offset);
            let to = (start + size64).min(end);
            let (src, dst) = ((from - offset) as usize, (from - start) as usize);
            let n = (to - from) as usize;
            record[dst..dst + n].copy_from_slice(&bytes[src..src + n]);
        }
    }
    records.into_iter().filter(|(_, r)| r[..] != ZEROS[..size]).map(|(i, r)| (i, Cow::Owned(r))).collect()
}

/// Under the right record size every used record starts its line field with a terminal
/// name (`pts/0`, `tty1`, `ssh`); under the wrong one the fields drift into each other. The
/// score is used records that fit minus those that do not, over whole records only.
fn score(records: &[(u64, Cow<[u8]>)], size: usize) -> i64 {
    let line = size - 288;
    records.iter().map(|(_, r)| if r[line] == 0 || r[line].is_ascii_graphic() { 1 } else { -1 }).sum()
}

/// The time of one record: 4 bytes in the 292-byte layout, 8 bytes in the 296-byte one.
fn seconds(record: &[u8], size: usize, big: bool) -> i64 {
    let mut raw = [0u8; 8];
    raw.copy_from_slice(&record[..8]);
    match (size, big) {
        (292, false) => i32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]).into(),
        (292, true) => i32::from_be_bytes([raw[0], raw[1], raw[2], raw[3]]).into(),
        (_, false) => i64::from_le_bytes(raw),
        (_, true) => i64::from_be_bytes(raw),
    }
}

fn parse(input: &Input, sink: &mut Sink) -> Result<()> {
    // A sparse file read as its pieces has no `data`: its length is the file's size.
    let len = if input.pieces.is_empty() { input.data.len() as u64 } else { input.size };
    if len == 0 {
        return Err(Error::skipped("empty file"));
    }
    // A whole file is a whole number of records: when only one size divides the length, that
    // is the layout. Otherwise (both fit, or the file is cut) the records' content decides.
    let [narrow, wide] = RECORD_SIZES;
    let size = match (len % narrow as u64 == 0, len % wide as u64 == 0) {
        (true, false) => narrow,
        (false, true) => wide,
        _ if score(&used(input, wide), wide) > score(&used(input, narrow), narrow) => wide,
        _ => narrow,
    };
    if len % size as u64 != 0 {
        sink.warn(format!("size {len} is not a multiple of {size}; trailing bytes ignored"));
    }
    // The file is sparse (index = UID), so nearly every record is zero and is left out here.
    let records = used(input, size);
    // The byte order (big-endian on s390x and older PowerPC) is the one under which more
    // records hold a time a login could have: this century, and not after the file was written.
    let latest = if input.mtime > 0 { input.mtime.saturating_add(86_400) } else { 4_102_444_800 };
    let plausible =
        |big: bool| records.iter().filter(|(_, r)| (946_684_800..=latest).contains(&seconds(r, size, big))).count();
    let big = plausible(true) > plausible(false);
    let passwd = input.host.read_text("etc/passwd").unwrap_or_default();
    let users = users(&passwd);
    let line = size - 288;
    for (uid, record) in &records {
        let (uid, record) = (*uid, &record[..]);
        let secs = seconds(record, size, big);
        sink.emit(
            Loc::Offset(uid * size as u64),
            &LastLogin {
                uid,
                user: users.get(&uid).copied().unwrap_or(""),
                time: (secs != 0).then(|| Timestamp::from_secs(secs, Basis::Recorded)),
                line: field(&record[line..line + 32]),
                remote_host: field(&record[line + 32..]),
            },
        )?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{fixture, render, run, run_on_host};

    fn record(secs: i32, line: &str, host: &str) -> Vec<u8> {
        let mut r = vec![0u8; 292];
        r[..4].copy_from_slice(&secs.to_le_bytes());
        r[4..4 + line.len()].copy_from_slice(line.as_bytes());
        r[36..36 + host.len()].copy_from_slice(host.as_bytes());
        r
    }

    /// Records written at the given UID offsets of an otherwise empty (sparse) file.
    fn sparse(entries: &[(usize, Vec<u8>)]) -> Vec<u8> {
        let end = entries.iter().map(|(uid, _)| (uid + 1) * 292).max().unwrap_or(0);
        let mut data = vec![0u8; end];
        for (uid, r) in entries {
            data[uid * 292..(uid + 1) * 292].copy_from_slice(r);
        }
        data
    }

    #[test]
    fn parses_lastlog_with_user_lookup() {
        let files: [(&str, &[u8]); 2] =
            [("var/log/lastlog", &fixture("lastlog/lastlog")), ("etc/passwd", &fixture("lastlog/passwd"))];
        insta::assert_snapshot!(run_on_host(&ARTIFACT, &files, "var/log/lastlog", 0));
    }

    #[test]
    fn sparse_file_with_distant_uids_and_no_passwd() {
        let data = sparse(&[
            (3, record(1_700_000_000, "pts/0", "")),
            (70_000, record(1_700_000_500, "ssh", "web01.example.com")),
        ]);
        insta::assert_snapshot!(run(&ARTIFACT, "var/log/lastlog", &data, 0));
    }

    /// Verified against Debian 12 `lastlog` on arm64, which printed the same three logins.
    #[test]
    fn aarch64_records_are_recognized() {
        let files: [(&str, &[u8]); 2] =
            [("var/log/lastlog", &fixture("lastlog/lastlog.aarch64")), ("etc/passwd", &fixture("lastlog/passwd"))];
        let out = run_on_host(&ARTIFACT, &files, "var/log/lastlog", 0);
        assert_eq!(out.lines().filter(|l| l.starts_with('{')).count(), 3, "{out}");
        assert!(
            out.contains("\"uid\":1,\"user\":\"alice\"")
                && out.contains("\"time\":\"2024-03-10T02:00:00Z\",\"line\":\"pts/1\",\"remote_host\":\"2001:db8::7\""),
            "{out}"
        );
    }

    /// One login on aarch64: under the x86-64 size the record's bytes also look plausible,
    /// so only the file length tells the layouts apart.
    #[test]
    fn a_single_aarch64_record_is_told_apart_by_the_file_length() {
        let mut data = vec![0u8; 1001 * 296];
        data[296_000..296_008].copy_from_slice(&1_700_000_000i64.to_le_bytes());
        data[296_008..296_013].copy_from_slice(b"pts/0");
        data[296_040..296_049].copy_from_slice(b"127.0.0.1");
        let out = run(&ARTIFACT, "var/log/lastlog", &data, 0);
        assert!(!out.contains("warning"), "{out}");
        let login = r#""uid":1000,"user":"","time":"2023-11-14T22:13:20Z","line":"pts/0","remote_host":"127.0.0.1""#;
        assert!(out.contains(login), "{out}");
    }

    /// s390x writes the time big-endian. Read the other way it is a date far from any login.
    #[test]
    fn big_endian_times_are_read() {
        let mut wide = vec![0u8; 1001 * 296];
        wide[296_000..296_008].copy_from_slice(&1_700_000_000i64.to_be_bytes());
        wide[296_008..296_013].copy_from_slice(b"pts/0");
        let out = run(&ARTIFACT, "var/log/lastlog", &wide, 1_700_000_100);
        assert!(out.contains(r#""uid":1000,"user":"","time":"2023-11-14T22:13:20Z","line":"pts/0""#), "{out}");

        let mut narrow = vec![0u8; 3 * 292];
        narrow[292..296].copy_from_slice(&1_700_000_000i32.to_be_bytes());
        narrow[296..300].copy_from_slice(b"tty1");
        let out = run(&ARTIFACT, "var/log/lastlog", &narrow, 1_700_000_100);
        assert!(out.contains(r#""uid":1,"user":"","time":"2023-11-14T22:13:20Z","line":"tty1""#), "{out}");
    }

    #[test]
    fn aarch64_with_a_trailing_byte_keeps_its_layout() {
        let mut data = fixture("lastlog/lastlog.aarch64");
        data.push(0);
        let files: [(&str, &[u8]); 2] = [("var/log/lastlog", &data), ("etc/passwd", &fixture("lastlog/passwd"))];
        let out = run_on_host(&ARTIFACT, &files, "var/log/lastlog", 0);
        assert_eq!(out.lines().filter(|l| l.starts_with('{')).count(), 3, "{out}");
        assert!(out.contains("2024-03-10T02:00:00Z") && out.contains("trailing bytes ignored"), "{out}");
    }

    #[test]
    fn truncated_last_record_is_dropped_with_a_warning() {
        let mut data =
            sparse(&[(0, record(1_700_000_000, "tty1", "")), (1, record(1_700_000_100, "pts/1", "198.51.100.7"))]);
        data.truncate(292 + 20); // cuts uid 1 inside its line field
        insta::assert_snapshot!(run(&ARTIFACT, "var/log/lastlog", &data, 0));
    }

    #[test]
    fn empty_and_all_zero_inputs() {
        assert!(run(&ARTIFACT, "var/log/lastlog", b"", 0).contains("skipped: empty file"));
        assert_eq!(run(&ARTIFACT, "var/log/lastlog", &vec![0u8; 292 * 200], 0), "");
    }

    /// The written blocks of `data`, as a filesystem would list them: `block`-sized pieces that
    /// are not all zeros, neighbours merged.
    fn pieces_of(data: &[u8], block: usize) -> Vec<(u64, Vec<u8>)> {
        let mut pieces: Vec<(u64, Vec<u8>)> = Vec::new();
        for (i, chunk) in data.chunks(block).enumerate() {
            if chunk.iter().all(|&b| b == 0) {
                continue;
            }
            let offset = (i * block) as u64;
            match pieces.last_mut() {
                Some((start, bytes)) if *start + bytes.len() as u64 == offset => bytes.extend_from_slice(chunk),
                _ => pieces.push((offset, chunk.to_vec())),
            }
        }
        pieces
    }

    /// Runs the parser on `pieces` of a file of `size` bytes, as for a sparse file in an image.
    fn run_pieces(files: &[(&str, &[u8])], pieces: &[(u64, Vec<u8>)], size: u64, mtime: i64) -> String {
        let refs: Vec<(u64, &[u8])> = pieces.iter().map(|(o, b)| (*o, b.as_slice())).collect();
        // The host needs the file listed; its bytes are not what the parser reads.
        let mut files = files.to_vec();
        if !files.iter().any(|(p, _)| *p == "var/log/lastlog") {
            files.push(("var/log/lastlog", b""));
        }
        crate::testing::with_host(&files, "var/log/lastlog", mtime, |input| {
            render(&ARTIFACT, &Input { data: &[], size, pieces: &refs, ..*input })
        })
    }

    /// The pieces of a sparse file give exactly what the whole file gives, for both layouts,
    /// whatever the block size: records cut by a block edge are put back together from zeros.
    #[test]
    fn pieces_of_a_sparse_file_give_what_the_whole_file_gives() {
        let passwd = fixture("lastlog/passwd");
        let narrow = sparse(&[
            (0, record(1_700_000_000, "tty1", "")),
            (3, record(1_700_000_100, "pts/0", "198.51.100.7")),
            (14, record(1_700_000_200, "pts/1", "edge.example")), // crosses the 4 KiB edge
            (70_000, record(1_700_000_500, "ssh", "web01.example.com")),
        ]);
        let wide = fixture("lastlog/lastlog.aarch64");
        for (data, mtime) in [(&narrow, 0), (&wide, 0)] {
            let files: [(&str, &[u8]); 2] = [("var/log/lastlog", data), ("etc/passwd", &passwd)];
            let whole = run_on_host(&ARTIFACT, &files, "var/log/lastlog", mtime);
            assert!(whole.contains("\"time\""), "{whole}");
            for block in [512, 1024, 4096] {
                let pieces = pieces_of(data, block);
                assert_eq!(run_pieces(&files, &pieces, data.len() as u64, mtime), whole, "block {block}");
            }
        }
    }

    /// A domain account (SSSD, winbind) has a UID near 1.5 billion, so the file is hundreds of
    /// gigabytes long with a few blocks written; only the pieces are ever held.
    #[test]
    fn a_domain_uid_hundreds_of_gigabytes_into_the_file() {
        let uid: u64 = 1_500_000_123;
        let start = uid * 292;
        let block_start = start / 4096 * 4096;
        let mut block = vec![0u8; 8192];
        let at = (start - block_start) as usize;
        block[at..at + 292].copy_from_slice(&record(1_790_000_000, "pts/2", "192.0.2.44"));
        let out = run_pieces(&[], &[(block_start, block)], (uid + 1) * 292, 0);
        assert!(!out.contains("warning"), "{out}");
        assert!(
            out.contains(
                r#""uid":1500000123,"user":"","time":"2026-09-21T14:13:20Z","line":"pts/2","remote_host":"192.0.2.44""#
            ),
            "{out}"
        );
    }

    #[test]
    fn hostile_pieces_never_panic() {
        let rec = record(1_700_000_000, "tty1", "");
        // Each case: the pieces, then the file size.
        let cases: Vec<(nixcavate_source::Pieces, u64)> = vec![
            (vec![(0, rec.clone())], 10),                          // a piece past the end of the file
            (vec![(u64::MAX - 10, rec.clone())], u64::MAX),        // offsets at the end of the range
            (vec![(0, rec.clone()), (100, rec.clone())], 292 * 2), // overlapping pieces
            (vec![(5, Vec::new())], 292),                          // an empty piece
            (vec![(290, rec.clone())], 1),                         // a size smaller than the piece offset
        ];
        for (pieces, size) in cases {
            run_pieces(&[], &pieces, size, 0);
        }
    }

    #[test]
    fn truncation_and_corruption_never_panic() {
        let data = fixture("lastlog/lastlog");
        for len in (0..data.len()).step_by(7) {
            run(&ARTIFACT, "var/log/lastlog", &data[..len], 0);
        }
        let mut seed = 0x2545_f491_4f6c_dd1du64;
        for _ in 0..200 {
            let mut copy = data.clone();
            for _ in 0..8 {
                seed ^= seed << 13;
                seed ^= seed >> 7;
                seed ^= seed << 17;
                let at = (seed % copy.len() as u64) as usize;
                copy[at] = (seed >> 32) as u8;
            }
            run(&ARTIFACT, "var/log/lastlog", &copy, 0);
        }
    }
}
