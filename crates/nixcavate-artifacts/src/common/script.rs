//! Two generic parsers for files whose mere presence or content is the evidence: scripts in
//! `cron.daily`, `rc.local`, shell profiles, `ld.so.preload`. Artifacts point their `parse`
//! at one of these.

use crate::text::{for_each_line, lossy};
use crate::Input;
use nixcavate_core::{Basis, Loc, Record, Result, Sink, Timestamp};
use serde::Serialize;

#[derive(Serialize)]
struct FileInfo<'a> {
    size: u64,
    /// Permission bits in octal, as collected (`100755`).
    mode: String,
    uid: u32,
    gid: u32,
    /// The file's modification time as the collection preserved it.
    modified: Option<Timestamp>,
    /// The `#!` line, without the `#!`.
    interpreter: &'a str,
    lines: u64,
}

impl Record for FileInfo<'_> {}

/// One record per file: its metadata and interpreter. For directories where any file is run.
pub fn file_info(input: &Input, sink: &mut Sink) -> Result<()> {
    let first_line = input.data.split(|&b| b == b'\n').next().unwrap_or_default();
    let shebang = first_line.strip_prefix(b"#!").map(|rest| lossy(rest));
    sink.emit(
        Loc::None,
        &FileInfo {
            size: input.data.len() as u64,
            mode: format!("{:o}", input.mode),
            uid: input.uid,
            gid: input.gid,
            modified: (input.mtime > 0).then(|| Timestamp::from_secs(input.mtime, Basis::Recorded)),
            interpreter: shebang.as_deref().map(str::trim).unwrap_or_default(),
            lines: memchr::memchr_iter(b'\n', input.data).count() as u64,
        },
    )
}

#[derive(Serialize)]
struct ContentLine<'a> {
    text: &'a str,
}

impl Record for ContentLine<'_> {}

/// One record per line that does something: blank lines and `#` comments are left out.
pub fn content_lines(input: &Input, sink: &mut Sink) -> Result<()> {
    for_each_line(input, |line| {
        let text = lossy(line.bytes);
        let text = text.trim();
        if text.is_empty() || text.starts_with('#') {
            return Ok(());
        }
        sink.emit(Loc::Line(line.number), &ContentLine { text })
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Artifact, Category, LINUX};

    const INFO: Artifact = Artifact::new("test-info", "test", Category::Persistence, LINUX, &["x"], file_info);
    const LINES: Artifact = Artifact::new("test-lines", "test", Category::Persistence, LINUX, &["x"], content_lines);

    #[test]
    fn file_info_reports_metadata_and_shebang() {
        let out = crate::testing::run(&INFO, "etc/cron.daily/job", b"#! /bin/sh -e\necho hi\n", 1_700_000_000);
        assert_eq!(
            out,
            "{\"host\":\"memory\",\"artifact\":\"test-info\",\"source_path\":\"etc/cron.daily/job\",\"source_line\":null,\
             \"size\":22,\"mode\":\"100644\",\"uid\":0,\"gid\":0,\"modified\":\"2023-11-14T22:13:20Z\",\
             \"interpreter\":\"/bin/sh -e\",\"lines\":2}\n"
        );
    }

    #[test]
    fn content_lines_skip_comments_and_blanks() {
        let out = crate::testing::run(&LINES, "etc/rc.local", b"#!/bin/sh\n\n  # note\n/opt/x --daemon\nexit 0\n", 0);
        let texts: Vec<&str> = out.lines().filter_map(|l| l.split("\"text\":\"").nth(1)).collect();
        assert_eq!(texts, ["/opt/x --daemon\"}", "exit 0\"}"]);
        assert!(out.contains("\"source_line\":4"));
    }
}
