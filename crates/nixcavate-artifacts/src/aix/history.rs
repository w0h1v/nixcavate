//! Command and action records users leave behind: `.sh_history` (ksh), `smit.script` and
//! `smit.log` (SMIT keeps every action it runs), and the text of `alog -o` output.
//!
//! `.sh_history` follows the Korn shell's history file, whose layout David Korn's `history.c`
//! (ksh93, public) documents: the first byte is 0x81 and the second a version number, each
//! command is NUL-terminated and starts on an even byte, the pair 0x81 0x00 after a command
//! cancels it, and a six-byte record (0x82, 0, three bytes of command number, 0) stores a command number. AIX's default
//! `ksh` is ksh88, the ancestor whose history file ksh93 reads; that the two are identical was
//! **not verified against a real AIX file**, so this is "one source, synthetic only" for AIX. A
//! file without the header is read as plain lines.
//!
//! The SMIT and alog files have no documented layout that could be fetched: their lines are kept
//! as written, with nothing inferred (no times).

use super::home_user;
use crate::text::{decompressed, for_each_line, lossy};
use crate::{Artifact, Category, Input, AIX};
use nixcavate_core::{Error, Loc, Record, Result, Sink};
use serde::Serialize;

pub const SH_HISTORY: Artifact = Artifact::new(
    "aix-sh-history",
    "ksh command history (.sh_history)",
    Category::Execution,
    AIX,
    &[".sh_history", "root/.sh_history", "home/*/.sh_history", "usr/home/*/.sh_history"],
    parse_sh_history,
);
pub const SMIT: Artifact = Artifact::new(
    "aix-smit",
    "SMIT actions and the commands they ran (smit.script, smit.log)",
    Category::Execution,
    AIX,
    &["smit.script", "smit.log", "root/smit.script", "root/smit.log", "home/*/smit.script", "home/*/smit.log"],
    parse_smit,
);
pub const ALOG: Artifact = Artifact::new(
    "aix-alog-output",
    "Boot, console and install logs saved with `alog -o`",
    Category::Logs,
    AIX,
    &["../live_response/hardware/alog_-o_-t_*.txt"],
    parse_alog,
);

// ---------------------------------------------------------------- .sh_history

#[derive(Serialize)]
struct Command<'a> {
    user: &'a str,
    command: String,
    /// The shell cancelled this command afterwards (a `0x81 0x00` marker).
    cancelled: bool,
}

impl Record for Command<'_> {}

const MAX_COMMANDS: usize = 5_000_000;

fn parse_sh_history(input: &Input, sink: &mut Sink) -> Result<()> {
    let data = decompressed(input.data)?;
    if data.is_empty() {
        return Err(Error::skipped("empty file"));
    }
    let user = home_user(input.path);
    // Without the header (a copy edited by hand, or another shell's file) the lines are the commands.
    let binary = data.starts_with(&[0x81]) && data.get(1).is_some_and(|v| *v <= 1);
    let mut pending: Option<(u64, String)> = None;
    let mut count = 0usize;
    let mut offset = if binary { 2usize } else { 0 };
    let separator = if binary { 0u8 } else { b'\n' };
    while offset < data.len() {
        if binary {
            // At the start of a command: a six-byte number marker (0x82, 0, three bytes, 0), the
            // cancel pair 0x81 0x00, a stray 0x81 (skipped), or padding to an even byte.
            match (data[offset], data.get(offset + 1)) {
                (0x82, Some(0)) => {
                    offset += 6;
                    continue;
                }
                (0x81, Some(0)) => {
                    if let Some((at, command)) = pending.take() {
                        sink.emit(Loc::Offset(at), &Command { user, command, cancelled: true })?;
                    }
                    offset += 2;
                    continue;
                }
                (0x81 | 0, _) => {
                    offset += 1;
                    continue;
                }
                _ => {}
            }
        }
        let end = memchr::memchr(separator, &data[offset..]).map_or(data.len(), |i| offset + i);
        let segment = &data[offset..end];
        let at = offset as u64;
        offset = end + 1;
        if segment.is_empty() {
            continue;
        }
        if let Some((at, command)) = pending.take() {
            sink.emit(Loc::Offset(at), &Command { user, command, cancelled: false })?;
        }
        count += 1;
        if count > MAX_COMMANDS {
            sink.warn(format!("stopped after {MAX_COMMANDS} commands"));
            break;
        }
        pending = Some((at, lossy(segment).trim_end_matches('\r').to_string()));
    }
    if let Some((at, command)) = pending {
        sink.emit(Loc::Offset(at), &Command { user, command, cancelled: false })?;
    }
    Ok(())
}

// ---------------------------------------------------------------- SMIT

#[derive(Serialize)]
struct SmitLine<'a> {
    user: &'a str,
    /// `script_command`, `script_comment` or `log`.
    kind: &'static str,
    text: &'a str,
}

impl Record for SmitLine<'_> {}

fn parse_smit(input: &Input, sink: &mut Sink) -> Result<()> {
    let user = home_user(input.path);
    let is_script = input.path.ends_with("smit.script");
    for_each_line(input, |line| {
        let text = lossy(line.bytes);
        let text = text.trim();
        if text.is_empty() {
            return Ok(());
        }
        let kind = match (is_script, text.starts_with('#')) {
            (true, false) => "script_command",
            (true, true) => "script_comment",
            (false, _) => "log",
        };
        sink.emit(Loc::Line(line.number), &SmitLine { user, kind, text })
    })
}

// ---------------------------------------------------------------- alog output

#[derive(Serialize)]
struct AlogLine<'a> {
    /// The alog type named in the collected file's name: `boot`, `console`, `bosinst`, `nim`.
    log: &'a str,
    text: &'a str,
}

impl Record for AlogLine<'_> {}

fn parse_alog(input: &Input, sink: &mut Sink) -> Result<()> {
    let name = input.path.rsplit('/').next().unwrap_or("");
    let log = name.strip_prefix("alog_-o_-t_").and_then(|n| n.strip_suffix(".txt")).unwrap_or("");
    for_each_line(input, |line| {
        let text = lossy(line.bytes);
        let text = text.trim_end();
        if text.trim().is_empty() {
            return Ok(());
        }
        sink.emit(Loc::Line(line.number), &AlogLine { log, text })
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::run;

    #[test]
    fn ksh_history_with_header_cancel_and_markers() {
        let mut data = vec![0x81, 0x01];
        data.extend_from_slice(b"ls -l\0");
        data.extend_from_slice(b"\x82\x00\x00\x07\x00\x00");
        data.extend_from_slice(b"rm -rf /tmp/x\0\x81\0");
        data.extend_from_slice(b"su - oracle\0\0");
        data.extend_from_slice(b"caf\xc3\xa9 \xff\0");
        let out = run(&SH_HISTORY, "home/alice/.sh_history", &data, 0);
        assert!(out.contains(r#""command":"rm -rf /tmp/x","cancelled":true"#), "{out}");
        assert!(out.contains(r#""user":"alice","command":"su - oracle","cancelled":false"#), "{out}");
        assert_eq!(out.matches("\"command\"").count(), 4, "{out}");
        insta::assert_snapshot!(out);
    }

    /// `test_files/aix-sh-history/make_fixtures.py` writes the layout of ksh93's `history.c`.
    #[test]
    fn the_fixture_reads_as_documented_and_survives_mutation() {
        let seed = crate::testing::fixture("aix-sh-history/sh_history");
        let out = run(&SH_HISTORY, "home/alice/.sh_history", &seed, 0);
        let commands: Vec<&str> = out.lines().filter_map(|l| l.split("\"command\":\"").nth(1)).collect();
        assert_eq!(commands.len(), 6, "{out}");
        assert!(
            out.contains(r#""command":"rm /var/adm/sulog","cancelled":true"#) && out.contains(r#""command":"exit""#),
            "{out}"
        );
        let mut state = 0x2545_F491_4F6C_DD1Du64;
        let mut next = || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        for _ in 0..1500 {
            let mut data = seed.clone();
            for _ in 0..1 + next() % 5 {
                let at = (next() % data.len() as u64) as usize;
                data[at] = next() as u8;
            }
            data.truncate(1 + (next() % data.len() as u64) as usize);
            let _ = run(&SH_HISTORY, ".sh_history", &data, 0);
        }
    }

    #[test]
    fn plain_lines_and_root_home() {
        let out = run(&SH_HISTORY, ".sh_history", b"id\nwho\n", 0);
        assert!(out.contains(r#""user":"root","command":"id""#), "{out}");
    }

    #[test]
    fn smit_and_alog() {
        let out = run(&SMIT, "smit.script", b"#\n# comment\nmkuser su=true mallory\n\n", 0);
        assert!(out.contains("script_command") && out.contains("script_comment"), "{out}");
        let out = run(&SMIT, "home/bob/smit.log", b"[TOP]\nsome action\n", 0);
        assert!(out.contains(r#""user":"bob","kind":"log""#), "{out}");
        let out = run(&ALOG, "../live_response/hardware/alog_-o_-t_boot.txt", b"0 0 line\nsecond\n", 0);
        assert!(out.contains(r#""log":"boot","text":"0 0 line""#), "{out}");
    }

    #[test]
    fn hostile() {
        for data in
            [&b""[..], b"\x81", b"\x81\x01", b"\x81\x01\0\0\x81\0\x81\0\x82", &[0x81u8; 5000][..], &[0u8; 5000][..]]
        {
            let _ = run(&SH_HISTORY, ".sh_history", data, 0);
            let _ = run(&SMIT, "smit.log", data, 0);
        }
    }
}
