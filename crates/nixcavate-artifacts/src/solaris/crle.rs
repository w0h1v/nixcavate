//! `var/ld/ld.config`, `var/ld/64/ld.config` (`var/ld/amd64`, `var/ld/sparcv9`): the runtime linker
//! configuration `crle(1)` writes. Every dynamically linked program reads it, so a changed
//! default library path or an added environment setting runs the attacker's library inside
//! every program (the Solaris counterpart of `ld.so.preload`).
//!
//! The file is binary: a header starting `?RLC` (class, byte order and machine follow, then the
//! version), a number of tables, and a string table. Only the header and the strings are read
//! here: the default and trusted directory lists and environment settings (`LD_PRELOAD=...`
//! shows up as such) are strings that start with `/` or `NAME=`; the hash and alternative-object
//! tables are not decoded and a warning says so.
//!
//! Verified on illumos (OmniOS): 32-bit (`version 4`, x86) and 64-bit (amd64) files made by `crle -c`
//! and `crle -64 -c`, against what `crle` and `crle -64` print for them. SPARC files and
//! files with alternative objects (`-a`, `-I`) or `-e` settings were not produced.

use crate::{Artifact, Category, Input, SOLARIS};
use nixcavate_core::{Error, Loc, Record, Result, Sink};
use serde::Serialize;

pub const ARTIFACT: Artifact = Artifact::new(
    "crle-config",
    "Runtime linker configuration made by crle (default library paths, environment)",
    Category::Persistence,
    SOLARIS,
    &["var/ld/ld.config", "var/ld/*/ld.config", "var/ld/*/*/ld.config", "var/share/ld/ld.config"],
    parse,
);

#[derive(Serialize)]
struct Entry<'a> {
    /// `32` or `64`, from the header.
    class: u8,
    byte_order: &'static str,
    machine: &'static str,
    version: u32,
    /// `path` (a directory or object, or a colon-separated list) or `environment` (`NAME=value`).
    kind: &'static str,
    value: &'a str,
    /// The directories of a path list.
    directories: Vec<&'a str>,
}

impl Record for Entry<'_> {}

fn machine(code: u16) -> &'static str {
    match code {
        2 => "sparc",
        3 => "i386",
        18 | 43 => "sparcv9",
        62 => "amd64",
        183 => "aarch64",
        _ => "unknown",
    }
}

/// True for the beginning of an environment setting: `LD_LIBRARY_PATH=`, `LD_PRELOAD_64=`...
fn is_environment(text: &str) -> bool {
    text.split_once('=').is_some_and(|(name, _)| {
        !name.is_empty() && name.bytes().all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_')
    })
}

fn parse(input: &Input, sink: &mut Sink) -> Result<()> {
    let data = input.data;
    if data.len() < 0x20 || data.get(..4) != Some(b"?RLC") {
        return Err(Error::format("not a crle configuration file (no ?RLC header)"));
    }
    let class = match data[4] {
        1 => 32,
        2 => 64,
        other => return Err(Error::format(format!("unknown class {other} in the crle header"))),
    };
    let big = match data[5] {
        1 => false,
        2 => true,
        other => return Err(Error::format(format!("unknown byte order {other} in the crle header"))),
    };
    let word = |at: usize| -> Option<u32> {
        let b = data.get(at..at + 4)?;
        let raw = [b[0], b[1], b[2], b[3]];
        Some(if big { u32::from_be_bytes(raw) } else { u32::from_le_bytes(raw) })
    };
    let code = {
        let raw = [data[6], data[7]];
        if big {
            u16::from_be_bytes(raw)
        } else {
            u16::from_le_bytes(raw)
        }
    };
    let version = word(0x10).unwrap_or(0);
    // The tables hold small numbers; the strings come after them. A string is a run of printable
    // bytes that ends at a NUL and starts with `/` or `NAME=`.
    let mut found = 0;
    for (offset, chunk) in data.split(|b| *b == 0).scan(0usize, |at, c| {
        let start = *at;
        *at += c.len() + 1;
        Some((start, c))
    }) {
        if offset < 0x20 || chunk.len() < 3 || !chunk.iter().all(|b| (0x20..0x7f).contains(b)) {
            continue;
        }
        let text = String::from_utf8_lossy(chunk);
        let kind = if text.starts_with('/') {
            "path"
        } else if is_environment(&text) {
            "environment"
        } else {
            continue;
        };
        found += 1;
        let directories = if kind == "path" { text.split(':').filter(|d| !d.is_empty()).collect() } else { Vec::new() };
        sink.emit(
            Loc::Offset(offset as u64),
            &Entry {
                class,
                byte_order: if big { "big-endian" } else { "little-endian" },
                machine: machine(code),
                version,
                kind,
                value: &text,
                directories,
            },
        )?;
        if found >= 10_000 {
            break;
        }
    }
    sink.warn("the crle tables of alternative objects and hashes are not decoded; only the strings are listed");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{fixture, run};

    /// `crle` printed `Default Library Path (ELF): /lib:/usr/lib:/tmp/.NXMK_CRLE` (version 4, 32-bit x86) and
    /// `/lib/64:/usr/lib/64:/tmp/.NXMK_CRLE64` (64-bit amd64) for these two files.
    #[test]
    fn real_configuration_files_equal_what_crle_prints() {
        let out32 = run(&ARTIFACT, "var/ld/ld.config", &fixture("crle-config/ld.config.32"), 0);
        let out64 = run(&ARTIFACT, "var/ld/64/ld.config", &fixture("crle-config/ld.config.64"), 0);
        insta::assert_snapshot!("ld32", out32);
        insta::assert_snapshot!("ld64", out64);
        let printed32 = String::from_utf8(fixture("crle-config/crle-32.txt")).unwrap();
        let printed64 = String::from_utf8(fixture("crle-config/crle-64.txt")).unwrap();
        assert!(printed32.contains("Default Library Path (ELF):\t/lib:/usr/lib:/tmp/.NXMK_CRLE"));
        assert!(printed64.contains("Default Library Path (ELF):\t/lib/64:/usr/lib/64:/tmp/.NXMK_CRLE64"));
        assert!(out32.contains(r#""class":32,"byte_order":"little-endian","machine":"i386","version":4,"kind":"path","value":"/lib:/usr/lib:/tmp/.NXMK_CRLE","directories":["/lib","/usr/lib","/tmp/.NXMK_CRLE"]"#), "{out32}");
        assert!(
            out64.contains(r#""class":64,"byte_order":"little-endian","machine":"amd64","version":4"#)
                && out64.contains(r#""directories":["/lib/64","/usr/lib/64","/tmp/.NXMK_CRLE64"]"#),
            "{out64}"
        );
        // The tables are not decoded, and the output says so.
        assert!(out32.contains("only the strings are listed"));
    }

    /// An environment setting is a string `NAME=value` in the same table.
    #[test]
    fn environment_strings_are_found() {
        let mut data = fixture("crle-config/ld.config.32");
        data.extend_from_slice(b"LD_PRELOAD=/tmp/evil.so\0");
        let out = run(&ARTIFACT, "var/ld/ld.config", &data, 0);
        assert!(out.contains(r#""kind":"environment","value":"LD_PRELOAD=/tmp/evil.so","directories":[]"#), "{out}");
    }

    #[test]
    fn other_files_are_refused() {
        assert!(run(&ARTIFACT, "var/ld/ld.config", b"", 0).contains("failed"));
        assert!(run(&ARTIFACT, "var/ld/ld.config", &[0u8; 64], 0).contains("no ?RLC header"));
        let mut bad = fixture("crle-config/ld.config.32");
        bad[4] = 9;
        assert!(run(&ARTIFACT, "var/ld/ld.config", &bad, 0).contains("unknown class"));
        bad[4] = 1;
        bad[5] = 9;
        assert!(run(&ARTIFACT, "var/ld/ld.config", &bad, 0).contains("unknown byte order"));
    }

    #[test]
    fn mutated_files_never_panic() {
        super::super::never_panics(&ARTIFACT, "var/ld/ld.config", &fixture("crle-config/ld.config.32"));
        super::super::never_panics(&ARTIFACT, "var/ld/64/ld.config", &fixture("crle-config/ld.config.64"));
    }
}
