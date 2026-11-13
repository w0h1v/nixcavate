//! Rosetta 2 translation cache: `private/var/db/oah/<id>/<id>/*.aot`. `oahd` writes one
//! ahead-of-time translated Mach-O (arm64) per x86_64 binary the first time it runs, so each
//! file is execution evidence on Apple Silicon, and the file's time says when the translation
//! was first made.
//!
//! What is recorded: the file name, the two cache directory names, size and SHA-256, the
//! Mach-O header (CPU type, file type), `LC_UUID` and the segment names, and the file time.
//! NOT recovered: the path of the original binary. As far as published research shows, the
//! cache holds no reliable path field, and the file name is a hash, not a name; this parser
//! does not guess one from strings in the file. The name can be matched against hashes of
//! candidate binaries only if that mapping is known.
//!
//! Format references: `<mach-o/loader.h>` (header and load commands). The cache layout follows
//! public write-ups of Rosetta 2 artifacts. Synthetic only: no real cache file was read; the
//! doubt is whether newer macOS releases keep the same directory layout and Mach-O shape.

use crate::{Artifact, Category, Input, MACOS};
use nixcavate_core::{Basis, Error, Event, Loc, Record, Result, Sink, Timestamp};
use serde::Serialize;
use sha2::{Digest, Sha256};

pub const ARTIFACT: Artifact = Artifact::new(
    "rosetta-aot",
    "Rosetta 2 translation cache (x86_64 execution evidence)",
    Category::Execution,
    MACOS,
    &["private/var/db/oah/*/*/*.aot", "var/db/oah/*/*/*.aot"],
    parse,
);

const MH_MAGIC_64: u32 = 0xfeed_facf;
const LC_SEGMENT_64: u32 = 0x19;
const LC_UUID: u32 = 0x1b;
const MAX_COMMANDS: u32 = 512;
const MAX_SEGMENTS: usize = 16;

#[derive(Serialize)]
struct Translation<'a> {
    name: &'a str,
    cache_dir: &'a str,
    cache_subdir: &'a str,
    size: usize,
    sha256: String,
    cpu_type: Option<String>,
    file_type: Option<u32>,
    uuid: Option<String>,
    segments: Vec<String>,
    /// The file's modification time as collected: when the translation was written.
    modified: Option<Timestamp>,
}

impl Record for Translation<'_> {
    fn events(&self) -> impl Iterator<Item = Event<'_>> {
        let message = format!("Rosetta wrote translation cache file {}", self.name);
        self.modified.map(|ts| Event::new(ts, "rosetta_translated", message)).into_iter()
    }
}

fn u32_at(data: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(data.get(at..at.checked_add(4)?)?.try_into().ok()?))
}

fn cpu_name(cpu: u32) -> String {
    match cpu {
        0x0100_000c => "arm64".into(),
        0x0100_0007 => "x86_64".into(),
        other => format!("{other:#x}"),
    }
}

struct Macho {
    cpu: u32,
    file_type: u32,
    uuid: Option<String>,
    segments: Vec<String>,
}

fn macho(data: &[u8]) -> Option<Macho> {
    if u32_at(data, 0)? != MH_MAGIC_64 {
        return None;
    }
    let (cpu, file_type, ncmds, sizeofcmds) =
        (u32_at(data, 4)?, u32_at(data, 12)?, u32_at(data, 16)?, u32_at(data, 20)?);
    let end = 32usize.checked_add(usize::try_from(sizeofcmds).ok()?)?.min(data.len());
    let (mut at, mut uuid, mut segments) = (32usize, None, Vec::new());
    for _ in 0..ncmds.min(MAX_COMMANDS) {
        let (cmd, size) = (u32_at(data, at)?, usize::try_from(u32_at(data, at + 4)?).ok()?);
        let next = at.checked_add(size).filter(|&n| size >= 8 && n <= end)?;
        if cmd == LC_UUID && size >= 24 {
            uuid = data.get(at + 8..at + 24).map(|b| b.iter().map(|x| format!("{x:02x}")).collect());
        } else if cmd == LC_SEGMENT_64 && size >= 24 && segments.len() < MAX_SEGMENTS {
            let raw = data.get(at + 8..at + 24)?;
            let name: Vec<u8> = raw.iter().copied().take_while(|&b| b != 0).collect();
            segments.push(String::from_utf8_lossy(&name).into_owned());
        }
        at = next;
    }
    Some(Macho { cpu, file_type, uuid, segments })
}

fn parse(input: &Input, sink: &mut Sink) -> Result<()> {
    let Some(header) = macho(input.data) else {
        return Err(Error::format("not a 64-bit Mach-O file"));
    };
    let mut parts = input.path.rsplit('/');
    let name = parts.next().unwrap_or_default();
    let (subdir, dir) = (parts.next().unwrap_or_default(), parts.next().unwrap_or_default());
    let digest = Sha256::digest(input.data);
    sink.emit(
        Loc::None,
        &Translation {
            name,
            cache_dir: dir,
            cache_subdir: subdir,
            size: input.data.len(),
            sha256: digest.iter().map(|b| format!("{b:02x}")).collect(),
            cpu_type: Some(cpu_name(header.cpu)),
            file_type: Some(header.file_type),
            uuid: header.uuid,
            segments: header.segments,
            modified: (input.mtime > 0).then(|| Timestamp::from_secs(input.mtime, Basis::Recorded)),
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::run;

    const PATH: &str = "private/var/db/oah/0123abcd/4567ef01/abcdef0123.aot";

    /// A 64-bit arm64 Mach-O with LC_UUID and one segment.
    fn sample() -> Vec<u8> {
        let mut out = Vec::new();
        for v in [MH_MAGIC_64, 0x0100_000c, 0, 2, 2, 24 + 72, 0, 0] {
            out.extend(v.to_le_bytes());
        }
        out.extend(LC_UUID.to_le_bytes());
        out.extend(24u32.to_le_bytes());
        out.extend((0..16).map(|i| i as u8));
        out.extend(LC_SEGMENT_64.to_le_bytes());
        out.extend(72u32.to_le_bytes());
        let mut name = b"__TEXT".to_vec();
        name.resize(16, 0);
        out.extend(name);
        out.resize(out.len() + 48, 0);
        out
    }

    #[test]
    fn reads_the_header_and_hashes_the_file() {
        let data = sample();
        let out = crate::testing::with_input(PATH, &data, 1_700_000_000, |input| {
            let mut sink = Sink::memory("h", "rosetta-aot", PATH, nixcavate_core::Format::Jsonl);
            (ARTIFACT.parse)(input, &mut sink).unwrap();
            String::from_utf8(sink.finish().unwrap().memory).unwrap()
        });
        for want in [
            "\"cpu_type\":\"arm64\"",
            "\"uuid\":\"000102030405060708090a0b0c0d0e0f\"",
            "\"segments\":[\"__TEXT\"]",
            "\"cache_dir\":\"0123abcd\"",
            "\"modified\":\"2023-11-14T22:13:20Z\"",
        ] {
            assert!(out.contains(want), "{want} in {out}");
        }
    }

    #[test]
    fn other_files_are_rejected() {
        assert!(run(&ARTIFACT, PATH, b"MZ", 0).contains("failed: "));
        assert!(run(&ARTIFACT, PATH, b"", 0).contains("failed: "));
    }

    #[test]
    fn damaged_headers_do_not_panic() {
        crate::macos::plist_util::tests::survives_damage(&ARTIFACT, PATH, &sample());
        // A command count far beyond the data, and a command that points backwards.
        let mut huge = sample();
        huge[16..20].copy_from_slice(&u32::MAX.to_le_bytes());
        run(&ARTIFACT, PATH, &huge, 0);
        let mut zero = sample();
        zero[36..40].copy_from_slice(&0u32.to_le_bytes());
        run(&ARTIFACT, PATH, &zero, 0);
    }
}
