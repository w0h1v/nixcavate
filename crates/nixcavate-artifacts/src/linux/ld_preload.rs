//! Dynamic linker configuration: `ld.so.preload` (libraries injected into every process) and
//! `ld.so.conf` (library search directories). Formats: ld.so(8), ldconfig(8).

use crate::text::{for_each_line, lossy};
use crate::{Artifact, Category, Input, LINUX};
use nixcavate_core::{Loc, Record, Result, Sink};
use serde::Serialize;

pub const ARTIFACT: Artifact = Artifact::new(
    "ld-preload",
    "Dynamic linker preload and search path configuration",
    Category::Persistence,
    LINUX,
    &["etc/ld.so.preload", "etc/ld.so.conf", "etc/ld.so.conf.d/*"],
    parse,
);

#[derive(Serialize)]
struct Entry<'a> {
    /// `preload`, `library_path` or `include`.
    kind: &'static str,
    path: &'a str,
}

impl Record for Entry<'_> {}

fn parse(input: &Input, sink: &mut Sink) -> Result<()> {
    let is_preload = input.path == "etc/ld.so.preload";
    for_each_line(input, |line| {
        let text = lossy(line.bytes);
        let text = text.split('#').next().unwrap_or_default().trim();
        let loc = Loc::Line(line.number);
        if is_preload {
            // Entries are separated by whitespace or colons, several to a line.
            for path in text.split(|c: char| c.is_whitespace() || c == ':').filter(|p| !p.is_empty()) {
                sink.emit(loc, &Entry { kind: "preload", path })?;
            }
        } else if let Some(globs) = text.strip_prefix("include").filter(|r| r.starts_with(char::is_whitespace)) {
            for path in globs.split_whitespace() {
                sink.emit(loc, &Entry { kind: "include", path })?;
            }
        } else if !text.is_empty() && !text.starts_with("hwcap") {
            sink.emit(loc, &Entry { kind: "library_path", path: text })?;
        }
        Ok(())
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{fixture, run};

    #[test]
    fn preload_splits_libraries_on_spaces_and_colons() {
        insta::assert_snapshot!(run(&ARTIFACT, "etc/ld.so.preload", &fixture("ld-preload/ld.so.preload"), 0));
    }

    #[test]
    fn conf_lists_directories_and_includes() {
        insta::assert_snapshot!(run(&ARTIFACT, "etc/ld.so.conf", &fixture("ld-preload/ld.so.conf"), 0));
    }

    #[test]
    fn empty_and_garbage_inputs_do_not_panic() {
        for path in ["etc/ld.so.preload", "etc/ld.so.conf"] {
            run(&ARTIFACT, path, b"", 0);
            run(&ARTIFACT, path, b"\xff\xfe\0::: \r\x80 include", 0);
        }
    }
}
