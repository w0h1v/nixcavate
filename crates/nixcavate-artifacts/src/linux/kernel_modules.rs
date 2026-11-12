//! Kernel modules loaded at boot (`/etc/modules`, `modules-load.d`) and modprobe configuration,
//! where `install` runs an arbitrary command instead of loading the module.
//! Formats: modules-load.d(5), modprobe.d(5).

use crate::text::{for_each_line, lossy};
use crate::{Artifact, Category, Input, LINUX};
use nixcavate_core::{Loc, Record, Result, Sink};
use serde::Serialize;

pub const ARTIFACT: Artifact = Artifact::new(
    "modules-load",
    "Kernel module loading and modprobe configuration",
    Category::Persistence,
    LINUX,
    &[
        "etc/modules",
        "etc/modules-load.d/*.conf",
        "usr/lib/modules-load.d/*.conf",
        "run/modules-load.d/*.conf",
        "etc/modprobe.d/*.conf",
        "usr/lib/modprobe.d/*.conf",
    ],
    parse,
);

#[derive(Serialize)]
struct Directive<'a> {
    /// `load` for modules listed in `modules`/`modules-load.d`; otherwise the modprobe.d
    /// directive (`install`, `remove`, `alias`, `options`, `blacklist`, `softdep`, ...).
    kind: &'a str,
    /// The module (for `alias`, the alias name).
    module: &'a str,
    /// The rest of the line. For `install` and `remove` it is the command that runs.
    arguments: &'a str,
}

impl Record for Directive<'_> {}

/// Splits off the first whitespace-delimited word.
fn word(text: &str) -> (&str, &str) {
    let text = text.trim();
    text.split_once(char::is_whitespace).map_or((text, ""), |(w, rest)| (w, rest.trim_start()))
}

fn parse(input: &Input, sink: &mut Sink) -> Result<()> {
    let is_modprobe = input.path.contains("modprobe.d/");
    let (mut pending, mut start) = (String::new(), 0);
    let emit = |logical: &str, number: u64, sink: &mut Sink| -> Result<()> {
        let logical = logical.trim();
        if logical.is_empty() || logical.starts_with(['#', ';']) {
            return Ok(());
        }
        let (first, rest) = word(logical);
        let (kind, module, arguments) = if is_modprobe {
            let (module, arguments) = word(rest);
            (first, module, arguments)
        } else {
            ("load", first, rest)
        };
        sink.emit(Loc::Line(number), &Directive { kind, module, arguments })
    };
    for_each_line(input, |line| {
        let text = lossy(line.bytes);
        if pending.is_empty() {
            start = line.number;
        }
        // Continuation indentation is not part of the rule.
        let text = if pending.is_empty() { &*text } else { text.trim_start() };
        // modprobe.d joins backslash-continued lines.
        if let Some(continued) = text.strip_suffix('\\').filter(|_| is_modprobe) {
            pending.push_str(continued);
            pending.push(' ');
            return Ok(());
        }
        pending.push_str(text);
        emit(&std::mem::take(&mut pending), start, sink)
    })?;
    emit(&pending, start, sink)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{fixture, run};

    #[test]
    fn modules_load_lists_modules() {
        insta::assert_snapshot!(run(&ARTIFACT, "etc/modules-load.d/net.conf", &fixture("modules-load/net.conf"), 0));
    }

    #[test]
    fn modprobe_directives_include_install_commands() {
        insta::assert_snapshot!(run(&ARTIFACT, "etc/modprobe.d/local.conf", &fixture("modules-load/local.conf"), 0));
    }

    #[test]
    fn empty_and_garbage_inputs_do_not_panic() {
        for path in ["etc/modules", "etc/modprobe.d/x.conf"] {
            run(&ARTIFACT, path, b"", 0);
            run(&ARTIFACT, path, b"\\\n\\\xff\0 \\", 0);
        }
    }
}
