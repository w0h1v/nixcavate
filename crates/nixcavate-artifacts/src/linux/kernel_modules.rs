//! Kernel modules loaded at boot (`/etc/modules`, `modules-load.d`) and modprobe configuration,
//! where `install` runs an arbitrary command instead of loading the module.
//! Formats: modules-load.d(5), modprobe.d(5).

use crate::text::{for_each_line, lossy};
use crate::{Artifact, Category, Input, LINUX};
use nixcavate_core::{Loc, Record, Result, Sink};
use nixcavate_source::glob::Pattern;
use nixcavate_source::Host;
use serde::Serialize;
use std::collections::HashSet;

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
    /// For a `load` directive when the host's `lib/modules` tree was collected: whether a
    /// module of that name is in it (a file, a built-in or an alias). `null` when the tree was
    /// not collected, and for modprobe directives.
    module_in_kernel_tree: Option<bool>,
}

impl Record for Directive<'_> {}

/// `-` and `_` are the same in module names; so is a `.ko` suffix with or without compression.
fn normalized(name: &str) -> String {
    name.trim().replace('-', "_")
}

/// The module names of the kernel trees in the collection (`lib/modules/<release>/`): module
/// files, `modules.builtin` and the aliases of `modules.alias`. `None` when no module file and
/// no `modules.dep` was collected, so that a collection without the tree gives no verdict.
fn collected_modules(host: &Host) -> Option<HashSet<String>> {
    let mut names = HashSet::new();
    let mut seen_tree = false;
    for pattern in ["lib/modules/**/*.ko*", "usr/lib/modules/**/*.ko*"] {
        for entry in host.find(&Pattern::new(pattern)).filter(|e| e.link.is_none()) {
            let file = entry.path.rsplit('/').next().unwrap_or_default();
            if let Some((name, _)) = file.split_once(".ko") {
                names.insert(normalized(name));
                seen_tree = true;
            }
        }
    }
    for pattern in ["lib/modules/*/modules.dep", "usr/lib/modules/*/modules.dep"] {
        seen_tree |= host.find(&Pattern::new(pattern)).next().is_some();
    }
    // Built-in modules are not files; aliases (`alias pci:... name`) are loadable by name too.
    for (pattern, name_field) in [
        ("lib/modules/*/modules.builtin", 0),
        ("usr/lib/modules/*/modules.builtin", 0),
        ("lib/modules/*/modules.alias", 2),
        ("usr/lib/modules/*/modules.alias", 2),
    ] {
        for entry in host.find(&Pattern::new(pattern)).filter(|e| e.link.is_none()) {
            let Ok(data) = host.open(entry) else { continue };
            for line in String::from_utf8_lossy(&data[..data.len().min(16 << 20)]).lines() {
                let field = if name_field == 0 { Some(line) } else { line.split_whitespace().nth(name_field) };
                let Some(field) = field else { continue };
                let file = field.rsplit('/').next().unwrap_or_default();
                names.insert(normalized(file.split_once(".ko").map_or(file, |(name, _)| name)));
            }
        }
    }
    seen_tree.then_some(names)
}

/// Splits off the first whitespace-delimited word.
fn word(text: &str) -> (&str, &str) {
    let text = text.trim();
    text.split_once(char::is_whitespace).map_or((text, ""), |(w, rest)| (w, rest.trim_start()))
}

fn parse(input: &Input, sink: &mut Sink) -> Result<()> {
    let is_modprobe = input.path.contains("modprobe.d/");
    let (mut pending, mut start) = (String::new(), 0);
    let tree = std::cell::OnceCell::new();
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
        let module_in_kernel_tree = if is_modprobe {
            None
        } else {
            tree.get_or_init(|| collected_modules(input.host)).as_ref().map(|names| names.contains(&normalized(module)))
        };
        sink.emit(Loc::Line(number), &Directive { kind, module, arguments, module_in_kernel_tree })
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
    fn load_directive_says_whether_the_module_is_in_the_collected_kernel_tree() {
        let conf: &[u8] = b"br-netfilter\nnxmk_unknown\nbuilt_in\naliased\nxz_mod\n";
        let files: &[(&str, &[u8])] = &[
            ("etc/modules-load.d/x.conf", conf),
            ("lib/modules/6.1.0/kernel/net/bridge/br_netfilter.ko", b"x"),
            ("lib/modules/6.1.0/kernel/x/xz_mod.ko.xz", b"x"),
            ("lib/modules/6.1.0/modules.builtin", b"kernel/fs/built_in.ko\n"),
            ("lib/modules/6.1.0/modules.alias", b"alias pci:v1d1 aliased\n"),
        ];
        let out = crate::testing::run_on_host(&ARTIFACT, files, "etc/modules-load.d/x.conf", 0);
        let flags: Vec<&str> = out
            .lines()
            .filter_map(|l| l.rsplit_once("\"module_in_kernel_tree\":"))
            .map(|(_, f)| &f[..f.len().min(5)])
            .collect();
        assert_eq!(flags, ["true}", "false", "true}", "true}", "true}"], "{out}");
        // No kernel tree collected: no verdict.
        let out = run(&ARTIFACT, "etc/modules-load.d/x.conf", conf, 0);
        assert_eq!(out.matches("\"module_in_kernel_tree\":null").count(), 5, "{out}");
        // modprobe directives never get a verdict.
        let out = crate::testing::run_on_host(
            &ARTIFACT,
            &[("etc/modprobe.d/x.conf", b"install a /bin/true\n"), files[1]],
            "etc/modprobe.d/x.conf",
            0,
        );
        assert!(out.contains("\"module_in_kernel_tree\":null"), "{out}");
    }

    #[test]
    fn empty_and_garbage_inputs_do_not_panic() {
        for path in ["etc/modules", "etc/modprobe.d/x.conf"] {
            run(&ARTIFACT, path, b"", 0);
            run(&ARTIFACT, path, b"\\\n\\\xff\0 \\", 0);
        }
    }
}
