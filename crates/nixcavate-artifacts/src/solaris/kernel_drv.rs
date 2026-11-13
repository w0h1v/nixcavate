//! `kernel/drv/*.conf` (and `usr/kernel/drv`, `platform/*/kernel/drv`): the configuration file of a
//! device driver. Format: driver.conf(5): statements ending in `;`: `name="x" parent="y"
//! instance=0;` declares a device node and `property=value;` sets a driver property. `#` starts a
//! comment. A `.conf` file that names a driver is how a pseudo driver is attached at boot.
//!
//! Whether a module with this name exists in the collected `kernel/drv` tree (or its `amd64` /
//! `sparcv9` subdirectory) is reported when such a tree was collected; a configuration file with
//! no driver behind it is unusual. Verified on illumos (OmniOS): 166 and 167 stock files and the
//! harness's added one.

use crate::text::lossy;
use crate::{Artifact, Category, Input, SOLARIS};
use nixcavate_core::{Loc, Record, Result, Sink};
use nixcavate_source::glob::Pattern;
use serde::Serialize;

pub const ARTIFACT: Artifact = Artifact::new(
    "kernel-drv",
    "Driver configuration files (driver.conf)",
    Category::Persistence,
    SOLARIS,
    &["kernel/drv/*.conf", "usr/kernel/drv/*.conf", "platform/*/kernel/drv/*.conf"],
    parse,
);

#[derive(Serialize)]
struct Driver<'a> {
    /// The file name without `.conf`: the driver it configures.
    driver: &'a str,
    /// Device-node statements (`name="x" parent="y" instance=0`).
    nodes: Vec<String>,
    /// Property statements (`ddi-forceattach=1`).
    properties: Vec<String>,
    /// Whether a module of this name is in the collected kernel tree; `null` when none was collected.
    module_in_kernel_tree: Option<bool>,
}

impl Record for Driver<'_> {}

fn module_present(input: &Input, driver: &str) -> Option<bool> {
    // The directory the configuration file is in, and its per-ISA subdirectories.
    let dir = input.path.rsplit_once('/').map_or("", |(d, _)| d);
    let present =
        ["amd64", "sparcv9", "arm64"].iter().any(|isa| input.host.lookup(&format!("{dir}/{isa}/{driver}")).is_some())
            || input.host.lookup(&format!("{dir}/{driver}")).is_some();
    if present {
        return Some(true);
    }
    // Only a collection that holds some modules can say one is missing.
    const TREES: [&str; 4] =
        ["kernel/drv/amd64/*", "kernel/drv/sparcv9/*", "usr/kernel/drv/amd64/*", "usr/kernel/drv/sparcv9/*"];
    let seen = TREES.iter().any(|tree| input.host.find(&Pattern::new(tree)).next().is_some());
    seen.then_some(false)
}

fn parse(input: &Input, sink: &mut Sink) -> Result<()> {
    let text = lossy(input.data);
    let without_comments: String =
        text.lines().map(|l| l.split('#').next().unwrap_or_default()).collect::<Vec<_>>().join("\n");
    let (mut nodes, mut properties) = (Vec::new(), Vec::new());
    for statement in without_comments.split(';').map(|s| s.split_whitespace().collect::<Vec<_>>().join(" ")) {
        if statement.is_empty() {
            continue;
        }
        let list = if statement.starts_with("name=") || statement.starts_with("name =") {
            &mut nodes
        } else {
            &mut properties
        };
        if list.len() < 10_000 {
            list.push(statement);
        }
    }
    let file = input.path.rsplit('/').next().unwrap_or_default();
    let driver = file.strip_suffix(".conf").unwrap_or(file);
    sink.emit(Loc::None, &Driver { driver, nodes, properties, module_in_kernel_tree: module_present(input, driver) })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{fixture, run, run_on_host};

    #[test]
    fn a_real_driver_conf_without_a_module() {
        let out = run(&ARTIFACT, "kernel/drv/nxmk_drv.conf", &fixture("kernel-drv/nxmk_drv.conf"), 0);
        insta::assert_snapshot!(out);
        assert!(out.contains(r#""driver":"nxmk_drv","nodes":["name=\"nxmk_drv\" parent=\"pseudo\" instance=0"],"properties":[],"module_in_kernel_tree":null"#), "{out}");
    }

    #[test]
    fn the_module_is_looked_for_in_a_collected_tree() {
        let conf = fixture("kernel-drv/nxmk_drv.conf");
        let files: [(&str, &[u8]); 3] =
            [("kernel/drv/nxmk_drv.conf", &conf), ("kernel/drv/amd64/other", b"x"), ("etc/svc/repository.db", b"x")];
        let out = run_on_host(&ARTIFACT, &files, "kernel/drv/nxmk_drv.conf", 0);
        assert!(out.contains(r#""module_in_kernel_tree":false"#), "{out}");
        let files: [(&str, &[u8]); 3] =
            [("kernel/drv/nxmk_drv.conf", &conf), ("kernel/drv/amd64/nxmk_drv", b"x"), ("etc/svc/repository.db", b"x")];
        let out = run_on_host(&ARTIFACT, &files, "kernel/drv/nxmk_drv.conf", 0);
        assert!(out.contains(r#""module_in_kernel_tree":true"#), "{out}");
    }

    #[test]
    fn statements_comments_and_properties() {
        let text = b"# comment\nname=\"a\" parent=\"pci\" unit-address=\"1\";\nname = \"b\" parent=\"pseudo\";\nddi-forceattach=1;\nprop=\"x\" # tail\n;\n";
        let out = run(&ARTIFACT, "kernel/drv/a.conf", text, 0);
        assert!(out.contains(r#""nodes":["name=\"a\" parent=\"pci\" unit-address=\"1\"","name = \"b\" parent=\"pseudo\""],"properties":["ddi-forceattach=1","prop=\"x\""]"#), "{out}");
        super::super::never_panics(&ARTIFACT, "kernel/drv/nxmk_drv.conf", &fixture("kernel-drv/nxmk_drv.conf"));
    }
}
