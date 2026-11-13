//! Installed VIBs (vSphere Installation Bundles), the packages of ESXi. A malicious VIB installed
//! with `--force` or after lowering the host acceptance level to `CommunitySupported` is a known
//! way to keep a backdoor across reboots, so these are persistence evidence as well as an
//! inventory.
//!
//! - `var/db/esximg/vibs/*.xml`: one descriptor per installed VIB, with its install date. The
//!   element names were checked against a VIB descriptor published in a public ESXi forensics
//!   tool's test data (listed in `docs/LIMITATIONS.md`).
//! - `esxcli software vib list` output, saved by `vm-support` (as `localcli_software-vib-list`)
//!   and by UAC (as `esxcli_software_vib_list`): a fixed-width table checked against a real
//!   6.7 listing. It carries the install day only.

use super::{iso_time, xml};
use crate::text::lossy;
use crate::{Artifact, Category, Input, ESXI};
use nixcavate_core::time::days_from_civil;
use nixcavate_core::{Basis, Error, Event, Loc, Record, Result, Sink, Timestamp};
use serde::Serialize;

pub const VIB: Artifact = Artifact::new(
    "esxi-vib",
    "Installed VIBs from the descriptors in /var/db/esximg/vibs",
    Category::Software,
    ESXI,
    &["var/db/esximg/vibs/*.xml"],
    parse_vib,
);

pub const VIB_LIST: Artifact = Artifact::new(
    "esxi-vib-list",
    "Installed VIBs from saved `esxcli software vib list` output",
    Category::Software,
    ESXI,
    &[
        "commands/localcli_software-vib-list.txt",
        "commands/esxcli_software-vib-list.txt",
        "../live_response/packages/esxcli_software_vib_list.txt",
    ],
    parse_vib_list,
);

#[derive(Serialize)]
struct Vib<'a> {
    name: &'a str,
    version: &'a str,
    vendor: &'a str,
    /// `bootbank` (kept across reboots) or `locker`.
    vib_type: &'a str,
    /// `certified`, `accepted`, `partner` or `community`. `community` means the VIB is not
    /// signed by VMware or a partner.
    acceptance_level: &'a str,
    summary: &'a str,
    release_date: Option<Timestamp>,
    install_date: Option<Timestamp>,
    /// The files the VIB puts on the host (first 100).
    files: Vec<&'a str>,
    /// SHA-256 checksums of the VIB's payloads, compressed and not.
    payload_sha256: Vec<&'a str>,
}

impl Record for Vib<'_> {
    fn events(&self) -> impl Iterator<Item = Event<'_>> {
        let text = format!("VIB {} {} installed ({})", self.name, self.version, self.acceptance_level);
        self.install_date.map(|ts| Event::new(ts, "package_installed", text)).into_iter()
    }
}

/// The most files of one VIB that are listed.
const MAX_FILES: usize = 100;

fn parse_vib(input: &Input, sink: &mut Sink) -> Result<()> {
    let text = lossy(input.data);
    let doc = xml::parse(&text);
    let vib = doc.root.child("vib").ok_or_else(|| Error::format("not a VIB descriptor: no <vib> element"))?;
    if doc.incomplete {
        sink.warn("the descriptor is cut or too large; the fields read are shown");
    }
    let sums = vib
        .child("payloads")
        .into_iter()
        .flat_map(|p| p.children_named("payload"))
        .flat_map(|p| p.children_named("checksum"))
        .filter(|c| c.attr("checksum-type").as_deref() == Some("sha-256"))
        .map(|c| &*c.text)
        .collect();
    let files = vib
        .child("file-list")
        .into_iter()
        .flat_map(|l| l.children_named("file"))
        .map(|f| &*f.text)
        .take(MAX_FILES)
        .collect();
    sink.emit(
        Loc::None,
        &Vib {
            name: vib.child_text("name"),
            version: vib.child_text("version"),
            vendor: vib.child_text("vendor"),
            vib_type: vib.child_text("type"),
            acceptance_level: vib.child_text("acceptance-level"),
            summary: vib.child_text("summary"),
            release_date: iso_time(input, vib.child_text("release-date")),
            install_date: iso_time(input, vib.child_text("installdate")),
            files,
            payload_sha256: sums,
        },
    )
}

#[derive(Serialize)]
struct Listed<'a> {
    name: &'a str,
    version: &'a str,
    vendor: &'a str,
    /// As `esxcli` prints it: `VMwareCertified`, `VMwareAccepted`, `PartnerSupported` or
    /// `CommunitySupported`.
    acceptance_level: &'a str,
    install_date: Option<Timestamp>,
}

impl Record for Listed<'_> {
    fn events(&self) -> impl Iterator<Item = Event<'_>> {
        let text = format!("VIB {} {} installed ({})", self.name, self.version, self.acceptance_level);
        self.install_date.map(|ts| Event::new(ts, "package_installed", text)).into_iter()
    }
}

/// The start columns of the named headers in a fixed-width table header.
fn columns(header: &str, names: &[&str]) -> Vec<Option<usize>> {
    names.iter().map(|name| header.find(name)).collect()
}

/// The text of column `index` of `row`: from its start to the start of the next column found.
fn cell<'a>(row: &'a str, starts: &[Option<usize>], index: usize) -> &'a str {
    let Some(from) = starts.get(index).copied().flatten() else { return "" };
    let to = starts.iter().skip(index + 1).flatten().copied().find(|&s| s > from).unwrap_or(row.len());
    row.get(from..to.min(row.len())).unwrap_or_default().trim()
}

/// `2024-09-02`: a day, as `esxcli` prints install dates.
fn day(text: &str) -> Option<Timestamp> {
    let mut parts = text.split('-');
    let (y, m, d) = (parts.next()?.parse().ok()?, parts.next()?.parse().ok()?, parts.next()?.parse().ok()?);
    (parts.next().is_none() && (1..=12).contains(&m) && (1..=31).contains(&d) && (1970..=9999).contains(&y))
        .then(|| Timestamp::from_days(days_from_civil(y, m, d), Basis::Recorded))
}

fn parse_vib_list(input: &Input, sink: &mut Sink) -> Result<()> {
    let text = lossy(input.data);
    let mut lines = text.lines().enumerate();
    let Some((_, header)) = lines.by_ref().find(|(_, l)| !l.trim().is_empty()) else {
        return Err(Error::skipped("empty file"));
    };
    let starts = columns(header, &["Name", "Version", "Vendor", "Acceptance Level", "Install Date", "Platforms"]);
    if starts[0] != Some(0) || starts[1].is_none() || starts[3].is_none() {
        return Err(Error::format("not an `esxcli software vib list` table: unrecognised header"));
    }
    for (index, row) in lines {
        // The dashed rule under the header, and blank lines.
        if row.trim().is_empty() || row.starts_with("---") {
            continue;
        }
        sink.emit(
            Loc::Line(index as u64 + 1),
            &Listed {
                name: cell(row, &starts, 0),
                version: cell(row, &starts, 1),
                vendor: cell(row, &starts, 2),
                acceptance_level: cell(row, &starts, 3),
                install_date: day(cell(row, &starts, 4)),
            },
        )?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{fixture, run};

    #[test]
    fn descriptor_with_install_date() {
        let out = run(&VIB, "var/db/esximg/vibs/example-1.xml", &fixture("esxi-vib/community.xml"), 0);
        insta::assert_snapshot!(out);
    }

    #[test]
    fn descriptor_without_install_date_has_no_event() {
        let out = run(&VIB, "var/db/esximg/vibs/stock.xml", &fixture("esxi-vib/stock.xml"), 0);
        assert!(!out.contains("--- timeline ---"), "{out}");
        assert!(out.contains("\"acceptance_level\":\"certified\""), "{out}");
    }

    #[test]
    fn not_a_descriptor_is_a_format_error() {
        let out = run(&VIB, "var/db/esximg/vibs/x.xml", b"<other/>", 0);
        assert!(out.contains("--- failed: not a VIB descriptor"), "{out}");
        assert!(run(&VIB, "var/db/esximg/vibs/x.xml", b"", 0).contains("failed"));
    }

    #[test]
    fn vib_list_table() {
        let out = run(&VIB_LIST, "commands/localcli_software-vib-list.txt", &fixture("esxi-vib/vib-list.txt"), 0);
        insta::assert_snapshot!(out);
    }

    #[test]
    fn damaged_inputs_do_not_panic() {
        for (artifact, path, name) in [
            (&VIB, "var/db/esximg/vibs/x.xml", "esxi-vib/community.xml"),
            (&VIB_LIST, "commands/localcli_software-vib-list.txt", "esxi-vib/vib-list.txt"),
        ] {
            let data = fixture(name);
            for n in 0..=data.len() {
                run(artifact, path, &data[..n], 0);
            }
            for i in (0..data.len()).step_by(5) {
                let mut flipped = data.clone();
                flipped[i] ^= 0xff;
                run(artifact, path, &flipped, 0);
            }
        }
    }
}
