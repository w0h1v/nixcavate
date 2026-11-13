//! SVR4 packaging: `var/sadm/pkg/*/pkginfo` (one file per installed package, `KEY=value` lines)
//! and `var/sadm/install/contents` (the file database: one line per path).
//!
//! `contents` lines are `path type class ...`: for `f`, `e`, `v`: `mode owner group size cksum
//! modtime package[...]`; for `d`, `x`, `p`: `mode owner group package[...]`; for `b`, `c`:
//! `major minor mode owner group package[...]`; for `s`, `l`: `path=target` then the packages.
//!
//! Checked on illumos: OmniOS keeps a `pkginfo` for every IPS package that carries a legacy
//! action (420 of them) and the real `pkgadd` (from `package/svr4`) writes both files, so one
//! package built with `pkgmk` and installed with `pkgadd` was compared with `pkginfo -l` and
//! `pkgchk -l`. Oracle Solaris 10 and 11 use the same files; Solaris 10 patch records
//! (`PATCHLIST`, `PATCH_INFO_*` in `pkginfo`) are read from the documentation only.

use crate::text::{for_each_line, lossy};
use crate::{Artifact, Category, Input, SOLARIS};
use nixcavate_core::time::{month_from_abbrev, parse_uint, secs_from_civil};
use nixcavate_core::{Basis, Event, Loc, Precision, Record, Result, Sink, Timestamp};
use serde::Serialize;

pub const PKGINFO: Artifact = Artifact::new(
    "svr4-pkginfo",
    "SVR4 packages installed (pkginfo)",
    Category::Software,
    SOLARIS,
    &["var/sadm/pkg/*/pkginfo"],
    parse_pkginfo,
);

pub const CONTENTS: Artifact = Artifact::new(
    "svr4-contents",
    "SVR4 file database (path, owner, size, checksum, package)",
    Category::Software,
    SOLARIS,
    &["var/sadm/install/contents"],
    parse_contents,
)
.split_lines();

#[derive(Serialize)]
struct Pkg<'a> {
    package: &'a str,
    name: &'a str,
    version: &'a str,
    arch: &'a str,
    category: &'a str,
    vendor: &'a str,
    basedir: &'a str,
    /// `INSTDATE` (`Nov 13 2026 01:16`), with no zone: the host's is assumed.
    installed: Option<Timestamp>,
    /// The patches a Solaris 10 package says it carries (`PATCHLIST`).
    patches: &'a str,
}

impl Record for Pkg<'_> {
    fn events(&self) -> impl Iterator<Item = Event<'_>> {
        let message = format!("{} installed ({} {})", self.package, self.name, self.version);
        self.installed.map(|ts| Event::new(ts, "package_installed", message)).into_iter()
    }
}

/// `Nov 13 2026 01:16` as wall-clock seconds.
fn instdate(text: &str) -> Option<i64> {
    let mut words = text.split_whitespace();
    let (month, day, year, clock) = (words.next()?, words.next()?, words.next()?, words.next()?);
    let (h, m) = clock.split_once(':')?;
    let num = |t: &str| parse_uint(t.as_bytes());
    secs_from_civil(
        i64::try_from(num(year)?).ok()?,
        month_from_abbrev(month.as_bytes())?,
        u32::try_from(num(day)?).ok()?,
        u32::try_from(num(h)?).ok()?,
        u32::try_from(num(m)?).ok()?,
        0,
    )
}

fn parse_pkginfo(input: &Input, sink: &mut Sink) -> Result<()> {
    let text = lossy(input.data);
    let value = |key: &str| {
        text.lines().find_map(|l| l.strip_prefix(key).and_then(|r| r.strip_prefix('='))).map_or("", str::trim)
    };
    let package = value("PKGINST");
    // The folder name is the instance when the file lacks it.
    let folder = input.path.rsplit('/').nth(1).unwrap_or_default();
    let package = if package.is_empty() { folder } else { package };
    if value("PKG").is_empty() && value("NAME").is_empty() {
        sink.warn("pkginfo has neither PKG nor NAME");
    }
    sink.emit(
        Loc::None,
        &Pkg {
            package,
            name: value("NAME"),
            version: value("VERSION"),
            arch: value("ARCH"),
            category: value("CATEGORY"),
            vendor: value("VENDOR"),
            basedir: value("BASEDIR"),
            installed: instdate(value("INSTDATE")).map(|wall| input.local_time(wall, 0, Precision::Seconds)),
            patches: value("PATCHLIST"),
        },
    )
}

#[derive(Serialize)]
struct Path<'a> {
    path: &'a str,
    /// The symbolic or hard link target, for `s` and `l`.
    target: &'a str,
    /// `f` file, `e` editable, `v` volatile, `d` directory, `x` exclusive directory, `p` pipe,
    /// `b` and `c` devices, `s` symlink, `l` hard link.
    file_type: &'a str,
    class: &'a str,
    mode: &'a str,
    owner: &'a str,
    group: &'a str,
    size: Option<u64>,
    checksum: Option<u64>,
    modified: Option<Timestamp>,
    /// The packages that own the path (`NAME` or `NAME:class`, with a leading `*` `+` `-` `!` flag as written).
    packages: Vec<&'a str>,
}

impl Record for Path<'_> {}

fn parse_contents(input: &Input, sink: &mut Sink) -> Result<()> {
    for_each_line(input, |line| {
        let text = lossy(line.bytes);
        let text = text.trim();
        if text.is_empty() || text.starts_with('#') {
            return Ok(());
        }
        let mut words = text.split_whitespace();
        let (Some(path), Some(kind), Some(class)) = (words.next(), words.next(), words.next()) else {
            sink.warn(format!("offset {}: expected path, type and class", line.offset));
            return Ok(());
        };
        let rest: Vec<&str> = words.collect();
        let (path, target) = match kind {
            "s" | "l" => path.split_once('=').unwrap_or((path, "")),
            _ => (path, ""),
        };
        // How many attribute words come before the package names.
        let (attrs, has_stats) = match kind {
            "f" | "e" | "v" => (6, true),
            "d" | "x" | "p" => (3, false),
            "b" | "c" => (5, false),
            "s" | "l" => (0, false),
            _ => {
                sink.warn(format!("offset {}: unknown file type {kind}", line.offset));
                return Ok(());
            }
        };
        let (Some(head), Some(packages)) = (rest.get(..attrs), rest.get(attrs..)) else {
            sink.warn(format!("offset {}: too few fields for type {kind}", line.offset));
            return Ok(());
        };
        let at = |i: usize| head.get(i).copied().unwrap_or_default();
        let (mode, owner, group) = match kind {
            "b" | "c" => (at(2), at(3), at(4)),
            "s" | "l" => ("", "", ""),
            _ => (at(0), at(1), at(2)),
        };
        let number = |i: usize| if has_stats { parse_uint(at(i).as_bytes()) } else { None };
        sink.emit(
            Loc::Offset(line.offset),
            &Path {
                path,
                target,
                file_type: kind,
                class,
                mode,
                owner,
                group,
                size: number(3),
                checksum: number(4),
                modified: number(5)
                    .and_then(|t| i64::try_from(t).ok())
                    .map(|t| Timestamp::from_secs_nanos(t, 0, Precision::Seconds, Basis::Recorded)),
                packages: packages.to_vec(),
            },
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{fixture, run};

    /// A package built with `pkgmk` and installed with the real `pkgadd`; `pkginfo -l NXexample` printed
    /// `INSTDATE: Nov 13 2026 01:16`, `VERSION: 1.0`, `ARCH: i386`, `CATEGORY: application`, `VENDOR: Example`.
    #[test]
    fn a_real_pkginfo_equals_pkginfo_l() {
        let out = run(&PKGINFO, "var/sadm/pkg/NXexample/pkginfo", &fixture("svr4-pkginfo/NXexample.pkginfo"), 0);
        insta::assert_snapshot!(out);
        let listing = String::from_utf8(fixture("svr4-pkginfo/pkginfo-l.txt")).unwrap();
        assert!(listing.contains("INSTDATE:  Nov 13 2026 01:16") && listing.contains("STATUS:  completely installed"));
        for want in [
            r#""package":"NXexample","name":"Example SVR4 package","version":"1.0","arch":"i386","category":"application","vendor":"Example","basedir":"/""#,
            r#""installed":"2026-11-13T01:16:00Z""#,
        ] {
            assert!(out.contains(want), "{want}\n{out}");
        }
        let legacy = run(&PKGINFO, "var/sadm/pkg/SUNW1394/pkginfo", &fixture("svr4-pkginfo/SUNW1394.pkginfo"), 0);
        insta::assert_snapshot!("legacy", legacy);
    }

    /// `pkgchk -l NXexample` lists the same two paths with the same mode, owner and group.
    #[test]
    fn a_real_contents_file() {
        let out = run(&CONTENTS, "var/sadm/install/contents", &fixture("svr4-contents/contents"), 0);
        insta::assert_snapshot!(out);
        assert!(out.contains(r#""path":"/opt/nxsvr4/readme","target":"","file_type":"f","class":"none","mode":"0644","owner":"root","group":"bin","size":21,"checksum":1871"#), "{out}");
        assert!(out.contains(r#""packages":["NXexample"]"#));
    }

    /// The other line types of contents(4), from its documentation.
    #[test]
    fn symlinks_devices_pipes_and_short_lines() {
        let data = b"/usr/bin/x=../lib/y s none SUNWa SUNWb\n/dev/null c none 13 2 0666 root sys SUNWc\n/var/fifo p none 0600 root sys SUNWd:cls\n/etc/a e preserve 0644 root sys 5 6 1700000000 SUNWe\n/short f none 0644\n/weird q none x\n# comment\n";
        let out = run(&CONTENTS, "var/sadm/install/contents", data, 0);
        assert!(out.contains(r#""path":"/usr/bin/x","target":"../lib/y","file_type":"s","class":"none","mode":"","owner":"","group":"","size":null,"checksum":null,"modified":null,"packages":["SUNWa","SUNWb"]"#), "{out}");
        assert!(out.contains(r#""path":"/dev/null","target":"","file_type":"c","class":"none","mode":"0666","owner":"root","group":"sys""#), "{out}");
        assert!(
            out.contains(r#""packages":["SUNWd:cls"]"#) && out.contains(r#""modified":"2023-11-14T22:13:20Z""#),
            "{out}"
        );
        assert!(out.contains("too few fields for type f") && out.contains("unknown file type q"), "{out}");
    }

    #[test]
    fn a_pkginfo_without_names_warns_and_uses_the_folder() {
        let out = run(&PKGINFO, "var/sadm/pkg/XYZ/pkginfo", b"junk\nINSTDATE=Foo 99 2026 99:99\n", 0);
        assert!(
            out.contains("neither PKG nor NAME")
                && out.contains(r#""package":"XYZ""#)
                && out.contains(r#""installed":null"#),
            "{out}"
        );
    }

    #[test]
    fn mutated_files_never_panic() {
        super::super::never_panics(
            &PKGINFO,
            "var/sadm/pkg/NXexample/pkginfo",
            &fixture("svr4-pkginfo/NXexample.pkginfo"),
        );
        super::super::never_panics(&CONTENTS, "var/sadm/install/contents", &fixture("svr4-contents/contents"));
    }
}
