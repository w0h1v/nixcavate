//! Host discovery: finds each host root inside a source and reads its name, OS and zone.

use crate::{Data, Entry, Pattern, Source, Tz};
use std::collections::BTreeSet;
use std::io;
use std::ops::Range;
use std::path::Path;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Os {
    Linux,
    Macos,
    /// No known layout was found; every artifact is tried.
    Unknown,
}

impl Os {
    pub fn as_str(self) -> &'static str {
        match self {
            Os::Linux => "linux",
            Os::Macos => "macos",
            Os::Unknown => "unknown",
        }
    }
}

/// One collected host: a root directory inside a source.
pub struct Host<'s> {
    pub name: String,
    pub os: Os,
    pub os_version: String,
    /// The root inside the source, with no trailing slash (`[root]` for UAC, `""` for a volume).
    pub root: String,
    pub tz: Tz,
    /// How `tz` was chosen, for the manifest.
    pub tz_description: String,
    pub source: &'s Source,
    range: Range<usize>,
}

/// A path is a host root when one of these lies directly below it.
const ROOT_MARKERS: [&str; 6] = [
    "etc/passwd",
    "etc/os-release",
    "etc/hostname",
    "System/Library/CoreServices/SystemVersion.plist",
    "var/log/",
    "private/var/db/",
];

/// UAC writes these beside the `[root]` directory of a collection.
const UAC_MARKERS: [&str; 3] = ["live_response/", "bodyfile/bodyfile.txt", "uac.log"];

/// The files host discovery reads, as patterns. A compressed tar keeps these while streaming.
pub const DISCOVERY_PATHS: &[&str] = &[
    "etc/hostname",
    "etc/os-release",
    "usr/lib/os-release",
    "etc/*-release",
    "etc/debian_version",
    "etc/localtime",
    "etc/timezone",
    "usr/share/zoneinfo/**",
    "private/etc/localtime",
    "Library/Preferences/SystemConfiguration/preferences.plist",
    "System/Library/CoreServices/SystemVersion.plist",
];

/// Finds the hosts in a source. A source with no recognizable layout yields one host of
/// unknown OS rooted at the source itself, so single log folders still parse.
///
/// `zoneinfo` is a zone database on the analyst's machine, used only when the evidence names
/// the host zone but does not contain its data.
pub fn discover<'s>(source: &'s Source, zoneinfo: Option<&Path>) -> Vec<Host<'s>> {
    let mut roots = BTreeSet::new();
    for entry in source.entries() {
        for marker in ROOT_MARKERS {
            if let Some(root) = root_before(&entry.path, marker) {
                // macOS keeps etc and var under /private.
                let root = root.strip_suffix("/private").or((root == "private").then_some("")).unwrap_or(root);
                roots.insert(root.to_string());
            }
        }
        // A UAC collection made with only live-response artifacts has no system files, but
        // its layout still says where the root is: `[root]` beside these.
        for marker in UAC_MARKERS {
            if let Some(collection) = root_before(&entry.path, marker) {
                roots.insert(if collection.is_empty() { "[root]".into() } else { format!("{collection}/[root]") });
            }
        }
    }
    // A root inside another root (a container layer, a chroot) belongs to the outer host.
    let mut kept: Vec<String> = Vec::new();
    for root in roots {
        let nested =
            kept.iter().any(|k| k.is_empty() || root.strip_prefix(k.as_str()).is_some_and(|r| r.starts_with('/')));
        if !nested {
            kept.push(root);
        }
    }
    if kept.is_empty() {
        kept.push(String::new());
    }
    kept.iter().map(|root| Host::new(source, root, zoneinfo)).collect()
}

/// The directory in front of the first place `marker` starts at a segment boundary.
fn root_before<'p>(path: &'p str, marker: &str) -> Option<&'p str> {
    let mut from = 0;
    while let Some(found) = path[from..].find(marker) {
        let at = from + found;
        let ends_right = marker.ends_with('/') || at + marker.len() == path.len();
        if ends_right && (at == 0 || path.as_bytes()[at - 1] == b'/') {
            return Some(path[..at].trim_end_matches('/'));
        }
        from = at + 1;
    }
    None
}

impl<'s> Host<'s> {
    fn new(source: &'s Source, root: &str, zoneinfo: Option<&Path>) -> Host<'s> {
        let mut host = Host {
            name: String::new(),
            os: Os::Unknown,
            os_version: String::new(),
            root: root.to_string(),
            tz: Tz::utc(),
            tz_description: String::new(),
            source,
            range: source.range_under(root),
        };
        let has = |dir: &str| !source.range_under(&host.join(dir)).is_empty();
        host.os = if has("System/Library") || has("private/var") || has("private/etc") || has("Library/Preferences") {
            Os::Macos
        } else if has("etc") || has("var/log") {
            Os::Linux
        } else {
            Os::Unknown
        };
        (host.name, host.os_version) = match host.os {
            Os::Macos => host.macos_identity(),
            _ => host.linux_identity(),
        };
        if host.name.is_empty() {
            // Fall back to the collection folder or the source file, which UAC names after the host.
            let folder = root.rsplit('/').find(|s| !s.is_empty() && !s.starts_with('['));
            let file = source.path.file_name().map(|n| without_extension(&n.to_string_lossy()).to_string());
            let label = folder.map(str::to_string).or(file).unwrap_or_else(|| "host".into());
            host.name = uac_host_name(&label).unwrap_or(&label).to_string();
        }
        (host.tz, host.tz_description) = host.zone(zoneinfo);
        host
    }

    fn join(&self, rel: &str) -> String {
        if self.root.is_empty() {
            rel.to_string()
        } else {
            format!("{}/{rel}", self.root)
        }
    }

    fn linux_identity(&self) -> (String, String) {
        let name = self.read_text("etc/hostname").unwrap_or_default();
        let name = name.lines().next().unwrap_or_default().trim().to_string();
        let release = self.read_text("etc/os-release").or_else(|| self.read_text("usr/lib/os-release"));
        let value = |text: &str, key: &str| {
            text.lines().find_map(|l| l.strip_prefix(key)).map(|v| v.trim().trim_matches('"').to_string())
        };
        let version = release.as_deref().and_then(|text| value(text, "PRETTY_NAME=")).or_else(|| self.release_file());
        (name, version.unwrap_or_default())
    }

    /// The version from the older per-distribution files, for a collection whose
    /// `etc/os-release` is a link to a file that was not collected.
    fn release_file(&self) -> Option<String> {
        let first_line = |rel: &str| {
            let text = self.read_text(rel)?;
            let line = text.lines().next()?.trim();
            (!line.is_empty()).then(|| line.to_string())
        };
        // `system-release` and `redhat-release` are often links that were not collected; the
        // file they point at is named after the distribution (`rocky-release`, `gentoo-release`).
        let named = Pattern::new("etc/*-release");
        let mut named: Vec<String> = self
            .find(&named)
            .map(|entry| self.rel(entry))
            .filter(|rel| !["etc/os-release", "etc/lsb-release", "etc/alpine-release"].contains(&rel.as_str()))
            .collect();
        named.sort_by_key(|rel| (rel != "etc/system-release", rel != "etc/redhat-release", rel.clone()));
        named
            .iter()
            .find_map(|rel| first_line(rel))
            .or_else(|| {
                let text = self.read_text("etc/lsb-release")?;
                let line = text.lines().find_map(|l| l.strip_prefix("DISTRIB_DESCRIPTION="))?;
                Some(line.trim().trim_matches('"').to_string())
            })
            .or_else(|| first_line("etc/debian_version").map(|v| format!("Debian {v}")))
            .or_else(|| first_line("etc/alpine-release").map(|v| format!("Alpine Linux {v}")))
    }

    fn macos_identity(&self) -> (String, String) {
        let plist = |rel: &str| self.read(rel).and_then(|data| crate::plist::parse(&data).ok());
        let text = |value: &plist::Value, key: &str| {
            value.as_dictionary().and_then(|d| d.get(key)).and_then(|v| v.as_string()).map(str::to_string)
        };
        let name = plist("Library/Preferences/SystemConfiguration/preferences.plist").and_then(|prefs| {
            let system = prefs.as_dictionary()?.get("System")?.as_dictionary()?;
            let computer = system.get("System").and_then(|s| text(s, "ComputerName"));
            computer.or_else(|| {
                system.get("Network")?.as_dictionary()?.get("HostNames").and_then(|h| text(h, "LocalHostName"))
            })
        });
        let version = plist("System/Library/CoreServices/SystemVersion.plist").map(|v| {
            let field = |key| text(&v, key).unwrap_or_default();
            format!("{} {} ({})", field("ProductName"), field("ProductVersion"), field("ProductBuildVersion"))
        });
        (name.unwrap_or_default(), version.unwrap_or_default())
    }

    /// The host zone: the TZif data in the evidence, else the named zone from `zoneinfo`,
    /// else UTC. The description says which.
    fn zone(&self, zoneinfo: Option<&Path>) -> (Tz, String) {
        let localtime = ["etc/localtime", "private/etc/localtime"];
        let link = localtime.iter().find_map(|p| self.lookup(p)?.link.clone());
        let named = link
            .as_deref()
            .and_then(|target| target.split_once("zoneinfo/").map(|(_, name)| name.to_string()))
            .or_else(|| self.read_text("etc/timezone").map(|t| t.trim().to_string()))
            .filter(|name| is_zone_name(name));
        let label = named.clone().unwrap_or_else(|| "unnamed zone".into());

        if let Some(tz) = localtime.iter().find_map(|p| Tz::parse(&self.read(p)?)) {
            return (tz, format!("{label} (zone data from the evidence)"));
        }
        if let (Some(name), Some(dir)) = (&named, zoneinfo) {
            if let Some(tz) = std::fs::read(dir.join(name)).ok().and_then(|bytes| Tz::parse(&bytes)) {
                return (tz, format!("{name} (named in the evidence; zone data from {})", dir.display()));
            }
        }
        match named {
            Some(name) => (Tz::utc(), format!("UTC (assumed; no zone data found for {name})")),
            None => (Tz::utc(), "UTC (assumed; the evidence names no zone)".into()),
        }
    }

    /// The entry's path relative to the host root. Entries beside the root (UAC
    /// `live_response/`) are shown with a leading `../`.
    pub fn rel(&self, entry: &Entry) -> String {
        if self.root.is_empty() {
            return entry.path.clone();
        }
        if let Some(rel) = entry.path.strip_prefix(&self.root).and_then(|r| r.strip_prefix('/')) {
            return rel.to_string();
        }
        let parent = self.parent();
        let beside = if parent.is_empty() { Some(entry.path.as_str()) } else { entry.path.strip_prefix(parent) };
        format!("../{}", beside.unwrap_or(&entry.path).trim_start_matches('/'))
    }

    fn parent(&self) -> &str {
        self.root.rsplit_once('/').map_or("", |(parent, _)| parent)
    }

    /// The entries matching a pattern.
    pub fn find<'a>(&'a self, pattern: &'a Pattern) -> impl Iterator<Item = &'s Entry> + 'a {
        let (base, range) = if pattern.is_parent_relative() && !self.root.is_empty() {
            (self.parent(), self.source.range_under(self.parent()))
        } else if pattern.is_parent_relative() {
            ("", 0..0)
        } else {
            (self.root.as_str(), self.range.clone())
        };
        let skip = if base.is_empty() { 0 } else { base.len() + 1 };
        self.source.entries()[range].iter().filter(move |e| pattern.matches(&e.path[skip..]))
    }

    /// Every entry under the host root.
    pub fn entries(&self) -> &'s [Entry] {
        &self.source.entries()[self.range.clone()]
    }

    /// The entry at a root-relative path, exactly as stored (links are not followed).
    pub fn lookup(&self, rel: &str) -> Option<&'s Entry> {
        self.source.entry(&self.join(rel))
    }

    /// The file at a root-relative path, following symlinks that stay inside the host root.
    /// A leading `../` reaches a file beside the root (UAC `live_response/`), as it does in
    /// artifact patterns; such files are looked up as they are, with no link following.
    pub fn entry(&self, rel: &str) -> Option<&'s Entry> {
        if let Some(beside) = rel.strip_prefix("../").filter(|_| !self.root.is_empty()) {
            let parent = self.parent();
            let path = normalize(beside)?;
            let path = if parent.is_empty() { path } else { format!("{parent}/{path}") };
            return self.source.entry(&path).filter(|e| e.link.is_none());
        }
        let mut rel = normalize(rel)?;
        for _ in 0..8 {
            let entry = self.lookup(&rel)?;
            let Some(target) = &entry.link else { return Some(entry) };
            rel = match target.strip_prefix('/') {
                Some(absolute) => normalize(absolute)?,
                None => normalize(&format!("{}/{target}", rel.rsplit_once('/').map_or("", |(dir, _)| dir)))?,
            };
        }
        None
    }

    pub fn open(&self, entry: &Entry) -> io::Result<Data> {
        self.source.read(entry)
    }

    /// Reads a file by root-relative path, following in-root symlinks.
    pub fn read(&self, rel: &str) -> Option<Data> {
        self.source.read(self.entry(rel)?).ok()
    }

    /// Reads a small text file (at most 16 MiB of it). Invalid UTF-8 is replaced.
    pub fn read_text(&self, rel: &str) -> Option<String> {
        self.read(rel).map(|data| String::from_utf8_lossy(&data[..data.len().min(16 << 20)]).into_owned())
    }
}

/// A file name without its archive or image extension.
fn without_extension(name: &str) -> &str {
    const EXTENSIONS: [&str; 14] = [
        ".tar.gz", ".tar.zst", ".tar.xz", ".tar.bz2", ".tgz", ".tbz2", ".tar", ".zip", ".e01", ".dd", ".raw", ".img",
        ".001", ".000",
    ];
    let lower = name.to_ascii_lowercase();
    let cut = EXTENSIONS.iter().find(|e| lower.ends_with(*e)).map_or(0, |e| e.len());
    // Lowercasing ASCII keeps byte lengths, so the cut lands on the same boundary.
    name.get(..name.len() - cut).filter(|stem| !stem.is_empty()).unwrap_or(name)
}

/// The host in a UAC collection name: `uac-<host>-<os>-<timestamp>[.tar.gz]`.
fn uac_host_name(label: &str) -> Option<&str> {
    let rest = label.strip_prefix("uac-")?;
    let os = ["-linux-", "-macos-", "-freebsd-", "-openbsd-", "-netbsd-", "-solaris-", "-aix-", "-esxi-", "-android-"];
    os.iter().filter_map(|os| rest.rfind(os)).max().map(|at| &rest[..at]).filter(|host| !host.is_empty())
}

/// Resolves `.` and `..`. Returns `None` when the path would leave the root.
fn normalize(path: &str) -> Option<String> {
    let mut parts: Vec<&str> = Vec::new();
    for part in path.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                parts.pop()?;
            }
            other => parts.push(other),
        }
    }
    Some(parts.join("/"))
}

/// A zone name is a relative path of plain segments; anything else is not looked up.
fn is_zone_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() < 64
        && name.split('/').all(|s| !s.is_empty() && s != "." && s != "..")
        && name.bytes().all(|b| b.is_ascii_alphanumeric() || b"/_+-".contains(&b))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_a_uac_root_and_ignores_nested_roots() {
        let source = Source::from_memory(&[
            ("uac-web01-linux/[root]/etc/passwd", b"root:x:0:0::/root:/bin/sh\n"),
            ("uac-web01-linux/[root]/etc/hostname", b"web01\n"),
            ("uac-web01-linux/[root]/etc/os-release", b"NAME=x\nPRETTY_NAME=\"Debian GNU/Linux 12 (bookworm)\"\n"),
            ("uac-web01-linux/[root]/var/lib/docker/overlay2/abc/diff/etc/passwd", b""),
            ("uac-web01-linux/live_response/process/ps.txt", b"PID\n"),
        ]);
        let hosts = discover(&source, None);
        assert_eq!(hosts.len(), 1);
        let host = &hosts[0];
        assert_eq!((host.name.as_str(), host.os, host.root.as_str()), ("web01", Os::Linux, "uac-web01-linux/[root]"));
        assert_eq!(host.os_version, "Debian GNU/Linux 12 (bookworm)");
        assert!(host.tz.is_utc_fallback());
        assert!(host.tz_description.starts_with("UTC (assumed"));

        let live = Pattern::new("../live_response/process/*.txt");
        let found: Vec<String> = host.find(&live).map(|e| host.rel(e)).collect();
        assert_eq!(found, ["../live_response/process/ps.txt"]);
        let passwd = Pattern::new("etc/passwd");
        assert_eq!(host.find(&passwd).map(|e| host.rel(e)).collect::<Vec<_>>(), ["etc/passwd"]);
    }

    #[test]
    fn a_live_response_only_collection_is_still_a_host() {
        let source = Source::from_memory(&[
            ("uac-db-linux-01-linux-20260101120000/live_response/process/ps.txt", b"PID\n"),
            ("uac-db-linux-01-linux-20260101120000/uac.log", b""),
        ]);
        let hosts = discover(&source, None);
        assert_eq!(hosts.len(), 1);
        assert_eq!(hosts[0].root, "uac-db-linux-01-linux-20260101120000/[root]");
        assert_eq!(hosts[0].name, "db-linux-01");
        let live = Pattern::new("../live_response/process/*.txt");
        assert_eq!(hosts[0].find(&live).count(), 1);
        assert_eq!(hosts[0].read_text("../live_response/process/ps.txt").as_deref(), Some("PID\n"));
        assert!(hosts[0].read("../../outside").is_none());

        // The same collection with no top-level folder, as UAC archives are packed.
        let flat = Source::from_memory(&[("bodyfile/bodyfile.txt", b""), ("live_response/x.txt", b"")]);
        let hosts = discover(&flat, None);
        assert_eq!((hosts.len(), hosts[0].root.as_str()), (1, "[root]"));
        assert_eq!(hosts[0].find(&Pattern::new("../bodyfile/bodyfile.txt")).count(), 1);
    }

    #[test]
    fn uac_names() {
        assert_eq!(uac_host_name("uac-web01-linux-20240310010203.tar.gz"), Some("web01"));
        assert_eq!(uac_host_name("uac-my-linux-box-linux-20240310010203"), Some("my-linux-box"));
        assert_eq!(uac_host_name("uac-mac1-macos-20240310010203.zip"), Some("mac1"));
        assert_eq!(uac_host_name("evidence.tar.gz"), None);
        assert_eq!(uac_host_name("uac--linux-1"), None);
    }

    #[test]
    fn two_collections_are_two_hosts() {
        let source = Source::from_memory(&[
            ("a/[root]/etc/hostname", b"alpha\n"),
            ("b/[root]/etc/hostname", b"beta\n"),
            ("b/[root]/var/log/syslog", b""),
        ]);
        let names: Vec<String> = discover(&source, None).into_iter().map(|h| h.name).collect();
        assert_eq!(names, ["alpha", "beta"]);
    }

    #[test]
    fn macos_root_sits_above_private() {
        let source = Source::from_memory(&[
            ("private/var/db/diagnostics/Persist/0001.tracev3", b""),
            ("private/etc/passwd", b""),
            ("private/var/log/system.log", b""),
            ("Users/sam/.zsh_history", b""),
        ]);
        let hosts = discover(&source, None);
        assert_eq!(hosts.len(), 1);
        assert_eq!((hosts[0].os, hosts[0].root.as_str()), (Os::Macos, ""));
    }

    #[test]
    fn unknown_layout_is_one_host() {
        let source = Source::from_memory(&[("logs/auth.log", b"")]);
        let hosts = discover(&source, None);
        assert_eq!((hosts.len(), hosts[0].os), (1, Os::Unknown));
    }

    /// A collection can hold `etc/os-release` as a link whose target was not collected.
    #[test]
    fn the_version_falls_back_to_the_distribution_release_files() {
        let version = |files: &[(&str, &[u8])]| {
            let mut all = vec![("r/etc/hostname", &b"h\n"[..])];
            all.extend_from_slice(files);
            discover(&Source::from_memory(&all), None)[0].os_version.clone()
        };
        assert_eq!(
            version(&[("r/etc/system-release", b"Rocky Linux release 9.4 (Blue Onyx)\n")]),
            "Rocky Linux release 9.4 (Blue Onyx)"
        );
        assert_eq!(
            version(&[("r/etc/lsb-release", b"DISTRIB_ID=Ubuntu\nDISTRIB_DESCRIPTION=\"Ubuntu 24.04.1 LTS\"\n")]),
            "Ubuntu 24.04.1 LTS"
        );
        assert_eq!(version(&[("r/etc/debian_version", b"13.1\n")]), "Debian 13.1");
        assert_eq!(version(&[("r/etc/alpine-release", b"3.22.1\n")]), "Alpine Linux 3.22.1");
        assert_eq!(
            version(&[("r/etc/rocky-release", b"Rocky Linux release 9.3 (Blue Onyx)\n")]),
            "Rocky Linux release 9.3 (Blue Onyx)"
        );
        let both: [(&str, &[u8]); 2] =
            [("r/etc/os-release", b"PRETTY_NAME=First\n"), ("r/etc/debian_version", b"13\n")];
        assert_eq!(version(&both), "First");
    }

    /// With no `etc/hostname`, the host is named after the evidence file, without the
    /// archive or image extension.
    #[test]
    fn the_fallback_name_drops_the_archive_extension() {
        for (file, name) in [
            ("export.tar", "export"),
            ("web01-files.zip", "web01-files"),
            ("case7.tar.gz", "case7"),
            ("disk.E01", "disk"),
            ("v1.2-host", "v1.2-host"),
        ] {
            let mut source = Source::from_memory(&[("etc/passwd", b"root:x:0:0::/root:/bin/sh\n")]);
            source.path = std::path::PathBuf::from(format!("/cases/{file}"));
            assert_eq!(discover(&source, None)[0].name, name, "{file}");
        }
    }

    #[test]
    fn follows_links_only_inside_the_root() {
        let mut source =
            Source::from_memory(&[("r/etc/hostname", b"h\n"), ("r/usr/lib/os-release", b"PRETTY_NAME=Linux\n")]);
        let link = |path: &str, target: &str| {
            let mut entry = Entry::memory(path, Vec::new().into(), 0);
            entry.link = Some(target.to_string());
            entry
        };
        source.entries.push(link("r/etc/os-release", "../usr/lib/os-release"));
        source.entries.push(link("r/etc/escape", "../../../etc/shadow"));
        source.entries.push(link("r/etc/loop", "loop"));
        source.entries.sort_by(|a, b| a.path.cmp(&b.path));
        let host = &discover(&source, None)[0];
        assert_eq!(host.read_text("etc/os-release").as_deref(), Some("PRETTY_NAME=Linux\n"));
        assert!(host.entry("etc/escape").is_none());
        assert!(host.entry("etc/loop").is_none());
        assert!(host.entry("../outside").is_none());
    }

    #[test]
    fn zone_names_are_validated() {
        assert!(is_zone_name("Europe/Berlin"));
        assert!(is_zone_name("Etc/GMT+5"));
        assert!(!is_zone_name("../../etc/shadow"));
        assert!(!is_zone_name("/etc/passwd"));
        assert!(!is_zone_name(""));
    }
}
