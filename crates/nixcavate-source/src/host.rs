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
    /// VMware ESXi.
    Esxi,
    FreeBsd,
    OpenBsd,
    NetBsd,
    /// Oracle Solaris and the illumos distributions.
    Solaris,
    Aix,
    /// No known layout was found; every artifact is tried.
    Unknown,
}

impl Os {
    pub fn as_str(self) -> &'static str {
        match self {
            Os::Linux => "linux",
            Os::Macos => "macos",
            Os::Esxi => "esxi",
            Os::FreeBsd => "freebsd",
            Os::OpenBsd => "openbsd",
            Os::NetBsd => "netbsd",
            Os::Solaris => "solaris",
            Os::Aix => "aix",
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
const ROOT_MARKERS: [&str; 8] = [
    "etc/passwd",
    "etc/os-release",
    "etc/hostname",
    "System/Library/CoreServices/SystemVersion.plist",
    "var/log/",
    "private/var/db/",
    // ESXi keeps its live logs in a ramdisk, and a vm-support bundle may hold only those.
    "var/run/log/",
    "etc/vmware/esx.conf",
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
    // FreeBSD, OpenBSD and NetBSD name and version themselves here.
    "etc/rc.conf",
    "etc/rc.conf.local",
    "etc/rc.conf.d/hostname",
    "etc/myname",
    "etc/release",
    "etc/motd",
    "var/db/freebsd-update/tag",
    "var/run/dmesg.boot",
    "../live_response/system/uname_-a.txt",
    "etc/nodename",
    "etc/release",
    "etc/default/init",
    "etc/TIMEZONE",
    "usr/share/lib/zoneinfo/**",
    "etc/vmware/esx.conf",
    "etc/hosts",
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
        host.os = host.detect_os(source);
        (host.name, host.os_version) = match host.os {
            Os::Macos => host.macos_identity(),
            Os::FreeBsd | Os::OpenBsd | Os::NetBsd => host.bsd_identity(),
            Os::Solaris => host.solaris_identity(),
            Os::Esxi => host.esxi_identity(),
            Os::Aix => host.aix_identity(),
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

    /// The operating system, from the layout below the root. Every system here has `etc/` and
    /// `var/log/`, so each is recognised by files only it has, the most specific first, and
    /// Linux is what remains. A UAC collection also names the system in its folder or file
    /// name (`uac-<host>-<os>-<time>`): that decides when the layout does not.
    fn detect_os(&self, source: &Source) -> Os {
        let has = |dir: &str| !source.range_under(&self.join(dir)).is_empty();
        let file = |path: &str| self.entry(path).is_some();
        if has("System/Library") || has("private/var") || has("private/etc") || has("Library/Preferences") {
            return Os::Macos;
        }
        if !(has("etc") || has("var/log") || has("var/adm") || has("var/run/log")) {
            return Os::Unknown;
        }
        let esxi_files = ["etc/vmware/esx.conf", "var/log/vmkernel.log", "var/run/log/vmkernel.log"];
        let esxi_daemons = ["etc/vmware/hostd/vmInventory.xml", "var/run/log/hostd.log", "var/log/hostd.log"];
        // Big logs may be present only as `vm-support` pieces; the host agent's folder is ESXi's.
        // VMware Workstation on Linux also has `etc/vmware/hostd`; ESXi has no `os-release`.
        // A link whose target was not collected still says the system has the file.
        let listed = |path: &str| self.lookup(path).is_some();
        let folder = self.root.rsplit('/').find(|s| !s.is_empty() && !s.starts_with('['));
        let file_name = source.path.file_name().map(|n| n.to_string_lossy().into_owned());
        let named = folder.and_then(uac_os).or_else(|| file_name.as_deref().and_then(uac_os));
        let linux_release = listed("etc/os-release") || file("usr/lib/os-release") || named == Some(Os::Linux);
        if esxi_files.iter().chain(&esxi_daemons).any(|path| file(path)) || has("etc/vmware/hostd") && !linux_release {
            Os::Esxi
        } else if has("etc/security")
            && (has("etc/objrepos")
                || has("var/adm/ras")
                || has("usr/lpp")
                // Stanza files only AIX has, for a copy of just `/etc/security` and `/var/adm`.
                || file("etc/security/user")
                || file("etc/security/lastlog")
                || file("etc/security/failedlogin"))
        {
            Os::Aix
        } else if has("etc/svc") || has("var/svc") || has("lib/svc") {
            Os::Solaris
        } else if !linux_release
            && (file("etc/release") && has("etc/rc.d") && !file("etc/freebsd-update.conf")
                || has("etc/pkg_install.conf.d"))
        {
            // Before FreeBSD: NetBSD has `etc/defaults` and `etc/rc.d` as well, and FreeBSD has no `etc/release`.
            // Not with an `os-release`: Mageia has `etc/release` and `etc/rc.d` too.
            Os::NetBsd
        } else if file("etc/freebsd-update.conf")
            || file("bin/freebsd-version")
            || has("etc/defaults") && has("etc/rc.d")
        {
            Os::FreeBsd
        } else if file("etc/installurl") || has("etc/examples") || file("var/log/authlog") && file("etc/pf.conf") {
            Os::OpenBsd
        } else {
            named.unwrap_or(Os::Linux)
        }
    }

    /// The name from `esx.conf` (`/adv/Misc/HostName`), else the first non-loopback name in
    /// `etc/hosts`; the version from the banner line every VMware daemon log starts with
    /// (`Section for VMware ESX, pid=1, version=6.7.0, build=19195723`).
    fn esxi_identity(&self) -> (String, String) {
        let quoted = |text: &str, key: &str| {
            let rest = text.lines().find_map(|l| l.strip_prefix(key))?.trim_start().strip_prefix('=')?;
            let name = rest.trim().trim_matches('"').trim();
            (!name.is_empty()).then(|| name.to_string())
        };
        let from_conf = self.read_text("etc/vmware/esx.conf").and_then(|conf| quoted(&conf, "/adv/Misc/HostName"));
        let from_hosts = || {
            let hosts = self.read_text("etc/hosts")?;
            hosts.lines().find_map(|line| {
                let mut words = line.split('#').next()?.split_whitespace();
                let address = words.next()?;
                let loopback = address.starts_with("127.") || address == "::1";
                (!loopback).then(|| words.next().map(str::to_string)).flatten()
            })
        };
        let name = from_conf.or_else(from_hosts).unwrap_or_default();
        let version = ["var/run/log/hostd.log", "var/log/hostd.log", "var/run/log/vpxa.log", "var/log/vpxa.log"]
            .iter()
            .find_map(|rel| {
                let data = self.read(rel)?;
                let head = String::from_utf8_lossy(&data[..data.len().min(4096)]).into_owned();
                let banner = head.lines().next()?;
                let after = banner.split("version=").nth(1)?;
                let version = after.split([',', ' ']).next()?;
                let build = banner.split("build=").nth(1).and_then(|b| b.split([',', ' ']).next());
                Some(match build {
                    Some(build) => format!("VMware ESXi {version} (build {build})"),
                    None => format!("VMware ESXi {version}"),
                })
            })
            .unwrap_or_default();
        (name, version)
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
            // A file of `KEY=value` settings (`etc/cloud-release`) is not a version line.
            (!line.is_empty() && !line.contains('=')).then(|| line.to_string())
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

    /// Host name and release of FreeBSD, OpenBSD and NetBSD. The name is `hostname=` in
    /// `rc.conf`, `rc.conf.local` or `rc.conf.d/hostname` (FreeBSD, NetBSD) or the first line of `etc/myname` (OpenBSD, NetBSD). The
    /// release is the `uname -a` a UAC collection saved, else what the system wrote to a file
    /// at install or boot: `etc/release` (NetBSD), the `freebsd-update` tag, the first line of
    /// `etc/motd` or `dmesg.boot` (OpenBSD, which the rc scripts write from `uname`).
    fn bsd_identity(&self) -> (String, String) {
        let rc_hostname = ["etc/rc.conf.d/hostname", "etc/rc.conf.local", "etc/rc.conf"].iter().find_map(|path| {
            let text = self.read_text(path)?;
            text.lines().find_map(|line| {
                let value = line.trim().strip_prefix("hostname=")?;
                let value = value.trim().trim_matches(['"', '\'']).trim();
                (!value.is_empty()).then(|| value.to_string())
            })
        });
        let first_line = |rel: &str| {
            let text = self.read_text(rel)?;
            let line = text.lines().next()?.trim();
            (!line.is_empty()).then(|| line.to_string())
        };
        let name = rc_hostname.or_else(|| first_line("etc/myname")).unwrap_or_default();
        // `FreeBSD host 14.5-RELEASE-p2 FreeBSD 14.5-RELEASE-p2 GENERIC amd64`: system and release.
        let uname = self.read_text("../live_response/system/uname_-a.txt").and_then(|text| {
            let mut words = text.split_whitespace();
            let (system, _host, release) = (words.next()?, words.next()?, words.next()?);
            Some(format!("{system} {release}"))
        });
        let version = uname
            .or_else(|| {
                // `freebsd-update|amd64|14.5-RELEASE-p2|`
                let tag = first_line("var/db/freebsd-update/tag")?;
                let release = tag.split('|').nth(2)?;
                Some(format!("FreeBSD {release}"))
            })
            .or_else(|| first_line("etc/release"))
            .or_else(|| first_line("etc/motd").filter(|l| l.starts_with("OpenBSD") || l.starts_with("NetBSD")))
            .or_else(|| {
                first_line("var/run/dmesg.boot").filter(|l| l.starts_with("OpenBSD") || l.starts_with("NetBSD"))
            })
            // `OpenBSD 7.8 (GENERIC.MP) #54: Sun Oct 12 12:58:11 MDT 2025`: keep what precedes the build date.
            .map(|line| line.split_once(": ").map_or(line.clone(), |(release, _)| release.to_string()));
        (name, version.unwrap_or_default())
    }

    /// Solaris and illumos keep the host name in `etc/nodename` (Oracle Solaris 11 also keeps it in
    /// the SMF repository, which is not read here) and the release in `etc/release`; illumos
    /// distributions add `etc/os-release`.
    fn solaris_identity(&self) -> (String, String) {
        let first_line = |rel: &str| {
            let text = self.read_text(rel)?;
            let line = text.lines().map(str::trim).find(|l| !l.is_empty())?.to_string();
            Some(line)
        };
        let name = first_line("etc/nodename").unwrap_or_default();
        let pretty = self.read_text("etc/os-release").and_then(|text| {
            text.lines().find_map(|l| l.strip_prefix("PRETTY_NAME=")).map(|v| v.trim().trim_matches('"').to_string())
        });
        (name, pretty.or_else(|| first_line("etc/release")).unwrap_or_default())
    }

    /// The `TZ` of a Solaris system: `etc/default/init` (`etc/TIMEZONE` links to it) holds `TZ=name`.
    fn solaris_tz(&self) -> Option<String> {
        let text = self.read_text("etc/default/init").or_else(|| self.read_text("etc/TIMEZONE"))?;
        let value = text.lines().find_map(|l| l.trim().strip_prefix("TZ="))?;
        let name = value.trim().trim_matches(['"', '\'']).to_string();
        is_zone_name(&name).then_some(name)
    }

    /// AIX keeps its host name in the ODM, which is not read, so the name comes from command
    /// output a collector saved (`hostname`, `uname -n`, `uname -a`, `lsattr -El inet0`) and the
    /// version from `oslevel -s`, `-r` or plain. Anything missing falls back to the collection's name.
    fn aix_identity(&self) -> (String, String) {
        let first_word = |rel: &str, skip: usize| {
            let text = self.read_text(rel)?;
            let word = text.lines().next()?.split_whitespace().nth(skip)?.to_string();
            (!word.is_empty()).then_some(word)
        };
        let name = first_word("../live_response/system/hostname.txt", 0)
            .or_else(|| first_word("../live_response/system/uname_-n.txt", 0))
            .or_else(|| {
                let text = self.read_text("../live_response/system/uname_-a.txt")?;
                let mut words = text.lines().next()?.split_whitespace();
                (words.next()? == "AIX").then(|| words.next().map(str::to_string)).flatten()
            })
            .or_else(|| {
                let text = self.read_text("../live_response/network/lsattr_-El_inet0.txt")?;
                text.lines().find_map(|l| l.strip_prefix("hostname")?.split_whitespace().next().map(str::to_string))
            })
            .unwrap_or_default();
        let version = first_word("../live_response/system/oslevel_-s.txt", 0)
            .or_else(|| first_word("../live_response/system/oslevel_-r.txt", 0))
            .or_else(|| first_word("../live_response/system/oslevel.txt", 0))
            .map(|level| format!("AIX {level}"))
            .unwrap_or_default();
        (name, version)
    }

    /// The zone AIX names in `TZ=` in `/etc/environment`: an Olson name (looked up in `zoneinfo`)
    /// or a POSIX string such as `CST6CDT`.
    fn aix_zone(&self, zoneinfo: Option<&Path>) -> Option<(Tz, String)> {
        let text = self.read_text("etc/environment")?;
        let spec = text
            .lines()
            .map(str::trim)
            .filter(|l| !l.starts_with(['#', '*']))
            .find_map(|l| l.strip_prefix("TZ=").map(|v| v.trim().trim_matches(['"', '\'']).to_string()))?;
        if let (true, Some(dir)) = (is_zone_name(&spec), zoneinfo) {
            if let Some(tz) = std::fs::read(dir.join(&spec)).ok().and_then(|bytes| Tz::parse(&bytes)) {
                return Some((tz, format!("{spec} (TZ in etc/environment; zone data from {})", dir.display())));
            }
        }
        let tz = Tz::from_posix(&spec)?;
        Some((tz, format!("{spec} (POSIX TZ in etc/environment)")))
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
            .or_else(|| if self.os == Os::Solaris { self.solaris_tz() } else { None })
            .filter(|name| is_zone_name(name));
        let label = named.clone().unwrap_or_else(|| "unnamed zone".into());

        if let Some(tz) = localtime.iter().find_map(|p| Tz::parse(&self.read(p)?)) {
            return (tz, format!("{label} (zone data from the evidence)"));
        }
        // Solaris has no `etc/localtime`: its zone data is under `usr/share/lib/zoneinfo`.
        if let Some(name) = named.as_deref().filter(|_| self.os == Os::Solaris) {
            if let Some(tz) = self.read(&format!("usr/share/lib/zoneinfo/{name}")).and_then(|data| Tz::parse(&data)) {
                return (tz, format!("{name} (TZ in the evidence; zone data from the evidence)"));
            }
            if matches!(name, "UTC" | "GMT" | "Etc/UTC" | "Etc/GMT") {
                return (Tz::utc(), format!("{name} (TZ in the evidence)"));
            }
        }
        if let (Some(name), Some(dir)) = (&named, zoneinfo) {
            if let Some(tz) = std::fs::read(dir.join(name)).ok().and_then(|bytes| Tz::parse(&bytes)) {
                return (tz, format!("{name} (named in the evidence; zone data from {})", dir.display()));
            }
        }
        if self.os == Os::Aix {
            if let Some(found) = self.aix_zone(zoneinfo) {
                return found;
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

/// The operating system a UAC collection name states: `uac-<host>-<os>-<timestamp>`. Only the
/// systems whose layout alone may not decide are answered.
fn uac_os(label: &str) -> Option<Os> {
    let rest = label.strip_prefix("uac-")?;
    let named = [
        ("-linux-", Os::Linux),
        ("-esxi-", Os::Esxi),
        ("-freebsd-", Os::FreeBsd),
        ("-openbsd-", Os::OpenBsd),
        ("-netbsd-", Os::NetBsd),
        ("-solaris-", Os::Solaris),
        ("-aix-", Os::Aix),
    ];
    named.iter().filter_map(|(name, os)| Some((rest.rfind(name)?, *os))).max_by_key(|(at, _)| *at).map(|(_, os)| os)
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
        // A `-release` file of settings (`etc/cloud-release`) is not a version line.
        let cloud: [(&str, &[u8]); 2] =
            [("r/etc/cloud-release", b"ID=genericcloud\n"), ("r/etc/debian_version", b"12.9\n")];
        assert_eq!(version(&cloud), "Debian 12.9");
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
    fn each_operating_system_is_told_from_its_own_files() {
        let os = |files: &[&str]| {
            let all: Vec<(&str, &[u8])> = files.iter().map(|f| (*f, &b"x\n"[..])).collect();
            discover(&Source::from_memory(&all), None)[0].os
        };
        assert_eq!(os(&["r/etc/passwd", "r/var/log/syslog"]), Os::Linux);
        assert_eq!(os(&["r/etc/passwd", "r/etc/vmware/esx.conf", "r/var/log/hostd.log"]), Os::Esxi);
        assert_eq!(os(&["r/var/run/log/hostd.log", "r/etc/hosts"]), Os::Esxi);
        assert_eq!(
            os(&["r/etc/hosts", "r/etc/vmware/hostd/hostsvc.xml", "r/var/run/log/hostd.log.FRAG-00000"]),
            Os::Esxi
        );
        // VMware Workstation on Linux has an etc/vmware too.
        assert_eq!(os(&["r/etc/passwd", "r/etc/vmware/config", "r/var/log/syslog"]), Os::Linux);
        assert_eq!(os(&["r/etc/os-release", "r/etc/vmware/hostd/config.xml", "r/var/log/syslog"]), Os::Linux);
        assert_eq!(os(&["r/etc/passwd", "r/etc/security/user", "r/etc/objrepos/CuAt", "r/var/adm/wtmp"]), Os::Aix);
        assert_eq!(os(&["r/etc/passwd", "r/etc/security/lastlog", "r/var/adm/sulog"]), Os::Aix);
        assert_eq!(
            os(&["r/etc/passwd", "r/etc/release", "r/etc/svc/repository.db", "r/var/adm/messages"]),
            Os::Solaris
        );
        assert_eq!(
            os(&["r/etc/passwd", "r/etc/defaults/rc.conf", "r/etc/rc.d/sshd", "r/var/log/auth.log"]),
            Os::FreeBsd
        );
        assert_eq!(os(&["r/etc/passwd", "r/etc/installurl", "r/var/log/authlog"]), Os::OpenBsd);
        assert_eq!(os(&["r/etc/passwd", "r/etc/release", "r/etc/rc.d/sshd", "r/var/log/authlog"]), Os::NetBsd);
        // Mageia and other Linux systems have `etc/release` and `etc/rc.d` as well.
        assert_eq!(os(&["r/etc/passwd", "r/etc/release", "r/etc/rc.d/init.d/x", "r/etc/os-release"]), Os::Linux);
        // NetBSD has `etc/defaults` and `etc/rc.d` like FreeBSD, and `etc/release` which FreeBSD lacks.
        assert_eq!(
            os(&["r/etc/passwd", "r/etc/release", "r/etc/defaults/rc.conf", "r/etc/rc.d/sshd", "r/var/log/authlog"]),
            Os::NetBsd
        );
        assert_eq!(os(&["r/Library/Preferences/x.plist", "r/private/var/log/system.log"]), Os::Macos);
        assert_eq!(os(&["r/var/log/x.log"]), Os::Linux);
        // A UAC collection names the system when its files do not decide.
        assert_eq!(os(&["uac-box-freebsd-20240310010203/[root]/etc/passwd"]), Os::FreeBsd);
        assert_eq!(os(&["uac-box-linux-20240310010203/[root]/etc/passwd"]), Os::Linux);
        assert_eq!(os(&["uac-freebsd-box-linux-20240310010203/[root]/etc/passwd"]), Os::Linux);
        // Mageia collected without the file its `etc/os-release` link points to.
        let mageia = "uac-box-linux-20240310010203/[root]/etc";
        let files = [format!("{mageia}/passwd"), format!("{mageia}/release"), format!("{mageia}/rc.d/init.d/x")];
        assert_eq!(os(&files.each_ref().map(String::as_str)), Os::Linux);
    }

    #[test]
    fn an_aix_host_is_named_and_dated_from_collected_command_output() {
        let tree: [(&str, &[u8]); 8] = [
            ("uac-fallback-aix-20240310010203/[root]/etc/passwd", b"root:!:0:0::/:/usr/bin/ksh\n"),
            ("uac-fallback-aix-20240310010203/[root]/etc/security/user", b"root:\n"),
            ("uac-fallback-aix-20240310010203/[root]/etc/objrepos/CuAt", b"x"),
            ("uac-fallback-aix-20240310010203/[root]/etc/environment", b"# c\nPATH=/usr/bin\nTZ=CST6CDT\n"),
            ("uac-fallback-aix-20240310010203/live_response/system/uname_-a.txt", b"AIX aixbox 2 7 00F9C5A04C00\n"),
            ("uac-fallback-aix-20240310010203/live_response/system/oslevel_-s.txt", b"7200-05-04-2220\n"),
            ("uac-fallback-aix-20240310010203/live_response/system/oslevel.txt", b"7.2.0.0\n"),
            ("uac-fallback-aix-20240310010203/uac.log", b""),
        ];
        let source = Source::from_memory(&tree);
        let hosts = discover(&source, None);
        let host = &hosts[0];
        assert_eq!((host.os, host.name.as_str(), host.os_version.as_str()), (Os::Aix, "aixbox", "AIX 7200-05-04-2220"));
        assert!(host.tz_description.contains("POSIX TZ"), "{}", host.tz_description);
        // 2024-03-10T12:00:00 in CST6CDT is UTC-6 before the March change and UTC-5 after it (DST began that morning).
        assert_eq!(host.tz.offset_at(1_710_000_000), -6 * 3600);
        assert_eq!(host.tz.offset_at(1_720_000_000), -5 * 3600);

        // Without any collected output the collection's own name is the host name.
        let bare: [(&str, &[u8]); 3] = [
            ("uac-fallback-aix-20240310010203/[root]/etc/passwd", b"root:!:0:0::/:/usr/bin/ksh\n"),
            ("uac-fallback-aix-20240310010203/[root]/etc/security/user", b"root:\n"),
            ("uac-fallback-aix-20240310010203/[root]/etc/objrepos/CuAt", b"x"),
        ];
        let source = Source::from_memory(&bare);
        let hosts = discover(&source, None);
        let host = &hosts[0];
        assert_eq!((host.os, host.name.as_str()), (Os::Aix, "fallback"));
    }

    /// Solaris and illumos: the name is in `etc/nodename`, the release in `etc/os-release` (illumos distributions) or
    /// `etc/release`, and the zone in `etc/default/init` (`etc/TIMEZONE` links to it).
    #[test]
    fn solaris_identity_and_zone() {
        let host_of = |files: &[(&str, &[u8])]| {
            let all: Vec<(&str, &[u8])> = files.to_vec();
            let source = Source::from_memory(&all);
            let host = discover(&source, None).remove(0);
            (host.os, host.name.clone(), host.os_version.clone(), host.tz_description.clone())
        };
        let (os, name, version, zone) = host_of(&[
            ("r/etc/svc/repository.db", b"x"),
            ("r/etc/nodename", b"nx-example\n"),
            ("r/etc/release", b"  OmniOS v11 r151054\n  Copyright\n"),
            ("r/etc/os-release", b"NAME=\"OmniOS\"\nPRETTY_NAME=\"OmniOS Community Edition v11 r151054\"\n"),
            ("r/etc/default/init", b"#\nTZ=UTC\nCMASK=022\n"),
        ]);
        assert_eq!(
            (os, name.as_str(), version.as_str()),
            (Os::Solaris, "nx-example", "OmniOS Community Edition v11 r151054")
        );
        assert_eq!(zone, "UTC (TZ in the evidence)");
        // Oracle Solaris has `etc/release` only; a named zone with no data stays UTC and says so.
        let (os, _, version, zone) = host_of(&[
            ("r/var/svc/log/x.log", b"x"),
            ("r/etc/passwd", b"x"),
            ("r/etc/nodename", b"box\n"),
            ("r/etc/release", b"                    Oracle Solaris 11.4 SPARC\n  Copyright (c) 1983\n"),
            ("r/etc/default/init", b"TZ=\"Europe/Berlin\"\n"),
        ]);
        assert_eq!((os, version.as_str()), (Os::Solaris, "Oracle Solaris 11.4 SPARC"));
        assert!(zone.starts_with("UTC (assumed; no zone data found for Europe/Berlin)"), "{zone}");
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
