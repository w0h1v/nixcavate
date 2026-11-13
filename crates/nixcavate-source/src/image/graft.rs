//! One host from the volumes of one disk: a root filesystem's `etc/fstab` says which other
//! volumes of the image are mounted where, and those volumes are listed under the root at their
//! mount points instead of as hosts of their own.
//!
//! A mount names its volume by `UUID=`, `LABEL=`, `PARTUUID=`, `PARTLABEL=`, a device path under
//! `/dev/disk/by-*`, `/dev/mapper` or `/dev/<vg>/<lv>` (LVM), `/dev/md*` (arrays) or, as a last
//! resort, the device name of the partition (`/dev/sda2`, only when the root itself is named that
//! way, so a disk that is not the one imaged is not mistaken for it). Only ext4 and XFS volumes
//! have a uuid and a label that can be read here; a volume that is not opened (vfat, swap) is not
//! in the image to be found.
//!
//! Everything in the fstab is evidence: it is read up to a size cap, mount points are normalised
//! and refused when they would leave the root, a volume is grafted once, never into itself, and
//! never when it is a root of its own (so no cycle can exist).

use super::{Opened, Part};
use crate::{Entry, Store};
use nixcavate_fs::{read_all, ReadAt};
use std::collections::HashSet;
use std::fs::File;
use std::io::{self, BufRead, BufReader, BufWriter, Write};
use std::path::{Path, PathBuf};

/// The most of `etc/fstab` that is read.
const FSTAB_MAX: u64 = 1 << 20;
/// Lines of it looked at, and grafts per root.
const MAX_LINES: usize = 8192;
const MAX_GRAFTS: usize = 256;
/// Mount point depth and component length.
const MAX_DEPTH: usize = 32;
const MAX_COMPONENT: usize = 255;

/// What names a volume in an fstab.
#[derive(Debug, Default, Clone)]
pub(super) struct Ident {
    /// Filesystem uuid, lower case with dashes.
    pub uuid: Option<String>,
    pub label: Option<String>,
    pub partuuid: Option<String>,
    pub partlabel: Option<String>,
    /// Partition number of a volume that is a whole partition.
    pub index: Option<usize>,
    /// `<vg>-<lv>` of a logical volume.
    pub lv: Option<String>,
    /// uuid as udev prints it, name and minor of an array.
    pub md: Option<(String, String, Option<u32>)>,
}

/// A volume that has been walked: its entries and body file, not yet placed in a host.
pub(super) struct Listed {
    pub name: String,
    /// Index in the image's volumes.
    pub volume: usize,
    pub entries: Vec<Entry>,
    /// The body file and the lines in it.
    pub body: Option<(PathBuf, u64)>,
    /// Inode and size of `etc/fstab`, when it is a regular file.
    pub fstab: Option<(u64, u64)>,
    pub ident: Ident,
}

/// The filesystem uuid and label read from the superblock at the start of `part`.
pub(super) fn probe(part: &Part, kind: Option<&str>) -> (Option<String>, Option<String>) {
    let read = |at: u64, len: usize| {
        let mut buf = vec![0u8; len];
        part.read_at(at, &mut buf).ok().map(|()| buf)
    };
    let (uuid, label) = match kind {
        Some("ext4") => read(1024, 1024).map(|sb| (sb[0x68..0x78].to_vec(), sb[0x78..0x88].to_vec())).unzip(),
        Some("xfs") => read(0, 120).map(|sb| (sb[32..48].to_vec(), sb[108..120].to_vec())).unzip(),
        _ => return (None, None),
    };
    let uuid = uuid.filter(|u: &Vec<u8>| u.iter().any(|&b| b != 0)).map(|u| {
        let hex: String = u.iter().map(|b| format!("{b:02x}")).collect();
        format!("{}-{}-{}-{}-{}", &hex[..8], &hex[8..12], &hex[12..16], &hex[16..20], &hex[20..])
    });
    let label = label
        .map(|l: Vec<u8>| String::from_utf8_lossy(&l[..l.iter().position(|&b| b == 0).unwrap_or(l.len())]).into_owned())
        .filter(|l| !l.is_empty());
    (uuid, label)
}

/// One mount of an fstab that may be an image's volume.
#[derive(Debug, PartialEq, Eq)]
struct Mount {
    spec: String,
    /// Normalised components of the mount point; empty for `/`.
    point: Vec<String>,
}

/// `\040` style octal escapes of fstab fields.
fn unescape(field: &str) -> String {
    let bytes = field.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        let octal =
            bytes.get(i + 1..i + 4).filter(|d| bytes[i] == b'\\' && d.iter().all(|b| (b'0'..=b'7').contains(b)));
        match octal {
            Some(d) => {
                out.push(d.iter().fold(0u32, |n, b| n * 8 + u32::from(b - b'0')) as u8);
                i += 4;
            }
            None => {
                out.push(bytes[i]);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// The components of an absolute mount point, or `None` when it would leave the root, is not
/// absolute, has a control character or is absurdly deep.
fn mount_point(field: &str) -> Option<Vec<String>> {
    let path = unescape(field);
    if !path.starts_with('/') {
        return None;
    }
    let mut out = Vec::new();
    for part in path.split('/').filter(|p| !p.is_empty() && *p != ".") {
        if part == ".." || part.len() > MAX_COMPONENT || part.chars().any(char::is_control) {
            return None;
        }
        out.push(part.to_string());
    }
    (out.len() <= MAX_DEPTH).then_some(out)
}

/// The mounts of an fstab worth looking at, and how many had a mount point that was refused.
fn parse(text: &str) -> (Vec<Mount>, usize) {
    let (mut mounts, mut refused) = (Vec::new(), 0);
    for line in text.lines().take(MAX_LINES) {
        let fields: Vec<&str> = line.split_whitespace().collect();
        let (spec, point, kind, options) = match fields.as_slice() {
            [spec, ..] if spec.starts_with('#') => continue,
            [spec, point, rest @ ..] => {
                (*spec, *point, rest.first().copied().unwrap_or(""), rest.get(1).copied().unwrap_or(""))
            }
            _ => continue,
        };
        // Swap has no files, and a bind mount shows files that are already in the tree.
        if kind == "swap" || kind == "bind" || options.split(',').any(|o| o == "bind" || o == "rbind") {
            continue;
        }
        // `tmpfs`, `proc` and `server:/export` are not devices of this image.
        if !spec.starts_with('/') && !spec.contains('=') && bsd_letter(spec).is_none() {
            continue;
        }
        match mount_point(point) {
            Some(point) => mounts.push(Mount { spec: unescape(spec), point }),
            None if point.starts_with('/') => refused += 1,
            None => {}
        }
    }
    (mounts, refused)
}

/// `\x20` style escapes of udev names under `/dev/disk/by-label` and `by-partlabel`.
fn udev_unescape(name: &str) -> String {
    let mut out = String::new();
    let mut rest = name;
    while let Some(at) = rest.find("\\x") {
        out.push_str(&rest[..at]);
        let hex = rest.get(at + 2..at + 4).and_then(|h| u8::from_str_radix(h, 16).ok());
        match hex {
            Some(b) => {
                out.push(char::from(b));
                rest = &rest[at + 4..];
            }
            None => {
                out.push_str("\\x");
                rest = &rest[at + 2..];
            }
        }
    }
    out.push_str(rest);
    out
}

/// The name of the disk in `/dev/sda2` or `/dev/nvme0n1p2`, and the partition number.
fn disk_and_number(device: &str) -> Option<(&str, usize)> {
    let name = device.strip_prefix("/dev/")?;
    if name.contains('/') {
        return None;
    }
    let digits = name.len() - name.trim_end_matches(|c: char| c.is_ascii_digit()).len();
    let number: usize = name.get(name.len() - digits..)?.parse().ok()?;
    let disk = &name[..name.len() - digits];
    // `nvme0n1p2` and `mmcblk0p1` put a `p` before the number when the disk name ends in a digit.
    let disk = match disk.strip_suffix('p') {
        Some(base) if base.ends_with(|c: char| c.is_ascii_digit()) => base,
        _ => disk,
    };
    (!disk.is_empty()).then_some((disk, number))
}

/// The partition letter, as a number from 1, of a BSD disklabel partition: `<16 hex digits>.d`
/// (an OpenBSD disk id) or `/dev/sd0d`, `/dev/wd0e`, `/dev/ada0s1a` (a unit number, then the letter).
fn bsd_letter(spec: &str) -> Option<usize> {
    let (disk, letter) = spec.split_at_checked(spec.len().checked_sub(1)?)?;
    let letter = letter.bytes().next().filter(|b| (b'a'..=b'p').contains(b))?;
    let duid = disk.strip_suffix('.').is_some_and(|id| id.len() == 16 && id.bytes().all(|b| b.is_ascii_hexdigit()));
    let device = disk.strip_prefix("/dev/").is_some_and(|name| {
        !name.contains('/') && name.ends_with(|c: char| c.is_ascii_digit()) && name.starts_with(char::is_alphabetic)
    });
    (duid || device).then_some(usize::from(letter - b'a') + 1)
}

/// `vg` and `lv` of a `/dev/mapper` name, where `-` in either is doubled.
fn mapper_parts(name: &str) -> Option<(String, String)> {
    let (mut vg, mut lv, mut in_lv) = (String::new(), String::new(), false);
    let mut chars = name.chars().peekable();
    while let Some(c) = chars.next() {
        let target = if in_lv { &mut lv } else { &mut vg };
        if c == '-' && chars.peek() == Some(&'-') {
            chars.next();
            target.push('-');
        } else if c == '-' && !in_lv {
            in_lv = true;
        } else {
            target.push(c);
        }
    }
    (in_lv && !vg.is_empty() && !lv.is_empty()).then_some((vg, lv))
}

/// The one volume `spec` names, or `None` when it names none or several.
fn resolve(spec: &str, volumes: &[Listed], root_disk: Option<&str>) -> Option<usize> {
    let unquote = |v: &str| v.trim_matches(['"', '\'']).to_string();
    let find = |test: &dyn Fn(&Ident) -> bool| {
        let mut found = volumes.iter().enumerate().filter(|(_, v)| test(&v.ident)).map(|(i, _)| i);
        let first = found.next()?;
        found.next().is_none().then_some(first)
    };
    let same = |a: &Option<String>, b: &str| a.as_deref().is_some_and(|a| a.eq_ignore_ascii_case(b));
    let (tag, value) = match spec.split_once('=') {
        Some((tag, value)) if !spec.starts_with('/') => (tag.to_ascii_uppercase(), unquote(value)),
        _ => {
            let by = |dir: &str| spec.strip_prefix(dir).map(str::to_string);
            if let Some(v) = by("/dev/disk/by-uuid/") {
                ("UUID".into(), v)
            } else if let Some(v) = by("/dev/disk/by-label/") {
                ("LABEL".into(), udev_unescape(&v))
            } else if let Some(v) = by("/dev/disk/by-partuuid/") {
                ("PARTUUID".into(), v)
            } else if let Some(v) = by("/dev/disk/by-partlabel/") {
                ("PARTLABEL".into(), udev_unescape(&v))
            } else if let Some(v) = by("/dev/disk/by-id/md-uuid-") {
                ("MD-UUID".into(), v)
            } else if let Some(v) = by("/dev/mapper/") {
                let (vg, lv) = mapper_parts(&v)?;
                ("LV".into(), super::md::clean(&format!("{vg}-{lv}"), 128))
            } else if let Some(v) = by("/dev/md/") {
                ("MD-NAME".into(), v)
            } else if let Some(v) = by("/dev/md") {
                ("MD-MINOR".into(), v)
            } else if let Some((vg, lv)) = spec.strip_prefix("/dev/").and_then(|p| p.split_once('/')) {
                if lv.contains('/') || ["disk", "mapper", "md", "pts", "shm"].contains(&vg) {
                    return None;
                }
                ("LV".into(), super::md::clean(&format!("{vg}-{lv}"), 128))
            } else if let Some(letter) = bsd_letter(spec) {
                // Label partitions are numbered `slice * 100 + letter`.
                return find(&|i| i.index.is_some_and(|index| index > 100 && index % 100 == letter));
            } else {
                let (disk, number) = disk_and_number(spec)?;
                (disk == root_disk?).then_some(())?;
                return find(&|i| i.index == Some(number));
            }
        }
    };
    match tag.as_str() {
        "UUID" => find(&|i| same(&i.uuid, &value)),
        "LABEL" => find(&|i| i.label.as_deref() == Some(value.as_str())),
        "PARTUUID" => find(&|i| same(&i.partuuid, &value)),
        "PARTLABEL" => find(&|i| i.partlabel.as_deref() == Some(value.as_str())),
        "LV" => find(&|i| i.lv.as_deref() == Some(value.as_str())),
        "MD-UUID" => find(&|i| i.md.as_ref().is_some_and(|m| m.0.eq_ignore_ascii_case(&value))),
        "MD-NAME" => find(&|i| i.md.as_ref().is_some_and(|m| m.1 == value)),
        "MD-MINOR" => {
            let minor = value.parse::<u32>().ok();
            let arrays = volumes.iter().filter(|v| v.ident.md.is_some()).count();
            // The number is a guess at the array's name; a lone array is the only candidate.
            find(&|i| i.md.as_ref().is_some_and(|m| m.2.is_some() && m.2 == minor || m.1 == value || arrays == 1))
        }
        _ => None,
    }
}

/// Parses `data` as an fstab and resolves every device against volumes that exist only by name,
/// for the fuzz target: no input may panic.
pub(super) fn fuzz(data: &[u8]) {
    let (mounts, _) = parse(&String::from_utf8_lossy(data));
    let volumes = vec![Listed {
        name: "p1".into(),
        volume: 0,
        entries: Vec::new(),
        body: None,
        fstab: None,
        ident: Ident { uuid: Some("a".into()), index: Some(2), lv: Some("a-b".into()), ..Ident::default() },
    }];
    for mount in &mounts {
        let _ = resolve(&mount.spec, &volumes, Some("sda"));
        let _ = bsd_letter(&mount.spec);
    }
}

/// A volume placed under a root.
struct Graft {
    child: usize,
    root: usize,
    point: Vec<String>,
}

/// Reads the start of the root's fstab.
fn read_fstab(volume: &Opened, inode: u64, size: u64) -> Option<String> {
    let bytes = read_all(&**volume, inode, size.min(FSTAB_MAX), FSTAB_MAX).ok()?;
    Some(String::from_utf8_lossy(&bytes).into_owned())
}

/// Places every volume that a root's fstab mounts under that root, writes one body file per host
/// and returns all entries. `notes` gets one line for what was hidden or refused.
pub(super) fn compose(
    mut listed: Vec<Listed>,
    volumes: &[Opened],
    scratch: &Path,
    notes: &mut Vec<String>,
) -> io::Result<Vec<Entry>> {
    let grafts = plan(&listed, volumes, notes);
    let mut out = Vec::new();
    let mut grafted = vec![false; listed.len()];
    for g in &grafts {
        grafted[g.child] = true;
    }
    for root in 0..listed.len() {
        if grafted[root] {
            continue;
        }
        let mine: Vec<&Graft> = grafts.iter().filter(|g| g.root == root).collect();
        if mine.is_empty() {
            let name = listed[root].name.clone();
            if let Some((path, _)) = listed[root].body.take() {
                out.push(body_entry(&name, path)?);
            }
            out.append(&mut listed[root].entries);
            continue;
        }
        merge(&mut listed, root, &mine, scratch, &mut out, notes)?;
    }
    Ok(out)
}

fn body_entry(name: &str, path: PathBuf) -> io::Result<Entry> {
    Ok(Entry {
        path: format!("{name}/bodyfile/bodyfile.txt"),
        size: std::fs::metadata(&path)?.len(),
        mtime: 0,
        mode: 0o644,
        uid: 0,
        gid: 0,
        link: None,
        store: Store::File(path),
    })
}

/// Which volumes go under which roots, deepest mount points last.
fn plan(listed: &[Listed], volumes: &[Opened], notes: &mut Vec<String>) -> Vec<Graft> {
    let mut grafts: Vec<Graft> = Vec::new();
    let mut taken = vec![false; listed.len()];
    for (root, volume) in listed.iter().enumerate() {
        let Some((inode, size)) = volume.fstab else { continue };
        if taken[root] {
            continue;
        }
        let Some(text) = volumes.get(volume.volume).and_then(|v| read_fstab(v, inode, size)) else { continue };
        let (mounts, refused) = parse(&text);
        // The device the root is on, when it is named by its device name.
        let root_disk = mounts
            .iter()
            .find(|m| m.point.is_empty())
            .and_then(|m| disk_and_number(&m.spec))
            .map(|(d, _)| d.to_string());
        let (mut points, mut repeats, mut mine) = (HashSet::new(), 0usize, Vec::new());
        for mount in mounts {
            if mount.point.is_empty() {
                continue;
            }
            let Some(child) = resolve(&mount.spec, listed, root_disk.as_deref()) else { continue };
            // A root is a host of its own; a volume is placed once, never into itself.
            if child == root || listed[child].fstab.is_some() || taken[child] {
                if child != root && listed[child].fstab.is_none() {
                    repeats += 1;
                }
                continue;
            }
            if mine.len() >= MAX_GRAFTS || !points.insert(mount.point.clone()) {
                repeats += 1;
                continue;
            }
            taken[child] = true;
            mine.push(Graft { child, root, point: mount.point });
        }
        let mut remarks = Vec::new();
        if size > FSTAB_MAX {
            remarks.push(format!("only the first {FSTAB_MAX} bytes of etc/fstab were read"));
        }
        if refused > 0 {
            remarks.push(format!("{refused} mount points that would leave the root were ignored"));
        }
        if repeats > 0 {
            remarks.push(format!("{repeats} mounts of a volume already placed or of one mount point were ignored"));
        }
        if !remarks.is_empty() {
            notes.push(format!("{}: {}", volume.name, remarks.join("; ")));
        }
        mine.sort_by_key(|g| g.point.len());
        grafts.extend(mine);
    }
    grafts
}

/// The path of entries of `listed[member]` mounted at `point`, as they appear in the host.
fn joined(point: &str, rel: &str) -> String {
    match (point.is_empty(), rel.is_empty()) {
        (true, _) => rel.to_string(),
        (false, true) => point.to_string(),
        (false, false) => format!("{point}/{rel}"),
    }
}

/// Merges the root `root` and its grafts into one host: entries moved under the mount points
/// (what a deeper mount covers is hidden) and the body files folded into one.
fn merge(
    listed: &mut [Listed],
    root: usize,
    grafts: &[&Graft],
    scratch: &Path,
    out: &mut Vec<Entry>,
    notes: &mut Vec<String>,
) -> io::Result<()> {
    let host = listed[root].name.clone();
    // Each member of the host with its mount point as a path; the root's is empty.
    let mut members: Vec<(usize, String)> = vec![(root, String::new())];
    members.extend(grafts.iter().map(|g| (g.child, g.point.join("/"))));
    // What covers a member: mount points below its own.
    let covers = |point: &str| -> Vec<String> {
        members
            .iter()
            .map(|(_, p)| p)
            .filter(|p| {
                !p.is_empty() && p.len() > point.len() && (point.is_empty() || p.starts_with(&format!("{point}/")))
            })
            .cloned()
            .collect()
    };
    let hidden_by = |covers: &[String], path: &str| {
        covers.iter().any(|c| path == c || path.strip_prefix(c.as_str()).is_some_and(|r| r.starts_with('/')))
    };
    let mut hidden_where: Vec<(String, usize)> = Vec::new();
    let combined = scratch.join(format!("bodyfile-{host}-host.txt"));
    let mut body = BufWriter::new(File::create(&combined)?);
    let mut lines = 0u64;
    for (member, point) in &members {
        let covered = covers(point);
        let prefix = format!("{}/[root]/", listed[*member].name);
        let mut hidden = 0usize;
        let entries = std::mem::take(&mut listed[*member].entries);
        for mut entry in entries {
            let Some(rel) = entry.path.strip_prefix(&prefix) else { continue };
            let full = joined(point, rel);
            if hidden_by(&covered, &full) {
                hidden += 1;
                continue;
            }
            entry.path = format!("{host}/[root]/{full}");
            out.push(entry);
        }
        if hidden > 0 {
            hidden_where.push((listed[*member].name.clone(), hidden));
        }
        if let Some((path, _)) = listed[*member].body.take() {
            lines += fold_body(&path, point, &covered, &mut body)?;
            let _ = std::fs::remove_file(&path);
        }
    }
    body.into_inner().map_err(io::IntoInnerError::into_error)?;
    if lines == 0 {
        let _ = std::fs::remove_file(&combined);
    } else {
        out.push(body_entry(&host, combined)?);
    }
    if !hidden_where.is_empty() {
        let total: usize = hidden_where.iter().map(|(_, n)| n).sum();
        let from: Vec<String> = hidden_where.iter().map(|(name, n)| format!("{n} of {name}")).collect();
        notes.push(format!(
            "{host}: {total} files are hidden under the volumes mounted over them ({})",
            from.join(", ")
        ));
    }
    Ok(())
}

/// Copies the body file lines at `from` that no volume covers, under the mount `point`.
/// Returns the lines written.
fn fold_body(from: &Path, point: &str, covered: &[String], to: &mut impl Write) -> io::Result<u64> {
    let mut reader = BufReader::new(File::open(from)?);
    let (mut line, mut written) = (String::new(), 0u64);
    loop {
        line.clear();
        if reader.read_line(&mut line)? == 0 {
            return Ok(written);
        }
        let Some(rest) = line.strip_prefix("0|") else {
            to.write_all(line.as_bytes())?;
            written += 1;
            continue;
        };
        // The name is everything before the nine fixed fields that follow it.
        let name = rest.rsplitn(10, '|').last().unwrap_or(rest);
        let path = name.strip_prefix('/').unwrap_or(name);
        let path_only = path.split(" -> ").next().unwrap_or(path);
        let full = joined(point, path_only);
        // The mount point's own directory line is kept (the volume's own listing has no line for
        // its root); what is below it on the covered volume is gone.
        if covered.iter().any(|c| full.strip_prefix(c.as_str()).is_some_and(|r| r.starts_with('/'))) {
            continue;
        }
        if point.is_empty() {
            to.write_all(line.as_bytes())?;
        } else {
            let tail = &rest[name.len()..];
            let joined_name = if path.is_empty() { point.to_string() } else { format!("{point}/{path}") };
            write!(to, "0|/{joined_name}{tail}")?;
        }
        written += 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ident(f: impl FnOnce(&mut Ident)) -> Ident {
        let mut i = Ident::default();
        f(&mut i);
        i
    }

    fn vol(name: &str, ident: Ident) -> Listed {
        Listed { name: name.into(), volume: 0, entries: Vec::new(), body: None, fstab: None, ident }
    }

    #[test]
    fn mount_points_are_normalised_and_escapes_decoded() {
        assert_eq!(mount_point("/boot"), Some(vec!["boot".into()]));
        assert_eq!(mount_point("//var///log/./audit/"), Some(vec!["var".into(), "log".into(), "audit".into()]));
        assert_eq!(mount_point("/mnt/my\\040disk"), Some(vec!["mnt".into(), "my disk".into()]));
        assert_eq!(mount_point("/"), Some(vec![]));
        for bad in ["/boot/../../etc", "/..", "boot", "none", "", "/a/\\000b", "/a/\\012b"] {
            assert_eq!(mount_point(bad), None, "{bad}");
        }
        assert_eq!(mount_point(&format!("/{}", "a/".repeat(40))), None);
    }

    #[test]
    fn fstab_lines_are_filtered() {
        let text = "# comment
UUID=1 / ext4 defaults 0 1
UUID=2 /boot ext4 defaults 0 2
                    /dev/sda3 none swap sw 0 0
tmpfs /tmp tmpfs defaults 0 0
/dev/sdb1 /mnt/x ext4 bind 0 0
                    LABEL=a /var xfs rw,rbind 0 0
LABEL=b /../x ext4 defaults 0 0
LABEL=c var ext4 defaults 0 0
                    server:/export /srv nfs defaults 0 0
LABEL=d /home
";
        let (mounts, refused) = parse(text);
        let specs: Vec<&str> = mounts.iter().map(|m| m.spec.as_str()).collect();
        assert_eq!(specs, ["UUID=1", "UUID=2", "LABEL=d"]);
        // OpenBSD names a partition by disk id and letter; its swap line has four fields.
        let (mounts, _) = parse("16f524d63aaee0fc.b none swap sw\n16f524d63aaee0fc.a / ffs rw 1 1\n16f524d63aaee0fc.d /usr ffs rw,nodev 1 2\n");
        let specs: Vec<&str> = mounts.iter().map(|m| m.spec.as_str()).collect();
        assert_eq!(specs, ["16f524d63aaee0fc.a", "16f524d63aaee0fc.d"]);
        assert_eq!(refused, 1);
    }

    #[test]
    fn specs_resolve_to_one_volume() {
        let vols = vec![
            vol(
                "p2",
                ident(|i| {
                    i.uuid = Some("aaaaaaaa-0000-0000-0000-000000000001".into());
                    i.label = Some("root".into());
                    i.index = Some(2);
                    i.partuuid = Some("11111111-2222-3333-4444-555555555555".into());
                    i.partlabel = Some("Linux filesystem".into());
                }),
            ),
            vol(
                "p3",
                ident(|i| {
                    i.uuid = Some("bbbbbbbb-0000-0000-0000-000000000002".into());
                    i.index = Some(3);
                }),
            ),
            vol("vg0-home", ident(|i| i.lv = Some("vg0-home".into()))),
            vol("vg-x-data", ident(|i| i.lv = Some("vg-x-data".into()))),
            vol(
                "md-data",
                ident(|i| i.md = Some(("a1b2c3d4:00000000:00000000:00000001".into(), "data".into(), Some(127)))),
            ),
        ];
        let r = |spec: &str| resolve(spec, &vols, Some("sda"));
        assert_eq!(r("UUID=AAAAAAAA-0000-0000-0000-000000000001"), Some(0));
        assert_eq!(r("UUID=\"bbbbbbbb-0000-0000-0000-000000000002\""), Some(1));
        assert_eq!(r("LABEL=root"), Some(0));
        assert_eq!(r("LABEL=Root"), None);
        assert_eq!(r("PARTUUID=11111111-2222-3333-4444-555555555555"), Some(0));
        assert_eq!(r("PARTLABEL=Linux filesystem"), Some(0));
        assert_eq!(r("/dev/disk/by-uuid/bbbbbbbb-0000-0000-0000-000000000002"), Some(1));
        assert_eq!(r("/dev/disk/by-label/root"), Some(0));
        assert_eq!(r("/dev/mapper/vg0-home"), Some(2));
        assert_eq!(r("/dev/vg0/home"), Some(2));
        assert_eq!(r("/dev/mapper/vg--x-data"), Some(3));
        assert_eq!(r("/dev/md127"), Some(4));
        assert_eq!(r("/dev/md/data"), Some(4));
        assert_eq!(r("/dev/disk/by-id/md-uuid-a1b2c3d4:00000000:00000000:00000001"), Some(4));
        assert_eq!(r("/dev/sda3"), Some(1));
        assert_eq!(r("/dev/sdb3"), None, "another disk");
        assert_eq!(resolve("/dev/sda3", &vols, None), None, "no root device to compare with");
        assert_eq!(r("/dev/mapper/vg0"), None);
        assert_eq!(r("UUID=nothing"), None);
        // Two volumes with one uuid (a clone): neither is chosen.
        let twins =
            vec![vol("a", ident(|i| i.uuid = Some("x".into()))), vol("b", ident(|i| i.uuid = Some("x".into())))];
        assert_eq!(resolve("UUID=x", &twins, None), None);
    }

    /// BSD disklabel partitions are numbered `slice * 100 + letter`: fstab names them by letter.
    #[test]
    fn bsd_label_partitions_resolve_by_letter() {
        let vols = vec![
            vol("p201", ident(|i| i.index = Some(201))),
            vol("p204", ident(|i| i.index = Some(204))),
            vol("p205", ident(|i| i.index = Some(205))),
        ];
        let r = |spec: &str| resolve(spec, &vols, None);
        assert_eq!(r("0123456789abcdef.d"), Some(1), "an OpenBSD disk id and letter");
        assert_eq!(r("0123456789abcdef.e"), Some(2));
        assert_eq!(r("/dev/sd0d"), Some(1));
        assert_eq!(r("/dev/ada0s2e"), Some(2));
        assert_eq!(r("0123456789abcdef.b"), None, "no such volume");
        assert_eq!(r("0123456789abcdeg.d"), None, "not a disk id");
        assert_eq!(r("/dev/sda"), None, "a Linux disk, not a letter");
        // Two labels with a `d`: neither is chosen.
        let two = vec![vol("p104", ident(|i| i.index = Some(104))), vol("p204", ident(|i| i.index = Some(204)))];
        assert_eq!(resolve("/dev/sd0d", &two, None), None);
        assert_eq!(bsd_letter("/dev/sd0q"), None);
    }

    #[test]
    fn device_names() {
        assert_eq!(disk_and_number("/dev/sda2"), Some(("sda", 2)));
        assert_eq!(disk_and_number("/dev/vdb12"), Some(("vdb", 12)));
        assert_eq!(disk_and_number("/dev/nvme0n1p3"), Some(("nvme0n1", 3)));
        assert_eq!(disk_and_number("/dev/mmcblk0p1"), Some(("mmcblk0", 1)));
        assert_eq!(disk_and_number("/dev/sda"), None);
        assert_eq!(disk_and_number("/dev/disk/x1"), None);
        assert_eq!(mapper_parts("rl-root"), Some(("rl".into(), "root".into())));
        assert_eq!(mapper_parts("my--vg-my--lv"), Some(("my-vg".into(), "my-lv".into())));
        assert_eq!(mapper_parts("nodash"), None);
    }

    #[test]
    fn body_lines_move_under_the_mount_point_and_covered_ones_go() {
        let dir = std::env::temp_dir().join(format!("nixcavate-graft-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let from = dir.join("body.txt");
        std::fs::write(
            &from,
            "0|/|2|drwxr-xr-x|0|0|4096|1|2|3|0\n0|/a b|3|-rw-r--r--|0|0|1|1|2|3|0\n0|/x|4|-rw-r--r--|0|0|1|1|2|3|0\n0|/x/y|6|-rw-r--r--|0|0|1|1|2|3|0\n0|/l -> /a|5|lrwxrwxrwx|0|0|1|1|2|3|0\n",
        )
        .unwrap();
        let mut out = Vec::new();
        let n = fold_body(&from, "boot", &["boot/x".to_string()], &mut out).unwrap();
        let text = String::from_utf8(out).unwrap();
        assert_eq!(n, 4);
        assert_eq!(
            text,
            "0|/boot|2|drwxr-xr-x|0|0|4096|1|2|3|0\n0|/boot/a b|3|-rw-r--r--|0|0|1|1|2|3|0\n0|/boot/x|4|-rw-r--r--|0|0|1|1|2|3|0\n0|/boot/l -> /a|5|lrwxrwxrwx|0|0|1|1|2|3|0\n"
        );
        let mut same = Vec::new();
        fold_body(&from, "", &[], &mut same).unwrap();
        assert_eq!(same, std::fs::read(&from).unwrap());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
