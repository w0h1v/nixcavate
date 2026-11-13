//! Software RAID and fstab grafting against disks made by the real tools: `test_files/image/raid`
//! and `test_files/image/graft` (see their `build.sh`). The truth is a real mount's sha256.

use super::*;
use crate::{discover, Source};
use nixcavate_fs::{Kind, Node};
use sha2::{Digest, Sha256};
use std::fs;
use std::io::{Seek, SeekFrom};

fn images() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../test_files/image")
}

/// A new empty folder for one test.
fn scratch(label: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("nixcavate-raid-{label}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    dir
}

/// Decompresses `src` to `dst`, leaving the all-zero blocks as holes.
fn unzstd(src: &Path, dst: &Path) {
    let mut decoder = zstd::stream::read::Decoder::new(File::open(src).unwrap()).unwrap();
    let mut file = File::create(dst).unwrap();
    let (mut block, mut total) = (vec![0u8; 1 << 20], 0u64);
    loop {
        let mut filled = 0;
        while filled < block.len() {
            let n = decoder.read(&mut block[filled..]).unwrap();
            if n == 0 {
                break;
            }
            filled += n;
        }
        if filled == 0 {
            break;
        }
        if block[..filled].iter().any(|&b| b != 0) {
            file.seek(SeekFrom::Start(total)).unwrap();
            file.write_all(&block[..filled]).unwrap();
        }
        total += filled as u64;
    }
    file.set_len(total).unwrap();
}

fn disk(dir: &Path, fixture: &str, name: &str) -> PathBuf {
    let path = dir.join(name);
    unzstd(&images().join(fixture), &path);
    path
}

fn open_disk(path: &Path) -> io::Result<Source> {
    Source::open(path, &|_| true, &path.with_extension("scratch"))
}

fn sha(bytes: &[u8]) -> String {
    Sha256::digest(bytes).iter().map(|b| format!("{b:02x}")).collect()
}

/// `(sha256, path)` of every file of a real mount, from `<name>.sha256`.
fn truth(name: &str) -> Vec<(String, String)> {
    let text = fs::read_to_string(images().join("raid").join(format!("{name}.sha256"))).unwrap();
    text.lines().map(|l| l.split_once("  ").map(|(h, p)| (h.to_string(), p.to_string())).unwrap()).collect()
}

/// Every file of the host is what the real mount had, and there are no others.
fn assert_tree(source: &Source, root: &str, expected: &[(String, String)]) {
    for (hash, path) in expected {
        let entry = source.entry(&format!("{root}{path}")).unwrap_or_else(|| panic!("{root}{path} is not listed"));
        assert_eq!(sha(&source.read(entry).unwrap()), *hash, "{path}");
    }
    let listed = source.entries().iter().filter(|e| e.path.starts_with(root) && e.link.is_none()).count();
    assert_eq!(listed, expected.len(), "files under {root}");
}

fn host_of(source: &Source) -> (String, String) {
    let hosts = discover(source, None);
    assert_eq!(hosts.len(), 1, "{:?}", hosts.iter().map(|h| &h.root).collect::<Vec<_>>());
    (hosts[0].name.clone(), hosts[0].root.clone())
}

/// (fixture, root of the host's volume). 0.90 arrays have no name: the root is `md-<8 hex>`.
const ARRAYS: &[(&str, &str)] = &[
    ("raid1-12", "md-fixture_r1"),
    ("raid1-090", "md-"),
    ("raid1-10", "md-fixture_r1"),
    ("raid1-11", "md-fixture_r1"),
    ("raid0-64k", "md-fixture_r0"),
    ("raid0-512k", "md-fixture_r0"),
    ("raid0-zones-orig", "md-fixture_z0"),
    ("raid0-zones-alt", "md-fixture_z0"),
    ("raid5-ls", "md-fixture_r5"),
    ("raid5-la", "md-fixture_r5"),
    ("raid5-rs", "md-fixture_r5"),
    ("raid5-ra", "md-fixture_r5"),
    ("raid5-090", "md-"),
    ("raid4", "md-fixture_r4"),
    ("raid6", "md-fixture_r6"),
    ("raid10-n2", "md-fixture_r10"),
    ("raid10-n2-3", "md-fixture_r10"),
    ("raid1-lvm", "vgr-root"),
];

#[test]
fn every_real_array_is_assembled_and_every_file_matches_the_mount() {
    let dir = scratch("arrays");
    for (name, prefix) in ARRAYS {
        let path = disk(&dir, &format!("raid/{name}.img.zst"), "disk.img");
        let source = open_disk(&path).unwrap_or_else(|e| panic!("{name}: {e}"));
        assert!(source.warnings.is_empty(), "{name}: {:?}", source.warnings);
        let (host, root) = host_of(&source);
        assert_eq!(host, "raidhost", "{name}");
        let volume = root.trim_end_matches("/[root]");
        assert!(volume.starts_with(prefix), "{name}: {root}");
        assert_tree(&source, &format!("{volume}/[root]"), &truth(name));
        // One host, one body file.
        let bodies = source.entries().iter().filter(|e| e.path.ends_with("bodyfile.txt")).count();
        assert_eq!(bodies, 1, "{name}");
    }
    let _ = fs::remove_dir_all(dir);
}

/// Zeroes the superblock areas of the members `gone` (numbered from 0 among the members) of the
/// disk at `path`.
fn remove_members(path: &Path, gone: &[usize]) {
    let mut data = fs::read(path).unwrap();
    let parts = partitions::scan(&Bytes(&data));
    let members: Vec<&Partition> = parts.iter().filter(|p| p.unsupported == Some(partitions::MD_REASON)).collect();
    for &index in gone {
        let (start, end) = (members[index].start as usize, (members[index].start + members[index].len) as usize);
        data[start..start + 8192].fill(0);
        data[end - 73728..end].fill(0);
    }
    fs::write(path, data).unwrap();
}

#[test]
fn a_degraded_raid5_is_rebuilt_from_parity_for_every_layout_and_member() {
    let dir = scratch("degraded");
    for name in ["raid5-ls", "raid5-la", "raid5-rs", "raid5-ra", "raid5-090", "raid4"] {
        let members = if name == "raid5-090" { 4 } else { 3 };
        for missing in 0..members {
            let path = disk(&dir, &format!("raid/{name}.img.zst"), "disk.img");
            remove_members(&path, &[missing]);
            let source = open_disk(&path).unwrap_or_else(|e| panic!("{name} without member {missing}: {e}"));
            assert!(
                source.warnings.iter().any(|w| w.contains("one member is missing")),
                "{name} {missing}: {:?}",
                source.warnings
            );
            let (_, root) = host_of(&source);
            assert_tree(&source, &root, &truth(name));
        }
    }
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn too_many_missing_members_is_one_note_with_the_reason() {
    let dir = scratch("toomany");
    for (name, gone, reason) in [
        ("raid5-ls", vec![0, 1], "2 of 3 members are not in the image"),
        ("raid6", vec![2], "RAID6 is read only with every member present"),
        ("raid0-64k", vec![1], "1 of 2 members are not in the image"),
        ("raid10-n2", vec![0, 1], "some data had all its copies there"),
    ] {
        let path = disk(&dir, &format!("raid/{name}.img.zst"), "disk.img");
        remove_members(&path, &gone);
        let err = open_disk(&path).err().unwrap().to_string();
        assert!(err.contains("no readable filesystem") && err.contains(reason), "{name}: {err}");
        assert_eq!(err.matches("not assembled").count(), 1, "{name}: {err}");
    }
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn raid10_loses_one_member_of_each_pair_without_losing_data() {
    let dir = scratch("raid10");
    for (name, gone) in
        [("raid10-n2", vec![0]), ("raid10-n2", vec![1, 2]), ("raid10-n2", vec![0, 3]), ("raid10-n2-3", vec![1])]
    {
        let path = disk(&dir, &format!("raid/{name}.img.zst"), "disk.img");
        remove_members(&path, &gone);
        let source = open_disk(&path);
        // Members 1 and 2 are copies of different chunks, so some chunk may lose both copies: the
        // check is that the answer is either the real data or a refusal, never wrong data.
        match source {
            Ok(source) => {
                let (_, root) = host_of(&source);
                assert_tree(&source, &root, &truth(name));
            }
            Err(e) => assert!(e.to_string().contains("all its copies"), "{name} {gone:?}: {e}"),
        }
    }
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn unsupported_raid10_layouts_are_named() {
    let dir = scratch("far");
    let path = disk(&dir, "raid/raid10-f2.img.zst", "disk.img");
    let err = open_disk(&path).err().unwrap().to_string();
    assert!(err.contains("RAID10 layout") && err.contains("only near layouts"), "{err}");
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn raid1_members_that_disagree_are_named_and_the_newest_is_read() {
    let dir = scratch("raid1");
    let path = disk(&dir, "raid/raid1-12.img.zst", "disk.img");
    let mut data = fs::read(&path).unwrap();
    let parts = partitions::scan(&Bytes(&data));
    let members: Vec<&Partition> = parts.iter().filter(|p| p.unsupported == Some(partitions::MD_REASON)).collect();
    let (first, second) = (members[0].start as usize, members[1].start as usize);
    // The first member is damaged and the second one is newer.
    data[first + (1 << 20)..first + (1 << 20) + 4096].fill(0xee);
    data[second + 4096 + 200..second + 4096 + 208].copy_from_slice(&1000u64.to_le_bytes());
    let end = second + members[1].len as usize;
    md::repair_checksum(&mut data[second..end]);
    fs::write(&path, data).unwrap();
    let source = open_disk(&path).unwrap();
    assert!(
        source.warnings.iter().any(|w| w.contains("disagree") && w.contains("read from p2")),
        "{:?}",
        source.warnings
    );
    let (_, root) = host_of(&source);
    assert_tree(&source, &root, &truth("raid1-12"));
    let _ = fs::remove_dir_all(dir);
}

/// One folder holding the per-disk images of `name` (its `-d<n>` files) as `disk<n>.img`.
fn split_dir(label: &str, name: &str, disks: usize) -> PathBuf {
    let dir = scratch(label);
    for n in 1..=disks {
        unzstd(&images().join(format!("raid/{name}-d{n}.img.zst")), &dir.join(format!("disk{n}.img")));
    }
    dir
}

#[test]
fn an_array_over_several_image_files_is_assembled_from_the_files_beside_the_evidence() {
    // RAID5 over three disks: opening the first finds the other two.
    let dir = split_dir("m5", "m-raid5", 3);
    let source = open_disk(&dir.join("disk1.img")).unwrap();
    assert!(
        source
            .warnings
            .iter()
            .any(|w| w.contains("also read from the images beside") && w.contains("disk2.img, disk3.img")),
        "{:?}",
        source.warnings
    );
    let (_, root) = host_of(&source);
    assert!(root.starts_with("md-fixture_m5"), "{root}");
    assert_tree(&source, &root, &truth("m-raid5"));
    // Opening a different one of the three gives the same host.
    let source = open_disk(&dir.join("disk3.img")).unwrap();
    assert_tree(&source, &host_of(&source).1, &truth("m-raid5"));
    // One missing disk is a degraded array, two are not an array.
    fs::remove_file(dir.join("disk3.img")).unwrap();
    let source = open_disk(&dir.join("disk1.img")).unwrap();
    assert!(source.warnings.iter().any(|w| w.contains("one member is missing")), "{:?}", source.warnings);
    assert_tree(&source, &host_of(&source).1, &truth("m-raid5"));
    fs::remove_file(dir.join("disk2.img")).unwrap();
    let err = open_disk(&dir.join("disk1.img")).err().unwrap().to_string();
    assert!(err.contains("2 of 3 members are not in the image"), "{err}");
    let _ = fs::remove_dir_all(dir);

    // RAID0 needs both members; RAID1 is complete with one.
    let dir = split_dir("m0", "m-raid0", 2);
    let source = open_disk(&dir.join("disk2.img")).unwrap();
    assert_tree(&source, &host_of(&source).1, &truth("m-raid0"));
    let _ = fs::remove_dir_all(dir);
    let dir = split_dir("m1", "m-raid1", 2);
    fs::remove_file(dir.join("disk2.img")).unwrap();
    let source = open_disk(&dir.join("disk1.img")).unwrap();
    assert_tree(&source, &host_of(&source).1, &truth("m-raid1"));
    assert!(source.warnings.is_empty(), "{:?}", source.warnings);
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn only_regular_files_beside_the_image_are_used_and_only_the_first_32_are_examined() {
    let dir = split_dir("bound", "m-raid0", 2);
    let second = dir.join("disk2.img");
    // A link to the other member is not followed.
    let out = scratch("bound-out");
    fs::rename(&second, out.join("real.img")).unwrap();
    std::os::unix::fs::symlink(out.join("real.img"), &second).unwrap();
    let err = open_disk(&dir.join("disk1.img")).err().unwrap().to_string();
    assert!(err.contains("1 of 2 members are not in the image"), "{err}");
    fs::remove_file(&second).unwrap();
    // The 33rd file in name order is never opened, however good it is.
    for n in 0..32 {
        fs::write(dir.join(format!("a{n:02}")), vec![1u8; 4096]).unwrap();
    }
    fs::rename(out.join("real.img"), dir.join("z.img")).unwrap();
    let err = open_disk(&dir.join("disk1.img")).err().unwrap().to_string();
    assert!(err.contains("1 of 2 members are not in the image"), "{err}");
    // With room for it, it is.
    fs::remove_file(dir.join("a00")).unwrap();
    fs::remove_file(dir.join("a01")).unwrap();
    let source = open_disk(&dir.join("disk1.img")).unwrap();
    assert_tree(&source, &host_of(&source).1, &truth("m-raid0"));
    let _ = fs::remove_dir_all(dir);
    let _ = fs::remove_dir_all(out);
}

// Grafting.

fn graft_truth() -> Vec<(String, String)> {
    let text = fs::read_to_string(images().join("graft/truth.tsv")).unwrap();
    text.lines()
        .map(|l| {
            let f: Vec<&str> = l.split('\t').collect();
            (f[2].to_string(), format!("/{}", f[0]))
        })
        .collect()
}

#[test]
fn the_volumes_of_one_disk_are_one_host() {
    let dir = scratch("graft");
    let path = disk(&dir, "graft/disk.img.zst", "disk.img");
    let source = open_disk(&path).unwrap();
    let (name, root) = host_of(&source);
    assert_eq!((name.as_str(), root.as_str()), ("graftbox", "p3/[root]"));
    // The files of the real mount, from four volumes; what the mounts cover is not there.
    assert_tree(&source, "p3/[root]", &graft_truth());
    assert!(
        source.entry("p3/[root]/boot/shadowed.txt").is_none()
            && source.entry("p3/[root]/var/log/rootvar.txt").is_none()
    );
    assert!(source.warnings.iter().any(|w| w.contains("2 files are hidden")), "{:?}", source.warnings);
    // One body file for the host, with the other volumes' files under their mount points.
    let bodies: Vec<&str> =
        source.entries().iter().map(|e| e.path.as_str()).filter(|p| p.ends_with("bodyfile.txt")).collect();
    assert_eq!(bodies, ["p3/bodyfile/bodyfile.txt"]);
    let body = String::from_utf8(source.read(source.entry(bodies[0]).unwrap()).unwrap().to_vec()).unwrap();
    for wanted in
        ["|/boot/vmlinuz-6.1.0|", "|/var/log/secure|", "|/home/alice/notes.txt|", "|/etc/passwd|", "|/boot|", "|/var|"]
    {
        assert_eq!(body.matches(wanted).count(), 1, "{wanted}");
    }
    assert!(!body.contains("shadowed") && !body.contains("rootvar"));
    // The volumes' own listings were not left behind.
    assert!(!source.entries().iter().any(|e| e.path.starts_with("p2/") || e.path.starts_with("p4/")));
    // Reads come from the right volume.
    let secure = source.entry("p3/[root]/var/log/secure").unwrap();
    assert!(String::from_utf8_lossy(&source.read(secure).unwrap()).contains("Accepted password for alice"));
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn partition_guids_and_names_are_what_sgdisk_prints() {
    let dir = scratch("guids");
    let path = disk(&dir, "graft/disk.img.zst", "disk.img");
    let parts = partitions::scan(&Mapped(map(&path).unwrap()));
    // `sgdisk -i N` of the same disk.
    let truth = [
        "c6b73734-7bef-43f4-b818-eb4b545befb5",
        "072817d4-4e59-43dc-b8db-84487e1fe5b9",
        "56484d8c-a1f0-4dda-9965-4fed2e23b231",
        "056f3f24-360b-4696-a63f-89f5173d5aa6",
        "1a315740-91cc-41c3-9af6-c9c7a267135a",
    ];
    let found: Vec<&str> = parts.iter().map(|p| p.partuuid.as_deref().unwrap_or("")).collect();
    assert_eq!(found, truth);
    let names: Vec<Option<&str>> = parts.iter().map(|p| p.partlabel.as_deref()).collect();
    assert_eq!(names, [None, None, None, Some("varpart"), None]);
    let _ = fs::remove_dir_all(dir);
}

// Hostile fstabs, on volumes made of nothing but a name and some files.

/// A filesystem of regular files, whose `etc/fstab` may claim to be any size.
struct Files {
    files: Vec<(String, Vec<u8>)>,
    /// The size `etc/fstab` claims, when it is not the length of its content.
    fstab_claims: Option<u64>,
}

impl Volume for Files {
    fn kind(&self) -> &'static str {
        "files"
    }

    fn walk(&self, visit: &mut dyn FnMut(Node), _warn: &mut dyn FnMut(String)) -> nixcavate_fs::Result<()> {
        let node = |path: &str, inode: u64, kind: Kind, size: u64| Node {
            path: path.into(),
            inode,
            kind,
            mode: if kind == Kind::File { 0o100644 } else { 0o040755 },
            uid: 0,
            gid: 0,
            size,
            allocated: size,
            links: 1,
            accessed: None,
            modified: Some(1_700_000_000_000_000_000),
            changed: None,
            created: None,
            link_target: None,
        };
        visit(node("", 2, Kind::Directory, 0));
        for (i, (path, data)) in self.files.iter().enumerate() {
            let size =
                if path == "etc/fstab" { self.fstab_claims.unwrap_or(data.len() as u64) } else { data.len() as u64 };
            visit(node(path, 10 + i as u64, Kind::File, size));
        }
        Ok(())
    }

    fn read(&self, inode: u64, offset: u64, buf: &mut [u8]) -> nixcavate_fs::Result<usize> {
        let (_, data) = self.files.get(inode as usize - 10).ok_or_else(|| nixcavate_fs::Error::corrupt("inode"))?;
        // A claimed size beyond the content reads as repeated lines, so 100 MB costs nothing to hold.
        let line = b"UUID=nothing /nowhere ext4 defaults 0 0\n";
        for (i, b) in buf.iter_mut().enumerate() {
            let at = offset as usize + i;
            *b = data.get(at).copied().unwrap_or(line[(at - data.len().min(at)) % line.len()]);
        }
        Ok(buf.len())
    }
}

/// The gpt512 fixture disk with a `Files` volume per partition of the table that has a name in
/// `volumes` (its start sector decides which): p1 at 2048, p2 at 18432, p3 at 51200, p4 at 67584.
type Fake<'a> = (u64, Vec<(&'a str, &'a str)>, Option<u64>);
type Owned = (u64, Vec<(String, Vec<u8>)>, Option<u64>);

fn fake_disk(volumes: &[Fake]) -> (Source, Vec<String>) {
    let volumes: Vec<Owned> = volumes
        .iter()
        .map(|(start, files, claims)| {
            (*start, files.iter().map(|(p, c)| (p.to_string(), c.as_bytes().to_vec())).collect(), *claims)
        })
        .collect();
    let open = move |p: Part| {
        volumes
            .iter()
            .filter(|(start, ..)| *start * 512 == p.start)
            .map(|(_, files, claims)| Box::new(Files { files: files.clone(), fstab_claims: *claims }) as Opened)
            .collect()
    };
    let source =
        Source::from_image(Path::new("disk.E01"), Arc::new(partitions::testing::Sparse::load("gpt512.parts")), &open)
            .unwrap();
    let warnings = source.warnings.clone();
    (source, warnings)
}

const ROOT: u64 = 18432;
const A: u64 = 2048;
const C: u64 = 67584;

fn root_files(fstab: &str) -> Vec<(&str, &str)> {
    vec![
        ("etc/passwd", "root:x:0:0::/root:/bin/sh\n"),
        ("etc/hostname", "box\n"),
        ("etc/fstab", fstab),
        ("boot/own.txt", "x"),
    ]
}

fn data_files() -> Vec<(&'static str, &'static str)> {
    vec![("kernel", "k"), ("sub/deep", "d")]
}

fn linux_hosts(source: &Source) -> usize {
    discover(source, None).iter().filter(|h| h.os != crate::Os::Unknown).count()
}

fn paths(source: &Source) -> Vec<&str> {
    source.entries().iter().map(|e| e.path.as_str()).filter(|p| !p.contains("bodyfile")).collect()
}

#[test]
fn partitions_are_grafted_by_device_name_in_the_order_of_their_depth() {
    // The root is `/dev/sda2`; `/dev/sda1` (p1) and `/dev/sda4` (p4) are mounted by number, the
    // deeper mount point first in the file. A device on another disk, a swap and a tmpfs are ignored.
    let fstab =
        "/dev/sda2 / ext4 defaults 0 1\n/dev/sda4 /var/data ext4 defaults 0 2\n/dev/sda1 /var ext4 defaults 0 2\n\
                 /dev/sdb4 /mnt/other ext4 defaults 0 2\ntmpfs /tmp tmpfs defaults 0 0\n/dev/sda5 none swap sw 0 0\n";
    let (source, warnings) =
        fake_disk(&[(ROOT, root_files(fstab), None), (A, data_files(), None), (C, data_files(), None)]);
    let all = paths(&source);
    for expected in [
        "p2/[root]/var/kernel",
        "p2/[root]/var/sub/deep",
        "p2/[root]/var/data/kernel",
        "p2/[root]/boot/own.txt",
        "p2/[root]/etc/fstab",
    ] {
        assert!(all.contains(&expected), "{expected} in {all:?}");
    }
    assert!(!all.iter().any(|p| p.starts_with("p1/") || p.starts_with("p4/")), "{all:?}");
    assert_eq!(linux_hosts(&source), 1);
    assert!(warnings.is_empty(), "{warnings:?}");
    let data = source.entry("p2/[root]/var/data/sub/deep").unwrap();
    assert_eq!(&*source.read(data).unwrap(), b"d");
}

#[test]
fn a_mount_over_content_hides_it_and_says_how_much() {
    let mut files = data_files();
    files.push(("own.txt", "from the mounted volume"));
    let mut root = root_files("/dev/sda2 / ext4 d 0 1\n/dev/sda1 /boot ext4 d 0 2\n");
    root.push(("boot/other.txt", "hidden too"));
    let (source, warnings) = fake_disk(&[(ROOT, root, None), (A, files, None)]);
    let own = source.entry("p2/[root]/boot/own.txt").unwrap();
    assert_eq!(&*source.read(own).unwrap(), b"from the mounted volume");
    assert!(source.entry("p2/[root]/boot/other.txt").is_none());
    assert!(warnings.iter().any(|w| w.contains("2 files are hidden")), "{warnings:?}");
}

#[test]
fn hostile_fstabs_graft_nothing_they_should_not() {
    let cases: &[(&str, &str)] = &[
        // Mount points that leave the root, relative ones, a control character.
        ("/dev/sda1 /../../etc ext4 d 0 0\n/dev/sda4 /a/../.. ext4 d 0 0\n/dev/sda1 boot ext4 d 0 0\n/dev/sda4 /x\\012y ext4 d 0 0\n", "mount points that would leave the root were ignored"),
        // A volume mounted inside itself, and the root named twice.
        ("/dev/sda2 / ext4 d 0 1\n/dev/sda2 /mnt/self ext4 d 0 1\n", ""),
    ];
    for (fstab, note) in cases {
        let (source, warnings) =
            fake_disk(&[(ROOT, root_files(fstab), None), (A, data_files(), None), (C, data_files(), None)]);
        let all = paths(&source);
        assert!(all.iter().any(|p| p.starts_with("p1/")) && all.iter().any(|p| p.starts_with("p4/")), "{all:?}");
        assert!(!all.iter().any(|p| p.contains("..") || p.contains("/mnt/")), "{all:?}");
        assert!(note.is_empty() || warnings.iter().any(|w| w.contains(note)), "{warnings:?}");
        assert_eq!(linux_hosts(&source), 1, "only the root has an etc/passwd");
    }
}

#[test]
fn two_volumes_on_one_mount_point_and_one_volume_twice_graft_the_first_only() {
    let fstab =
        "/dev/sda2 / ext4 d 0 1\n/dev/sda1 /data ext4 d 0 2\n/dev/sda4 /data ext4 d 0 2\n/dev/sda1 /again ext4 d 0 2\n";
    let (source, warnings) =
        fake_disk(&[(ROOT, root_files(fstab), None), (A, data_files(), None), (C, data_files(), None)]);
    let all = paths(&source);
    assert!(all.contains(&"p2/[root]/data/kernel") && !all.iter().any(|p| p.starts_with("p2/[root]/again")), "{all:?}");
    assert!(all.contains(&"p4/[root]/kernel"), "the second volume stays a host of its own: {all:?}");
    assert!(warnings.iter().any(|w| w.contains("2 mounts")), "{warnings:?}");
}

#[test]
fn two_roots_each_graft_their_own_and_never_each_other() {
    let second = vec![
        ("etc/passwd", "root:x:0:0::/root:/bin/sh\n"),
        ("etc/fstab", "/dev/sda1 / ext4 d 0 1\n/dev/sda2 /mnt/old ext4 d 0 2\n/dev/sda4 /boot ext4 d 0 2\n"),
    ];
    let first = root_files("/dev/sda2 / ext4 d 0 1\n/dev/sda4 /boot ext4 d 0 2\n/dev/sda1 /mnt/other ext4 d 0 2\n");
    let (source, _) = fake_disk(&[(ROOT, first, None), (A, second, None), (C, data_files(), None)]);
    let all = paths(&source);
    // The first root (p1, in volume order) takes the shared volume; neither root is a mount of the other.
    assert!(all.contains(&"p1/[root]/boot/kernel"), "{all:?}");
    assert!(!all.iter().any(|p| p.starts_with("p2/[root]/boot/") && p.ends_with("kernel")), "{all:?}");
    assert!(all.contains(&"p2/[root]/etc/passwd") && all.contains(&"p1/[root]/etc/passwd"));
    assert!(!all.iter().any(|p| p.contains("/mnt/old") || p.contains("/mnt/other")), "{all:?}");
    assert_eq!(linux_hosts(&source), 2);
}

#[test]
fn a_huge_fstab_is_read_only_in_part() {
    let fstab = "/dev/sda2 / ext4 d 0 1\n/dev/sda1 /boot ext4 d 0 2\n";
    // Claims 100 MB; the rest of it reads as lines that match nothing.
    let (source, warnings) = fake_disk(&[(ROOT, root_files(fstab), Some(100_000_000)), (A, data_files(), None)]);
    assert!(paths(&source).contains(&"p2/[root]/boot/kernel"));
    assert!(warnings.iter().any(|w| w.contains("only the first 1048576 bytes of etc/fstab were read")), "{warnings:?}");
}

#[test]
fn mutated_images_and_fstabs_never_panic() {
    // Flip bytes in the superblocks of a real RAID5 disk and of the graft disk's partition table
    // area; building the volumes must return, whatever the result.
    let dir = scratch("mutate");
    let path = disk(&dir, "raid/raid5-ls.img.zst", "disk.img");
    let data = fs::read(&path).unwrap();
    let parts = partitions::scan(&Bytes(&data));
    let reader: Shared = Arc::new(Mem(data.clone()));
    let mut done = 0;
    for part in parts.iter().filter(|p| p.unsupported == Some(partitions::MD_REASON)) {
        for i in (0..300usize).step_by(3) {
            for mask in [0x01u8, 0x80, 0xff] {
                let mut bad = data.clone();
                bad[part.start as usize + 4096 + i] ^= mask;
                let end = (part.start + part.len) as usize;
                md::repair_checksum(&mut bad[part.start as usize..end]);
                let r: Shared = Arc::new(Mem(bad));
                let parts = partitions::scan(&r);
                let _ = Source::from_image(Path::new("x.img"), r, &open_volumes).map(|s| s.entries().len());
                let _ = parts;
                done += 1;
            }
        }
    }
    assert!(done > 250);
    drop(reader);
    let _ = fs::remove_dir_all(dir);
}

/// Checks a real acquisition against a real mount, for the corpus (not run by default):
/// `NIXCAVATE_REAL_IMAGE=<first image> NIXCAVATE_REAL_SHA256=<sha256sum output made from the
/// mounted host, paths as ./etc/passwd> cargo test -p nixcavate-source --release real_acquisition
/// -- --ignored --nocapture`. Every listed file must read back with the same sha256.
#[test]
#[ignore = "needs a real disk image from the corpus"]
fn real_acquisition_matches_a_real_mount() {
    let (Some(image), Some(sums)) =
        (std::env::var_os("NIXCAVATE_REAL_IMAGE"), std::env::var_os("NIXCAVATE_REAL_SHA256"))
    else {
        panic!("set NIXCAVATE_REAL_IMAGE and NIXCAVATE_REAL_SHA256")
    };
    let source =
        Source::open(Path::new(&image), &|_| true, &std::env::temp_dir().join("nixcavate-real-scratch")).unwrap();
    for note in &source.warnings {
        println!("note: {note}");
    }
    let hosts = discover(&source, None);
    println!("hosts: {:?}", hosts.iter().map(|h| (&h.name, &h.root)).collect::<Vec<_>>());
    assert_eq!(hosts.len(), 1);
    let root = &hosts[0].root;
    let (mut checked, mut bad, mut missing) = (0, 0, 0);
    for line in fs::read_to_string(sums).unwrap().lines() {
        let Some((hash, path)) = line.split_once("  ") else { continue };
        match source.entry(&format!("{root}/{}", path.trim_start_matches("./"))) {
            None => {
                missing += 1;
                println!("missing {path}");
            }
            Some(entry) => {
                checked += 1;
                if sha(&source.read(entry).unwrap()) != hash {
                    bad += 1;
                    println!("differs {path}");
                }
            }
        }
    }
    println!("checked {checked} files: {bad} differ, {missing} are missing");
    assert!(checked > 0 && bad == 0 && missing == 0);
}
