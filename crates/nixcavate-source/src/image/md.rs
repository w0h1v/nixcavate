//! Linux software RAID (md): the arrays assembled from the member partitions of an image.
//!
//! Written from the kernel's `Documentation/admin-guide/md.rst`, `drivers/md/md_p.h` (the
//! on-disk superblocks), `raid0.c`, `raid5.c` (`raid5_compute_sector`) and `raid10.c`
//! (`__raid10_find_phys`). Two superblock formats are read: version 1.x (magic 0xa92b4efc at the
//! start for 1.1, at 4 KiB for 1.2, and 8 KiB from the end, 4 KiB aligned, for 1.0; fields little
//! endian) and the old 0.90 (the last 64 KiB aligned block minus 64 KiB; fields in the byte order
//! of the machine that wrote it, little endian here). Both are checked as the kernel checks them
//! (checksum, `super_offset`, device counts).
//!
//! Members are grouped by the array's set uuid and put in the order of their roles. Assembled
//! and read: linear, RAID0 (members of unequal size make zones, with either recorded layout),
//! RAID1 (the member with the most events), RAID10 in the near layout with two copies or more,
//! RAID4 and RAID5 (all four classic layouts and the two parity-on-one-disk ones; one missing
//! member is rebuilt by XOR) and RAID6 with every member present. An array being reshaped, with
//! too many members missing, or in a layout not listed is named in one note and left out.
//!
//! Nothing here trusts the disk: every size, count and offset is range checked, no allocation
//! is sized by evidence, and members are only ever read at bounded offsets.

use super::{Part, Shared};
use nixcavate_fs::{le32, le64, ReadAt, Slice};
use std::collections::{BTreeMap, HashSet};
use std::io;
use std::sync::Arc;

const SECTOR: u64 = 512;
const MAGIC: u32 = 0xa92b_4efc;
/// The most roles a version 1.x superblock can describe (`(4096 - 256) / 2`).
const MAX_DEVS_V1: u32 = 1920;
/// Disks a 0.90 superblock can describe.
const MAX_DEVS_V090: u32 = 27;
/// Arrays assembled from one image.
const MAX_ARRAYS: usize = 256;
/// Characters of a name kept.
const MAX_NAME: usize = 64;
/// Largest chunk accepted, in sectors (1 GiB).
const MAX_CHUNK: u64 = 2 << 20;

/// Version 1.x feature bits (`md_p.h`).
const FEATURE_RECOVERY_OFFSET: u32 = 2;
const FEATURE_RESHAPE_ACTIVE: u32 = 4;
const FEATURE_JOURNAL: u32 = 512;
const FEATURE_RAID0_LAYOUT: u32 = 4096;

/// What a member is in its array.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// Slot `n` of the array.
    Data(u32),
    Spare,
    Faulty,
    Journal,
}

/// The fields of a superblock that assembly needs.
#[derive(Debug, Clone)]
pub struct Super {
    /// `0.90` or `1.0`, `1.1`, `1.2`.
    pub version: &'static str,
    pub uuid: [u8; 16],
    pub name: String,
    /// -1 linear, 0, 1, 4, 5, 6, 10; others are not supported.
    pub level: i64,
    pub layout: u32,
    /// In sectors.
    pub chunk: u64,
    pub raid_disks: u32,
    /// Used size of each member, in sectors.
    pub dev_sectors: u64,
    /// Where the data starts on the member, in sectors.
    pub data_offset: u64,
    /// Sectors of data on this member.
    pub data_size: u64,
    pub events: u64,
    pub role: Role,
    /// The md minor recorded by 0.90 arrays.
    pub minor: Option<u32>,
    reshape: bool,
    recovering: bool,
    journal: bool,
    raid0_layout: bool,
}

/// A partition (or whole disk) with a RAID superblock.
pub struct Member {
    /// Names the member in notes: `p3`, or the file and partition of another image.
    pub label: String,
    pub part: Arc<Part>,
    pub sb: Super,
}

/// An assembled array, read like a partition.
pub struct Array {
    /// `md-<name or first 8 hex of the uuid>`, restricted to `[A-Za-z0-9_.+-]`.
    pub name: String,
    pub reader: Shared,
    pub len: u64,
    /// The set uuid as `mdadm` and udev print it: `xxxxxxxx:xxxxxxxx:xxxxxxxx:xxxxxxxx`.
    pub uuid: String,
    /// The array's name without the host part (`host:name`), or empty.
    pub set_name: String,
    pub minor: Option<u32>,
}

fn eof() -> io::Error {
    io::Error::new(io::ErrorKind::UnexpectedEof, "read past the end of the array")
}

fn read_vec(part: &Part, at: u64, len: u64) -> Option<Vec<u8>> {
    if at.checked_add(len)? > part.size() {
        return None;
    }
    let mut buf = vec![0u8; usize::try_from(len).ok()?];
    part.read_at(at, &mut buf).ok()?;
    Some(buf)
}

/// The text of a uuid the way `mdadm` prints it: each 4 bytes as a little endian number.
pub fn uuid_text(uuid: &[u8; 16]) -> String {
    let word = |i: usize| le32(uuid, i * 4);
    format!("{:08x}:{:08x}:{:08x}:{:08x}", word(0), word(1), word(2), word(3))
}

/// Characters outside `[A-Za-z0-9_.+-]` become `_`; at most `max` characters are kept.
pub fn clean(s: &str, max: usize) -> String {
    s.chars().take(max).map(|c| if c.is_ascii_alphanumeric() || "_.+-".contains(c) { c } else { '_' }).collect()
}

// Superblocks.

/// The superblock of `part`, whichever of the five places it is in.
pub fn read_super(part: &Part) -> Option<Super> {
    let sectors = part.size() / SECTOR;
    let at090 = (sectors & !127).checked_sub(128);
    let at10 = sectors.saturating_sub(16) & !7;
    at090
        .and_then(|at| parse_090(part, at))
        .or_else(|| parse_1(part, at10, "1.0"))
        .or_else(|| parse_1(part, 0, "1.1"))
        .or_else(|| parse_1(part, 8, "1.2"))
}

/// Sum of 32-bit words folded to 32 bits, as the kernel's `calc_sb_csum` and `calc_sb_1_csum`.
fn checksum(block: &[u8], skip_word: usize) -> u32 {
    let mut sum = 0u64;
    let mut words = block.chunks_exact(4);
    for (i, w) in words.by_ref().enumerate() {
        if i != skip_word {
            sum += u64::from(u32::from_le_bytes([w[0], w[1], w[2], w[3]]));
        }
    }
    if let [a, b] = words.remainder() {
        sum += u64::from(u16::from_le_bytes([*a, *b]));
    }
    ((sum & 0xffff_ffff) + (sum >> 32)) as u32
}

fn parse_090(part: &Part, at: u64) -> Option<Super> {
    let block = read_vec(part, at.checked_mul(SECTOR)?, 4096)?;
    // Magic, major version 0, and the checksum word at 152.
    if le32(&block, 0) != MAGIC || le32(&block, 4) != 0 || checksum(&block, 38) != le32(&block, 152) {
        return None;
    }
    let raid_disks = le32(&block, 40);
    let chunk_bytes = u64::from(le32(&block, 260));
    if raid_disks == 0 || raid_disks > MAX_DEVS_V090 || chunk_bytes % SECTOR != 0 || chunk_bytes / SECTOR > MAX_CHUNK {
        return None;
    }
    let mut uuid = [0u8; 16];
    for (i, from) in [20usize, 52, 56, 60].into_iter().enumerate() {
        uuid[i * 4..i * 4 + 4].copy_from_slice(&block[from..from + 4]);
    }
    // This device's own descriptor is the last 128 bytes: number, major, minor, raid_disk, state.
    let (slot, state) = (le32(&block, 3968 + 12), le32(&block, 3968 + 16));
    let role = if state & 1 != 0 {
        Role::Faulty
    } else if state & 4 != 0 && slot < raid_disks {
        Role::Data(slot)
    } else {
        Role::Spare
    };
    let dev_sectors = u64::from(le32(&block, 32)) * 2;
    Some(Super {
        version: "0.90",
        uuid,
        name: String::new(),
        level: i64::from(le32(&block, 28) as i32),
        layout: le32(&block, 256),
        chunk: chunk_bytes / SECTOR,
        raid_disks,
        dev_sectors,
        data_offset: 0,
        data_size: dev_sectors,
        events: le64(&block, 156),
        role,
        minor: Some(le32(&block, 44)),
        // Minor version 91 marks a reshape in progress.
        reshape: le32(&block, 8) >= 91,
        recovering: false,
        journal: false,
        raid0_layout: false,
    })
}

fn parse_1(part: &Part, at: u64, version: &'static str) -> Option<Super> {
    let block = read_vec(part, at.checked_mul(SECTOR)?, 4096)?;
    let max_dev = le32(&block, 220);
    // Magic, major version 1, the number of roles, and that the superblock is where it says.
    if le32(&block, 0) != MAGIC || le32(&block, 4) != 1 || max_dev > MAX_DEVS_V1 || le64(&block, 144) != at {
        return None;
    }
    let size = 256 + max_dev as usize * 2;
    let mut copy = block.get(..size)?.to_vec();
    copy[216..220].fill(0);
    if checksum(&copy, usize::MAX) != le32(&block, 216) {
        return None;
    }
    let raid_disks = le32(&block, 92);
    let chunk = u64::from(le32(&block, 88));
    if raid_disks == 0 || raid_disks > MAX_DEVS_V1 || chunk > MAX_CHUNK {
        return None;
    }
    let features = le32(&block, 8);
    let dev_number = le32(&block, 160);
    let role = match (dev_number < max_dev).then(|| block.get(256 + dev_number as usize * 2..)).flatten() {
        Some([lo, hi, ..]) => match u16::from_le_bytes([*lo, *hi]) {
            0xffff => Role::Spare,
            0xfffe => Role::Faulty,
            0xfffd => Role::Journal,
            n if u32::from(n) < raid_disks => Role::Data(u32::from(n)),
            _ => Role::Spare,
        },
        _ => Role::Spare,
    };
    let name_bytes = &block[32..64];
    let name_len = name_bytes.iter().position(|&b| b == 0).unwrap_or(name_bytes.len());
    Some(Super {
        version,
        uuid: block[16..32].try_into().ok()?,
        name: String::from_utf8_lossy(&name_bytes[..name_len]).into_owned(),
        level: i64::from(le32(&block, 72) as i32),
        layout: le32(&block, 76),
        chunk,
        raid_disks,
        dev_sectors: le64(&block, 80),
        data_offset: le64(&block, 128),
        data_size: le64(&block, 136),
        events: le64(&block, 200),
        role,
        minor: None,
        reshape: features & FEATURE_RESHAPE_ACTIVE != 0,
        recovering: features & FEATURE_RECOVERY_OFFSET != 0,
        journal: features & FEATURE_JOURNAL != 0,
        raid0_layout: features & FEATURE_RAID0_LAYOUT != 0,
    })
}

/// Recomputes the checksum of the superblock of `device` (a whole member image), for tests and
/// the fuzz target that change superblock fields.
#[doc(hidden)]
pub fn repair_checksum(device: &mut [u8]) {
    let sectors = device.len() as u64 / SECTOR;
    let at090 = (sectors & !127).checked_sub(128).map(|s| (s * SECTOR) as usize);
    let at10 = ((sectors.saturating_sub(16) & !7) * SECTOR) as usize;
    if let Some(at) = at090.filter(|&at| device.get(at..at + 4096).is_some_and(|b| le32(b, 0) == MAGIC)) {
        let sum = checksum(&device[at..at + 4096], 38);
        device[at + 152..at + 156].copy_from_slice(&sum.to_le_bytes());
    }
    for at in [at10, 0, 4096] {
        let Some(block) = device.get(at..at + 4096) else { continue };
        if le32(block, 0) != MAGIC || le32(block, 4) != 1 {
            continue;
        }
        let size = (256 + le32(block, 220) as usize * 2).min(4096);
        let mut copy = block[..size].to_vec();
        copy[216..220].fill(0);
        let sum = checksum(&copy, usize::MAX);
        device[at + 216..at + 220].copy_from_slice(&sum.to_le_bytes());
    }
}

// Assembly.

/// The arrays of `members` that lack a member some other image may hold: their set uuids.
/// RAID1 is complete with one member, so it never asks.
pub fn wanted(members: &[Member]) -> HashSet<[u8; 16]> {
    let mut slots: BTreeMap<[u8; 16], (i64, u32, HashSet<u32>)> = BTreeMap::new();
    for m in members {
        let entry = slots.entry(m.sb.uuid).or_insert((m.sb.level, m.sb.raid_disks, HashSet::new()));
        if let Role::Data(n) = m.sb.role {
            entry.2.insert(n);
        }
    }
    slots
        .into_iter()
        .filter(|(_, (level, disks, have))| *level != 1 && have.len() < *disks as usize)
        .map(|(u, _)| u)
        .collect()
}

/// Level name for notes.
fn level_name(level: i64) -> String {
    match level {
        -1 => "linear".into(),
        n @ (0 | 1 | 4 | 5 | 6 | 10) => format!("RAID{n}"),
        n => format!("level {n}"),
    }
}

/// One member at its place in the array: reads go `at` bytes into the member.
struct Dev {
    part: Arc<Part>,
    at: u64,
}

impl Dev {
    fn read(&self, offset: u64, buf: &mut [u8]) -> io::Result<()> {
        self.part.read_at(self.at.checked_add(offset).ok_or_else(eof)?, buf)
    }
}

fn dev(m: &Member) -> Dev {
    Dev { part: m.part.clone(), at: m.sb.data_offset * SECTOR }
}

/// Builds every array the members make. Notes say what was left out and why.
pub fn open(members: Vec<Member>) -> (Vec<Array>, Vec<String>) {
    let mut groups: BTreeMap<[u8; 16], Vec<Member>> = BTreeMap::new();
    for m in members {
        groups.entry(m.sb.uuid).or_default().push(m);
    }
    let (mut arrays, mut notes, mut names) = (Vec::new(), Vec::new(), HashSet::new());
    for (uuid, group) in groups.into_iter().take(MAX_ARRAYS) {
        let mut remarks = Vec::new();
        let head = group.iter().max_by_key(|m| m.sb.events).map(|m| m.sb.clone());
        let Some(head) = head else { continue };
        let set_name = head.name.rsplit(':').next().unwrap_or_default().to_string();
        let uuid_text = uuid_text(&uuid);
        let base =
            if head.name.is_empty() { uuid_text.replace(':', "").chars().take(8).collect() } else { head.name.clone() };
        let mut name = format!("md-{}", clean(&base, MAX_NAME));
        for n in 2.. {
            if names.insert(name.clone()) {
                break;
            }
            name = format!("md-{}_{n}", clean(&base, MAX_NAME));
        }
        let tag = format!(
            "software RAID {name} ({}, {} members, metadata {})",
            level_name(head.level),
            head.raid_disks,
            head.version
        );
        match build(group, &head, &mut remarks) {
            Ok((reader, len)) => {
                if !remarks.is_empty() {
                    notes.push(format!("{tag}: {}", remarks.join("; ")));
                }
                arrays.push(Array { name, reader, len, uuid: uuid_text, set_name, minor: head.minor });
            }
            Err(why) => {
                remarks.insert(0, why);
                notes.push(format!("{tag} not assembled: {}", remarks.join("; ")));
            }
        }
    }
    (arrays, notes)
}

/// The array of one group of members whose newest superblock is `head`.
fn build(group: Vec<Member>, head: &Super, remarks: &mut Vec<String>) -> Result<(Shared, u64), String> {
    if head.reshape {
        return Err("the array was being reshaped, so its data is laid out two ways".into());
    }
    let (level, n) = (head.level, head.raid_disks as usize);
    if !matches!(level, -1 | 0 | 1 | 4 | 5 | 6 | 10) {
        return Err(format!("{} is not supported", level_name(level)));
    }
    if head.journal && matches!(level, 4..=6) {
        remarks.push("a write journal is present and was not replayed".into());
    }
    // Members of this array as the newest superblock describes it, one per role.
    let mut slots: Vec<Option<Member>> = (0..n).map(|_| None).collect();
    for m in group {
        let fits = |s: &Super| {
            (s.level, s.raid_disks, s.chunk, s.layout) == (head.level, head.raid_disks, head.chunk, head.layout)
        };
        let Role::Data(role) = m.sb.role else { continue };
        if !fits(&m.sb) {
            remarks.push(format!("{} disagrees about the array's shape and was not used", m.label));
            continue;
        }
        let region = m.sb.data_offset.checked_add(m.sb.data_size).and_then(|s| s.checked_mul(SECTOR));
        if m.sb.data_size == 0 || region.is_none_or(|end| end > m.part.size()) {
            remarks.push(format!("{} is smaller than its superblock says and was not used", m.label));
            continue;
        }
        if m.sb.recovering {
            remarks.push(format!("{} was only partly rebuilt and was not used", m.label));
            continue;
        }
        let Some(slot) = slots.get_mut(role as usize) else { continue };
        match slot {
            Some(held) if held.sb.events >= m.sb.events => {
                remarks.push(format!("{} and {} both claim role {role}; {} was used", held.label, m.label, held.label));
            }
            Some(held) => {
                remarks.push(format!("{} and {} both claim role {role}; {} was used", held.label, m.label, m.label));
                *slot = Some(m);
            }
            None => *slot = Some(m),
        }
    }
    let newest = slots.iter().flatten().map(|m| m.sb.events).max().ok_or("no member holds data")?;
    // Redundant levels drop members that missed updates: their data may be stale.
    if matches!(level, 4 | 5 | 6 | 10) {
        for slot in &mut slots {
            if slot.as_ref().is_some_and(|m| m.sb.events < newest) {
                if let Some(old) = slot.take() {
                    remarks.push(format!(
                        "{} is out of date (events {} of {newest}) and was not used",
                        old.label, old.sb.events
                    ));
                }
            }
        }
    }
    let present = slots.iter().flatten().count();
    let missing = n - present;
    let labels =
        |slots: &[Option<Member>]| slots.iter().flatten().map(|m| m.label.clone()).collect::<Vec<_>>().join(", ");
    let per_dev = |slots: &[Option<Member>]| -> Result<u64, String> {
        let used = if head.dev_sectors == 0 { head.data_size } else { head.dev_sectors };
        // Every member must hold the used size.
        if slots.iter().flatten().any(|m| m.sb.data_size < used) {
            return Err("a member holds less data than the array's used size".into());
        }
        used.checked_mul(SECTOR).ok_or_else(|| "the used size overflows".to_string())
    };
    let round = |bytes: u64, chunk_bytes: u64| bytes / chunk_bytes * chunk_bytes;
    match level {
        1 => {
            let best = slots.iter().flatten().max_by_key(|m| m.sb.events).ok_or("no member holds data")?;
            if slots.iter().flatten().any(|m| m.sb.events != best.sb.events) {
                let list: Vec<String> =
                    slots.iter().flatten().map(|m| format!("{} has {} events", m.label, m.sb.events)).collect();
                remarks.push(format!("the members disagree ({}); read from {}", list.join(", "), best.label));
            }
            let len = per_dev(&slots)?;
            let reader: Shared = Arc::new(Slice { inner: best.part.clone(), start: best.sb.data_offset * SECTOR, len });
            Ok((reader, len))
        }
        -1 => {
            if missing > 0 {
                return Err(format!("{missing} of {n} members are not in the image"));
            }
            let chunk_bytes = head.chunk * SECTOR;
            let mut segments = Vec::new();
            let mut total = 0u64;
            for m in slots.iter().flatten() {
                let mut size = m.sb.data_size * SECTOR;
                if chunk_bytes > 0 {
                    size = round(size, chunk_bytes);
                }
                segments.push((total, dev(m)));
                total = total.checked_add(size).ok_or("the sizes overflow")?;
            }
            let ends: Vec<u64> = segments.iter().skip(1).map(|(start, _)| *start).chain([total]).collect();
            Ok((Arc::new(Linear { segments, ends, len: total }), total))
        }
        0 => {
            if missing > 0 {
                return Err(format!("{missing} of {n} members are not in the image"));
            }
            raid0(&slots, head).map(|r| {
                let len = r.len;
                (Arc::new(r) as Shared, len)
            })
        }
        4..=6 => {
            let max_missing = usize::from(level != 6);
            if missing > max_missing {
                let what = if level == 6 {
                    "RAID6 is read only with every member present"
                } else {
                    "RAID5 can lose one member"
                };
                return Err(format!(
                    "{missing} of {n} members are not in the image ({what}; found {})",
                    labels(&slots)
                ));
            }
            let chunk_bytes = head.chunk * SECTOR;
            if chunk_bytes == 0 {
                return Err("the chunk size is zero".into());
            }
            let parity = if level == 6 { 2 } else { 1 };
            if n <= parity || !layout_valid(level, head.layout) {
                return Err(format!("the layout {} with {n} members is not supported", head.layout));
            }
            let used = round(per_dev(&slots)?, chunk_bytes);
            let len = used.checked_mul((n - parity) as u64).filter(|&l| l > 0).ok_or("the array has no usable size")?;
            if missing == 1 {
                remarks.push("one member is missing; its data is rebuilt from parity".into());
            }
            let devs = slots.iter().map(|s| s.as_ref().map(dev)).collect();
            Ok((Arc::new(Parity { devs, level, layout: head.layout, chunk: chunk_bytes, len }), len))
        }
        10 => {
            let (near, far) = (head.layout & 255, head.layout >> 8 & 255);
            if far != 1 || head.layout >> 16 != 0 || near < 2 || near as usize > n {
                return Err(format!(
                    "the RAID10 layout (near {near}, far {far}, offset {}) is not supported; only near layouts with two copies or more",
                    head.layout >> 16 & 1
                ));
            }
            let chunk_bytes = head.chunk * SECTOR;
            if chunk_bytes == 0 {
                return Err("the chunk size is zero".into());
            }
            // Every chunk needs a copy on a member that is there.
            let near = near as usize;
            for k in 0..n {
                if (0..near).all(|j| slots[(k * near + j) % n].is_none()) {
                    return Err(format!(
                        "{missing} of {n} members are not in the image, and some data had all its copies there"
                    ));
                }
            }
            let chunks = per_dev(&slots)? / chunk_bytes;
            let len = (chunks * n as u64 / near as u64)
                .checked_mul(chunk_bytes)
                .filter(|&l| l > 0)
                .ok_or("the array has no usable size")?;
            if missing > 0 {
                remarks.push(format!("{missing} members are missing; their data is read from the copies"));
            }
            let devs = slots.iter().map(|s| s.as_ref().map(dev)).collect();
            Ok((Arc::new(Raid10 { devs, near, chunk: chunk_bytes, len }), len))
        }
        _ => Err(format!("{} is not supported", level_name(level))),
    }
}

/// Layouts of `raid5.c`: left/right, asymmetric/symmetric (0 to 3) and, for RAID5 and RAID4, the
/// parity-on-one-disk layouts used during conversions (4 and 5).
fn layout_valid(level: i64, layout: u32) -> bool {
    match level {
        4 => layout == 0 || layout == 4 || layout == 5,
        _ => layout <= 5,
    }
}

// Linear.

struct Linear {
    /// Start in the array of each member, and the member.
    segments: Vec<(u64, Dev)>,
    /// End in the array of each segment.
    ends: Vec<u64>,
    len: u64,
}

impl ReadAt for Linear {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<()> {
        let end = offset.checked_add(buf.len() as u64).filter(|&e| e <= self.len).ok_or_else(eof)?;
        let (mut pos, mut done) = (offset, 0usize);
        while pos < end {
            let at = self.ends.partition_point(|&e| e <= pos);
            let (start, dev) = self.segments.get(at).ok_or_else(eof)?;
            let piece = end.min(*self.ends.get(at).ok_or_else(eof)?) - pos;
            let n = usize::try_from(piece).map_err(|_| eof())?;
            dev.read(pos - start, buf.get_mut(done..done + n).ok_or_else(eof)?)?;
            pos += piece;
            done += n;
        }
        Ok(())
    }

    fn size(&self) -> u64 {
        self.len
    }
}

// RAID0.

struct Zone {
    start: u64,
    end: u64,
    /// Where the zone starts on each of its members.
    dev_start: u64,
    devs: Vec<usize>,
}

struct Raid0 {
    devs: Vec<Dev>,
    zones: Vec<Zone>,
    chunk: u64,
    /// The layout that picks a member from the chunk's number inside its zone (layout 2).
    in_zone: bool,
    len: u64,
}

fn raid0(slots: &[Option<Member>], head: &Super) -> Result<Raid0, String> {
    let chunk = head.chunk.checked_mul(SECTOR).filter(|&c| c > 0).ok_or("the chunk size is zero")?;
    // Each member's sectors rounded down to whole chunks, as `create_strip_zones` does.
    let sizes: Vec<u64> = slots.iter().flatten().map(|m| m.sb.data_size * SECTOR / chunk * chunk).collect();
    if sizes.contains(&0) {
        return Err("a member is smaller than one chunk".into());
    }
    let mut zones = Vec::new();
    let (mut cut, mut start) = (0u64, 0u64);
    loop {
        let devs: Vec<usize> = (0..sizes.len()).filter(|&i| sizes[i] > cut).collect();
        let Some(smallest) = devs.iter().map(|&i| sizes[i]).min() else { break };
        let end = (smallest - cut)
            .checked_mul(devs.len() as u64)
            .and_then(|z| start.checked_add(z))
            .ok_or("the sizes overflow")?;
        zones.push(Zone { start, end, dev_start: cut, devs });
        (cut, start) = (smallest, end);
    }
    let in_zone = match (zones.len(), head.raid0_layout, head.layout) {
        (1, _, _) => false,
        (_, true, 1) => false,
        (_, true, 2) => true,
        _ => return Err("members of unequal size need a recorded RAID0 layout, which this array does not have".into()),
    };
    Ok(Raid0 { devs: slots.iter().flatten().map(dev).collect(), zones, chunk, in_zone, len: start })
}

impl ReadAt for Raid0 {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<()> {
        let end = offset.checked_add(buf.len() as u64).filter(|&e| e <= self.len).ok_or_else(eof)?;
        let (mut pos, mut done) = (offset, 0usize);
        while pos < end {
            let zone = self.zones.get(self.zones.partition_point(|z| z.end <= pos)).ok_or_else(eof)?;
            let (rel, count) = (pos - zone.start, zone.devs.len() as u64);
            let in_chunk = pos % self.chunk;
            let piece = (self.chunk - in_chunk).min(end - pos);
            // The member comes from the chunk's number in the whole array (layout 1) or in the zone.
            let number = if self.in_zone { rel / self.chunk } else { pos / self.chunk };
            let member = zone.devs.get((number % count) as usize).and_then(|&i| self.devs.get(i)).ok_or_else(eof)?;
            let row = rel / self.chunk / count;
            let at = row
                .checked_mul(self.chunk)
                .and_then(|o| o.checked_add(zone.dev_start))
                .and_then(|o| o.checked_add(in_chunk))
                .ok_or_else(eof)?;
            let n = usize::try_from(piece).map_err(|_| eof())?;
            member.read(at, buf.get_mut(done..done + n).ok_or_else(eof)?)?;
            pos += piece;
            done += n;
        }
        Ok(())
    }

    fn size(&self) -> u64 {
        self.len
    }
}

// RAID4, RAID5 and RAID6.

struct Parity {
    /// By role; `None` for the one member that is not there.
    devs: Vec<Option<Dev>>,
    level: i64,
    layout: u32,
    /// Bytes.
    chunk: u64,
    len: u64,
}

impl Parity {
    /// The member holding data chunk `number`, and the row (stripe) it is in: `raid5_compute_sector`.
    fn place(&self, number: u64) -> (usize, u64) {
        let n = self.devs.len() as u64;
        let parity = if self.level == 6 { 2 } else { 1 };
        let data = n - parity;
        let (stripe, slot) = (number / data, number % data);
        let rotate = stripe % n;
        let member = if self.level == 6 {
            match self.layout {
                0 | 1 => {
                    let p = if self.layout == 0 { n - 1 - rotate } else { rotate };
                    if p == n - 1 {
                        slot + 1
                    } else if slot >= p {
                        slot + 2
                    } else {
                        slot
                    }
                }
                2 => (n - 1 - rotate + 2 + slot) % n,
                3 => (rotate + 2 + slot) % n,
                4 => slot + 2,
                _ => slot,
            }
        } else {
            match (self.level, self.layout) {
                (4, 4) | (5, 4) => slot + 1,
                (4, _) | (5, 5) => slot,
                (_, 0) => {
                    let p = n - 1 - rotate;
                    if slot >= p {
                        slot + 1
                    } else {
                        slot
                    }
                }
                (_, 1) => {
                    if slot >= rotate {
                        slot + 1
                    } else {
                        slot
                    }
                }
                (_, 2) => (n - 1 - rotate + 1 + slot) % n,
                _ => (rotate + 1 + slot) % n,
            }
        };
        (member as usize, stripe)
    }
}

impl ReadAt for Parity {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<()> {
        let end = offset.checked_add(buf.len() as u64).filter(|&e| e <= self.len).ok_or_else(eof)?;
        let (mut pos, mut done) = (offset, 0usize);
        while pos < end {
            let in_chunk = pos % self.chunk;
            let piece = (self.chunk - in_chunk).min(end - pos);
            let (member, stripe) = self.place(pos / self.chunk);
            let at = stripe.checked_mul(self.chunk).and_then(|o| o.checked_add(in_chunk)).ok_or_else(eof)?;
            let n = usize::try_from(piece).map_err(|_| eof())?;
            let out = buf.get_mut(done..done + n).ok_or_else(eof)?;
            match self.devs.get(member) {
                Some(Some(dev)) => dev.read(at, out)?,
                // The member is not there: the XOR of all the others (data and parity) is its chunk.
                _ => {
                    out.fill(0);
                    let mut other = vec![0u8; n];
                    for dev in self.devs.iter().flatten() {
                        dev.read(at, &mut other)?;
                        out.iter_mut().zip(&other).for_each(|(a, b)| *a ^= b);
                    }
                }
            }
            pos += piece;
            done += n;
        }
        Ok(())
    }

    fn size(&self) -> u64 {
        self.len
    }
}

// RAID10, near layout.

struct Raid10 {
    devs: Vec<Option<Dev>>,
    near: usize,
    chunk: u64,
    len: u64,
}

impl ReadAt for Raid10 {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<()> {
        let end = offset.checked_add(buf.len() as u64).filter(|&e| e <= self.len).ok_or_else(eof)?;
        let (mut pos, mut done) = (offset, 0usize);
        let n = self.devs.len() as u64;
        while pos < end {
            let in_chunk = pos % self.chunk;
            let piece = (self.chunk - in_chunk).min(end - pos);
            // `__raid10_find_phys`: the first copy is at chunk * near_copies, the rest on the next members.
            let first = (pos / self.chunk).checked_mul(self.near as u64).ok_or_else(eof)?;
            let (stripe, member) = (first / n, first % n);
            let copy = (0..self.near as u64)
                .filter_map(|j| {
                    let slot = member + j;
                    let dev = self.devs.get((slot % n) as usize)?.as_ref()?;
                    Some((dev, stripe + slot / n))
                })
                .next()
                .ok_or_else(|| io::Error::other("no member holds this part of the array"))?;
            let at = copy.1.checked_mul(self.chunk).and_then(|o| o.checked_add(in_chunk)).ok_or_else(eof)?;
            let len = usize::try_from(piece).map_err(|_| eof())?;
            copy.0.read(at, buf.get_mut(done..done + len).ok_or_else(eof)?)?;
            pos += piece;
            done += len;
        }
        Ok(())
    }

    fn size(&self) -> u64 {
        self.len
    }
}

#[cfg(test)]
mod tests {
    use super::super::Mem;
    use super::*;

    /// 4 KiB chunks and a data area that starts 8 KiB into each member.
    const CHUNK: u64 = 4096;
    const DATA: u64 = 8192;

    fn pattern(i: usize) -> u8 {
        (i.wrapping_mul(2_654_435_761) >> 11) as u8 ^ (i >> 9) as u8
    }

    /// What goes into a version 1.2 superblock.
    #[derive(Clone)]
    struct Spec {
        level: i32,
        layout: u32,
        chunk: u32,
        disks: u32,
        /// This member's slot (or 0xffff, 0xfffe).
        role: u16,
        events: u64,
        dev_sectors: u64,
        data_size: u64,
        features: u32,
        uuid: u8,
        name: &'static str,
    }

    fn spec(level: i32, layout: u32, disks: u32, role: u16, dev_bytes: u64) -> Spec {
        Spec {
            level,
            layout,
            chunk: (CHUNK / 512) as u32,
            disks,
            role,
            events: 7,
            dev_sectors: dev_bytes / 512,
            data_size: dev_bytes / 512,
            features: 0,
            uuid: 0xaa,
            name: "host:test",
        }
    }

    /// A member image: version 1.2 superblock at 4 KiB, `dev_bytes` of data from 8 KiB.
    fn member_image(s: &Spec, dev_bytes: u64) -> Vec<u8> {
        let mut img = vec![0u8; (DATA + dev_bytes) as usize + 8192];
        let sb = &mut img[4096..8192];
        sb[0..4].copy_from_slice(&MAGIC.to_le_bytes());
        sb[4..8].copy_from_slice(&1u32.to_le_bytes());
        sb[8..12].copy_from_slice(&s.features.to_le_bytes());
        sb[16..32].fill(s.uuid);
        sb[32..32 + s.name.len()].copy_from_slice(s.name.as_bytes());
        sb[72..76].copy_from_slice(&s.level.to_le_bytes());
        sb[76..80].copy_from_slice(&s.layout.to_le_bytes());
        sb[80..88].copy_from_slice(&s.dev_sectors.to_le_bytes());
        sb[88..92].copy_from_slice(&s.chunk.to_le_bytes());
        sb[92..96].copy_from_slice(&s.disks.to_le_bytes());
        sb[128..136].copy_from_slice(&(DATA / 512).to_le_bytes());
        sb[136..144].copy_from_slice(&s.data_size.to_le_bytes());
        sb[144..152].copy_from_slice(&8u64.to_le_bytes());
        sb[160..164].copy_from_slice(&0u32.to_le_bytes()); // dev_number: roles[0] is this member's
        sb[200..208].copy_from_slice(&s.events.to_le_bytes());
        sb[220..224].copy_from_slice(&1u32.to_le_bytes());
        sb[256..258].copy_from_slice(&s.role.to_le_bytes());
        repair_checksum(&mut img);
        img
    }

    fn part(img: Vec<u8>) -> Part {
        let len = img.len() as u64;
        let inner: Shared = Arc::new(Mem(img));
        Slice { inner, start: 0, len }
    }

    fn members(images: Vec<Vec<u8>>) -> Vec<Member> {
        images
            .into_iter()
            .enumerate()
            .filter(|(_, img)| !img.is_empty())
            .map(|(i, img)| {
                let part = part(img);
                let sb = read_super(&part).expect("a superblock");
                Member { label: format!("p{}", i + 1), part: Arc::new(part), sb }
            })
            .collect()
    }

    fn array_bytes(array: &Array) -> Vec<u8> {
        let mut buf = vec![0u8; array.len as usize];
        array.reader.read_at(0, &mut buf).unwrap();
        buf
    }

    /// The members of a RAID5 or RAID6 array of `rows` stripes, written stripe by stripe the way
    /// the layout describes, and the array they hold.
    fn parity_set(level: i32, layout: u32, n: usize, rows: usize) -> (Vec<Vec<u8>>, Vec<u8>) {
        let (c, parity) = (CHUNK as usize, if level == 6 { 2 } else { 1 });
        let data = n - parity;
        let dev_bytes = (rows * c) as u64;
        let mut images: Vec<Vec<u8>> =
            (0..n).map(|r| member_image(&spec(level, layout, n as u32, r as u16, dev_bytes), dev_bytes)).collect();
        let array: Vec<u8> = (0..rows * data * c).map(pattern).collect();
        for stripe in 0..rows {
            let rotate = stripe % n;
            // Where the parity (and for RAID6 the Q) chunk and the first data chunk are.
            let (p, q, first) = match (level, layout) {
                (5, 0 | 2) => (n - 1 - rotate, None, 0),
                (5, _) => (rotate, None, 0),
                (6, 0 | 2) => (n - 1 - rotate, Some((n - rotate) % n), 0),
                (_, _) => (rotate, Some((rotate + 1) % n), 0),
            };
            let _ = first;
            let symmetric = matches!(layout, 2 | 3);
            let mut xor = vec![0u8; c];
            for i in 0..data {
                let d = if symmetric {
                    (p + parity + i) % n
                } else {
                    // Asymmetric: data fills the disks in order, skipping the parity (and Q).
                    (0..n).filter(|&m| m != p && Some(m) != q).nth(i).unwrap()
                };
                let chunk = &array[(stripe * data + i) * c..(stripe * data + i + 1) * c];
                xor.iter_mut().zip(chunk).for_each(|(a, b)| *a ^= b);
                let at = DATA as usize + stripe * c;
                images[d][at..at + c].copy_from_slice(chunk);
            }
            let at = DATA as usize + stripe * c;
            images[p][at..at + c].copy_from_slice(&xor);
            if let Some(q) = q {
                images[q][at..at + c].fill(0x5a);
            }
        }
        for img in &mut images {
            repair_checksum(img);
        }
        (images, array)
    }

    fn assemble(images: Vec<Vec<u8>>) -> (Vec<Array>, Vec<String>) {
        open(members(images))
    }

    #[test]
    fn raid5_layouts_are_read_as_the_layout_describes_them() {
        for layout in 0..4 {
            let (images, expected) = parity_set(5, layout, 4, 9);
            let (arrays, notes) = assemble(images);
            assert!(notes.is_empty(), "{notes:?}");
            assert_eq!(arrays.len(), 1);
            assert_eq!(array_bytes(&arrays[0]), expected, "layout {layout}");
            assert_eq!(arrays[0].name, "md-host_test");
        }
    }

    #[test]
    fn raid5_with_one_member_missing_is_rebuilt_by_xor() {
        for layout in 0..4 {
            for missing in 0..4 {
                let (mut images, expected) = parity_set(5, layout, 4, 9);
                images[missing] = Vec::new();
                let (arrays, notes) = assemble(images);
                assert_eq!(array_bytes(&arrays[0]), expected, "layout {layout}, member {missing} missing");
                assert!(notes[0].contains("rebuilt from parity"), "{notes:?}");
            }
        }
    }

    #[test]
    fn raid5_with_two_missing_and_raid6_with_one_missing_are_one_note_each() {
        let (mut images, _) = parity_set(5, 2, 4, 4);
        images[0] = Vec::new();
        images[1] = Vec::new();
        let (arrays, notes) = assemble(images);
        assert!(arrays.is_empty());
        assert_eq!(notes.len(), 1);
        assert!(
            notes[0].contains("not assembled") && notes[0].contains("2 of 4 members are not in the image"),
            "{notes:?}"
        );

        let (mut images, _) = parity_set(6, 2, 5, 4);
        images[3] = Vec::new();
        let (arrays, notes) = assemble(images);
        assert!(arrays.is_empty());
        assert!(notes[0].contains("RAID6 is read only with every member present"), "{notes:?}");
    }

    #[test]
    fn raid6_data_is_read_in_all_four_layouts() {
        for layout in 0..4 {
            let (images, expected) = parity_set(6, layout, 5, 11);
            let (arrays, notes) = assemble(images);
            assert!(notes.is_empty(), "{notes:?}");
            assert_eq!(array_bytes(&arrays[0]), expected, "layout {layout}");
        }
    }

    #[test]
    fn raid0_alternates_chunks_and_raid1_picks_the_newest_member() {
        let c = CHUNK as usize;
        let dev = 6 * c;
        let array: Vec<u8> = (0..2 * dev).map(pattern).collect();
        let mut images: Vec<Vec<u8>> =
            (0..2).map(|r| member_image(&spec(0, 0, 2, r as u16, dev as u64), dev as u64)).collect();
        for k in 0..12 {
            let at = DATA as usize + (k / 2) * c;
            images[k % 2][at..at + c].copy_from_slice(&array[k * c..(k + 1) * c]);
        }
        let (arrays, notes) = assemble(images);
        assert!(notes.is_empty(), "{notes:?}");
        assert_eq!(array_bytes(&arrays[0]), array);

        // RAID1: the second member is newer and the first holds other bytes.
        let good: Vec<u8> = (0..dev).map(pattern).collect();
        let (mut a, mut b) = (
            member_image(&spec(1, 0, 2, 0, dev as u64), dev as u64),
            member_image(&Spec { events: 9, ..spec(1, 0, 2, 1, dev as u64) }, dev as u64),
        );
        a[DATA as usize..DATA as usize + dev].fill(0xee);
        b[DATA as usize..DATA as usize + dev].copy_from_slice(&good);
        let (arrays, notes) = assemble(vec![a, b]);
        assert_eq!(array_bytes(&arrays[0]), good);
        assert!(notes[0].contains("disagree") && notes[0].contains("read from p2"), "{notes:?}");
    }

    #[test]
    fn raid10_near_reads_any_copy() {
        let c = CHUNK as usize;
        for (n, near) in [(4usize, 2usize), (3, 2), (4, 4), (5, 3)] {
            let rows = 6;
            let chunks = rows * n / near;
            let array: Vec<u8> = (0..chunks * c).map(pattern).collect();
            let dev = (rows * c) as u64;
            let layout = near as u32 | 1 << 8;
            let mut images: Vec<Vec<u8>> =
                (0..n).map(|r| member_image(&spec(10, layout, n as u32, r as u16, dev), dev)).collect();
            for k in 0..chunks {
                for j in 0..near {
                    let slot = k * near + j;
                    let at = DATA as usize + (slot / n) * c;
                    images[slot % n][at..at + c].copy_from_slice(&array[k * c..(k + 1) * c]);
                }
            }
            let (arrays, notes) = assemble(images.clone());
            assert!(notes.is_empty(), "{notes:?}");
            assert_eq!(array_bytes(&arrays[0]), array, "n {n} near {near}");
            // Losing a member leaves a copy of everything when the copies are on other members.
            let mut degraded = images;
            degraded[0] = Vec::new();
            let (arrays, notes) = assemble(degraded);
            if near >= 2 && n > 2 && notes.iter().all(|x| !x.contains("not assembled")) {
                assert_eq!(array_bytes(&arrays[0]), array, "n {n} near {near} without member 0");
            }
        }
    }

    #[test]
    fn raid10_other_layouts_and_levels_are_named() {
        let dev = 4 * CHUNK;
        let make = |level: i32, layout: u32| {
            let images: Vec<Vec<u8>> = (0..2).map(|r| member_image(&spec(level, layout, 2, r, dev), dev)).collect();
            assemble(images)
        };
        let (arrays, notes) = make(10, 0x102 ^ 0x300); // far 2... near 2 far 3? layout bytes: near 2, far 1 is 0x102
        assert!(arrays.is_empty() && notes[0].contains("RAID10 layout"), "{notes:?}");
        let (arrays, notes) = make(10, 2 | 2 << 8);
        assert!(arrays.is_empty() && notes[0].contains("not supported"), "{notes:?}");
        let (arrays, notes) = make(-4, 0);
        assert!(arrays.is_empty() && notes[0].contains("level -4 is not supported"), "{notes:?}");
        let (arrays, notes) = make(1, 0);
        assert!(notes.is_empty() && arrays.len() == 1);
    }

    #[test]
    fn a_reshape_is_named_and_skipped() {
        let dev = 4 * CHUNK;
        let images: Vec<Vec<u8>> = (0..2)
            .map(|r| member_image(&Spec { features: FEATURE_RESHAPE_ACTIVE, ..spec(1, 0, 2, r, dev) }, dev))
            .collect();
        let (arrays, notes) = assemble(images);
        assert!(arrays.is_empty() && notes.len() == 1 && notes[0].contains("being reshaped"), "{notes:?}");
    }

    #[test]
    fn linear_arrays_concatenate_their_members() {
        let c = CHUNK as usize;
        let (small, large) = (3 * c, 5 * c);
        let array: Vec<u8> = (0..small + large).map(pattern).collect();
        let mut a = member_image(&spec(-1, 0, 2, 0, small as u64), small as u64);
        let mut b = member_image(&spec(-1, 0, 2, 1, large as u64), large as u64);
        a[DATA as usize..DATA as usize + small].copy_from_slice(&array[..small]);
        b[DATA as usize..DATA as usize + large].copy_from_slice(&array[small..]);
        let (arrays, notes) = assemble(vec![a.clone(), b.clone()]);
        assert!(notes.is_empty(), "{notes:?}");
        assert_eq!(array_bytes(&arrays[0]), array);
        let (arrays, notes) = assemble(vec![b]);
        assert!(arrays.is_empty() && notes[0].contains("1 of 2 members are not in the image"), "{notes:?}");
    }

    #[test]
    fn members_that_claim_one_slot_and_stale_members_are_remarked() {
        let (mut images, expected) = parity_set(5, 2, 3, 6);
        // A copy of member 1 claiming its slot again, with an older event count.
        let dev = 6 * CHUNK;
        let twin = member_image(&Spec { events: 3, ..spec(5, 2, 3, 1, dev) }, dev);
        images.push(twin);
        let (arrays, notes) = assemble(images);
        assert_eq!(array_bytes(&arrays[0]), expected);
        assert!(notes[0].contains("both claim role 1"), "{notes:?}");

        // A member that missed updates is dropped and rebuilt from the others.
        let (mut images, expected) = parity_set(5, 2, 3, 6);
        let stale = Spec { events: 2, ..spec(5, 2, 3, 2, dev) };
        let mut old = member_image(&stale, dev);
        old[DATA as usize..].fill(0x33);
        images[2] = old;
        let (arrays, notes) = assemble(images);
        assert_eq!(array_bytes(&arrays[0]), expected);
        assert!(notes[0].contains("out of date"), "{notes:?}");
    }

    #[test]
    fn two_arrays_make_two_arrays_and_names_are_unique_and_safe() {
        let dev = 4 * CHUNK;
        let one = |uuid: u8, name: &'static str| {
            (0..2).map(|r| member_image(&Spec { uuid, name, ..spec(1, 0, 2, r, dev) }, dev)).collect::<Vec<_>>()
        };
        let mut all = one(1, "h:data");
        all.extend(one(2, "h:data"));
        all.extend(one(3, "../../etc/x y"));
        let (arrays, _) = assemble(all);
        let names: Vec<&str> = arrays.iter().map(|a| a.name.as_str()).collect();
        assert_eq!(names, ["md-h_data", "md-h_data_2", "md-.._.._etc_x_y"]);
        assert_eq!(arrays[0].set_name, "data");
        assert_eq!(arrays[0].uuid, "01010101:01010101:01010101:01010101");
    }

    #[test]
    fn nonsense_in_a_superblock_is_never_trusted() {
        let dev = 4 * CHUNK;
        let base = |f: &dyn Fn(&mut Spec)| {
            let mut s = spec(5, 2, 3, 0, dev);
            f(&mut s);
            (0..3).map(|r| member_image(&Spec { role: r, ..s.clone() }, dev)).collect::<Vec<_>>()
        };
        // Zero or huge disk counts, chunk sizes and sizes: no superblock or no array, never a panic.
        for images in [
            base(&|s| s.disks = 0),
            base(&|s| s.disks = 100_000),
            base(&|s| s.chunk = 0),
            base(&|s| s.chunk = u32::MAX),
            base(&|s| s.dev_sectors = u64::MAX),
            base(&|s| s.data_size = u64::MAX),
            base(&|s| s.data_size = 0),
            base(&|s| s.layout = 99),
            base(&|s| s.level = i32::MIN),
            base(&|s| s.role = 0xfffd),
        ] {
            let (arrays, _) = assemble_lenient(images);
            for array in arrays {
                let mut buf = vec![0u8; 8192];
                let _ = array.reader.read_at(0, &mut buf);
                let _ = array.reader.read_at(array.len.saturating_sub(10), &mut buf);
                let _ = array.reader.read_at(u64::MAX - 3, &mut buf[..2]);
            }
        }
    }

    /// Like [`assemble`], but members whose superblock does not parse are left out.
    fn assemble_lenient(images: Vec<Vec<u8>>) -> (Vec<Array>, Vec<String>) {
        let members = images
            .into_iter()
            .enumerate()
            .filter_map(|(i, img)| {
                let part = part(img);
                let sb = read_super(&part)?;
                Some(Member { label: format!("p{i}"), part: Arc::new(part), sb })
            })
            .collect();
        open(members)
    }

    #[test]
    fn an_old_090_superblock_and_the_end_positions_are_found() {
        // A 0.90 superblock in the last 64 KiB aligned block minus 64 KiB of a 1 MiB device.
        let mut img = vec![0u8; 1 << 20];
        let at = (((1 << 20) / 512) & !127usize) * 512 - 65536;
        let sb = &mut img[at..at + 4096];
        sb[0..4].copy_from_slice(&MAGIC.to_le_bytes());
        sb[28..32].copy_from_slice(&1u32.to_le_bytes()); // level 1
        sb[32..36].copy_from_slice(&512u32.to_le_bytes()); // size, KiB
        sb[40..44].copy_from_slice(&2u32.to_le_bytes());
        sb[20..24].copy_from_slice(&0x1122_3344u32.to_le_bytes());
        sb[156..164].copy_from_slice(&42u64.to_le_bytes());
        sb[3968 + 12..3968 + 16].copy_from_slice(&1u32.to_le_bytes()); // raid_disk 1
        sb[3968 + 16..3968 + 20].copy_from_slice(&6u32.to_le_bytes()); // active, sync
        let sum = checksum(sb, 38);
        sb[152..156].copy_from_slice(&sum.to_le_bytes());
        let found = read_super(&part(img.clone())).unwrap();
        assert_eq!((found.version, found.level, found.raid_disks, found.events), ("0.90", 1, 2, 42));
        assert_eq!((found.role, found.dev_sectors, found.data_offset), (Role::Data(1), 1024, 0));
        assert!(uuid_text(&found.uuid).starts_with("11223344:"));
        // A flipped bit anywhere in the block breaks the checksum.
        for bit in [0usize, 100, 2000, 4095] {
            let mut bad = img.clone();
            bad[at + bit] ^= 0x10;
            assert!(read_super(&part(bad)).is_none(), "byte {bit}");
        }
    }

    #[test]
    fn mutated_members_never_panic_or_hang() {
        let (images, _) = parity_set(5, 2, 3, 4);
        for (m, base) in images.iter().enumerate() {
            for i in (4096..4096 + 300).chain(8100..8192) {
                for mask in [0x01u8, 0x80, 0xff, 0x10] {
                    for repair in [false, true] {
                        let mut all = images.clone();
                        all[m][i] ^= mask;
                        if repair {
                            repair_checksum(&mut all[m]);
                        }
                        let (arrays, _) = assemble_lenient(all);
                        for array in arrays {
                            let mut buf = vec![0u8; 5000];
                            let _ = array.reader.read_at(0, &mut buf);
                            let _ = array.reader.read_at(array.len.saturating_sub(2500), &mut buf[..2500]);
                        }
                    }
                }
            }
            for len in [0, 1, 4095, 4096, 8191, 8192, base.len() / 2, base.len() - 1] {
                let mut all = images.clone();
                all[m].truncate(len);
                let (arrays, _) = assemble_lenient(all);
                for array in arrays {
                    let mut buf = vec![0u8; 5000];
                    let _ = array.reader.read_at(array.len.saturating_sub(5000), &mut buf);
                }
            }
        }
    }
}
