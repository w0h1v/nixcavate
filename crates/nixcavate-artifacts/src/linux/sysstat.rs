//! sysstat's binary activity files: `var/log/sysstat/saDD` and `var/log/sa/saDD` (also `saYYYYMMDD`
//! and their `.xz` rotations), written by `sadc(8)` and read by `sar` and `sadf`.
//!
//! Only the 12.x data file format (`format_magic` 0x2175: sysstat 12.5 to at least 12.7) from a
//! 64-bit little-endian machine is read, because only that was validated against `sadf -j` of the
//! same file. Any other file is skipped with `unsupported sysstat file version`. Within a file,
//! an activity whose layout differs from the one validated is skipped and named in one warning.
//! The layout follows the structures documented in sysstat's `sa.h` and `rd_stats.h`; the file
//! describes its own activities (id, layout version, item size and count), which are all
//! checked before use.
//!
//! One row per measurement: CPU (`all` and each CPU), memory and swap, load and run queue,
//! process creation and context switches, each network interface, each block device. Rates and
//! percentages are what `sar` computes from two consecutive samples, so the first sample after a
//! start has none. Disks have only their device numbers (`major:minor`): `sadf` resolves names
//! from the running system, which a file does not carry. Timeline events: only the restart records
//! sadc writes when it starts (each new file, and a reboot).

use crate::text::{decompressed, lossy};
use crate::{Artifact, Category, Input, LINUX};
use nixcavate_core::{Basis, Error, Event, Loc, Precision, Record, Result, Sink, Timestamp};
use serde::Serialize;

pub const ARTIFACT: Artifact = Artifact::new(
    "sysstat",
    "sysstat system activity history (CPU, memory, load, network, disk per interval)",
    Category::Activity,
    LINUX,
    &[
        "var/log/sysstat/sa??",
        "var/log/sysstat/sa????????",
        "var/log/sysstat/sa??.*",
        "var/log/sysstat/sa????????.*",
        "var/log/sa/sa??",
        "var/log/sa/sa????????",
        "var/log/sa/sa??.*",
        "var/log/sa/sa????????.*",
    ],
    parse,
);

const SYSSTAT_MAGIC: u16 = 0xd596;
const FORMAT_MAGIC: u16 = 0x2175;
const MAGIC_SIZE: usize = 76;
const HEADER_SIZE: usize = 336;
const ACTIVITY_SIZE: usize = 36;
const RECORD_HEADER_SIZE: usize = 24;
const MAX_ACTIVITIES: usize = 64;
const MAX_ITEMS: i64 = 65_536;
/// More items of one activity in one record than any machine has (sysstat's own limits are
/// lower): the activity is skipped, so a damaged count cannot make a record allocate gigabytes.
const MAX_ROWS: i64 = 16_384;

const R_STATS: u8 = 1;
const R_RESTART: u8 = 2;
const R_LAST_STATS: u8 = 3;
const R_COMMENT: u8 = 4;
const R_EXTRA_MAX: u8 = 15;

/// An activity this parser understands: its id, layout version and the size of one item.
struct Known {
    id: u32,
    magic: u32,
    size: usize,
}

const CPU: Known = Known { id: 1, magic: 0x8b, size: 80 };
const PCSW: Known = Known { id: 2, magic: 0x8b, size: 16 };
const MEMORY: Known = Known { id: 7, magic: 0x8b, size: 136 };
const QUEUE: Known = Known { id: 9, magic: 0x8c, size: 40 };
const DISK: Known = Known { id: 11, magic: 0x8c, size: 80 };
const NET_DEV: Known = Known { id: 12, magic: 0x8d, size: 80 };

#[derive(Serialize)]
struct Row {
    time: Option<Timestamp>,
    /// `cpu`, `memory`, `load`, `process`, `network`, `disk`, `restart` or `comment`.
    metric: &'static str,
    /// The CPU number or `all`, the interface name, `major:minor` of a disk, or empty.
    item: String,
    /// Seconds since the previous sample; None for the first one after a start.
    interval_seconds: Option<f64>,
    cpu_user_pct: Option<f64>,
    cpu_nice_pct: Option<f64>,
    cpu_system_pct: Option<f64>,
    cpu_iowait_pct: Option<f64>,
    cpu_steal_pct: Option<f64>,
    cpu_idle_pct: Option<f64>,
    mem_total_kib: Option<u64>,
    mem_free_kib: Option<u64>,
    mem_available_kib: Option<u64>,
    mem_buffers_kib: Option<u64>,
    mem_cached_kib: Option<u64>,
    mem_committed_kib: Option<u64>,
    mem_active_kib: Option<u64>,
    mem_inactive_kib: Option<u64>,
    mem_dirty_kib: Option<u64>,
    mem_anon_kib: Option<u64>,
    mem_slab_kib: Option<u64>,
    swap_total_kib: Option<u64>,
    swap_free_kib: Option<u64>,
    run_queue: Option<u64>,
    tasks: Option<u64>,
    blocked: Option<u64>,
    load_1: Option<f64>,
    load_5: Option<f64>,
    load_15: Option<f64>,
    forks_per_s: Option<f64>,
    context_switches_per_s: Option<f64>,
    rx_packets_per_s: Option<f64>,
    tx_packets_per_s: Option<f64>,
    rx_kib_per_s: Option<f64>,
    tx_kib_per_s: Option<f64>,
    disk_tps: Option<f64>,
    disk_read_kib_per_s: Option<f64>,
    disk_write_kib_per_s: Option<f64>,
    disk_util_pct: Option<f64>,
    /// The comment text of a `comment` row, or what a `restart` row says.
    note: String,
}

impl Row {
    fn new(time: Option<Timestamp>, metric: &'static str, item: String, interval: Option<f64>) -> Self {
        Row {
            time,
            metric,
            item,
            interval_seconds: interval,
            cpu_user_pct: None,
            cpu_nice_pct: None,
            cpu_system_pct: None,
            cpu_iowait_pct: None,
            cpu_steal_pct: None,
            cpu_idle_pct: None,
            mem_total_kib: None,
            mem_free_kib: None,
            mem_available_kib: None,
            mem_buffers_kib: None,
            mem_cached_kib: None,
            mem_committed_kib: None,
            mem_active_kib: None,
            mem_inactive_kib: None,
            mem_dirty_kib: None,
            mem_anon_kib: None,
            mem_slab_kib: None,
            swap_total_kib: None,
            swap_free_kib: None,
            run_queue: None,
            tasks: None,
            blocked: None,
            load_1: None,
            load_5: None,
            load_15: None,
            forks_per_s: None,
            context_switches_per_s: None,
            rx_packets_per_s: None,
            tx_packets_per_s: None,
            rx_kib_per_s: None,
            tx_kib_per_s: None,
            disk_tps: None,
            disk_read_kib_per_s: None,
            disk_write_kib_per_s: None,
            disk_util_pct: None,
            note: String::new(),
        }
    }
}

impl Record for Row {
    fn events(&self) -> impl Iterator<Item = Event<'_>> {
        let restart = (self.metric == "restart").then_some(()).and(self.time);
        restart
            .map(|ts| Event::new(ts, "activity_restart", format!("sysstat collection (re)started: {}", self.note)))
            .into_iter()
    }
}

// ---- reading the file ----

fn u32_at(data: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(data.get(at..at.checked_add(4)?)?.try_into().ok()?))
}

fn u64_at(data: &[u8], at: usize) -> Option<u64> {
    Some(u64::from_le_bytes(data.get(at..at.checked_add(8)?)?.try_into().ok()?))
}

fn i32_at(data: &[u8], at: usize) -> Option<i32> {
    u32_at(data, at).map(|v| v as i32)
}

/// One activity as the file describes it.
struct Activity {
    id: u32,
    magic: u32,
    nr: i64,
    nr2: i64,
    has_nr: bool,
    size: i64,
}

#[derive(Clone, Default)]
struct Net {
    name: String,
    rx_packets: u64,
    tx_packets: u64,
    rx_bytes: u64,
    tx_bytes: u64,
    rx_compressed: u64,
    tx_compressed: u64,
    multicast: u64,
}

impl Net {
    /// The counters `sar` compares with the previous sample. If any went backwards and none of
    /// the overflow rules applies, the interface was unregistered and registered again, and
    /// the previous counters are taken as zero (as for an interface that is new).
    fn reference(&self, prev: Option<&Net>) -> Net {
        let zero = Net { name: self.name.clone(), ..Net::default() };
        let Some(p) = prev else { return zero };
        let decreased = self.rx_packets < p.rx_packets
            || self.tx_packets < p.tx_packets
            || self.rx_bytes < p.rx_bytes
            || self.tx_bytes < p.tx_bytes
            || self.rx_compressed < p.rx_compressed
            || self.tx_compressed < p.tx_compressed
            || self.multicast < p.multicast;
        if !decreased {
            return p.clone();
        }
        const HALF: u64 = u64::MAX >> 1;
        let overflow = (self.rx_bytes < p.rx_bytes && self.rx_packets > p.rx_packets && p.rx_bytes > HALF)
            || (self.tx_bytes < p.tx_bytes && self.tx_packets > p.tx_packets && p.tx_bytes > HALF)
            || (self.rx_packets < p.rx_packets && self.rx_bytes > p.rx_bytes && p.rx_packets > HALF)
            || (self.tx_packets < p.tx_packets && self.tx_bytes > p.tx_bytes && p.tx_packets > HALF);
        if overflow {
            p.clone()
        } else {
            zero
        }
    }
}

#[derive(Clone, Default)]
struct Disk {
    major: u32,
    minor: u32,
    nr_ios: u64,
    rd_sect: u64,
    wr_sect: u64,
    dc_sect: u64,
    tot_ticks: u32,
}

impl Disk {
    /// As for networks: when the I/O count and every non-zero sector counter went backwards the
    /// device was replaced, and the previous counters are zero; a single wrapped counter is not.
    fn reference(&self, prev: Option<&Disk>) -> Disk {
        let zero = Disk { major: self.major, minor: self.minor, ..Disk::default() };
        let Some(p) = prev else { return zero };
        let reset = self.nr_ios < p.nr_ios
            && (p.rd_sect == 0 || self.rd_sect < p.rd_sect)
            && (p.wr_sect == 0 || self.wr_sect < p.wr_sect)
            && (p.dc_sect == 0 || self.dc_sect < p.dc_sect);
        if reset {
            zero
        } else {
            p.clone()
        }
    }
}

/// What rates are computed from: the previous statistics sample.
#[derive(Default)]
struct Snapshot {
    uptime_cs: u64,
    cpu: Vec<[u64; 10]>,
    pcsw: Option<(u64, u64)>,
    net: Vec<Net>,
    disk: Vec<Disk>,
}

/// `sar`'s `S_VALUE`: the difference per second, computed in unsigned arithmetic like sar does
/// (a counter that went backwards wraps; the callers have already handled resets).
fn rate(prev: u64, curr: u64, seconds: f64) -> f64 {
    if seconds <= 0.0 {
        0.0
    } else {
        curr.wrapping_sub(prev) as f64 / seconds
    }
}

fn round(value: f64, places: i32) -> f64 {
    let scale = 10f64.powi(places);
    (value * scale).round() / scale
}

/// `sar`'s `ll_sp_value`: the share of `total` jiffies, 0 when a counter went backwards.
fn percent(prev: u64, curr: u64, total: u64) -> f64 {
    if curr < prev {
        0.0
    } else {
        round((curr - prev) as f64 / total.max(1) as f64 * 100.0, 4)
    }
}

/// The jiffies one CPU accounted for between two samples (guest time is already inside user
/// and nice). Like `sar`, this also repairs the previous sample when iowait or idle went
/// backwards, as they do when a CPU comes back online.
fn per_cpu_interval(curr: &[u64; 10], prev: &mut [u64; 10]) -> u64 {
    // Indices: 0 user, 1 nice, 2 sys, 3 idle, 4 iowait, 5 steal, 6 hardirq, 7 softirq, 8 guest, 9 guest nice.
    let mut shift = 0u64;
    if curr[0].wrapping_sub(curr[8]) < prev[0].wrapping_sub(prev[8]) {
        shift = shift.wrapping_add(prev[0].wrapping_sub(prev[8]).wrapping_sub(curr[0].wrapping_sub(curr[8])));
    }
    if curr[1].wrapping_sub(curr[9]) < prev[1].wrapping_sub(prev[9]) {
        shift = shift.wrapping_add(prev[1].wrapping_sub(prev[9]).wrapping_sub(curr[1].wrapping_sub(curr[9])));
    }
    const NEAR_MAX: u64 = u64::MAX - 0x7ffff;
    if curr[4] < prev[4] && prev[4] < NEAR_MAX {
        prev[4] = if curr[3] > prev[3] || prev[3] >= NEAR_MAX { curr[4] } else { 0 };
    }
    if curr[3] < prev[3] && prev[3] < NEAR_MAX {
        prev[3] = 0;
    }
    let sum = |c: &[u64; 10]| [0, 1, 2, 4, 3, 5, 6, 7].iter().fold(0u64, |acc, &i| acc.wrapping_add(c[i]));
    sum(curr).wrapping_sub(sum(prev)).wrapping_add(shift)
}

/// One CPU's row (or `all`) as `sar -u` computes it: user and nice as counted (guest included),
/// system as system plus IRQ time.
fn cpu_row(
    time: Option<Timestamp>,
    item: String,
    interval: f64,
    prev: &[u64; 10],
    curr: &[u64; 10],
    total: u64,
) -> Row {
    let mut row = Row::new(time, "cpu", item, Some(interval));
    if total == 0 {
        // A tickless CPU: sar shows it idle.
        (row.cpu_user_pct, row.cpu_nice_pct, row.cpu_system_pct) = (Some(0.0), Some(0.0), Some(0.0));
        (row.cpu_iowait_pct, row.cpu_steal_pct, row.cpu_idle_pct) = (Some(0.0), Some(0.0), Some(100.0));
        return row;
    }
    let system = |c: &[u64; 10]| c[2].wrapping_add(c[6]).wrapping_add(c[7]);
    row.cpu_user_pct = Some(percent(prev[0], curr[0], total));
    row.cpu_nice_pct = Some(percent(prev[1], curr[1], total));
    row.cpu_system_pct = Some(percent(system(prev), system(curr), total));
    row.cpu_iowait_pct = Some(percent(prev[4], curr[4], total));
    row.cpu_steal_pct = Some(percent(prev[5], curr[5], total));
    row.cpu_idle_pct = Some(percent(prev[3], curr[3], total));
    row
}

/// The rows for CPU `all` and every CPU. On a machine with several CPUs `all` is the sum of
/// the individual CPUs, and a CPU that is offline or has just appeared is left out.
fn cpu_rows(time: Option<Timestamp>, interval: f64, prev: &[[u64; 10]], curr: &[[u64; 10]]) -> Vec<Row> {
    let mut rows = Vec::new();
    let pairs = curr.len().min(prev.len());
    if pairs == 0 {
        return rows;
    }
    if pairs == 1 {
        let mut p = prev[0];
        let total = per_cpu_interval(&curr[0], &mut p);
        rows.push(cpu_row(time, "all".to_string(), interval, &p, &curr[0], total.max(1)));
        return rows;
    }
    let mut hidden = vec![false; pairs];
    let (mut all_prev, mut all_curr, mut all_total) = ([0u64; 10], [0u64; 10], 0u64);
    let mut adjusted = prev[..pairs].to_vec();
    for i in 1..pairs {
        let tot = |c: &[u64; 10]| [0, 1, 2, 3, 4, 5, 6, 7].iter().fold(0u64, |acc, &k| acc.wrapping_add(c[k]));
        let mut current = curr[i];
        if tot(&current) == 0 {
            // Offline: its previous values stand in for the current ones.
            hidden[i] = true;
            current = adjusted[i];
        }
        if tot(&adjusted[i]) == 0 {
            hidden[i] = true;
            continue;
        }
        all_total = all_total.wrapping_add(per_cpu_interval(&current, &mut adjusted[i]));
        for k in 0..10 {
            all_prev[k] = all_prev[k].wrapping_add(adjusted[i][k]);
            all_curr[k] = all_curr[k].wrapping_add(current[k]);
        }
    }
    rows.push(cpu_row(time, "all".to_string(), interval, &all_prev, &all_curr, all_total.max(1)));
    for i in 1..pairs {
        if hidden[i] {
            continue;
        }
        let mut p = prev[i];
        let total = per_cpu_interval(&curr[i], &mut p);
        rows.push(cpu_row(time, (i - 1).to_string(), interval, &p, &curr[i], total));
    }
    rows
}

fn parse(input: &Input, sink: &mut Sink) -> Result<()> {
    let data = decompressed(input.data)?;
    if data.is_empty() {
        return Err(Error::skipped("empty file"));
    }
    let magic = data.get(..2).map(|b| u16::from_le_bytes([b[0], b[1]]));
    let swapped = magic.map(|m| m.swap_bytes());
    if magic != Some(SYSSTAT_MAGIC) && swapped != Some(SYSSTAT_MAGIC) {
        return Err(Error::format("not a sysstat data file"));
    }
    let format = data.get(2..4).map(|b| u16::from_le_bytes([b[0], b[1]])).unwrap_or(0);
    let version = match data.get(4..8) {
        Some(v) => format!("{}.{}.{}", v[0], v[1], v[2]),
        None => String::new(),
    };
    if magic != Some(SYSSTAT_MAGIC) {
        return Err(Error::skipped(format!(
            "unsupported sysstat file version {version}: big-endian file (format {format:#06x})"
        )));
    }
    if format != FORMAT_MAGIC {
        return Err(Error::skipped(format!("unsupported sysstat file version {version} (data file format {format:#06x}; only {FORMAT_MAGIC:#06x}, sysstat 12.5 and later, is read)")));
    }
    let bad = |why: &str| Error::format(format!("sysstat file header: {why}"));
    if u32_at(&data, 8) != Some(HEADER_SIZE as u32) {
        return Err(Error::skipped(format!(
            "unsupported sysstat file version {version}: header size {:?}",
            u32_at(&data, 8)
        )));
    }
    let header = data.get(MAGIC_SIZE..MAGIC_SIZE + HEADER_SIZE).ok_or_else(|| bad("truncated"))?;
    let (hz, act_nr) = (u64_at(header, 8).unwrap_or(0), u32_at(header, 20).unwrap_or(0) as usize);
    let (act_size, rec_size) = (u32_at(header, 52).unwrap_or(0) as usize, u32_at(header, 56).unwrap_or(0) as usize);
    if header.get(66).copied() != Some(8) {
        return Err(Error::skipped(format!("unsupported sysstat file version {version}: not from a 64-bit machine")));
    }
    if act_size != ACTIVITY_SIZE || rec_size != RECORD_HEADER_SIZE || act_nr == 0 || act_nr > MAX_ACTIVITIES || hz == 0
    {
        return Err(Error::skipped(format!(
            "unsupported sysstat file version {version}: record or activity layout differs"
        )));
    }
    let nodename =
        lossy(header.get(132..197).map(|n| &n[..n.iter().position(|&b| b == 0).unwrap_or(n.len())]).unwrap_or(&[]))
            .into_owned();
    let mut activities = Vec::with_capacity(act_nr);
    let mut at = MAGIC_SIZE + HEADER_SIZE;
    for _ in 0..act_nr {
        let entry = data.get(at..at + ACTIVITY_SIZE).ok_or_else(|| bad("activity list truncated"))?;
        activities.push(Activity {
            id: u32_at(entry, 0).unwrap_or(0),
            magic: u32_at(entry, 4).unwrap_or(0),
            nr: i64::from(i32_at(entry, 8).unwrap_or(0)),
            nr2: i64::from(i32_at(entry, 12).unwrap_or(0)),
            has_nr: i32_at(entry, 16).unwrap_or(0) != 0,
            size: i64::from(i32_at(entry, 20).unwrap_or(0)),
        });
        at += ACTIVITY_SIZE;
    }
    // Only validated layouts are decoded; the others are skipped by their stated size.
    let known = [&CPU, &PCSW, &MEMORY, &QUEUE, &DISK, &NET_DEV];
    let mut unsupported: Vec<u32> = Vec::new();
    for a in &activities {
        if let Some(k) = known.iter().find(|k| k.id == a.id) {
            if a.magic != k.magic || a.size != k.size as i64 {
                unsupported.push(a.id);
            }
        }
    }
    unsupported.sort_unstable();
    unsupported.dedup();
    if !unsupported.is_empty() {
        sink.warn(format!("activities {unsupported:?} have a layout version that was not validated: not read"));
    }

    let mut previous: Option<Snapshot> = None;
    let mut warned_many = false;
    let mut records = 0usize;
    while at < data.len() {
        let record_at = at;
        let Some(head) = data.get(at..at + RECORD_HEADER_SIZE) else {
            sink.warn(format!("{} trailing bytes after the last whole record ignored", data.len() - at));
            break;
        };
        let (uptime_cs, ust_time) = (u64_at(head, 0).unwrap_or(0), u64_at(head, 8).unwrap_or(0));
        let (extra_next, kind, hour, minute, second) =
            (u32_at(head, 16).unwrap_or(0), head[20], head[21], head[22], head[23]);
        if kind == 0 || kind > R_EXTRA_MAX || hour > 23 || minute > 59 || second > 60 {
            sink.warn(format!(
                "damaged record at offset {record_at}: the {} bytes after it are not read",
                data.len() - record_at
            ));
            break;
        }
        at += RECORD_HEADER_SIZE;
        let time =
            i64::try_from(ust_time).ok().and_then(|s| Timestamp::checked(s, 0, Precision::Seconds, Basis::Recorded));
        let skip_extra = |at: &mut usize| -> bool {
            let mut guard = 0;
            loop {
                let (Some(nr), Some(size), Some(next)) =
                    (u32_at(&data, *at), u32_at(&data, *at + 4), u32_at(&data, *at + 8))
                else {
                    return false;
                };
                if nr > 8192 || size > 1024 || guard > 1024 {
                    return false;
                }
                guard += 1;
                *at += 24 + nr as usize * size as usize;
                if next == 0 {
                    return *at <= data.len();
                }
            }
        };
        match kind {
            R_RESTART => {
                let cpus = i32_at(&data, at);
                at += 4;
                if extra_next != 0 && !skip_extra(&mut at) {
                    sink.warn(format!("damaged record at offset {record_at}"));
                    break;
                }
                let mut row = Row::new(time, "restart", String::new(), None);
                row.note = format!("{} CPUs", cpus.map_or(0, |c| c.max(0)));
                sink.emit(Loc::Offset(input.offset + record_at as u64), &row)?;
                previous = None;
            }
            R_COMMENT => {
                let text = data
                    .get(at..at + 64)
                    .map(|t| lossy(&t[..t.iter().position(|&b| b == 0).unwrap_or(t.len())]).into_owned());
                at += 64;
                if extra_next != 0 && !skip_extra(&mut at) {
                    break;
                }
                let mut row = Row::new(time, "comment", String::new(), None);
                row.note = text.unwrap_or_default();
                sink.emit(Loc::Offset(input.offset + record_at as u64), &row)?;
            }
            R_STATS | R_LAST_STATS => {
                if extra_next != 0 && !skip_extra(&mut at) {
                    sink.warn(format!("damaged record at offset {record_at}"));
                    break;
                }
                let mut current = Snapshot { uptime_cs, ..Snapshot::default() };
                let mut rows: Vec<Row> = Vec::new();
                let seconds = previous
                    .as_ref()
                    .and_then(|p| uptime_cs.checked_sub(p.uptime_cs))
                    .filter(|d| *d > 0)
                    .map(|d| d as f64 / 100.0);
                let mut ok = true;
                let mut too_many = false;
                for a in &activities {
                    let count = if a.has_nr {
                        let Some(n) = i32_at(&data, at) else {
                            ok = false;
                            break;
                        };
                        at += 4;
                        i64::from(n)
                    } else {
                        a.nr
                    };
                    if !(0..=MAX_ITEMS).contains(&count)
                        || !(1..=4096).contains(&a.nr2)
                        || !(0..=1024).contains(&a.size)
                    {
                        ok = false;
                        break;
                    }
                    let bytes = (count * a.nr2 * a.size) as usize;
                    let Some(block) = data.get(at..at + bytes) else {
                        ok = false;
                        break;
                    };
                    at += bytes;
                    if unsupported.contains(&a.id) || a.nr2 != 1 {
                        continue;
                    }
                    if count > MAX_ROWS {
                        too_many = true;
                        continue;
                    }
                    let items = block.chunks_exact(a.size.max(1) as usize);
                    match a.id {
                        1 => {
                            let all: Vec<[u64; 10]> = items
                                .map(|c| {
                                    let mut v = [0u64; 10];
                                    for (i, slot) in v.iter_mut().enumerate() {
                                        *slot = u64_at(c, i * 8).unwrap_or(0);
                                    }
                                    v
                                })
                                .collect();
                            if let (Some(s), Some(p)) = (seconds, previous.as_ref()) {
                                rows.extend(cpu_rows(time, s, &p.cpu, &all));
                            }
                            current.cpu = all;
                        }
                        2 => {
                            if let Some(c) = items.clone().next() {
                                let (cs, forks) = (u64_at(c, 0).unwrap_or(0), u64_at(c, 8).unwrap_or(0));
                                let mut row = Row::new(time, "process", String::new(), seconds);
                                if let (Some(s), Some((pcs, pforks))) =
                                    (seconds, previous.as_ref().and_then(|p| p.pcsw))
                                {
                                    row.forks_per_s = Some(round(rate(pforks, forks, s), 4));
                                    row.context_switches_per_s = Some(round(rate(pcs, cs, s), 4));
                                }
                                rows.push(row);
                                current.pcsw = Some((cs, forks));
                            }
                        }
                        7 => {
                            if let Some(m) = items.clone().next() {
                                let g = |off: usize| u64_at(m, off);
                                let mut row = Row::new(time, "memory", String::new(), seconds);
                                row.mem_free_kib = g(0);
                                row.mem_buffers_kib = g(8);
                                row.mem_cached_kib = g(16);
                                row.mem_total_kib = g(24);
                                row.swap_free_kib = g(32);
                                row.swap_total_kib = g(40);
                                row.mem_committed_kib = g(56);
                                row.mem_active_kib = g(64);
                                row.mem_inactive_kib = g(72);
                                row.mem_dirty_kib = g(80);
                                row.mem_anon_kib = g(88);
                                row.mem_slab_kib = g(96);
                                row.mem_available_kib = g(128);
                                rows.push(row);
                            }
                        }
                        9 => {
                            if let Some(q) = items.clone().next() {
                                let mut row = Row::new(time, "load", String::new(), seconds);
                                row.run_queue = u64_at(q, 0);
                                row.blocked = u64_at(q, 8);
                                row.tasks = u64_at(q, 16);
                                let load = |off: usize| u32_at(q, off).map(|v| f64::from(v) / 100.0);
                                row.load_1 = load(24);
                                row.load_5 = load(28);
                                row.load_15 = load(32);
                                rows.push(row);
                            }
                        }
                        12 => {
                            let nets: Vec<Net> = items
                                .map(|c| {
                                    let name = c.get(60..76).unwrap_or(&[]);
                                    Net {
                                        name: lossy(&name[..name.iter().position(|&b| b == 0).unwrap_or(name.len())])
                                            .into_owned(),
                                        rx_packets: u64_at(c, 0).unwrap_or(0),
                                        tx_packets: u64_at(c, 8).unwrap_or(0),
                                        rx_bytes: u64_at(c, 16).unwrap_or(0),
                                        tx_bytes: u64_at(c, 24).unwrap_or(0),
                                        rx_compressed: u64_at(c, 32).unwrap_or(0),
                                        tx_compressed: u64_at(c, 40).unwrap_or(0),
                                        multicast: u64_at(c, 48).unwrap_or(0),
                                    }
                                })
                                .collect();
                            if let (Some(s), Some(before)) = (seconds, previous.as_ref()) {
                                for n in &nets {
                                    let mut row = Row::new(time, "network", n.name.clone(), seconds);
                                    let p = n.reference(before.net.iter().find(|x| x.name == n.name));
                                    row.rx_packets_per_s = Some(round(rate(p.rx_packets, n.rx_packets, s), 4));
                                    row.tx_packets_per_s = Some(round(rate(p.tx_packets, n.tx_packets, s), 4));
                                    row.rx_kib_per_s = Some(round(rate(p.rx_bytes, n.rx_bytes, s) / 1024.0, 4));
                                    row.tx_kib_per_s = Some(round(rate(p.tx_bytes, n.tx_bytes, s) / 1024.0, 4));
                                    rows.push(row);
                                }
                            } else {
                                rows.extend(nets.iter().map(|n| Row::new(time, "network", n.name.clone(), seconds)));
                            }
                            current.net = nets;
                        }
                        11 => {
                            let disks: Vec<Disk> = items
                                .map(|c| Disk {
                                    major: u32_at(c, 64).unwrap_or(0),
                                    minor: u32_at(c, 68).unwrap_or(0),
                                    nr_ios: u64_at(c, 0).unwrap_or(0),
                                    rd_sect: u64_at(c, 24).unwrap_or(0),
                                    wr_sect: u64_at(c, 32).unwrap_or(0),
                                    dc_sect: u64_at(c, 40).unwrap_or(0),
                                    tot_ticks: u32_at(c, 56).unwrap_or(0),
                                })
                                .collect();
                            for d in &disks {
                                let mut row = Row::new(time, "disk", format!("{}:{}", d.major, d.minor), seconds);
                                if let (Some(s), Some(before)) = (seconds, previous.as_ref()) {
                                    let p = d.reference(
                                        before.disk.iter().find(|x| x.major == d.major && x.minor == d.minor),
                                    );
                                    row.disk_tps = Some(round(rate(p.nr_ios, d.nr_ios, s), 4));
                                    // A sector is 512 bytes.
                                    row.disk_read_kib_per_s = Some(round(rate(p.rd_sect, d.rd_sect, s) / 2.0, 4));
                                    row.disk_write_kib_per_s = Some(round(rate(p.wr_sect, d.wr_sect, s) / 2.0, 4));
                                    // tot_ticks counts milliseconds of busy time.
                                    row.disk_util_pct =
                                        Some(round(f64::from(d.tot_ticks.wrapping_sub(p.tot_ticks)) / s / 10.0, 4));
                                }
                                rows.push(row);
                            }
                            current.disk = disks;
                        }
                        _ => {}
                    }
                }
                if too_many && !warned_many {
                    warned_many = true;
                    sink.warn(format!(
                        "record at offset {record_at}: an activity has more than {MAX_ROWS} items, not read"
                    ));
                }
                if !ok {
                    sink.warn(format!(
                        "record at offset {record_at} is cut short or damaged: the {} bytes after it are not read",
                        data.len() - record_at
                    ));
                    break;
                }
                for row in &rows {
                    sink.emit(Loc::Offset(input.offset + record_at as u64), row)?;
                }
                previous = Some(current);
            }
            _ => {
                // Extra record types carry only the extra structures after the header.
                if extra_next != 0 && !skip_extra(&mut at) {
                    break;
                }
            }
        }
        records += 1;
    }
    if records == 0 {
        sink.warn(format!("no records after the header (host {nodename})"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{fixture, run};
    use serde_json::Value;

    fn rows(out: &str) -> Vec<Value> {
        out.lines()
            .take_while(|l| !l.starts_with("---"))
            .filter(|l| l.starts_with('{'))
            .filter_map(|l| serde_json::from_str(l).ok())
            .collect()
    }

    fn close(got: &Value, want: f64, tolerance: f64, what: &str) {
        let got = got.as_f64().unwrap_or_else(|| panic!("{what}: no value"));
        assert!((got - want).abs() <= tolerance, "{what}: {got} vs {want}");
    }

    /// Every number `sadf -j -- -A` printed for the same file (the reference), against the rows:
    /// sadf leaves out the first sample (the baseline), which has no rates.
    fn compare(dir: &str) -> usize {
        let data = fixture(&format!("sysstat/{dir}/sa13"));
        let out = run(&ARTIFACT, "var/log/sysstat/sa13", &data, 0);
        assert!(!out.contains("--- warning") && !out.contains("--- failed"), "{dir}: {out}");
        let all = rows(&out);
        let reference: Value = serde_json::from_slice(&fixture(&format!("sysstat/{dir}/sadf.json"))).unwrap();
        let statistics = reference["sysstat"]["hosts"][0]["statistics"].as_array().unwrap();
        // block device numbers as the container named them
        let devices: std::collections::HashMap<String, String> =
            String::from_utf8(fixture(&format!("sysstat/{dir}/devices.txt")))
                .unwrap()
                .lines()
                .filter_map(|l| l.split_once(' ').map(|(mm, name)| (name.to_string(), mm.to_string())))
                .collect();
        let times: Vec<&str> = {
            let mut t: Vec<&str> = all.iter().map(|r| r["time"].as_str().unwrap()).collect();
            t.dedup();
            t
        };
        assert_eq!(times.len(), statistics.len() + 1, "{dir}: samples");
        let mut compared = 0;
        for (n, stat) in statistics.iter().enumerate() {
            let time = times[n + 1];
            let mine: Vec<&Value> = all.iter().filter(|r| r["time"] == time).collect();
            let one = |metric: &str, item: &str| -> &Value {
                mine.iter()
                    .find(|r| r["metric"] == metric && r["item"] == item)
                    .unwrap_or_else(|| panic!("{dir} {time}: no {metric} {item}"))
            };
            let at = |k: &str| format!("{dir} {time} {k}");
            // the timestamp and interval
            let stamp = &stat["timestamp"];
            assert_eq!(&time[..10], stamp["date"].as_str().unwrap());
            assert_eq!(&time[11..19], stamp["time"].as_str().unwrap());
            close(&one("load", "")["interval_seconds"], stamp["interval"].as_f64().unwrap(), 1.0, &at("interval"));
            for cpu in stat["cpu-load"].as_array().unwrap() {
                let row = one("cpu", cpu["cpu"].as_str().unwrap());
                let f = |k: &str| cpu[k].as_f64().unwrap();
                // the default `sar -u` counts guest time in user (and guest nice in nice), as -A does not
                close(&row["cpu_user_pct"], f("usr") + f("guest"), 0.03, &at("usr"));
                close(&row["cpu_nice_pct"], f("nice") + f("gnice"), 0.03, &at("nice"));
                // the default `sar -u` folds IRQ time into system, which -A lists separately
                close(&row["cpu_system_pct"], f("sys") + f("irq") + f("soft"), 0.03, &at("sys"));
                close(&row["cpu_iowait_pct"], f("iowait"), 0.02, &at("iowait"));
                close(&row["cpu_steal_pct"], f("steal"), 0.02, &at("steal"));
                close(&row["cpu_idle_pct"], f("idle"), 0.02, &at("idle"));
                compared += 6;
            }
            let p = &stat["process-and-context-switch"];
            close(&one("process", "")["forks_per_s"], p["proc"].as_f64().unwrap(), 0.006, &at("proc"));
            close(&one("process", "")["context_switches_per_s"], p["cswch"].as_f64().unwrap(), 0.006, &at("cswch"));
            let m = &stat["memory"];
            let mem = one("memory", "");
            for (field, key) in [
                ("mem_free_kib", "memfree"),
                ("mem_available_kib", "avail"),
                ("mem_buffers_kib", "buffers"),
                ("mem_cached_kib", "cached"),
                ("mem_committed_kib", "commit"),
                ("mem_active_kib", "active"),
                ("mem_inactive_kib", "inactive"),
                ("mem_dirty_kib", "dirty"),
                ("mem_anon_kib", "anonpg"),
                ("mem_slab_kib", "slab"),
                ("swap_free_kib", "swpfree"),
            ] {
                assert_eq!(mem[field], m[key], "{}", at(key));
                compared += 1;
            }
            // memused = total - free - buffers - cached - slab; the file's total makes it checkable
            let used = mem["mem_total_kib"].as_u64().unwrap()
                - mem["mem_free_kib"].as_u64().unwrap()
                - mem["mem_buffers_kib"].as_u64().unwrap()
                - mem["mem_cached_kib"].as_u64().unwrap()
                - mem["mem_slab_kib"].as_u64().unwrap();
            assert_eq!(used, m["memused"].as_u64().unwrap(), "{}", at("memused"));
            assert_eq!(
                mem["swap_total_kib"].as_u64().unwrap() - mem["swap_free_kib"].as_u64().unwrap(),
                m["swpused"].as_u64().unwrap(),
                "{}",
                at("swpused")
            );
            let q = &stat["queue"];
            let load = one("load", "");
            assert_eq!(load["run_queue"], q["runq-sz"]);
            assert_eq!(load["tasks"], q["plist-sz"]);
            assert_eq!(load["blocked"], q["blocked"]);
            close(&load["load_1"], q["ldavg-1"].as_f64().unwrap(), 0.0001, &at("ldavg-1"));
            close(&load["load_5"], q["ldavg-5"].as_f64().unwrap(), 0.0001, &at("ldavg-5"));
            close(&load["load_15"], q["ldavg-15"].as_f64().unwrap(), 0.0001, &at("ldavg-15"));
            compared += 5;
            for iface in stat["network"]["net-dev"].as_array().unwrap() {
                let row = one("network", iface["iface"].as_str().unwrap());
                close(&row["rx_packets_per_s"], iface["rxpck"].as_f64().unwrap(), 0.006, &at("rxpck"));
                close(&row["tx_packets_per_s"], iface["txpck"].as_f64().unwrap(), 0.006, &at("txpck"));
                close(&row["rx_kib_per_s"], iface["rxkB"].as_f64().unwrap(), 0.006, &at("rxkB"));
                close(&row["tx_kib_per_s"], iface["txkB"].as_f64().unwrap(), 0.006, &at("txkB"));
                compared += 4;
            }
            for disk in stat["disk"].as_array().unwrap() {
                let name = disk["disk-device"].as_str().unwrap();
                let Some(numbers) = devices.get(name) else { continue };
                let row = one("disk", numbers);
                close(&row["disk_tps"], disk["tps"].as_f64().unwrap(), 0.006, &at("tps"));
                close(&row["disk_read_kib_per_s"], disk["rkB"].as_f64().unwrap(), 0.006, &at("rkB"));
                close(&row["disk_write_kib_per_s"], disk["wkB"].as_f64().unwrap(), 0.006, &at("wkB"));
                close(&row["disk_util_pct"], disk["util-percent"].as_f64().unwrap(), 0.02, &at("util"));
                compared += 4;
            }
        }
        compared
    }

    /// Three real files (sysstat 12.6.1 on Debian 12 and Ubuntu 24.04, 12.5.4 on Rocky 9) against
    /// `sadf -j` of the same file.
    #[test]
    fn rows_match_sadf() {
        let total: usize = ["debian12", "ubuntu2404", "rocky9"].iter().map(|d| compare(d)).sum();
        assert!(total > 1500, "{total}");
    }

    #[test]
    fn a_real_file_as_rows() {
        let out = run(&ARTIFACT, "var/log/sysstat/sa13", &fixture("sysstat/debian12/sa13"), 0);
        let all = rows(&out);
        assert!(all.iter().any(|r| r["metric"] == "cpu" && r["item"] == "all"));
        assert!(all.iter().filter(|r| r["metric"] == "network").all(|r| !r["item"].as_str().unwrap().is_empty()));
        // first sample has the level values but no rates
        let first = all[0]["time"].as_str().unwrap();
        assert!(all.iter().filter(|r| r["time"] == first).all(|r| r["interval_seconds"].is_null()));
    }

    /// A real sysstat 10.1.5 file (CentOS 7; data file format 0x2171) is not read.
    #[test]
    fn a_real_old_file_is_skipped() {
        let out = run(&ARTIFACT, "var/log/sa/sa13", &fixture("sysstat/centos7/sa13"), 0);
        assert!(out.contains("skipped: unsupported sysstat file version 10.1.5 (data file format 0x2171"), "{out}");
    }

    #[test]
    fn other_versions_are_skipped_with_a_clear_reason() {
        let mut old = fixture("sysstat/debian12/sa13");
        old[2..4].copy_from_slice(&0x2171u16.to_le_bytes());
        old[4..7].copy_from_slice(&[10, 1, 5]);
        let out = run(&ARTIFACT, "var/log/sa/sa13", &old, 0);
        assert!(out.contains("skipped: unsupported sysstat file version 10.1.5 (data file format 0x2171"), "{out}");
        let mut swapped = fixture("sysstat/debian12/sa13");
        swapped[..2].copy_from_slice(&0xd596u16.swap_bytes().to_le_bytes());
        assert!(run(&ARTIFACT, "var/log/sa/sa13", &swapped, 0)
            .contains("unsupported sysstat file version 12.6.1: big-endian"));
        assert!(run(&ARTIFACT, "var/log/sa/sa13", b"sar text\n", 0).contains("not a sysstat data file"));
        assert!(run(&ARTIFACT, "var/log/sa/sa13", b"", 0).contains("empty"));
        let mut other_layout = fixture("sysstat/debian12/sa13");
        let activities = MAGIC_SIZE + HEADER_SIZE;
        other_layout[activities + 4..activities + 8].copy_from_slice(&0x99u32.to_le_bytes()); // CPU activity magic
        let out = run(&ARTIFACT, "var/log/sysstat/sa13", &other_layout, 0);
        assert!(out.contains("activities [1] have a layout version that was not validated: not read"), "{out}");
        assert!(!out.contains(r#""metric":"cpu""#) && out.contains(r#""metric":"memory""#), "{out}");
    }

    #[test]
    fn truncated_and_damaged_files_are_reported_not_trusted() {
        let data = fixture("sysstat/debian12/sa13");
        let out = run(&ARTIFACT, "var/log/sysstat/sa13", &data[..data.len() - 100], 0);
        assert!(out.contains("is cut short or damaged"), "{out}");
        let mut damaged = data.clone();
        let activities = u32::from_le_bytes(data[MAGIC_SIZE + 20..MAGIC_SIZE + 24].try_into().unwrap()) as usize;
        let first_record = MAGIC_SIZE + HEADER_SIZE + activities * ACTIVITY_SIZE;
        damaged[first_record + 20] = 99;
        assert!(run(&ARTIFACT, "var/log/sysstat/sa13", &damaged, 0).contains("damaged record at offset"));
    }

    #[test]
    fn mutations_never_panic() {
        let data = fixture("sysstat/debian12/sa13");
        let mut seed = 0xabcd_ef01_2345_6789u64;
        for round in 0..1500 {
            let mut copy = data.clone();
            for _ in 0..(1 + round % 10) {
                seed ^= seed << 13;
                seed ^= seed >> 7;
                seed ^= seed << 17;
                // most of the damage near the headers, where the sizes live
                let span = if round % 2 == 0 { 2048 } else { copy.len() };
                let at = (seed % span as u64) as usize;
                copy[at] = (seed >> 32) as u8;
            }
            if round % 7 == 0 {
                copy.truncate((seed % copy.len() as u64) as usize);
            }
            run(&ARTIFACT, "var/log/sysstat/sa13", &copy, 0);
        }
    }
}
