//! The macOS Unified Log: `tracev3` files under `/private/var/db/diagnostics` or in a
//! `.logarchive`, rendered the way `log show` renders them. Format: libyal dtformats, "Apple
//! Unified Logging and Activity Tracing formats"; os_log(3) and log(1) for message rendering.
//!
//! A tracev3 file holds no text: format strings and image paths are in the `uuidtext` tree
//! and the shared-cache (`dsc`) files, and wall-clock time comes from the `timesync`
//! database. All three are read as companions, relative to the store the file is in.
//!
//! Every entry present in the files is output, including entries in files that `log show` no
//! longer displays. On a reference archive `log show` displayed about 85% of the entries
//! present. It leaves out whole `Special` files, not single entries, and does not follow the
//! per-entry TTL: a displayed file held entries with a 1-day TTL nearly 5 days old, while the
//! next file, whose entries all had TTLs of 4 days or more, was left out. A log archive's
//! `Info.plist` holds per-class cutoffs (`SpecialMetadata.TTL`, keys such as `ttl01` and
//! `ttl30`, each a continuous time); the rule `log show` uses to select files is not
//! established. The per-entry TTL is the `ttl_days` column (1 to 30 days; in the reference
//! archive only entries in `Special` files carry one).
//!
//! Columns beyond `log show`'s fields:
//! - `source_offset` is the file offset of the chunk holding the entry: for most entries an
//!   LZ4 chunk set, shared by the hundreds of entries compressed in it. `chunk_offset` is the
//!   offset of the entry's record within that chunk set's decompressed data (within the chunk
//!   itself for a chunk outside a chunk set): for a firehose entry, the tracepoint (its firehose
//!   chunk's offset, plus 16 for the chunk header and 32 for the firehose preamble, plus the
//!   tracepoint's offset); for a simpledump or statedump, its chunk. The two locate an entry.
//! - `time_estimated` is true when the timesync database has no record for the entry's boot,
//!   so its time was estimated from the file header's wall clock (a warning says so too).
//! - `ttl_days`, above.
//!
//! An entry whose values are in an oversize chunk that is not in its own file is looked up in
//! the previous and next tracev3 files of the same directory (by name); if none has it, its
//! values show `<oversize data in another file>`. At most 64 MiB of oversize data is kept per
//! task; past that, values show `<oversize data not kept>` and a warning says so.
//!
//! The patterns match every copy of a log store in the evidence (the live store, `.logarchive`
//! bundles, sysdiagnose folders), and each copy is parsed, so the same entry can appear once
//! per copy.

mod firehose;
mod format;
mod strings;
mod timesync;
mod tracev3;

use crate::text::lossy;
use crate::{Artifact, Category, Input, MACOS};
use firehose::{Firehose, Oversize, Tracepoint, Value};
use nixcavate_core::{Basis, Error, Event, Loc, Precision, Record, Result, Sink, Timestamp};
use nixcavate_source::{Entry as FileEntry, Host};
use serde::Serialize;
use std::borrow::Cow;
use std::collections::HashMap;
use std::fmt::Write;
use std::rc::Rc;
use strings::{SharedCache, Strings, Text, Uuidtext};
use timesync::Timesync;
use tracev3::{Catalog, Chunk, Chunks, Header, Process, Reader};

pub const ARTIFACT: Artifact = Artifact::new(
    "unified-log",
    "Unified Log entries (tracev3)",
    Category::Logs,
    MACOS,
    &[
        "**/Persist/*.tracev3",
        "**/Special/*.tracev3",
        "**/Signpost/*.tracev3",
        "**/HighVolume/*.tracev3",
        "**/logdata.LiveData.tracev3",
    ],
    parse,
)
.companions(&["**/uuidtext/**", "**/timesync/*.timesync", "**/*.logarchive/**"]);

#[derive(Serialize)]
struct Entry<'a> {
    chunk_offset: u64,
    time: Timestamp,
    time_estimated: bool,
    event_type: &'static str,
    log_type: &'static str,
    pid: Option<u32>,
    euid: Option<u32>,
    thread_id: u64,
    activity_id: u64,
    process: Cow<'a, str>,
    sender: Cow<'a, str>,
    subsystem: Cow<'a, str>,
    category: Cow<'a, str>,
    message: String,
    format: Cow<'a, str>,
    boot_uuid: &'a str,
    ttl_days: Option<u8>,
}

const EVENT_CHARS: usize = 300;

impl Record for Entry<'_> {
    fn events(&self) -> impl Iterator<Item = Event<'_>> {
        let name = self.process.rsplit('/').next().unwrap_or_default();
        let mut message = format!("{name}: {}", self.message);
        if let Some((cut, _)) = message.char_indices().nth(EVENT_CHARS) {
            message.truncate(cut);
        }
        std::iter::once(Event::new(self.time, "log", message))
    }
}

fn log_type(kind: u8, value: u8) -> &'static str {
    match (kind, value) {
        (firehose::ACTIVITY, 1) => "create",
        (firehose::ACTIVITY, 3) => "useraction",
        (firehose::ACTIVITY, _) => "activity",
        (firehose::SIGNPOST, v) => match v & 0x3 {
            0 => "event",
            1 => "begin",
            2 => "end",
            _ => "signpost",
        },
        (_, 0x01) => "info",
        (_, 0x02) => "debug",
        (_, 0x10) => "error",
        (_, 0x11) => "fault",
        _ => "default",
    }
}

fn event_type(kind: u8) -> &'static str {
    match kind {
        firehose::ACTIVITY => "activity",
        firehose::TRACE => "trace",
        firehose::SIGNPOST => "signpost",
        firehose::LOSS => "loss",
        _ => "log",
    }
}

/// Activity identifiers carry a flag in the top bit that `log show` does not print.
fn activity(aid: u64) -> u64 {
    aid & 0x00ff_ffff_ffff_ffff
}

fn text(t: &Option<Text>) -> Cow<'_, str> {
    t.as_ref().map_or(Cow::Borrowed(""), |t| lossy(t.bytes()))
}

/// A format string for the `format` column, cut like a message.
fn format_column(format: &str) -> Cow<'_, str> {
    if format.len() <= format::MAX_TEXT {
        return Cow::Borrowed(format);
    }
    let mut cut = format.to_string();
    format::cut(&mut cut);
    Cow::Owned(cut)
}

/// The full source path of a root-relative path.
fn full_path(host: &Host, rel: &str) -> String {
    match host.root.as_str() {
        "" => rel.to_string(),
        root => format!("{root}/{rel}"),
    }
}

/// A statedump's payload. A property list (data type 1) is shown the way `log show` shows it:
/// binary and XML ones through Foundation's `description` format, old-style (text) ones as
/// written, since they are in that format already. Other types (protobuf, objects that `log
/// show` decodes with a library) are shown by size, as is a property list that does not parse.
fn statedump_payload(kind: u32, payload: &[u8], out: &mut String) {
    if kind == 1 {
        let text = tracev3::cstr(payload);
        if text.trim_ascii_start().starts_with(b"{") || text.trim_ascii_start().starts_with(b"(") {
            out.push_str(&lossy(&text[..text.len().min(format::MAX_TEXT + 1)]));
            return;
        }
        if let Ok(value) = nixcavate_source::plist::parse(payload) {
            format::description(&value, 0, out);
            return;
        }
    }
    let _ = write!(out, "<{} bytes of statedump data, type {kind}>", payload.len());
}

/// Where the store's companions are, from the path of a tracev3 file in it.
fn roots(path: &str) -> (String, String) {
    let parent = |p: &str| p.rsplit_once('/').map_or(String::new(), |(dir, _)| dir.to_string());
    let dir = parent(path);
    let name = dir.rsplit('/').next().unwrap_or_default();
    let store = match name {
        "Persist" | "Special" | "Signpost" | "HighVolume" => parent(&dir),
        _ => dir,
    };
    // A live system keeps uuidtext beside diagnostics; an archive keeps both together.
    let strings = match store.rsplit('/').next() {
        Some("diagnostics") => match parent(&store) {
            p if p.is_empty() => "uuidtext".to_string(),
            p => format!("{p}/uuidtext"),
        },
        _ => store.clone(),
    };
    (store, strings)
}

fn load_timesync(host: &Host, store: &str, sink: &mut Sink) -> Timesync {
    let mut timesync = Timesync::default();
    let dir = [host.root.as_str(), store, "timesync/"].iter().filter(|s| !s.is_empty()).copied().collect::<Vec<_>>();
    let prefix = dir.join("/");
    let entries = host.source.entries();
    let start = entries.partition_point(|e| e.path < prefix);
    for entry in entries[start..].iter().take_while(|e| e.path.starts_with(&prefix)) {
        if entry.link.is_none() && entry.path.ends_with(".timesync") {
            if let Ok(data) = host.open(entry) {
                if let Err(at) = timesync.add(&data) {
                    sink.warn(format!("{}: unknown record at offset {at}; the rest is ignored", entry.path));
                }
            }
        }
    }
    timesync.finish();
    timesync
}

/// The string files of the process a firehose chunk belongs to.
struct Files {
    main: Option<Rc<Uuidtext>>,
    dsc: Option<Rc<SharedCache>>,
}

/// The most oversize data kept per task, in bytes (each chunk also counts 64 for its entry).
const OVERSIZE_BUDGET: usize = 64 << 20;

/// Oversize chunks by (first proc_id, second proc_id, data reference): public and private
/// data, and the private size.
type OversizeMap = HashMap<(u64, u32, u32), (Vec<u8>, u16)>;

/// What became of a tracepoint's oversize chunk.
enum OversizeFound<'c> {
    Data(&'c (Vec<u8>, u16)),
    /// Not found, and some oversize data was dropped for the budget: it may have been this.
    NotKept,
    /// Not in this file or its neighbours.
    Elsewhere,
}

struct Context<'h> {
    host: &'h Host<'h>,
    /// The tracev3 file's path, relative to the host root.
    path: &'h str,
    file: &'h [u8],
    strings: Strings<'h>,
    timesync: Timesync,
    header: Header,
    boot: String,
    /// Oversize chunks seen so far.
    oversize: OversizeMap,
    /// Bytes counted against [`OVERSIZE_BUDGET`].
    oversize_kept: usize,
    /// Whether an oversize chunk was dropped for the budget.
    oversize_dropped: bool,
    /// Whether the whole file was searched for oversize chunks.
    oversize_scanned: bool,
    /// The previous and next tracev3 files, found on the first miss; how many were read.
    neighbours: Option<[Option<&'h FileEntry>; 2]>,
    neighbours_read: usize,
    /// Entries showing `<oversize data in another file>` and `<oversize data not kept>`.
    oversize_elsewhere: u64,
    oversize_not_kept: u64,
    unconverted: u64,
}

impl<'h> Context<'h> {
    /// The oversize chunk a tracepoint refers to. It is usually written before the tracepoint;
    /// when it is not, the rest of the file is searched once, then the previous and next files.
    fn oversize(&mut self, proc_id: (u64, u32), data_ref: u32) -> OversizeFound<'_> {
        let key = (proc_id.0, proc_id.1, data_ref);
        if !self.oversize.contains_key(&key) && !self.oversize_scanned {
            self.oversize_scanned = true;
            self.scan_oversize(self.file);
        }
        while !self.oversize.contains_key(&key) && self.neighbours_read < 2 {
            let neighbour = self.neighbours()[self.neighbours_read];
            self.neighbours_read += 1;
            let Some(data) = neighbour.and_then(|entry| self.host.open(entry).ok()) else { continue };
            let header = Chunks::new(&data).next().and_then(|c| c.ok()).filter(|c| c.tag == tracev3::HEADER);
            if header.and_then(|c| Header::parse(c.data)).is_some_and(|h| h.boot == self.header.boot) {
                self.scan_oversize(&data);
            }
        }
        match self.oversize.get(&key) {
            Some(found) => OversizeFound::Data(found),
            None if self.oversize_dropped => OversizeFound::NotKept,
            None => OversizeFound::Elsewhere,
        }
    }

    /// The tracev3 files before and after this one in its directory, by name.
    fn neighbours(&mut self) -> [Option<&'h FileEntry>; 2] {
        *self.neighbours.get_or_insert_with(|| {
            let path = full_path(self.host, self.path);
            let dir = path.rsplit_once('/').map_or("", |(dir, _)| dir);
            let prefix = if dir.is_empty() { String::new() } else { format!("{dir}/") };
            let entries = self.host.entries();
            let start = entries.partition_point(|e| e.path < prefix);
            let files: Vec<&FileEntry> = entries[start..]
                .iter()
                .take_while(|e| e.path.starts_with(&prefix))
                .filter(|e| e.link.is_none() && e.path.ends_with(".tracev3") && !e.path[prefix.len()..].contains('/'))
                .collect();
            match files.iter().position(|e| e.path == path) {
                Some(at) => [at.checked_sub(1).map(|i| files[i]), files.get(at + 1).copied()],
                None => [None, None],
            }
        })
    }

    /// Adds the oversize chunks in the chunk sets of a tracev3 file.
    fn scan_oversize(&mut self, file: &[u8]) {
        let mut buf = Vec::new();
        for chunk in Chunks::new(file).flatten().filter(|c| c.tag == tracev3::CHUNKSET) {
            let Ok(len) = tracev3::decompress(chunk.data, &mut buf) else { continue };
            for inner in Chunks::new(&buf[..len]).flatten() {
                self.add_oversize(&inner);
            }
        }
    }

    fn add_oversize(&mut self, chunk: &Chunk) {
        let Some(o) = Oversize::parse(chunk.data).filter(|_| chunk.tag == tracev3::OVERSIZE) else { return };
        let key = (o.proc_id.0, o.proc_id.1, o.data_ref);
        if self.oversize.contains_key(&key) {
            return;
        }
        let cost = o.data.len() + 64;
        if self.oversize_kept + cost > OVERSIZE_BUDGET {
            self.oversize_dropped = true;
            return;
        }
        self.oversize_kept += cost;
        self.oversize.insert(key, (o.data.to_vec(), o.private_size));
    }

    /// The wall-clock time of a continuous time, and whether it was estimated from the file
    /// header because the timesync database has no record for the boot.
    fn time(&mut self, continuous: u64) -> (Timestamp, bool) {
        let mut estimated = false;
        let nanos = self.timesync.wall_nanos(&self.header.boot, continuous).unwrap_or_else(|| {
            self.unconverted += 1;
            estimated = true;
            let h = &self.header;
            let delta = timesync::ticks_to_nanos(continuous.abs_diff(h.continuous), h.numerator, h.denominator);
            let base = h.wall_secs.saturating_mul(1_000_000_000);
            if continuous >= h.continuous {
                base.saturating_add(delta)
            } else {
                base.saturating_sub(delta)
            }
        });
        (Timestamp::new(nanos, Precision::Nanos, Basis::Recorded), estimated)
    }

    /// The format string and sender image of a tracepoint. `files` are the process's main
    /// executable and shared cache, resolved once per firehose chunk.
    fn lookup(&mut self, process: &Process, files: &Files, tp: &Tracepoint) -> (Option<Text>, Option<Text>) {
        use firehose::FormatAt as S;
        let image =
            || process.images.iter().find(|i| tp.pc.wrapping_sub(i.load_address) < i.size as u64).map(|i| i.uuid);
        if tp.dynamic {
            let sender = match tp.strings {
                Some(S::MainExe) => files.main.as_ref().map(Uuidtext::path_text),
                Some(S::SharedCache) => files.dsc.as_ref().and_then(|c| SharedCache::sender(c, tp.pc)),
                Some(S::UuidRelative(uuid)) => self.strings.image_path(&uuid, None),
                _ => None,
            };
            return (Some(Text::Static("%s")), sender);
        }
        let file = match tp.strings {
            Some(S::SharedCache) => {
                return files.dsc.as_ref().map_or((None, None), |c| SharedCache::lookup(c, tp.format, tp.pc));
            }
            Some(S::MainExe) => files.main.clone(),
            Some(S::UuidRelative(uuid)) => self.strings.uuidtext(&uuid),
            Some(S::Absolute) => image().and_then(|uuid| self.strings.uuidtext(&uuid)),
            _ => None,
        };
        file.map_or((None, None), |f| Uuidtext::lookup(&f, tp.format))
    }

    fn process_path(&mut self, process: Option<&Process>) -> Option<Text> {
        let process = process?;
        self.strings.image_path(&process.main?, process.dsc.as_ref())
    }

    /// `offset` is the chunk's offset in its chunk set (0 outside one).
    fn firehose<'a>(
        &mut self,
        data: &'a [u8],
        catalog: Option<&Catalog>,
        at: Loc,
        offset: usize,
        items: &mut Vec<Value<'a>>,
        sink: &mut Sink,
    ) -> Result<()> {
        let Some(chunk) = Firehose::parse(data) else {
            sink.warn("truncated firehose chunk");
            return Ok(());
        };
        let process = catalog.and_then(|c| c.process(chunk.proc_id.0, chunk.proc_id.1));
        let process_path = self.process_path(process);
        let files = Files {
            main: process.and_then(|p| p.main).and_then(|u| self.strings.uuidtext(&u)),
            dsc: process.and_then(|p| p.dsc).and_then(|u| self.strings.dsc(&u)),
        };
        for tracepoint in chunk.tracepoints() {
            let (tp_offset, raw) = match tracepoint {
                Ok(found) => found,
                Err(e) => {
                    sink.warn(e);
                    break;
                }
            };
            let Some(tp) = Tracepoint::parse(raw, &chunk, std::mem::take(items)) else {
                sink.warn(format!("undecodable tracepoint at {tp_offset} of a firehose chunk"));
                continue;
            };
            let (format, sender) = process.map_or((None, None), |p| self.lookup(p, &files, &tp));
            let (subsystem, category) = match (catalog, process, tp.subsystem) {
                (Some(c), Some(p), Some(id)) => c.subsystem(p, id).unwrap_or_default(),
                _ => (&[][..], &[][..]),
            };
            let format_text = text(&format);
            let mut message = String::new();
            const MISSING: &str = "<decode: missing data>";
            match tp.kind {
                firehose::LOSS => {
                    message = format!("lost {} unreliable message(s)", tp.lost);
                }
                firehose::ACTIVITY => message.push_str(&format_text),
                _ if format.is_none() => message.push_str("<missing format string>"),
                _ => match tp.oversize.map(|r| self.oversize(chunk.proc_id, r)) {
                    Some(OversizeFound::Data((data, private))) => {
                        let mut values = Vec::new();
                        Oversize::items(data, *private, &mut values);
                        format::render(&format_text, &values, MISSING, &mut message);
                    }
                    Some(OversizeFound::NotKept) => {
                        self.oversize_not_kept += 1;
                        format::render(&format_text, &tp.items, "<oversize data not kept>", &mut message);
                    }
                    Some(OversizeFound::Elsewhere) => {
                        self.oversize_elsewhere += 1;
                        format::render(&format_text, &tp.items, "<oversize data in another file>", &mut message);
                    }
                    None => format::render(&format_text, &tp.items, MISSING, &mut message),
                },
            }
            format::cut(&mut message);
            // `log show` drops trailing newlines.
            message.truncate(message.trim_end().len());
            let (time, time_estimated) = self.time(chunk.base.wrapping_add(tp.delta));
            let aid = if tp.kind == firehose::ACTIVITY { tp.new_aid } else { tp.current_aid };
            sink.emit(
                at,
                &Entry {
                    chunk_offset: (offset + 16 + 32 + tp_offset) as u64,
                    time,
                    time_estimated,
                    event_type: event_type(tp.kind),
                    log_type: log_type(tp.kind, tp.log_type),
                    pid: process.map(|p| p.pid),
                    euid: process.map(|p| p.euid),
                    thread_id: tp.thread,
                    activity_id: activity(aid),
                    process: text(&process_path),
                    sender: text(&sender),
                    subsystem: lossy(subsystem),
                    category: lossy(category),
                    message,
                    format: format_column(&format_text),
                    boot_uuid: &self.boot,
                    ttl_days: tp.ttl,
                },
            )?;
            *items = tp.items;
        }
        Ok(())
    }

    fn simpledump(
        &mut self,
        data: &[u8],
        catalog: Option<&Catalog>,
        at: Loc,
        offset: usize,
        sink: &mut Sink,
    ) -> Option<Result<()>> {
        let mut r = Reader::new(data);
        let proc_id = (r.u64()?, r.u32()?);
        let (ttl, kind) = (r.u8()?, r.u8()?);
        r.pos = 16;
        let (continuous, thread, _offset) = (r.u64()?, r.u64()?, r.u64()?);
        let (sender, dsc) = (r.uuid()?, r.uuid()?);
        let (_unknown, subsystem_size, message_size) = (r.u32()?, r.u32()?, r.u32()?);
        let subsystem = tracev3::cstr(r.bytes(subsystem_size as usize)?);
        let message = tracev3::cstr(r.bytes(message_size as usize)?);
        let process = catalog.and_then(|c| c.process(proc_id.0, proc_id.1));
        let process_path = self.process_path(process);
        let sender = self.strings.image_path(&sender, Some(&dsc));
        let (time, time_estimated) = self.time(continuous);
        let mut message = lossy(message).into_owned();
        format::cut(&mut message);
        Some(sink.emit(
            at,
            &Entry {
                chunk_offset: offset as u64,
                time,
                time_estimated,
                event_type: "simpledump",
                log_type: log_type(firehose::LOG, kind),
                pid: process.map(|p| p.pid),
                euid: process.map(|p| p.euid),
                thread_id: thread,
                activity_id: 0,
                process: text(&process_path),
                sender: text(&sender),
                subsystem: lossy(subsystem),
                category: Cow::Borrowed(""),
                message,
                format: Cow::Borrowed(""),
                boot_uuid: &self.boot,
                ttl_days: Some(ttl).filter(|&t| t != 0),
            },
        ))
    }

    /// A statedump: its title, then its payload (see [`statedump_payload`]).
    fn statedump(
        &mut self,
        data: &[u8],
        catalog: Option<&Catalog>,
        at: Loc,
        offset: usize,
        sink: &mut Sink,
    ) -> Option<Result<()>> {
        let mut r = Reader::new(data);
        let proc_id = (r.u64()?, r.u32()?);
        r.pos = 16;
        let (continuous, aid, sender) = (r.u64()?, r.u64()?, r.uuid()?);
        let (kind, size) = (r.u32()?, r.u32()?);
        r.pos = 184;
        let title = tracev3::cstr(r.bytes(64)?);
        let payload = r.rest();
        let payload = &payload[..payload.len().min(size as usize)];
        let mut message = lossy(title).into_owned();
        if !message.is_empty() {
            message.push('\n');
        }
        statedump_payload(kind, payload, &mut message);
        format::cut(&mut message);
        let process = catalog.and_then(|c| c.process(proc_id.0, proc_id.1));
        let process_path = self.process_path(process);
        let sender = self.strings.image_path(&sender, process.and_then(|p| p.dsc.as_ref()));
        let (time, time_estimated) = self.time(continuous);
        Some(sink.emit(
            at,
            &Entry {
                chunk_offset: offset as u64,
                time,
                time_estimated,
                event_type: "statedump",
                log_type: "default",
                pid: process.map(|p| p.pid),
                euid: process.map(|p| p.euid),
                thread_id: 0,
                activity_id: activity(aid),
                process: text(&process_path),
                sender: text(&sender),
                subsystem: Cow::Borrowed(""),
                category: Cow::Borrowed(""),
                message,
                format: Cow::Borrowed(""),
                boot_uuid: &self.boot,
                ttl_days: None,
            },
        ))
    }

    /// Handles one chunk found inside a chunk set (or, unusually, at the top level, where
    /// its offset is taken as 0).
    fn chunk<'a>(
        &mut self,
        chunk: &Chunk<'a>,
        catalog: Option<&Catalog>,
        at: Loc,
        items: &mut Vec<Value<'a>>,
        sink: &mut Sink,
    ) -> Result<()> {
        let offset = chunk.offset;
        let done = match chunk.tag {
            tracev3::FIREHOSE => return self.firehose(chunk.data, catalog, at, offset, items, sink),
            tracev3::OVERSIZE => {
                self.add_oversize(chunk);
                Some(Ok(()))
            }
            tracev3::SIMPLEDUMP => self.simpledump(chunk.data, catalog, at, offset, sink),
            tracev3::STATEDUMP => self.statedump(chunk.data, catalog, at, offset, sink),
            tag => {
                sink.warn(format!("unknown chunk 0x{tag:x} in a chunk set"));
                Some(Ok(()))
            }
        };
        done.unwrap_or_else(|| {
            sink.warn(format!("truncated chunk 0x{:x}", chunk.tag));
            Ok(())
        })
    }
}

fn parse(input: &Input, sink: &mut Sink) -> Result<()> {
    let mut chunks = Chunks::new(input.data);
    let header = match chunks.next() {
        None => return Err(Error::skipped("empty file")),
        Some(Ok(chunk)) if chunk.tag == tracev3::HEADER => {
            Header::parse(chunk.data).ok_or_else(|| Error::format("truncated header chunk"))?
        }
        _ => return Err(Error::format("not a tracev3 file: no header chunk")),
    };
    let (store, strings_root) = roots(input.path);
    let mut ctx = Context {
        host: input.host,
        path: input.path,
        file: input.data,
        strings: Strings::new(input.host, strings_root),
        timesync: load_timesync(input.host, &store, sink),
        boot: tracev3::uuid_string(&header.boot),
        header,
        oversize: HashMap::new(),
        oversize_kept: 0,
        oversize_dropped: false,
        oversize_scanned: false,
        neighbours: None,
        neighbours_read: 0,
        oversize_elsewhere: 0,
        oversize_not_kept: 0,
        unconverted: 0,
    };
    let mut catalog: Option<Catalog> = None;
    let mut buf = Vec::new();
    for chunk in chunks {
        let chunk = match chunk {
            Ok(chunk) => chunk,
            Err(e) => {
                sink.warn(e);
                break;
            }
        };
        let at = Loc::Offset(input.offset + chunk.offset as u64);
        match chunk.tag {
            tracev3::CATALOG => {
                catalog = Catalog::parse(chunk.data);
                if catalog.is_none() {
                    sink.warn(format!("offset {}: undecodable catalog", chunk.offset));
                }
            }
            tracev3::CHUNKSET => {
                let len = match tracev3::decompress(chunk.data, &mut buf) {
                    Ok(len) => len,
                    Err(e) => {
                        sink.warn(format!("offset {}: chunk set: {e}", chunk.offset));
                        continue;
                    }
                };
                let mut items = Vec::new();
                for inner in Chunks::new(&buf[..len]) {
                    match inner {
                        Ok(inner) => ctx.chunk(&inner, catalog.as_ref(), at, &mut items, sink)?,
                        Err(e) => sink.warn(format!("offset {}: chunk set: {e}", chunk.offset)),
                    }
                }
            }
            _ => {
                let mut items = Vec::new();
                let top = Chunk { offset: 0, ..chunk };
                ctx.chunk(&top, catalog.as_ref(), at, &mut items, sink)?;
            }
        }
    }
    if ctx.oversize_elsewhere > 0 {
        sink.warn(format!(
            "{} entries refer to oversize data in neither this file nor the files beside it; \
             their values show <oversize data in another file>",
            ctx.oversize_elsewhere
        ));
    }
    if ctx.oversize_dropped {
        sink.warn(format!(
            "more than {} MiB of oversize data; {} entries refer to data not kept and show <oversize data not kept>",
            OVERSIZE_BUDGET >> 20,
            ctx.oversize_not_kept
        ));
    }
    if ctx.unconverted > 0 {
        sink.warn(format!(
            "{} entries had no timesync record for boot {}; their time is estimated from the file header",
            ctx.unconverted, ctx.boot
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests;
