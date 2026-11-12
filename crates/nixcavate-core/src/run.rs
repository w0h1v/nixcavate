//! Sorted run files: the timeline events of one task, ordered by time.
//!
//! A task writes its events here while it parses. `super-timeline` memory-maps every run and
//! merges them, so no artifact is parsed twice. The merge is parallel: a sparse index at the
//! end of each run lets it cut all runs at the same instants and merge the pieces
//! independently.
//!
//! Layout (integers little-endian):
//!
//! ```text
//! magic "NXRUN\x02\0\0"
//! host, artifact, source_path        each: u32 length + UTF-8 bytes
//! events, sorted by timestamp:
//!   i64 utc_nanos | u8 precision | u8 basis | u8 loc_kind | u64 loc
//!   u16 + kind | u32 + message | u16 + rule | u16 + level
//! index: one (i64 utc_nanos, u64 offset into events) per ~64 KiB of events
//! u64 index entries | u64 events length | i64 last timestamp | magic "NXRUNIDX"
//! ```

use crate::error::{Error, Result};
use crate::row::{csv_field, json_str, Format};
use crate::time::{Basis, Precision, Timestamp};
use std::cmp::Reverse;
use std::collections::{BTreeMap, BinaryHeap};
use std::io::{self, Write};
use std::panic::{self, AssertUnwindSafe};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Condvar, Mutex};
use std::thread;

const MAGIC: &[u8; 8] = b"NXRUN\x02\0\0";
const INDEX_MAGIC: &[u8; 8] = b"NXRUNIDX";
/// Bytes of the fixed part of an event, before its strings.
const EVENT_FIXED: usize = 19;
/// Event bytes between index entries.
const INDEX_STRIDE: usize = 64 << 10;
/// Index entries per merge partition: about 8 MiB of events.
const PARTITION_SAMPLES: usize = 128;

/// Where in the source a record or event came from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Loc {
    None,
    /// 1-based line number.
    Line(u64),
    /// Byte offset from the start of the (decompressed) file.
    Offset(u64),
}

/// The fields shared by every event of a run.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RunHeader<'a> {
    pub host: &'a str,
    pub artifact: &'a str,
    pub source_path: &'a str,
}

/// One timeline row, minus the run header.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TimelineEvent<'a> {
    pub ts: Timestamp,
    pub loc: Loc,
    /// What the timestamp means: `login`, `modified`, `installed`.
    pub kind: &'a str,
    pub message: &'a str,
    /// Sigma rule title and level; empty for parsed artifacts.
    pub rule: &'a str,
    pub level: &'a str,
}

/// Collects encoded events in memory until they are sorted and written as a run.
#[derive(Default)]
pub struct EventBuffer {
    data: Vec<u8>,
    /// `(timestamp, offset into data)`; sorting this sorts the run.
    index: Vec<(i64, u32)>,
    /// True once an event arrived with an earlier time than the one before it.
    unsorted: bool,
}

impl EventBuffer {
    pub fn len(&self) -> usize {
        self.index.len()
    }

    pub fn is_empty(&self) -> bool {
        self.index.is_empty()
    }

    /// Bytes held in memory; the sink spills a run when this passes its budget.
    pub fn bytes(&self) -> usize {
        self.data.len()
    }

    pub fn push(&mut self, event: &TimelineEvent) {
        self.unsorted |= self.index.last().is_some_and(|&(last, _)| event.ts.utc < last);
        self.index.push((event.ts.utc, self.data.len() as u32));
        let (loc_kind, loc) = match event.loc {
            Loc::None => (0u8, 0),
            Loc::Line(n) => (1, n),
            Loc::Offset(n) => (2, n),
        };
        let out = &mut self.data;
        out.extend_from_slice(&event.ts.utc.to_le_bytes());
        out.extend_from_slice(&[event.ts.precision as u8, event.ts.basis as u8, loc_kind]);
        out.extend_from_slice(&loc.to_le_bytes());
        put_short(out, event.kind);
        // Messages are capped; with the sink's spill budget the u32 offsets cannot overflow.
        let message = truncate(event.message, 1 << 20);
        out.extend_from_slice(&(message.len() as u32).to_le_bytes());
        out.extend_from_slice(message.as_bytes());
        put_short(out, event.rule);
        put_short(out, event.level);
    }

    /// Writes the buffered events as one sorted run and empties the buffer.
    ///
    /// Logs arrive in time order already, so the usual case writes the buffer as it is. Only
    /// out-of-order input pays for a sort and a reordering copy.
    pub fn write_run(&mut self, header: &RunHeader, out: &mut impl Write) -> io::Result<()> {
        out.write_all(MAGIC)?;
        for text in [header.host, header.artifact, header.source_path] {
            out.write_all(&(text.len() as u32).to_le_bytes())?;
            out.write_all(text.as_bytes())?;
        }
        if self.unsorted {
            let ends: Vec<u32> =
                self.index.iter().skip(1).map(|&(_, start)| start).chain([self.data.len() as u32]).collect();
            let mut order: Vec<u32> = (0..self.index.len() as u32).collect();
            // Stable, so events with equal timestamps keep their source order.
            order.sort_by_key(|&i| self.index[i as usize].0);
            let mut sorted = Vec::with_capacity(self.data.len());
            let mut index = Vec::with_capacity(self.index.len());
            for i in order {
                let (ts, start) = self.index[i as usize];
                index.push((ts, sorted.len() as u32));
                sorted.extend_from_slice(&self.data[start as usize..ends[i as usize] as usize]);
            }
            self.data = sorted;
            self.index = index;
        }
        out.write_all(&self.data)?;

        // The sparse index: the first event at or after each stride boundary.
        let mut samples = Vec::new();
        let mut next_boundary = 0usize;
        for &(ts, offset) in &self.index {
            if offset as usize >= next_boundary {
                samples.extend_from_slice(&ts.to_le_bytes());
                samples.extend_from_slice(&u64::from(offset).to_le_bytes());
                next_boundary = offset as usize + INDEX_STRIDE;
            }
        }
        let entries = (samples.len() / 16) as u64;
        samples.extend_from_slice(&entries.to_le_bytes());
        samples.extend_from_slice(&(self.data.len() as u64).to_le_bytes());
        samples.extend_from_slice(&self.index.last().map_or(i64::MIN, |&(ts, _)| ts).to_le_bytes());
        samples.extend_from_slice(INDEX_MAGIC);
        out.write_all(&samples)?;

        self.data.clear();
        self.index.clear();
        self.unsorted = false;
        Ok(())
    }
}

fn truncate(text: &str, max: usize) -> &str {
    if text.len() <= max {
        return text;
    }
    let mut end = max;
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    &text[..end]
}

fn put_short(out: &mut Vec<u8>, text: &str) {
    let text = truncate(text, u16::MAX as usize);
    out.extend_from_slice(&(text.len() as u16).to_le_bytes());
    out.extend_from_slice(text.as_bytes());
}

fn corrupt() -> Error {
    Error::format("corrupt timeline run")
}

fn take<'a>(rest: &mut &'a [u8], n: usize) -> Result<&'a [u8]> {
    if rest.len() < n {
        return Err(corrupt());
    }
    let (head, tail) = rest.split_at(n);
    *rest = tail;
    Ok(head)
}

fn take_str<'a>(rest: &mut &'a [u8], len_bytes: usize) -> Result<&'a str> {
    let raw = take(rest, len_bytes)?;
    let len = raw.iter().rev().fold(0usize, |acc, &b| acc << 8 | b as usize);
    std::str::from_utf8(take(rest, len)?).map_err(|_| corrupt())
}

fn u64_at(data: &[u8], at: usize) -> Result<u64> {
    let bytes = data.get(at..at.checked_add(8).ok_or_else(corrupt)?).ok_or_else(corrupt)?;
    Ok(u64::from_le_bytes(bytes.try_into().map_err(|_| corrupt())?))
}

/// One run read back from disk. Every read is bounds-checked: run files may be truncated or
/// corrupt, and that must be an error, never a panic.
pub struct Run<'a> {
    pub header: RunHeader<'a>,
    events: &'a [u8],
    /// `(timestamp, offset into events)`, ascending.
    samples: Vec<(i64, usize)>,
    /// The time of the last event, so a partition can skip runs that end before it.
    last_ts: i64,
}

impl<'a> Run<'a> {
    pub fn parse(data: &'a [u8]) -> Result<Self> {
        let mut rest = data;
        if take(&mut rest, MAGIC.len())? != MAGIC {
            return Err(Error::format("not a timeline run"));
        }
        let host = take_str(&mut rest, 4)?;
        let artifact = take_str(&mut rest, 4)?;
        let source_path = take_str(&mut rest, 4)?;

        let footer = rest.len().checked_sub(32).ok_or_else(corrupt)?;
        if &rest[footer + 24..] != INDEX_MAGIC {
            return Err(corrupt());
        }
        let entries = usize::try_from(u64_at(rest, footer)?).map_err(|_| corrupt())?;
        let events_len = usize::try_from(u64_at(rest, footer + 8)?).map_err(|_| corrupt())?;
        let last_ts = u64_at(rest, footer + 16)? as i64;
        let index_len = entries.checked_mul(16).ok_or_else(corrupt)?;
        if events_len.checked_add(index_len) != Some(footer) {
            return Err(corrupt());
        }
        let events = &rest[..events_len];
        let mut samples = Vec::with_capacity(entries);
        for i in 0..entries {
            let at = events_len + i * 16;
            let offset = usize::try_from(u64_at(rest, at + 8)?).map_err(|_| corrupt())?;
            let ts = u64_at(rest, at)? as i64;
            let in_order = samples.last().is_none_or(|&(last_ts, last_offset)| last_ts <= ts && last_offset < offset);
            if offset >= events_len || !in_order {
                return Err(corrupt());
            }
            samples.push((ts, offset));
        }
        Ok(Self { header: RunHeader { host, artifact, source_path }, events, samples, last_ts })
    }

    /// The event at `*pos`, advancing `*pos` past it.
    fn event_at(&self, pos: &mut usize) -> Result<TimelineEvent<'a>> {
        let mut rest = self.events.get(*pos..).ok_or_else(corrupt)?;
        let before = rest.len();
        let fixed = take(&mut rest, EVENT_FIXED)?;
        let utc = i64::from_le_bytes(fixed[0..8].try_into().map_err(|_| corrupt())?);
        let precision = Precision::from_u8(fixed[8]).ok_or_else(corrupt)?;
        let basis = Basis::from_u8(fixed[9]).ok_or_else(corrupt)?;
        let loc_value = u64::from_le_bytes(fixed[11..19].try_into().map_err(|_| corrupt())?);
        let loc = match fixed[10] {
            0 => Loc::None,
            1 => Loc::Line(loc_value),
            2 => Loc::Offset(loc_value),
            _ => return Err(corrupt()),
        };
        let event = TimelineEvent {
            ts: Timestamp::new(utc, precision, basis),
            loc,
            kind: take_str(&mut rest, 2)?,
            message: take_str(&mut rest, 4)?,
            rule: take_str(&mut rest, 2)?,
            level: take_str(&mut rest, 2)?,
        };
        *pos += before - rest.len();
        Ok(event)
    }

    /// The offset of the first event at or after `ts`: the index finds the stride, a short
    /// scan finds the event.
    fn position(&self, ts: i64) -> Result<usize> {
        let after = self.samples.partition_point(|&(sample, _)| sample < ts);
        let Some(&(_, mut pos)) = after.checked_sub(1).and_then(|i| self.samples.get(i)) else { return Ok(0) };
        while pos < self.events.len() {
            let mut next = pos;
            if self.event_at(&mut next)?.ts.utc >= ts {
                break;
            }
            pos = next;
        }
        Ok(pos)
    }

    /// Where a cut falls in this run, which is run number `index`. Events are ordered by
    /// `(time, run, offset)`, so at the cut's own instant, earlier runs lie wholly before the
    /// cut and later runs wholly after it. That lets a cut split any number of events that
    /// share one timestamp.
    fn cut_position(&self, index: usize, cut: Cut) -> Result<usize> {
        match index.cmp(&cut.run) {
            std::cmp::Ordering::Less => {
                cut.ts.checked_add(1).map_or(Ok(self.events.len()), |after| self.position(after))
            }
            std::cmp::Ordering::Equal => Ok(cut.offset),
            std::cmp::Ordering::Greater => self.position(cut.ts),
        }
    }

    /// All events in order.
    pub fn events(&self) -> impl Iterator<Item = Result<TimelineEvent<'a>>> + '_ {
        let mut pos = 0;
        std::iter::from_fn(move || (pos < self.events.len()).then(|| self.event_at(&mut pos)))
    }
}

/// A point in the merged order where one partition ends and the next begins: an index entry
/// of one of the runs.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct Cut {
    ts: i64,
    run: usize,
    offset: usize,
}

pub const TIMELINE_COLUMNS: &str =
    "timestamp,precision,basis,host,artifact,event,message,source_path,source_line,source_offset,rule,level";

/// The parts of a row that are the same for every event of a run, formatted once.
struct RowParts {
    /// Goes between the basis and the event kind.
    origin: Vec<u8>,
    /// Goes between the message and the location.
    path: Vec<u8>,
}

impl RowParts {
    fn new(header: &RunHeader, format: Format) -> Self {
        let (mut origin, mut path) = (Vec::new(), Vec::new());
        if format == Format::Csv {
            origin.push(b',');
            csv_field(&mut origin, header.host.as_bytes());
            origin.push(b',');
            csv_field(&mut origin, header.artifact.as_bytes());
            origin.push(b',');
            path.push(b',');
            csv_field(&mut path, header.source_path.as_bytes());
            path.push(b',');
        } else {
            origin.extend_from_slice(b",\"host\":");
            json_str(&mut origin, header.host);
            origin.extend_from_slice(b",\"artifact\":");
            json_str(&mut origin, header.artifact);
            origin.extend_from_slice(b",\"event\":");
            path.extend_from_slice(b",\"source_path\":");
            json_str(&mut path, header.source_path);
        }
        Self { origin, path }
    }
}

/// Merges sorted runs into one timeline, on up to `threads` threads. Ties keep the order of
/// `runs`, so the output is the same for a given input order whatever the thread count.
/// Returns the number of rows written.
pub fn merge(runs: &[&[u8]], format: Format, threads: usize, out: &mut (impl Write + Send)) -> Result<u64> {
    let runs = runs.iter().map(|data| Run::parse(data)).collect::<Result<Vec<_>>>()?;
    let parts: Vec<RowParts> = runs.iter().map(|run| RowParts::new(&run.header, format)).collect();

    // Cut every run at the same points, chosen from the runs' own index entries so that
    // each partition holds a similar amount of data.
    let mut samples: Vec<Cut> = runs
        .iter()
        .enumerate()
        .flat_map(|(run, r)| r.samples.iter().map(move |&(ts, offset)| Cut { ts, run, offset }))
        .collect();
    samples.sort_unstable();
    let cuts: Vec<Cut> = samples.iter().copied().skip(PARTITION_SAMPLES).step_by(PARTITION_SAMPLES).collect();
    let partitions = cuts.len() + 1;

    match format {
        Format::Csv => writeln!(out, "{TIMELINE_COLUMNS}")?,
        Format::Json => out.write_all(b"[")?,
        Format::Jsonl => {}
    }
    let next = AtomicUsize::new(0);
    let writer =
        Mutex::new(OrderedWriter { out, next: 0, pending: BTreeMap::new(), rows: 0, wrote: false, error: None });
    let ready = Condvar::new();
    let workers = threads.clamp(1, partitions);
    thread::scope(|scope| {
        for _ in 0..workers {
            scope.spawn(|| loop {
                let partition = next.fetch_add(1, Ordering::Relaxed);
                if partition >= partitions {
                    return;
                }
                // Do not run far ahead of the writer: finished partitions wait in memory.
                let mut state = writer.lock().unwrap_or_else(|e| e.into_inner());
                while state.error.is_none() && partition >= state.next + 2 * workers {
                    state = ready.wait(state).unwrap_or_else(|e| e.into_inner());
                }
                if state.error.is_some() {
                    return;
                }
                drop(state);

                let from = partition.checked_sub(1).map(|i| cuts[i]);
                let to = cuts.get(partition).copied();
                // A panic here must not leave the other workers waiting for this partition.
                let merged = panic::catch_unwind(AssertUnwindSafe(|| merge_partition(&runs, &parts, format, from, to)));
                let result = merged.unwrap_or_else(|_| Err(Error::format("the timeline merge panicked")));
                let mut state = writer.lock().unwrap_or_else(|e| e.into_inner());
                match result {
                    Ok(done) => state.accept(partition, done, format),
                    Err(e) => state.error = Some(e),
                }
                ready.notify_all();
            });
        }
    });
    let state = writer.into_inner().unwrap_or_else(|e| e.into_inner());
    if let Some(error) = state.error {
        return Err(error);
    }
    if format == Format::Json {
        state.out.write_all(b"]\n")?;
    }
    Ok(state.rows)
}

/// Writes finished partitions in order, holding those that finish early.
struct OrderedWriter<'w, W> {
    out: &'w mut W,
    next: usize,
    pending: BTreeMap<usize, (Vec<u8>, u64)>,
    rows: u64,
    wrote: bool,
    error: Option<Error>,
}

impl<W: Write> OrderedWriter<'_, W> {
    fn accept(&mut self, partition: usize, done: (Vec<u8>, u64), format: Format) {
        self.pending.insert(partition, done);
        while let Some((bytes, rows)) = self.pending.remove(&self.next) {
            self.next += 1;
            self.rows += rows;
            // In a JSON array every row was written with a leading separator; the first row
            // of the whole output drops it.
            let skip = if format == Format::Json && !self.wrote && !bytes.is_empty() { 2 } else { 0 };
            self.wrote |= !bytes.is_empty();
            if let Err(e) = self.out.write_all(&bytes[skip..]) {
                self.error = Some(e.into());
                return;
            }
        }
    }
}

/// Merges the events between two cuts of every run into formatted rows.
fn merge_partition(
    runs: &[Run],
    parts: &[RowParts],
    format: Format,
    from: Option<Cut>,
    to: Option<Cut>,
) -> Result<(Vec<u8>, u64)> {
    // Per run: the next event's offset, and where this partition ends.
    let mut cursors = Vec::with_capacity(runs.len());
    let mut heap = BinaryHeap::new();
    let mut current = Vec::with_capacity(runs.len());
    for (i, run) in runs.iter().enumerate() {
        // Most runs do not reach into most partitions; those cost nothing here.
        let first_ts = run.samples.first().map(|&(ts, _)| ts);
        let outside = first_ts.is_none_or(|first| to.is_some_and(|cut| first > cut.ts))
            || from.is_some_and(|cut| run.last_ts < cut.ts);
        let (mut pos, end) = if outside {
            (0, 0)
        } else {
            let start = from.map_or(Ok(0), |cut| run.cut_position(i, cut))?;
            (start, to.map_or(Ok(run.events.len()), |cut| run.cut_position(i, cut))?)
        };
        let event = if pos < end { Some(run.event_at(&mut pos)?) } else { None };
        if let Some(event) = &event {
            heap.push(Reverse((event.ts.utc, i)));
        }
        current.push(event);
        cursors.push((pos, end));
    }

    let (low, high) = (from.map_or(i64::MIN, |cut| cut.ts), to.map_or(i64::MAX, |cut| cut.ts));
    let mut out = Vec::new();
    let mut rows = 0u64;
    while let Some(Reverse((ts, i))) = heap.pop() {
        let Some(event) = current[i].take() else { continue };
        // A run whose events are not in the order its index claims would silently misorder
        // the timeline; that is corruption, not data.
        if ts < low || ts > high {
            return Err(Error::format("timeline run is not sorted"));
        }
        write_row(&mut out, format, &parts[i], &event);
        rows += 1;
        let (pos, end) = &mut cursors[i];
        if *pos < *end {
            let next = runs[i].event_at(pos)?;
            if next.ts.utc < ts {
                return Err(Error::format("timeline run is not sorted"));
            }
            heap.push(Reverse((next.ts.utc, i)));
            current[i] = Some(next);
        }
    }
    Ok((out, rows))
}

fn write_row(out: &mut Vec<u8>, format: Format, parts: &RowParts, event: &TimelineEvent) {
    let mut time = [0u8; 30];
    let time_len = event.ts.format(&mut time);
    let time = &time[..time_len];
    let (line, offset) = match event.loc {
        Loc::None => (None, None),
        Loc::Line(n) => (Some(n), None),
        Loc::Offset(n) => (None, Some(n)),
    };
    let mut number = itoa::Buffer::new();
    if format == Format::Csv {
        out.extend_from_slice(time);
        out.push(b',');
        out.extend_from_slice(event.ts.precision.as_str().as_bytes());
        out.push(b',');
        out.extend_from_slice(event.ts.basis.as_str().as_bytes());
        out.extend_from_slice(&parts.origin);
        csv_field(out, event.kind.as_bytes());
        out.push(b',');
        csv_field(out, event.message.as_bytes());
        out.extend_from_slice(&parts.path);
        if let Some(n) = line {
            out.extend_from_slice(number.format(n).as_bytes());
        }
        out.push(b',');
        if let Some(n) = offset {
            out.extend_from_slice(number.format(n).as_bytes());
        }
        out.push(b',');
        csv_field(out, event.rule.as_bytes());
        out.push(b',');
        csv_field(out, event.level.as_bytes());
        out.push(b'\n');
        return;
    }
    if format == Format::Json {
        out.extend_from_slice(b",\n");
    }
    out.extend_from_slice(b"{\"timestamp\":\"");
    out.extend_from_slice(time);
    out.extend_from_slice(b"\",\"precision\":\"");
    out.extend_from_slice(event.ts.precision.as_str().as_bytes());
    out.extend_from_slice(b"\",\"basis\":\"");
    out.extend_from_slice(event.ts.basis.as_str().as_bytes());
    out.push(b'"');
    out.extend_from_slice(&parts.origin);
    json_str(out, event.kind);
    out.extend_from_slice(b",\"message\":");
    json_str(out, event.message);
    out.extend_from_slice(&parts.path);
    for (key, value) in [(&b",\"source_line\":"[..], line), (b",\"source_offset\":", offset)] {
        out.extend_from_slice(key);
        match value {
            Some(n) => out.extend_from_slice(number.format(n).as_bytes()),
            None => out.extend_from_slice(b"null"),
        }
    }
    out.extend_from_slice(b",\"rule\":");
    json_str(out, event.rule);
    out.extend_from_slice(b",\"level\":");
    json_str(out, event.level);
    out.push(b'}');
    if format == Format::Jsonl {
        out.push(b'\n');
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event(secs: i64, message: &str) -> TimelineEvent<'_> {
        TimelineEvent {
            ts: Timestamp::from_secs(secs, Basis::Recorded),
            loc: Loc::Line(secs as u64),
            kind: "login",
            message,
            rule: "",
            level: "",
        }
    }

    fn run(source: &str, events: &[(i64, &str)]) -> Vec<u8> {
        let mut buffer = EventBuffer::default();
        for &(secs, message) in events {
            buffer.push(&event(secs, message));
        }
        let mut out = Vec::new();
        buffer.write_run(&RunHeader { host: "web01", artifact: "wtmp", source_path: source }, &mut out).unwrap();
        assert!(buffer.is_empty());
        out
    }

    fn merged(runs: &[&[u8]], format: Format, threads: usize) -> String {
        let mut out = Vec::new();
        merge(runs, format, threads, &mut out).unwrap();
        String::from_utf8(out).unwrap()
    }

    #[test]
    fn round_trips_events_in_time_order() {
        let data = run("var/log/wtmp", &[(30, "c"), (10, "a, with comma"), (20, "b")]);
        let parsed = Run::parse(&data).unwrap();
        assert_eq!(parsed.header.source_path, "var/log/wtmp");
        let seen: Vec<_> =
            parsed.events().map(|e| e.unwrap()).map(|e| (e.ts.utc / 1_000_000_000, e.message, e.loc)).collect();
        assert_eq!(
            seen,
            vec![(10, "a, with comma", Loc::Line(10)), (20, "b", Loc::Line(20)), (30, "c", Loc::Line(30))]
        );
    }

    #[test]
    fn merges_runs_and_breaks_ties_by_run_order() {
        let a = run("a", &[(1, "a1"), (5, "a5")]);
        let b = run("b", &[(1, "b1"), (3, "b3")]);
        let text = merged(&[&a, &b], Format::Csv, 1);
        let messages: Vec<&str> = text.lines().skip(1).map(|l| l.split(',').nth(6).unwrap()).collect();
        assert_eq!(messages, ["a1", "b1", "b3", "a5"]);
        assert!(text.starts_with(TIMELINE_COLUMNS));
        assert!(text.contains("1970-01-01T00:00:03Z,seconds,recorded,web01,wtmp,login,b3,b,3,,,"));
    }

    #[test]
    fn json_output_is_valid() {
        let a = run("a", &[(1, "quote \" here"), (2, "x")]);
        let rows: Vec<serde_json::Value> = serde_json::from_str(&merged(&[&a], Format::Json, 1)).unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0]["message"], "quote \" here");
        assert_eq!(rows[0]["source_line"], 1);
        assert!(rows[0]["source_offset"].is_null());
        assert_eq!((rows[0]["host"].as_str(), rows[0]["event"].as_str()), (Some("web01"), Some("login")));
        let lines = merged(&[&a], Format::Jsonl, 1);
        assert_eq!(lines.lines().filter(|l| serde_json::from_str::<serde_json::Value>(l).is_ok()).count(), 2);
    }

    /// Enough events to span many index strides and partitions, with heavy ties and
    /// out-of-order input: every thread count must give byte-identical output.
    #[test]
    fn parallel_merge_equals_sequential_merge() {
        let mut state = 0x2545_f491_4f6c_dd1du64;
        let mut random = move || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        let padding = "x".repeat(700);
        let runs: Vec<Vec<u8>> = (0..5)
            .map(|r| {
                let mut buffer = EventBuffer::default();
                for n in 0..30_000u64 {
                    // Run 0 is strictly ordered; the others jitter and repeat timestamps.
                    let secs = if r == 0 { n as i64 } else { (random() % 3_000) as i64 * 10 };
                    let message = format!("run {r} event {n} {padding}");
                    buffer.push(&event(secs, &message));
                }
                let mut out = Vec::new();
                let source = format!("src{r}");
                buffer.write_run(&RunHeader { host: "h", artifact: "a", source_path: &source }, &mut out).unwrap();
                out
            })
            .collect();
        let slices: Vec<&[u8]> = runs.iter().map(|r| &r[..]).collect();
        assert!(Run::parse(slices[0]).unwrap().samples.len() > 200, "the test must span many strides");
        for format in [Format::Csv, Format::Json, Format::Jsonl] {
            let one = merged(&slices, format, 1);
            assert_eq!(one.lines().count(), 150_000 + usize::from(format == Format::Csv));
            for threads in [2, 8] {
                assert!(one == merged(&slices, format, threads), "{format:?} differs with {threads} threads");
            }
        }
        let rows: Vec<serde_json::Value> = serde_json::from_str(&merged(&slices, Format::Json, 8)).unwrap();
        let times: Vec<&str> = rows.iter().map(|r| r["timestamp"].as_str().unwrap()).collect();
        assert!(times.windows(2).all(|w| w[0] <= w[1]), "the merged timeline is ordered");
    }

    /// One timestamp shared by every event must still split into many partitions, or the
    /// merge would hold the whole output in memory.
    #[test]
    fn equal_timestamps_are_split_across_partitions() {
        let padding = "y".repeat(900);
        let runs: Vec<Vec<u8>> = (0..3)
            .map(|r| {
                let mut buffer = EventBuffer::default();
                for n in 0..20_000 {
                    buffer.push(&event(42, &format!("run {r} event {n} {padding}")));
                }
                let mut out = Vec::new();
                let source = format!("src{r}");
                buffer.write_run(&RunHeader { host: "h", artifact: "a", source_path: &source }, &mut out).unwrap();
                out
            })
            .collect();
        let slices: Vec<&[u8]> = runs.iter().map(|r| &r[..]).collect();
        let one = merged(&slices, Format::Jsonl, 1);
        assert_eq!(one.lines().count(), 60_000);
        assert!(one == merged(&slices, Format::Jsonl, 8));
        // Ties keep run order, then source order.
        let position = |needle: &str| one.find(needle).unwrap();
        assert!(position("run 0 event 19999 ") < position("run 1 event 0 "));
        assert!(position("run 1 event 7 ") < position("run 1 event 8 "));

        let parsed: Vec<Run> = slices.iter().map(|data| Run::parse(data).unwrap()).collect();
        let (ts, offset) = parsed[1].samples[5];
        let cut = Cut { ts, run: 1, offset };
        assert_eq!(parsed[0].cut_position(0, cut).unwrap(), parsed[0].events.len());
        assert_eq!(parsed[1].cut_position(1, cut).unwrap(), cut.offset);
        assert_eq!(parsed[2].cut_position(2, cut).unwrap(), 0);
    }

    #[test]
    fn corrupt_runs_are_errors_not_panics() {
        let data = run("a", &[(1, "one"), (2, "two")]);
        assert!(Run::parse(b"garbage!").is_err());
        for cut in 0..data.len() {
            assert!(merge(&[&data[..cut]], Format::Jsonl, 2, &mut Vec::new()).is_err(), "cut at {cut}");
        }
        let mut state = 7u64;
        for _ in 0..2_000 {
            state = state.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
            let mut copy = data.clone();
            copy[(state >> 33) as usize % data.len()] ^= (state >> 20) as u8 | 1;
            let _ = merge(&[&copy], Format::Csv, 2, &mut Vec::new());
        }
    }

    #[test]
    fn empty_merge_writes_only_the_frame() {
        assert_eq!(merged(&[], Format::Json, 4), "[]\n");
        let empty = run("a", &[]);
        assert_eq!(merged(&[&empty], Format::Json, 4), "[]\n");
        assert_eq!(merged(&[&empty], Format::Csv, 1), format!("{TIMELINE_COLUMNS}\n"));
    }
}
