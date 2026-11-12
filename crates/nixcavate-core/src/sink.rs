//! The sink receives records from a parser and owns all output for one task: the record file
//! and the task's sorted timeline runs. Parsers never touch files or formats.

use crate::error::{Error, Result};
use crate::row::{self, csv_field, json_str, Format};
use crate::run::{EventBuffer, Loc, RunHeader, TimelineEvent};
use crate::time::Timestamp;
use serde::Serialize;
use std::borrow::Cow;
use std::fs::{self, File};
use std::io::{self, Write};
use std::path::PathBuf;

/// One timeline entry derived from a record.
pub struct Event<'a> {
    pub ts: Timestamp,
    /// What the timestamp means: `login`, `modified`, `installed`.
    pub kind: &'static str,
    pub message: Cow<'a, str>,
}

impl<'a> Event<'a> {
    pub fn new(ts: Timestamp, kind: &'static str, message: impl Into<Cow<'a, str>>) -> Self {
        Self { ts, kind, message: message.into() }
    }
}

/// A parsed row. The timeline mapping lives next to the record type.
pub trait Record: Serialize {
    /// The timeline events of this record. Records with no timestamp keep the default.
    fn events(&self) -> impl Iterator<Item = Event<'_>> {
        std::iter::empty()
    }
}

/// Where a sink writes its records.
pub enum Target {
    /// Created on the first record, so empty inputs leave no file behind.
    File(PathBuf),
    Stdout,
    /// Kept in memory and returned by [`Sink::finish`]; used by tests.
    Memory,
}

/// What a finished task produced.
#[derive(Debug, Default)]
pub struct Summary {
    pub records: u64,
    pub events: u64,
    /// The earliest and latest event times, so a partly parsed input shows what it covers.
    pub first_event: Option<Timestamp>,
    pub last_event: Option<Timestamp>,
    pub outputs: Vec<PathBuf>,
    pub runs: Vec<PathBuf>,
    pub warnings: Vec<String>,
    /// The records, for [`Target::Memory`].
    pub memory: Vec<u8>,
    /// The timeline run, when no run path was given.
    pub memory_run: Vec<u8>,
}

/// Record bytes buffered before a write.
const FLUSH_BYTES: usize = 256 << 10;
/// Event bytes buffered before a sorted run is spilled to disk.
const SPILL_BYTES: usize = 16 << 20;
const MAX_WARNINGS: usize = 20;

/// Creates an output file, refusing to replace one. Two tasks can never share an output
/// name; if a file is already there, something is wrong and overwriting would hide it.
fn create_new(path: &std::path::Path) -> io::Result<File> {
    fs::OpenOptions::new().write(true).create_new(true).open(path)
}

pub struct Sink {
    format: Format,
    host: String,
    artifact: &'static str,
    source_path: String,
    /// The leading cells or keys shared by every row of this task.
    prefix: Vec<u8>,
    /// Prebuilt `,"name":` fragments for the record type, in field order.
    json_keys: Vec<Vec<u8>>,
    /// The JSON key of the location column, known once the first record arrives.
    loc_key: Vec<u8>,
    /// True once the header or opening bracket has been written.
    started: bool,
    target: Target,
    file: Option<File>,
    buf: Vec<u8>,
    /// Length of `buf` up to the last complete row.
    committed: usize,
    records: u64,
    events: EventBuffer,
    event_count: u64,
    /// Runs are written to `<run_base>.<n>.run`. `None` keeps the run in memory.
    run_base: Option<PathBuf>,
    keep_events: bool,
    summary: Summary,
    dropped_warnings: u64,
}

impl Sink {
    pub fn new(
        host: &str,
        artifact: &'static str,
        source_path: &str,
        format: Format,
        target: Target,
        run_base: Option<PathBuf>,
    ) -> Self {
        let mut prefix = Vec::new();
        if format == Format::Csv {
            for text in [host, artifact, source_path] {
                csv_field(&mut prefix, text.as_bytes());
                prefix.push(b',');
            }
        } else {
            prefix.extend_from_slice(b"{\"host\":");
            json_str(&mut prefix, host);
            prefix.extend_from_slice(b",\"artifact\":");
            json_str(&mut prefix, artifact);
            prefix.extend_from_slice(b",\"source_path\":");
            json_str(&mut prefix, source_path);
        }
        Self {
            format,
            host: host.to_string(),
            artifact,
            source_path: source_path.to_string(),
            prefix,
            json_keys: Vec::new(),
            loc_key: Vec::new(),
            started: false,
            target,
            file: None,
            buf: Vec::with_capacity(FLUSH_BYTES + (16 << 10)),
            committed: 0,
            records: 0,
            events: EventBuffer::default(),
            event_count: 0,
            run_base,
            keep_events: true,
            summary: Summary::default(),
            dropped_warnings: 0,
        }
    }

    /// Drops timeline events instead of collecting them, for one-off parses with no timeline.
    pub fn without_events(mut self) -> Self {
        self.keep_events = false;
        self
    }

    /// An in-memory sink for tests and one-off parsing.
    pub fn memory(host: &str, artifact: &'static str, source_path: &str, format: Format) -> Self {
        Self::new(host, artifact, source_path, format, Target::Memory, None)
    }

    /// Writes one record and its timeline events.
    ///
    /// Within one task every call must use the same `Loc` variant: it names a CSV column.
    pub fn emit<R: Record>(&mut self, at: Loc, record: &R) -> Result<()> {
        let row_error = |e: row::RowError| Error::format(format!("record serialization: {e}"));

        // A failed or panicking emit must not leave half a row behind.
        self.buf.truncate(self.committed);
        if !self.started {
            self.start(at, record).map_err(row_error)?;
            // The frame is kept even if this first row then fails.
            self.started = true;
            self.committed = self.buf.len();
        }
        if self.format == Format::Json && self.records > 0 {
            self.buf.extend_from_slice(b",\n");
        }
        self.buf.extend_from_slice(&self.prefix);
        self.buf.extend_from_slice(&self.loc_key);
        match at {
            Loc::Line(n) | Loc::Offset(n) => self.buf.extend_from_slice(itoa::Buffer::new().format(n).as_bytes()),
            Loc::None if self.format == Format::Csv => {}
            Loc::None => self.buf.extend_from_slice(b"null"),
        }
        row::write_fields(record, self.format, &self.json_keys, &mut self.buf).map_err(row_error)?;
        match self.format {
            Format::Csv => self.buf.push(b'\n'),
            Format::Jsonl => self.buf.extend_from_slice(b"}\n"),
            Format::Json => self.buf.push(b'}'),
        }
        self.records += 1;
        self.committed = self.buf.len();

        // Building events costs a formatted message each, so it is skipped when unwanted.
        if self.keep_events {
            for event in record.events() {
                self.events.push(&TimelineEvent {
                    ts: event.ts,
                    loc: at,
                    kind: event.kind,
                    message: &event.message,
                    rule: "",
                    level: "",
                });
                self.event_count += 1;
                let (first, last) = (&mut self.summary.first_event, &mut self.summary.last_event);
                if first.is_none_or(|t| event.ts.utc < t.utc) {
                    *first = Some(event.ts);
                }
                if last.is_none_or(|t| event.ts.utc > t.utc) {
                    *last = Some(event.ts);
                }
            }
        }
        if self.events.bytes() >= SPILL_BYTES && self.run_base.is_some() {
            self.spill_run()?;
        }
        if self.buf.len() >= FLUSH_BYTES {
            self.flush()?;
        }
        Ok(())
    }

    /// Runs once, on the first record: learns the record's field names, rejects reserved
    /// ones, and writes whatever the format puts in front of the first row.
    fn start<R: Record>(&mut self, at: Loc, record: &R) -> std::result::Result<(), row::RowError> {
        let loc_name = if matches!(at, Loc::Offset(_)) { "source_offset" } else { "source_line" };
        match self.format {
            Format::Csv => {
                let mut header = b"host,artifact,source_path,".to_vec();
                header.extend_from_slice(loc_name.as_bytes());
                row::write_csv_header(record, &mut header)?;
                header.push(b'\n');
                self.buf.extend_from_slice(&header);
            }
            Format::Json | Format::Jsonl => {
                self.json_keys = row::json_keys(record)?;
                self.loc_key = format!(",\"{loc_name}\":").into_bytes();
                if self.format == Format::Json {
                    self.buf.push(b'[');
                }
            }
        }
        Ok(())
    }

    /// Notes a problem that did not stop the parse. Shown in the manifest.
    pub fn warn(&mut self, message: impl Into<String>) {
        if self.summary.warnings.len() < MAX_WARNINGS {
            self.summary.warnings.push(message.into());
        } else {
            self.dropped_warnings += 1;
        }
    }

    pub fn records(&self) -> u64 {
        self.records
    }

    fn flush(&mut self) -> io::Result<()> {
        match &self.target {
            Target::Memory => return Ok(()),
            Target::Stdout => {}
            Target::File(path) => {
                if self.file.is_none() {
                    if let Some(parent) = path.parent() {
                        fs::create_dir_all(parent)?;
                    }
                    self.file = Some(create_new(path)?);
                    self.summary.outputs.push(path.clone());
                }
            }
        }
        let written = match (&self.target, &mut self.file) {
            (Target::Stdout, _) => io::stdout().lock().write_all(&self.buf),
            (_, Some(file)) => file.write_all(&self.buf),
            _ => Ok(()),
        };
        // Cleared even on failure: a retry could write the same rows twice.
        self.buf.clear();
        self.committed = 0;
        written
    }

    fn spill_run(&mut self) -> io::Result<()> {
        let Some(base) = &self.run_base else { return Ok(()) };
        let mut name = base.clone().into_os_string();
        name.push(format!(".{}.run", self.summary.runs.len()));
        let path = PathBuf::from(name);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        // A run is written in a few large pieces, so the file needs no buffering.
        let header = RunHeader { host: &self.host, artifact: self.artifact, source_path: &self.source_path };
        self.events.write_run(&header, &mut create_new(&path)?)?;
        self.summary.runs.push(path);
        Ok(())
    }

    /// Flushes everything and reports what was written.
    pub fn finish(mut self) -> Result<Summary> {
        self.buf.truncate(self.committed);
        if self.format == Format::Json && self.started {
            self.buf.extend_from_slice(b"]\n");
        }
        if !self.buf.is_empty() {
            self.flush()?;
        }
        if !self.events.is_empty() {
            if self.run_base.is_some() {
                self.spill_run()?;
            } else {
                let header = RunHeader { host: &self.host, artifact: self.artifact, source_path: &self.source_path };
                self.events.write_run(&header, &mut self.summary.memory_run)?;
            }
        }
        if self.dropped_warnings > 0 {
            self.summary.warnings.push(format!("... and {} more warnings", self.dropped_warnings));
        }
        self.summary.records = self.records;
        self.summary.events = self.event_count;
        self.summary.memory = std::mem::take(&mut self.buf);
        Ok(self.summary)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::run::Run;
    use crate::time::Basis;

    #[derive(Serialize)]
    struct Login<'a> {
        user: &'a str,
        time: Timestamp,
    }

    impl Record for Login<'_> {
        fn events(&self) -> impl Iterator<Item = Event<'_>> {
            std::iter::once(Event::new(self.time, "login", format!("{} logged in", self.user)))
        }
    }

    fn fill(sink: &mut Sink) {
        for (line, user, secs) in [(1, "root", 20), (2, "o'brien, pat", 10)] {
            sink.emit(Loc::Line(line), &Login { user, time: Timestamp::from_secs(secs, Basis::Recorded) }).unwrap();
        }
    }

    fn render(format: Format) -> String {
        let mut sink = Sink::memory("web01", "wtmp", "var/log/wtmp", format);
        fill(&mut sink);
        String::from_utf8(sink.finish().unwrap().memory).unwrap()
    }

    #[test]
    fn csv_has_header_and_common_columns() {
        assert_eq!(
            render(Format::Csv),
            "host,artifact,source_path,source_line,user,time\n\
             web01,wtmp,var/log/wtmp,1,root,1970-01-01T00:00:20Z\n\
             web01,wtmp,var/log/wtmp,2,\"o'brien, pat\",1970-01-01T00:00:10Z\n"
        );
    }

    #[test]
    fn jsonl_rows_are_objects() {
        let text = render(Format::Jsonl);
        let rows: Vec<serde_json::Value> = text.lines().map(|l| serde_json::from_str(l).unwrap()).collect();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[1]["host"], "web01");
        assert_eq!(rows[1]["source_line"], 2);
        assert_eq!(rows[1]["user"], "o'brien, pat");
    }

    #[test]
    fn json_is_one_array() {
        let rows: Vec<serde_json::Value> = serde_json::from_str(&render(Format::Json)).unwrap();
        assert_eq!(rows.len(), 2);
    }

    #[test]
    fn events_come_out_sorted() {
        let mut sink = Sink::memory("web01", "wtmp", "var/log/wtmp", Format::Jsonl);
        fill(&mut sink);
        let summary = sink.finish().unwrap();
        assert_eq!((summary.records, summary.events), (2, 2));
        let span = (summary.first_event.unwrap().to_rfc3339(), summary.last_event.unwrap().to_rfc3339());
        assert_eq!(span, ("1970-01-01T00:00:10Z".to_string(), "1970-01-01T00:00:20Z".to_string()));
        let run = Run::parse(&summary.memory_run).unwrap();
        let first = run.events().next().unwrap().unwrap();
        assert_eq!((first.message, first.loc), ("o'brien, pat logged in", Loc::Line(2)));
    }

    /// A record whose nested value fails to serialize part-way through.
    #[derive(Serialize)]
    struct Fragile {
        n: u8,
        #[serde(serialize_with = "fail_when_odd")]
        tags: Vec<u8>,
    }

    impl Record for Fragile {}

    fn fail_when_odd<S: serde::Serializer>(tags: &[u8], s: S) -> std::result::Result<S::Ok, S::Error> {
        use serde::ser::{Error, SerializeSeq};
        let mut seq = s.serialize_seq(None)?;
        for tag in tags {
            seq.serialize_element(tag)?;
        }
        if tags.len() % 2 == 1 {
            return Err(S::Error::custom("odd"));
        }
        seq.end()
    }

    #[test]
    fn a_failed_row_leaves_no_trace_in_any_format() {
        for format in [Format::Csv, Format::Jsonl, Format::Json] {
            let mut sink = Sink::memory("h", "a", "p", format);
            // The very first row fails, then rows succeed and fail in turn.
            for (n, tags) in [(0, vec![9]), (1, vec![1, 2]), (2, vec![3]), (3, vec![]), (4, vec![5, 6, 7])] {
                let result = sink.emit(Loc::Line(n as u64), &Fragile { n, tags: tags.clone() });
                assert_eq!(result.is_ok(), tags.len() % 2 == 0);
            }
            let summary = sink.finish().unwrap();
            assert_eq!(summary.records, 2);
            let text = String::from_utf8(summary.memory).unwrap();
            match format {
                Format::Csv => assert_eq!(
                    text,
                    "host,artifact,source_path,source_line,n,tags\nh,a,p,1,1,\"[1,2]\"\nh,a,p,3,3,[]\n"
                ),
                Format::Jsonl => {
                    let rows: Vec<serde_json::Value> = text.lines().map(|l| serde_json::from_str(l).unwrap()).collect();
                    assert_eq!(
                        (rows.len(), rows[0]["source_line"].as_u64(), rows[1]["n"].as_u64()),
                        (2, Some(1), Some(3))
                    );
                }
                Format::Json => assert_eq!(serde_json::from_str::<Vec<serde_json::Value>>(&text).unwrap().len(), 2),
            }
        }
    }

    #[test]
    fn an_existing_output_file_is_never_replaced() {
        let dir = std::env::temp_dir().join(format!("nixcavate-sink-exists-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let out = dir.join("x.csv");
        fs::write(&out, "precious").unwrap();
        let mut sink = Sink::new("h", "wtmp", "p", Format::Csv, Target::File(out.clone()), None);
        fill(&mut sink);
        assert!(sink.finish().is_err());
        assert_eq!(fs::read_to_string(&out).unwrap(), "precious");
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn files_are_created_only_when_there_is_output() {
        let dir = std::env::temp_dir().join(format!("nixcavate-sink-test-{}", std::process::id()));
        let out = dir.join("Accounts/wtmp/x.csv");
        let sink = Sink::new("h", "wtmp", "p", Format::Csv, Target::File(out.clone()), Some(dir.join("runs/x")));
        assert!(sink.finish().unwrap().outputs.is_empty());
        assert!(!out.exists());

        let mut sink = Sink::new("h", "wtmp", "p", Format::Csv, Target::File(out.clone()), Some(dir.join("runs/x")));
        fill(&mut sink);
        sink.warn("odd entry");
        let summary = sink.finish().unwrap();
        assert_eq!(summary.outputs, vec![out.clone()]);
        assert_eq!(summary.runs, vec![dir.join("runs/x.0.run")]);
        assert_eq!(summary.warnings, vec!["odd entry"]);
        assert!(fs::read_to_string(&out).unwrap().ends_with("1970-01-01T00:00:10Z\n"));
        fs::remove_dir_all(&dir).unwrap();
    }
}
