//! The loop and record shared by line logs that start every entry with a date and time
//! (cloud-init, unattended-upgrades, the dnf debug logs, zypper). Each artifact supplies the
//! function that knows its own line format; this module only handles what they have in common:
//! lines that continue the previous entry (a traceback, a wrapped message) and the times.

use crate::text::{for_each_line, lossy};
use crate::Input;
use nixcavate_core::time::ParsedTime;
use nixcavate_core::{Basis, Error, Event, Loc, Record, Result, Sink, Timestamp};
use serde::Serialize;

/// One entry, as a format's line splitter found it.
pub struct Parsed<'a> {
    pub time: Option<Timestamp>,
    pub level: Option<&'a str>,
    /// The module, component or program that wrote the entry.
    pub source: Option<&'a str>,
    pub pid: Option<u32>,
    pub message: &'a str,
    /// False for entries too frequent to be timeline events (debug output).
    pub timeline: bool,
}

#[derive(Serialize)]
struct Entry<'a> {
    time: Option<Timestamp>,
    level: Option<&'a str>,
    source: Option<&'a str>,
    pid: Option<u32>,
    message: &'a str,
    #[serde(skip)]
    kind: &'static str,
    #[serde(skip)]
    timeline: bool,
}

impl Record for Entry<'_> {
    fn events(&self) -> impl Iterator<Item = Event<'_>> {
        let message = || crate::common::syslog::timeline_message(self.source.unwrap_or_default(), self.message);
        self.time.filter(|_| self.timeline).map(|t| Event::new(t, self.kind, message())).into_iter()
    }
}

/// A time as the log wrote it: with a zone it is recorded, without one the host zone is
/// assumed.
pub fn timestamp(input: &Input, parsed: &ParsedTime) -> Timestamp {
    match parsed.offset {
        Some(_) => Timestamp::from_secs_nanos(parsed.secs, parsed.nanos, parsed.precision, Basis::Recorded),
        None => input.local_time(parsed.secs, parsed.nanos, parsed.precision),
    }
}

/// Splits one line; `None` when it does not start an entry.
pub type Split = for<'a> fn(&Input, &'a str) -> Option<Parsed<'a>>;

/// One record per non-blank line. A line `split` does not recognise continues the entry before
/// it and is kept as a record with no time. A file whose first line is not an entry is not this
/// format at all (`what` names it in the error).
pub fn parse(input: &Input, sink: &mut Sink, what: &str, kind: &'static str, split: Split) -> Result<()> {
    let mut seen = false;
    for_each_line(input, |line| {
        let text = lossy(line.bytes);
        let text = text.trim_end();
        if text.trim().is_empty() {
            return Ok(());
        }
        let entry = match split(input, text) {
            Some(found) => found,
            None if !seen => return Err(Error::format(format!("not {what}: the first line starts no entry"))),
            None => Parsed { time: None, level: None, source: None, pid: None, message: text, timeline: false },
        };
        seen = true;
        let record = Entry {
            time: entry.time,
            level: entry.level,
            source: entry.source,
            pid: entry.pid,
            message: entry.message,
            kind,
            timeline: entry.timeline,
        };
        sink.emit(Loc::Line(line.number), &record)
    })?;
    if seen {
        Ok(())
    } else {
        Err(Error::skipped("empty file"))
    }
}
