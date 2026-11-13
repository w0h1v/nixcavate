//! The AIX error log as `errpt` prints it, collected by UAC (`errpt -a`). The raw log
//! (`var/adm/ras/errlog`) is a binary file whose layout could not be established from two
//! independent public sources, so it is **not read**; `errpt` output is.
//!
//! Two layouts are read:
//! * the detailed one (`errpt -a`): blocks separated by a line of dashes, each with `LABEL:`,
//!   `IDENTIFIER:`, `Date/Time:`, `Sequence Number:`, `Machine Id:`, `Node Id:`, `Class:`,
//!   `Type:`, `Resource Name:`, `Location:` and a `Description` section. **Synthetic only**:
//!   no real `errpt -a` output was available, the layout is from IBM's documentation of the command.
//! * the one-line summary (`IDENTIFIER TIMESTAMP T C RESOURCE_NAME DESCRIPTION`, the timestamp
//!   `MMDDhhmmYY`). Checked against three public samples of `errpt` listings in a Ruby parser's
//!   test data (taken from vendor community posts and a VIOS write-up): 51 rows, 51 read, no
//!   warning; the timestamps decode to the dates the samples' own context gives (April 2016).
//!
//! Times have no zone: the host zone is assumed.

use super::clock::{ctime, two_digit_year};
use crate::text::{for_each_line, lossy};
use crate::{Artifact, Category, Input, AIX};
use nixcavate_core::time::secs_from_civil;
use nixcavate_core::{Event, Loc, Precision, Record, Result, Sink, Timestamp};
use serde::Serialize;

pub const ARTIFACT: Artifact = Artifact::new(
    "aix-errpt",
    "AIX error log entries (errpt output)",
    Category::Logs,
    AIX,
    &["../live_response/system/errpt_-a.txt", "../live_response/system/errpt.txt"],
    parse,
);

#[derive(Serialize, Default)]
struct ErrorEntry<'a> {
    label: Option<&'a str>,
    identifier: Option<&'a str>,
    time: Option<Timestamp>,
    sequence_number: Option<&'a str>,
    node_id: Option<&'a str>,
    /// `H` hardware, `S` software, `O` operator message, `U` undetermined.
    class: Option<&'a str>,
    /// `PERM`, `TEMP`, `PEND`, `PERF`, `INFO`, `UNKN` in the detailed form; `P`, `T`, `I`... in the summary.
    error_type: Option<&'a str>,
    resource_name: Option<&'a str>,
    location: Option<&'a str>,
    description: Option<String>,
}

impl Record for ErrorEntry<'_> {
    fn events(&self) -> impl Iterator<Item = Event<'_>> {
        self.time
            .map(|ts| {
                Event::new(
                    ts,
                    "log",
                    format!(
                        "errpt {} {}: {}",
                        self.label.or(self.identifier).unwrap_or("?"),
                        self.resource_name.unwrap_or("?"),
                        self.description.as_deref().unwrap_or("")
                    ),
                )
            })
            .into_iter()
    }
}

fn value<'a>(text: &'a str, key: &str) -> Option<&'a str> {
    text.strip_prefix(key).map(str::trim)
}

fn parse(input: &Input, sink: &mut Sink) -> Result<()> {
    let stamp = |wall: i64| input.local_time(wall, 0, Precision::Seconds);
    let mut summary = false;
    let (mut started_at, mut in_description, mut blocks) = (0u64, false, 0u64);
    let mut open = false;
    // The strings live in the closure's own text; owned copies keep the borrow checker simple here.
    struct Owned {
        label: Option<String>,
        identifier: Option<String>,
        time: Option<Timestamp>,
        sequence: Option<String>,
        node: Option<String>,
        class: Option<String>,
        kind: Option<String>,
        resource: Option<String>,
        location: Option<String>,
        description: Option<String>,
    }
    let blank = || Owned {
        label: None,
        identifier: None,
        time: None,
        sequence: None,
        node: None,
        class: None,
        kind: None,
        resource: None,
        location: None,
        description: None,
    };
    let mut block = blank();
    let flush = |sink: &mut Sink, block: &Owned, at: u64| -> Result<()> {
        sink.emit(
            Loc::Line(at),
            &ErrorEntry {
                label: block.label.as_deref(),
                identifier: block.identifier.as_deref(),
                time: block.time,
                sequence_number: block.sequence.as_deref(),
                node_id: block.node.as_deref(),
                class: block.class.as_deref(),
                error_type: block.kind.as_deref(),
                resource_name: block.resource.as_deref(),
                location: block.location.as_deref(),
                description: block.description.clone(),
            },
        )
    };
    let mut first = true;
    for_each_line(input, |line| {
        let text = lossy(line.bytes);
        let trimmed = text.trim();
        if first && !trimmed.is_empty() {
            first = false;
            summary = trimmed.starts_with("IDENTIFIER TIMESTAMP");
            if summary {
                return Ok(());
            }
        }
        if summary {
            let words: Vec<&str> = trimmed.split_whitespace().collect();
            let [id, ts, kind, class, resource, rest @ ..] = &words[..] else {
                if !trimmed.is_empty() {
                    sink.warn(format!("line {}: not an errpt summary row", line.number));
                }
                return Ok(());
            };
            let digits = |r: std::ops::Range<usize>| ts.get(r)?.parse::<u32>().ok();
            let when = (ts.len() == 10 && ts.bytes().all(|b| b.is_ascii_digit()))
                .then(|| {
                    secs_from_civil(
                        two_digit_year(digits(8..10)?),
                        digits(0..2)?,
                        digits(2..4)?,
                        digits(4..6)?,
                        digits(6..8)?,
                        0,
                    )
                })
                .flatten();
            let entry = ErrorEntry {
                identifier: Some(id),
                time: when.map(stamp),
                class: Some(class),
                error_type: Some(kind),
                resource_name: Some(resource),
                description: Some(rest.join(" ")),
                ..ErrorEntry::default()
            };
            if when.is_none() {
                sink.warn(format!("line {}: timestamp {ts} is not MMDDhhmmYY", line.number));
            }
            return sink.emit(Loc::Line(line.number), &entry);
        }
        if trimmed.starts_with("-----") && trimmed.bytes().all(|b| b == b'-') && trimmed.len() >= 20 {
            if open {
                flush(sink, &block, started_at)?;
            }
            block = blank();
            (open, started_at, in_description) = (true, line.number, false);
            blocks += 1;
            return Ok(());
        }
        if !open {
            return Ok(());
        }
        if in_description {
            if trimmed.is_empty() {
                in_description = false;
            } else if block.description.is_none() {
                block.description = Some(trimmed.to_string());
            }
            return Ok(());
        }
        let own = |v: &str| Some(v.to_string()).filter(|v| !v.is_empty());
        if trimmed == "Description" {
            in_description = true;
        } else if let Some(v) = value(trimmed, "LABEL:") {
            block.label = own(v);
        } else if let Some(v) = value(trimmed, "IDENTIFIER:") {
            block.identifier = own(v);
        } else if let Some(v) = value(trimmed, "Date/Time:") {
            block.time = ctime(v).map(stamp);
        } else if let Some(v) = value(trimmed, "Sequence Number:") {
            block.sequence = own(v);
        } else if let Some(v) = value(trimmed, "Node Id:") {
            block.node = own(v);
        } else if let Some(v) = value(trimmed, "Class:") {
            block.class = own(v);
        } else if let Some(v) = value(trimmed, "Type:") {
            block.kind = own(v);
        } else if let Some(v) = value(trimmed, "Resource Name:") {
            block.resource = own(v);
        } else if let Some(v) = value(trimmed, "Location:") {
            block.location = own(v);
        }
        Ok(())
    })?;
    if open && !summary {
        flush(sink, &block, started_at)?;
    }
    if !summary && blocks == 0 && !first {
        sink.warn("no `errpt -a` blocks (lines of dashes) and no summary header: not errpt output");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::run;

    /// The first rows of a public sample (an `errpt` listing of a VIOS during a partition migration).
    const SUMMARY: &[u8] = b"IDENTIFIER TIMESTAMP T C RESOURCE_NAME DESCRIPTION\nA5E6DB96   0414083416 I S pmig           Client Partition Migration Completed\n516A2BC4   0414083316 P H hdisk9         CONNECTION FAILURE\nBAD        12 x\n";

    #[test]
    fn summary_listing() {
        let out = run(&ARTIFACT, "../live_response/system/errpt.txt", SUMMARY, 0);
        assert!(out.contains("2016-04-14T08:34:00Z"), "{out}");
        assert!(out.contains("not an errpt summary row"), "{out}");
        insta::assert_snapshot!(out);
    }

    #[test]
    fn detailed_blocks() {
        let data = b"---------------------------------------------------------------------------\nLABEL:          SSH_ERR\nIDENTIFIER:     1A2B3C4D\n\nDate/Time:       Wed Mar 10 01:02:03 UTC 2021\nSequence Number: 1234\nMachine Id:      00F7AB124C00\nNode Id:         aixhost\nClass:           S\nType:            INFO\nWPAR:            Global\nResource Name:   sshd\nLocation:        \n\nDescription\nAUTHENTICATION FAILURE\n\nProbable Causes\nSomething\n---------------------------------------------------------------------------\nLABEL:          DUMP_STATS\nIDENTIFIER:     9DBCFDEE\n\nDate/Time:       Wed Mar 10 02:00:00 2021\nResource Name:   errdemon\n\nDescription\nERROR LOGGING TURNED ON\n";
        let out = run(&ARTIFACT, "../live_response/system/errpt_-a.txt", data, 0);
        assert_eq!(out.matches("\"label\"").count(), 2, "{out}");
        assert!(
            out.contains(r#""description":"AUTHENTICATION FAILURE""#) && out.contains("2021-03-10T02:00:00Z"),
            "{out}"
        );
        insta::assert_snapshot!(out);
    }

    #[test]
    fn hostile() {
        for data in [
            &b""[..],
            b"-------------------------\n",
            b"IDENTIFIER TIMESTAMP\nx\n",
            b"\xff\xfe\0\n",
            &[b'-'; 5000][..],
            b"IDENTIFIER TIMESTAMP T C R D\nA 9999999999 I S x y\n",
        ] {
            let _ = run(&ARTIFACT, "../live_response/system/errpt_-a.txt", data, 0);
        }
    }
}
