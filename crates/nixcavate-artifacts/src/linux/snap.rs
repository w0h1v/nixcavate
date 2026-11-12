//! Snap packages: `/var/lib/snapd/state.json`, snapd's persisted state (JSON). `data.snaps`
//! maps each installed snap name to its revision history (`sequence`) and the current revision.
//! The file is read defensively: every field is optional and a wrong type is treated as absent.

use crate::{Artifact, Category, Input, LINUX};
use nixcavate_core::time::parse_iso8601;
use nixcavate_core::{Error, Event, Loc, Record, Result, Sink, Timestamp};
use serde::Serialize;
use serde_json::Value;

pub const ARTIFACT: Artifact =
    Artifact::new("snap", "Installed snaps", Category::Software, LINUX, &["var/lib/snapd/state.json"], parse);

#[derive(Serialize)]
struct Snap<'a> {
    time: Option<Timestamp>,
    snap: &'a str,
    snap_type: &'a str,
    current_revision: String,
    channel: &'a str,
    revisions: Vec<String>,
    active: bool,
}

impl Record for Snap<'_> {
    fn events(&self) -> impl Iterator<Item = Event<'_>> {
        let message = format!("snap {} refreshed (revision {})", self.snap, self.current_revision);
        self.time.map(|ts| Event::new(ts, "snap_refreshed", message)).into_iter()
    }
}

/// Revisions are strings in snapd's JSON, but a number is accepted too.
fn revision(value: Option<&Value>) -> Option<String> {
    match value? {
        Value::String(s) => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        _ => None,
    }
}

fn parse(input: &Input, sink: &mut Sink) -> Result<()> {
    if input.data.iter().all(u8::is_ascii_whitespace) {
        return Err(Error::skipped("empty file"));
    }
    let state: Value = serde_json::from_slice(input.data).map_err(|e| Error::format(format!("not JSON: {e}")))?;
    let Some(snaps) = state.pointer("/data/snaps").and_then(Value::as_object) else {
        return Err(Error::skipped("no installed snaps in this state"));
    };
    for (name, snap) in snaps {
        let str_of = |key: &str| snap.get(key).and_then(Value::as_str);
        let sequence = snap.get("sequence").and_then(Value::as_array).map(Vec::as_slice).unwrap_or_default();
        let current = revision(snap.get("current")).unwrap_or_default();
        // The current revision's own record holds the channel it was installed from.
        let current_channel = sequence
            .iter()
            .find(|side| revision(side.get("revision")).as_deref() == Some(current.as_str()))
            .and_then(|side| side.get("channel")?.as_str());
        let channel = str_of("channel").or(str_of("tracking-channel")).or(current_channel).unwrap_or_default();
        let time = str_of("last-refresh-time").or(str_of("last-refresh")).and_then(|text| {
            let (parsed, _) = parse_iso8601(text.as_bytes())?;
            Some(parsed.recorded().unwrap_or_else(|| input.local_time(parsed.secs, parsed.nanos, parsed.precision)))
        });
        if time.is_none() && (str_of("last-refresh-time").is_some() || str_of("last-refresh").is_some()) {
            sink.warn(format!("snap {name}: unreadable refresh time"));
        }
        sink.emit(
            Loc::None,
            &Snap {
                time,
                snap: name,
                snap_type: str_of("type").unwrap_or_default(),
                current_revision: current,
                channel,
                revisions: sequence.iter().filter_map(|side| revision(side.get("revision"))).collect(),
                active: snap.get("active").and_then(Value::as_bool).unwrap_or(false),
            },
        )?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{fixture, run};

    #[test]
    fn parses_snaps() {
        insta::assert_snapshot!(run(&ARTIFACT, "var/lib/snapd/state.json", &fixture("snap/state.json"), 0));
    }

    #[test]
    fn other_inputs_are_skipped_or_rejected() {
        let path = "var/lib/snapd/state.json";
        assert!(run(&ARTIFACT, path, b"", 0).contains("skipped: empty file"));
        assert!(run(&ARTIFACT, path, b"{\"data\":{}}", 0).contains("skipped: no installed snaps"));
        assert!(run(&ARTIFACT, path, b"{\"data\":", 0).contains("failed: not JSON"));
        assert!(run(&ARTIFACT, path, b"[1,2]", 0).contains("skipped"));
    }
}
