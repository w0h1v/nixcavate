//! Installer history: `/Library/Receipts/InstallHistory.plist`, a property list array with
//! one dict per install (`date`, `displayName`, `displayVersion`, `processName`,
//! `packageIdentifiers`, `contentType`). Format: Apple's property list DTD (`plist(5)`); the
//! observed keys are the ones `softwareupdated` and `installd` write.

use super::plist_util::{date, parse as read_plist, string, strings_of};
use crate::{Artifact, Category, Input, MACOS};
use nixcavate_core::{Error, Event, Loc, Record, Result, Sink, Timestamp};
use plist::Value;
use serde::Serialize;

pub const ARTIFACT: Artifact = Artifact::new(
    "install-history",
    "Software installed by the macOS installer",
    Category::Software,
    MACOS,
    &["Library/Receipts/InstallHistory.plist"],
    parse,
);

/// A plist date; `None` with a warning when it is present but outside 1677-2262.
fn install_time(sink: &mut Sink, value: Option<&Value>) -> Option<Timestamp> {
    let value = value?;
    let time = date(value);
    if time.is_none() && value.as_date().is_some() {
        sink.warn("date is not a valid time; left empty");
    }
    time
}

#[derive(Serialize)]
struct Install {
    time: Option<Timestamp>,
    name: Option<String>,
    version: Option<String>,
    process: Option<String>,
    content_type: Option<String>,
    package_ids: Vec<String>,
}

impl Record for Install {
    fn events(&self) -> impl Iterator<Item = Event<'_>> {
        let message = format!(
            "{} {} installed by {}",
            self.name.as_deref().unwrap_or("unknown package"),
            self.version.as_deref().unwrap_or(""),
            self.process.as_deref().unwrap_or("unknown process")
        );
        self.time.map(|ts| Event::new(ts, "software_installed", message)).into_iter()
    }
}

fn parse(input: &Input, sink: &mut Sink) -> Result<()> {
    let root = read_plist(input.data)?;
    let Some(entries) = root.as_array() else {
        return Err(Error::skipped("not an array of installs"));
    };
    for (index, entry) in entries.iter().enumerate() {
        let Some(entry) = entry.as_dictionary() else {
            sink.warn(format!("entry {index}: not a dictionary"));
            continue;
        };
        let time = install_time(sink, entry.get("date"));
        sink.emit(
            Loc::None,
            &Install {
                time,
                name: string(entry, "displayName").map(str::to_owned),
                version: string(entry, "displayVersion").map(str::to_owned),
                process: string(entry, "processName").map(str::to_owned),
                content_type: string(entry, "contentType").map(str::to_owned),
                package_ids: strings_of(entry, "packageIdentifiers"),
            },
        )?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{fixture, run};

    const PATH: &str = "Library/Receipts/InstallHistory.plist";

    #[test]
    fn parses_installs_and_tolerates_wrong_types() {
        insta::assert_snapshot!(run(&ARTIFACT, PATH, &fixture("install-history/InstallHistory.plist"), 0));
    }

    #[test]
    fn other_inputs_are_not_parsed() {
        assert!(run(&ARTIFACT, PATH, b"", 0).contains("skipped: empty file"));
        assert!(run(&ARTIFACT, PATH, b"not a plist", 0).contains("failed: "));
        let dict = fixture("xprotect-meta/Info.plist");
        assert!(run(&ARTIFACT, PATH, &dict, 0).contains("skipped: not an array"));
    }

    #[test]
    fn absurd_dates_are_dropped_with_a_warning() {
        let xml = b"<plist version=\"1.0\"><array><dict><key>date</key><date>9999-12-31T00:00:00Z</date>\
                    <key>displayName</key><string>x</string></dict></array></plist>";
        let out = run(&ARTIFACT, PATH, xml, 0);
        assert!(out.contains("\"time\":null") && out.contains("is not a valid time"), "{out}");
        assert!(!out.contains("2262") && !out.contains("9999"), "{out}");
    }

    #[test]
    fn damaged_files_do_not_panic() {
        let data = fixture("install-history/InstallHistory.plist");
        for len in 0..data.len() {
            run(&ARTIFACT, PATH, &data[..len], 0);
        }
        let mut seed = 3u32;
        for _ in 0..200 {
            let mut copy = data.clone();
            seed = seed.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            let at = (seed >> 8) as usize % copy.len();
            copy[at] ^= (seed & 0xff) as u8 | 1;
            run(&ARTIFACT, PATH, &copy, 0);
        }
    }
}
