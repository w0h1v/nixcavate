//! Kernel extensions and system extensions: code loaded into or alongside the kernel.
//! Kexts are bundles with an `Info.plist` (Apple's Information Property List Key Reference);
//! `/Library/SystemExtensions/db.plist` is the system-extension database, whose keys are not
//! documented and are matched tolerantly (`extensions` array of dictionaries).
//!
//! A kext's `modified` is the `Info.plist` file's modification time: collection metadata, not
//! something the bundle records, and it produces no timeline event.

use super::plist_util::{first_string, parse, string, strings_of};
use crate::{Artifact, Category, Input, MACOS};
use nixcavate_core::{Basis, Error, Loc, Record, Result, Sink, Timestamp};
use plist::{Dictionary, Value};
use serde::Serialize;

pub const KEXTS: Artifact = Artifact::new(
    "kernel-extensions",
    "Third-party kernel extensions (persistence)",
    Category::Persistence,
    MACOS,
    &["Library/Extensions/*.kext/Contents/Info.plist", "Library/Extensions/*.kext/Info.plist"],
    parse_kext,
);

pub const SYSTEM_EXTENSIONS: Artifact = Artifact::new(
    "system-extensions",
    "Installed system extensions (persistence)",
    Category::Persistence,
    MACOS,
    &["Library/SystemExtensions/db.plist"],
    parse_system_extensions,
);

#[derive(Serialize)]
struct Kext<'a> {
    bundle_id: Option<&'a str>,
    name: Option<&'a str>,
    version: Option<&'a str>,
    executable: Option<&'a str>,
    min_os: Option<&'a str>,
    modified: Option<Timestamp>,
}

impl Record for Kext<'_> {}

fn parse_kext(input: &Input, sink: &mut Sink) -> Result<()> {
    let value = parse(input.data)?;
    let Some(info) = value.as_dictionary() else {
        return Err(Error::format("Info.plist is not a dictionary"));
    };
    let directory = input.path.split('/').find_map(|part| part.strip_suffix(".kext"));
    sink.emit(
        Loc::Line(1),
        &Kext {
            bundle_id: string(info, "CFBundleIdentifier"),
            name: string(info, "CFBundleName").or(directory),
            version: first_string(info, &["CFBundleShortVersionString", "CFBundleVersion"]),
            executable: string(info, "CFBundleExecutable"),
            min_os: string(info, "LSMinimumSystemVersion"),
            modified: (input.mtime > 0).then(|| Timestamp::from_secs(input.mtime, Basis::Recorded)),
        },
    )
}

#[derive(Serialize)]
struct SystemExtension<'a> {
    identifier: Option<&'a str>,
    team_id: Option<&'a str>,
    version: Option<&'a str>,
    state: Option<&'a str>,
    categories: Vec<String>,
    origin_path: Option<&'a str>,
    staged_path: Option<&'a str>,
}

impl Record for SystemExtension<'_> {}

/// The version is a string, or a `bundleVersion` dictionary of the usual bundle keys.
fn extension_version(ext: &Dictionary) -> Option<&str> {
    first_string(ext, &["version", "CFBundleShortVersionString", "CFBundleVersion"]).or_else(|| {
        let bundle = ext.get("bundleVersion").or_else(|| ext.get("version"))?.as_dictionary()?;
        first_string(bundle, &["CFBundleShortVersionString", "CFBundleVersion"])
    })
}

fn parse_system_extensions(input: &Input, sink: &mut Sink) -> Result<()> {
    let value = parse(input.data)?;
    let Some(db) = value.as_dictionary() else {
        return Err(Error::format("db.plist is not a dictionary"));
    };
    let Some(Value::Array(extensions)) = db.get("extensions") else {
        return Err(Error::skipped("db.plist has no extensions array"));
    };
    for (index, ext) in extensions.iter().filter_map(Value::as_dictionary).enumerate() {
        sink.emit(
            Loc::Line(index as u64 + 1),
            &SystemExtension {
                identifier: first_string(ext, &["identifier", "bundleIdentifier"]),
                team_id: first_string(ext, &["teamID", "teamIdentifier"]),
                version: extension_version(ext),
                state: string(ext, "state"),
                categories: strings_of(ext, "categories"),
                origin_path: first_string(ext, &["originPath"]),
                staged_path: first_string(ext, &["stagedBundlePath", "stagedBundleURL", "bundlePath"]),
            },
        )?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::macos::plist_util::tests::survives_damage;
    use crate::testing::{fixture, run};

    #[test]
    fn kext_with_contents_directory() {
        let data = fixture("kernel-extensions/Info.plist");
        insta::assert_snapshot!(run(
            &KEXTS,
            "Library/Extensions/Example.kext/Contents/Info.plist",
            &data,
            1_700_000_000
        ));
    }

    #[test]
    fn kext_name_falls_back_to_directory() {
        let data = fixture("kernel-extensions/Info-noname.plist");
        insta::assert_snapshot!(run(&KEXTS, "Library/Extensions/Bare.kext/Info.plist", &data, 0));
    }

    #[test]
    fn system_extension_database() {
        let data = fixture("system-extensions/db.plist");
        insta::assert_snapshot!(run(&SYSTEM_EXTENSIONS, "Library/SystemExtensions/db.plist", &data, 0));
    }

    #[test]
    fn bad_inputs() {
        assert!(run(&KEXTS, "Library/Extensions/A.kext/Info.plist", b"nope", 0).contains("failed: not a property list"));
        assert!(run(&SYSTEM_EXTENSIONS, "Library/SystemExtensions/db.plist", b"", 0).contains("skipped: empty file"));
        let data = fixture("system-extensions/db.plist");
        survives_damage(&SYSTEM_EXTENSIONS, "Library/SystemExtensions/db.plist", &data);
    }
}
