//! Legacy and plug-in persistence locations on macOS that a default install leaves empty or
//! nearly so: StartupItems, `rc.local` and `launchd.conf`, Folder Action scripts, and plug-in
//! bundles that the system loads into its own processes (authorization plug-ins, Directory
//! Services plug-ins, Spotlight importers, Quick Look generators, screen savers, Internet
//! plug-ins).
//!
//! References: Apple's "Daemons and Services Programming Guide" (StartupItems, deprecated since
//! OS X 10.10), `launchd.conf(5)` and rc scripts (`/etc/rc.common`), the Authorization Services
//! documentation (authorization plug-ins live in `/Library/Security/SecurityAgentPlugins`), and
//! Apple Script "Folder Actions" documentation. Bundles are read from `Contents/Info.plist`.
//! The files themselves are the evidence, so most records are file metadata.
//!
//! Synthetic only: no real bundle of these kinds was read.

use super::plist_util::{parse, string};
use super::util::clip;
use crate::common::home::user_from_path;
use crate::common::script;
use crate::{Artifact, Category, Input, MACOS};
use nixcavate_core::{Basis, Error, Event, Loc, Record, Result, Sink, Timestamp};
use plist::Value;
use serde::Serialize;

pub const STARTUP_ITEMS: Artifact = Artifact::new(
    "startup-items",
    "Legacy StartupItems (deprecated boot-time scripts)",
    Category::Persistence,
    MACOS,
    &["Library/StartupItems/*/*", "System/Library/StartupItems/*/*"],
    script::file_info,
);

pub const RC_FILES: Artifact = Artifact::new(
    "legacy-rc",
    "Legacy rc.local, rc.common and launchd.conf commands",
    Category::Persistence,
    MACOS,
    &["private/etc/rc.local", "private/etc/launchd.conf", "private/etc/rc.common", "etc/rc.local", "etc/launchd.conf"],
    script::content_lines,
);

pub const FOLDER_ACTIONS: Artifact = Artifact::new(
    "folder-action-scripts",
    "Folder Action scripts (run when a folder's contents change)",
    Category::Persistence,
    MACOS,
    &["Library/Scripts/Folder Action Scripts/*", "Users/*/Library/Scripts/Folder Action Scripts/*"],
    script::file_info,
);

pub const PLUGINS: Artifact = Artifact::new(
    "system-plugins",
    "Plug-in bundles loaded by system components",
    Category::Persistence,
    MACOS,
    &[
        "Library/Security/SecurityAgentPlugins/*/Contents/Info.plist",
        "Library/DirectoryServices/PlugIns/*/Contents/Info.plist",
        "Library/Spotlight/*/Contents/Info.plist",
        "Users/*/Library/Spotlight/*/Contents/Info.plist",
        "Library/QuickLook/*/Contents/Info.plist",
        "Users/*/Library/QuickLook/*/Contents/Info.plist",
        "Library/Screen Savers/*/Contents/Info.plist",
        "Users/*/Library/Screen Savers/*/Contents/Info.plist",
        "Library/Internet Plug-Ins/*/Contents/Info.plist",
        "Users/*/Library/Internet Plug-Ins/*/Contents/Info.plist",
    ],
    parse_plugin,
);

#[derive(Serialize)]
struct Plugin<'a> {
    user: &'a str,
    /// `authorization_plugin`, `directory_services_plugin`, `spotlight_importer`,
    /// `quicklook_generator`, `screen_saver` or `internet_plugin`.
    kind: &'static str,
    /// The bundle's folder name.
    bundle: &'a str,
    bundle_id: Option<String>,
    name: Option<String>,
    executable: Option<String>,
    version: Option<String>,
    /// `Info.plist` modification time as collected.
    modified: Option<Timestamp>,
}

impl Record for Plugin<'_> {
    fn events(&self) -> impl Iterator<Item = Event<'_>> {
        let message = format!("{} bundle {} written", self.kind, self.bundle);
        self.modified.map(|ts| Event::new(ts, "activity", message)).into_iter()
    }
}

fn kind(path: &str) -> &'static str {
    if path.contains("/SecurityAgentPlugins/") {
        "authorization_plugin"
    } else if path.contains("/DirectoryServices/PlugIns/") {
        "directory_services_plugin"
    } else if path.contains("/Spotlight/") {
        "spotlight_importer"
    } else if path.contains("/QuickLook/") {
        "quicklook_generator"
    } else if path.contains("/Screen Savers/") {
        "screen_saver"
    } else {
        "internet_plugin"
    }
}

fn parse_plugin(input: &Input, sink: &mut Sink) -> Result<()> {
    let value = parse(input.data)?;
    let Value::Dictionary(info) = value else { return Err(Error::format("Info.plist is not a dictionary")) };
    // `.../<bundle>/Contents/Info.plist`.
    let mut parts = input.path.rsplit('/').skip(2);
    let bundle = parts.next().unwrap_or_default();
    let text = |key: &str| string(&info, key).map(|s| clip(s, 256));
    sink.emit(
        Loc::None,
        &Plugin {
            user: user_from_path(input.path),
            kind: kind(input.path),
            bundle,
            bundle_id: text("CFBundleIdentifier"),
            name: text("CFBundleName").or_else(|| text("CFBundleDisplayName")),
            executable: text("CFBundleExecutable"),
            version: text("CFBundleShortVersionString").or_else(|| text("CFBundleVersion")),
            modified: (input.mtime > 0).then(|| Timestamp::from_secs(input.mtime, Basis::Recorded)),
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{fixture, run};

    #[test]
    fn plugin_bundles_say_what_they_are() {
        let auth = "Library/Security/SecurityAgentPlugins/Evil.bundle/Contents/Info.plist";
        let out = run(&PLUGINS, auth, &fixture("legacy-persistence/Info.plist"), 1_700_000_000);
        assert!(
            out.contains("\"kind\":\"authorization_plugin\"") && out.contains("\"bundle\":\"Evil.bundle\""),
            "{out}"
        );
        let user = "Users/alice/Library/Screen Savers/Saver.saver/Contents/Info.plist";
        let out = run(&PLUGINS, user, &fixture("legacy-persistence/Info.plist"), 0);
        assert!(out.contains("\"kind\":\"screen_saver\"") && out.contains("\"user\":\"alice\""), "{out}");
        insta::assert_snapshot!(run(&PLUGINS, auth, &fixture("legacy-persistence/Info.plist"), 1_700_000_000));
    }

    #[test]
    fn script_artifacts_report_files_and_lines() {
        let rc = run(&RC_FILES, "private/etc/rc.local", b"#!/bin/sh\n/opt/x --daemon\n", 0);
        assert!(rc.contains("/opt/x --daemon"), "{rc}");
        let item =
            run(&STARTUP_ITEMS, "Library/StartupItems/Evil/Evil", b"#!/bin/sh\n. /etc/rc.common\n", 1_700_000_000);
        assert!(item.contains("\"interpreter\":\"/bin/sh\""), "{item}");
    }

    #[test]
    fn damaged_plists_do_not_panic() {
        let path = "Library/QuickLook/X.qlgenerator/Contents/Info.plist";
        crate::macos::plist_util::tests::survives_damage(&PLUGINS, path, &fixture("legacy-persistence/Info.plist"));
    }
}
