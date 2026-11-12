//! Installed Flatpak applications: the `metadata` keyfile of each deployed commit. Format:
//! flatpak-metadata(5), a desktop-entry style keyfile with `[Application]` and `[Context]`.
//! System installs live under `var/lib/flatpak`, per-user installs under `.local/share/flatpak`.

use crate::common::home::user_from_path;
use crate::text::{for_each_line, lossy};
use crate::{Artifact, Category, Input, LINUX};
use nixcavate_core::{Error, Loc, Record, Result, Sink};
use serde::Serialize;

pub const ARTIFACT: Artifact = Artifact::new(
    "flatpak",
    "Installed Flatpak applications",
    Category::Software,
    LINUX,
    &[
        "var/lib/flatpak/app/*/*/*/*/metadata",
        "home/*/.local/share/flatpak/app/*/*/*/*/metadata",
        "root/.local/share/flatpak/app/*/*/*/*/metadata",
    ],
    parse,
);

#[derive(Serialize, Default)]
struct App {
    user: String,
    app: String,
    runtime: String,
    sdk: String,
    command: String,
    shared: String,
    sockets: String,
    devices: String,
    filesystems: String,
}

impl Record for App {}

#[derive(PartialEq)]
enum Section {
    Application,
    Context,
    Other,
}

fn parse(input: &Input, sink: &mut Sink) -> Result<()> {
    let mut app = App::default();
    let mut section = Section::Other;
    let mut seen_application = false;
    for_each_line(input, |line| {
        let text = lossy(line.bytes);
        let text = text.trim();
        if let Some(name) = text.strip_prefix('[').and_then(|t| t.strip_suffix(']')) {
            section = match name {
                "Application" => Section::Application,
                "Context" => Section::Context,
                _ => Section::Other,
            };
            seen_application |= section == Section::Application;
            return Ok(());
        }
        let Some((key, value)) = text.split_once('=') else { return Ok(()) };
        let (key, value) = (key.trim(), value.trim().to_string());
        let slot = match (&section, key) {
            (Section::Application, "name") => &mut app.app,
            (Section::Application, "runtime") => &mut app.runtime,
            (Section::Application, "sdk") => &mut app.sdk,
            (Section::Application, "command") => &mut app.command,
            (Section::Context, "shared") => &mut app.shared,
            (Section::Context, "sockets") => &mut app.sockets,
            (Section::Context, "devices") => &mut app.devices,
            (Section::Context, "filesystems") => &mut app.filesystems,
            _ => return Ok(()),
        };
        *slot = value;
        Ok(())
    })?;
    if !seen_application {
        return Err(Error::skipped("no [Application] section"));
    }
    app.user = user_from_path(input.path).to_string();
    sink.emit(Loc::None, &app)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{fixture, run};

    #[test]
    fn parses_system_and_user_installs() {
        let data = fixture("flatpak/metadata");
        let system = run(&ARTIFACT, "var/lib/flatpak/app/org.example.Editor/x86_64/stable/0123abcd/metadata", &data, 0);
        let user = run(
            &ARTIFACT,
            "home/alice/.local/share/flatpak/app/org.example.Editor/x86_64/stable/0123abcd/metadata",
            &data,
            0,
        );
        insta::assert_snapshot!(format!("{system}{user}"));
    }

    #[test]
    fn runtimes_and_empty_files_are_skipped() {
        let path = "var/lib/flatpak/app/a/x86_64/stable/c/metadata";
        assert!(run(&ARTIFACT, path, b"[Runtime]\nname=org.freedesktop.Platform\n", 0)
            .contains("skipped: no [Application]"));
        assert!(run(&ARTIFACT, path, b"", 0).contains("skipped"));
    }
}
