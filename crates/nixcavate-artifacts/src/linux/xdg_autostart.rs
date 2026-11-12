//! XDG autostart entries: desktop files started at graphical login, system-wide and per user.
//! Format: freedesktop.org Desktop Entry Specification.

use crate::common::home::user_from_path;
use crate::text::{for_each_line, lossy};
use crate::{Artifact, Category, Input, LINUX};
use nixcavate_core::{Error, Loc, Record, Result, Sink};
use serde::Serialize;

pub const ARTIFACT: Artifact = Artifact::new(
    "xdg-autostart",
    "XDG autostart desktop entries",
    Category::Persistence,
    LINUX,
    &["etc/xdg/autostart/*.desktop", "home/*/.config/autostart/*.desktop", "root/.config/autostart/*.desktop"],
    parse,
);

#[derive(Serialize)]
struct Entry<'a> {
    /// Empty for system-wide entries.
    user: &'a str,
    name: String,
    exec: String,
    try_exec: String,
    entry_type: String,
    hidden: bool,
    no_display: bool,
    only_show_in: String,
    /// `X-GNOME-Autostart-enabled`; true when absent.
    enabled: bool,
    comment: String,
}

impl Record for Entry<'_> {}

fn parse(input: &Input, sink: &mut Sink) -> Result<()> {
    let mut entry = Entry {
        user: user_from_path(input.path),
        name: String::new(),
        exec: String::new(),
        try_exec: String::new(),
        entry_type: String::new(),
        hidden: false,
        no_display: false,
        only_show_in: String::new(),
        enabled: true,
        comment: String::new(),
    };
    let (mut in_group, mut found, mut first_line) = (false, false, 0);
    for_each_line(input, |line| {
        let text = lossy(line.bytes);
        let text = text.trim();
        if text.starts_with('[') {
            in_group = text == "[Desktop Entry]";
            if in_group && !found {
                (found, first_line) = (true, line.number);
            }
            return Ok(());
        }
        if !in_group || text.starts_with('#') {
            return Ok(());
        }
        // Keys with a locale (`Name[de]`) are other keys and do not match.
        let Some((key, value)) = text.split_once('=') else { return Ok(()) };
        let (key, value) = (key.trim(), value.trim());
        let is_true = value == "true";
        match key {
            "Name" => entry.name = value.into(),
            "Exec" => entry.exec = value.into(),
            "TryExec" => entry.try_exec = value.into(),
            "Type" => entry.entry_type = value.into(),
            "Hidden" => entry.hidden = is_true,
            "NoDisplay" => entry.no_display = is_true,
            "OnlyShowIn" => entry.only_show_in = value.into(),
            "X-GNOME-Autostart-enabled" => entry.enabled = is_true,
            "Comment" => entry.comment = value.into(),
            _ => {}
        }
        Ok(())
    })?;
    if !found {
        return Err(Error::format("no [Desktop Entry] group"));
    }
    sink.emit(Loc::Line(first_line), &entry)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{fixture, run};

    #[test]
    fn user_entry_with_hidden_and_disabled_flags() {
        insta::assert_snapshot!(run(
            &ARTIFACT,
            "home/alice/.config/autostart/updater.desktop",
            &fixture("xdg-autostart/updater.desktop"),
            0
        ));
    }

    #[test]
    fn system_entry() {
        insta::assert_snapshot!(run(
            &ARTIFACT,
            "etc/xdg/autostart/nm-applet.desktop",
            &fixture("xdg-autostart/nm-applet.desktop"),
            0
        ));
    }

    #[test]
    fn empty_and_garbage_inputs_do_not_panic() {
        let path = "root/.config/autostart/x.desktop";
        run(&ARTIFACT, path, b"", 0);
        run(&ARTIFACT, path, b"\xff\0[Desktop Entry\n=\n[Desktop Entry]\nExec", 0);
    }
}
