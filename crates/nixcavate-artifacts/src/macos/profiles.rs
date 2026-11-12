//! Configuration profile payloads as macOS applies them: managed preferences (one plist per
//! preference domain, optionally per user) and the profile Settings directory. Plain
//! property lists; the interesting content is which keys an MDM or profile forces.

use super::plist_util::{json, parse, JSON_DEPTH};
use crate::{Artifact, Category, Input, MACOS};
use nixcavate_core::{Loc, Record, Result, Sink};
use serde::Serialize;

pub const ARTIFACT: Artifact = Artifact::new(
    "managed-preferences",
    "Managed preferences and configuration profile settings",
    Category::Persistence,
    MACOS,
    &[
        "Library/Managed Preferences/*.plist",
        "Library/Managed Preferences/*/*.plist",
        "private/var/db/ConfigurationProfiles/Settings/*.plist",
    ],
    parse_profile,
);

#[derive(Serialize)]
struct Preferences<'a> {
    /// The subdirectory of `Managed Preferences` (a user name, or `mobile`); empty otherwise.
    user: &'a str,
    /// The preference domain: the file name without `.plist`.
    domain: &'a str,
    keys: Vec<&'a str>,
    settings: serde_json::Value,
}

impl Record for Preferences<'_> {}

fn parse_profile(input: &Input, sink: &mut Sink) -> Result<()> {
    let value = parse(input.data)?;
    let user = input
        .path
        .split_once("Managed Preferences/")
        .and_then(|(_, rest)| rest.split_once('/'))
        .map_or("", |(user, _)| user);
    let file = input.path.rsplit('/').next().unwrap_or_default();
    let keys = value.as_dictionary().map(|d| d.keys().map(String::as_str).collect()).unwrap_or_default();
    sink.emit(
        Loc::Line(1),
        &Preferences {
            user,
            domain: file.strip_suffix(".plist").unwrap_or(file),
            keys,
            settings: json(&value, JSON_DEPTH),
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::macos::plist_util::tests::survives_damage;
    use crate::testing::{fixture, run};

    #[test]
    fn user_managed_preferences() {
        let data = fixture("managed-preferences/com.example.restrictions.plist");
        insta::assert_snapshot!(run(
            &ARTIFACT,
            "Library/Managed Preferences/alice/com.example.restrictions.plist",
            &data,
            0
        ));
    }

    #[test]
    fn system_wide_and_profile_settings() {
        let data = fixture("managed-preferences/com.example.restrictions.plist");
        let system = run(&ARTIFACT, "Library/Managed Preferences/com.example.restrictions.plist", &data, 0);
        assert!(system.contains("\"user\":\"\""), "{system}");
        let settings =
            run(&ARTIFACT, "private/var/db/ConfigurationProfiles/Settings/com.example.restrictions.plist", &data, 0);
        assert!(settings.contains("\"user\":\"\"") && settings.contains("\"domain\":\"com.example.restrictions\""));
    }

    #[test]
    fn bad_inputs() {
        let path = "Library/Managed Preferences/x.plist";
        assert!(run(&ARTIFACT, path, b"nope", 0).contains("failed: not a property list"));
        assert!(run(&ARTIFACT, path, b"", 0).contains("skipped: empty file"));
        survives_damage(&ARTIFACT, path, &fixture("managed-preferences/com.example.restrictions.plist"));
    }
}
