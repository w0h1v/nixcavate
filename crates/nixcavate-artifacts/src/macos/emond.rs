//! The Event Monitor daemon: rules that run commands when system events occur (deprecated, but
//! still read at boot on older systems, and a known persistence spot). Format: emond(8) rule
//! plists, an array of rules each holding `actions`; and `emond.plist`, the daemon config.

use super::plist_util::{boolean, parse, string, strings_of};
use crate::{Artifact, Category, Input, MACOS};
use nixcavate_core::{Error, Loc, Record, Result, Sink};
use plist::{Dictionary, Value};
use serde::Serialize;

pub const ARTIFACT: Artifact = Artifact::new(
    "emond",
    "Event Monitor rules and configuration (persistence)",
    Category::Persistence,
    MACOS,
    &["private/etc/emond.d/rules/*.plist", "private/etc/emond.d/emond.plist"],
    parse_emond,
);

#[derive(Serialize)]
struct Action<'a> {
    /// The rule name, or `config` for the daemon's own `emond.plist`.
    rule: Option<&'a str>,
    enabled: Option<bool>,
    event_types: Vec<String>,
    action_type: Option<&'a str>,
    command: Option<&'a str>,
    /// For `config`: `additionalRulesPaths`, the extra places rules are loaded from.
    arguments: Vec<String>,
    run_as: Option<String>,
}

impl Record for Action<'_> {}

/// `user` is a name in most rules, but a uid number is accepted too.
fn run_as(action: &Dictionary) -> Option<String> {
    match action.get("user")? {
        Value::String(s) => Some(s.clone()),
        Value::Integer(i) => i.as_signed().map(|n| n.to_string()),
        _ => None,
    }
}

fn parse_emond(input: &Input, sink: &mut Sink) -> Result<()> {
    let value = parse(input.data)?;
    if input.path.ends_with("emond.d/emond.plist") {
        let Some(config) = value.as_dictionary() else {
            return Err(Error::format("emond.plist is not a dictionary"));
        };
        return sink.emit(
            Loc::Line(1),
            &Action {
                rule: Some("config"),
                enabled: None,
                event_types: Vec::new(),
                action_type: None,
                command: None,
                arguments: strings_of(config, "additionalRulesPaths"),
                run_as: None,
            },
        );
    }
    let rules: Vec<&Dictionary> = match &value {
        Value::Array(items) => items.iter().filter_map(Value::as_dictionary).collect(),
        Value::Dictionary(rule) => vec![rule],
        _ => return Err(Error::format("emond rules file is neither an array nor a dictionary")),
    };
    for (index, rule) in rules.into_iter().enumerate() {
        let Some(Value::Array(actions)) = rule.get("actions") else { continue };
        for action in actions.iter().filter_map(Value::as_dictionary) {
            sink.emit(
                Loc::Line(index as u64 + 1),
                &Action {
                    rule: string(rule, "name"),
                    enabled: boolean(rule, "enabled"),
                    event_types: strings_of(rule, "eventTypes"),
                    action_type: string(action, "type"),
                    command: string(action, "command"),
                    arguments: strings_of(action, "arguments"),
                    run_as: run_as(action),
                },
            )?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::macos::plist_util::tests::survives_damage;
    use crate::testing::{fixture, run};

    #[test]
    fn rules_give_one_record_per_action() {
        let data = fixture("emond/rules.plist");
        insta::assert_snapshot!(run(&ARTIFACT, "private/etc/emond.d/rules/example.plist", &data, 0));
    }

    #[test]
    fn daemon_config() {
        let data = fixture("emond/emond.plist");
        insta::assert_snapshot!(run(&ARTIFACT, "private/etc/emond.d/emond.plist", &data, 0));
    }

    #[test]
    fn bad_inputs() {
        let path = "private/etc/emond.d/rules/x.plist";
        assert!(run(&ARTIFACT, path, b"nope", 0).contains("failed: not a property list"));
        assert!(run(&ARTIFACT, path, b"", 0).contains("skipped: empty file"));
        survives_damage(&ARTIFACT, path, &fixture("emond/rules.plist"));
    }
}
