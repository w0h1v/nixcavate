//! `/etc/group`: local groups and their members. Format: group(5).

use crate::text::{for_each_line, lossy};
use crate::{Artifact, Category, Input, UNIX};
use nixcavate_core::{Loc, Record, Result, Sink};
use serde::Serialize;

pub const ARTIFACT: Artifact =
    Artifact::new("group", "Local groups and members", Category::Accounts, UNIX, &["etc/group", "etc/group-"], parse);

#[derive(Serialize)]
struct Group<'a> {
    group: &'a str,
    /// `x` means the password is in `gshadow`; anything else is unusual.
    password_field: &'a str,
    gid: Option<u32>,
    members: Vec<&'a str>,
}

impl Record for Group<'_> {}

fn parse(input: &Input, sink: &mut Sink) -> Result<()> {
    for_each_line(input, |line| {
        let text = lossy(line.bytes);
        if text.trim().is_empty() || text.starts_with('#') {
            return Ok(());
        }
        let fields: Vec<&str> = text.split(':').collect();
        if fields.len() != 4 {
            sink.warn(format!("line {}: expected 4 fields, found {}", line.number, fields.len()));
            return Ok(());
        }
        sink.emit(
            Loc::Line(line.number),
            &Group {
                group: fields[0],
                password_field: fields[1],
                gid: fields[2].parse().ok(),
                members: fields[3].split(',').filter(|m| !m.is_empty()).collect(),
            },
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{fixture, run};

    #[test]
    fn parses_groups() {
        insta::assert_snapshot!(run(&ARTIFACT, "etc/group", &fixture("group/group"), 0));
    }

    #[test]
    fn empty_input_emits_nothing() {
        assert_eq!(run(&ARTIFACT, "etc/group-", b"", 0), "");
    }
}
