//! `etc/project`: resource-control projects. Format: project(5), `name:projid:comment:user-list:
//! group-list:attributes`. Users and groups are comma separated and may use `*`, `!` and `!name`.
//!
//! Verified on illumos: the stock `system`, `user.root`, `noproject`, `default` and `group.staff`
//! lines and the one the harness added. Not a persistence mechanism by itself; it records which
//! accounts run under which limits and attributes (including `project.pool`).

use crate::text::{for_each_line, lossy};
use crate::{Artifact, Category, Input, SOLARIS};
use nixcavate_core::{Loc, Record, Result, Sink};
use serde::Serialize;

pub const ARTIFACT: Artifact = Artifact::new(
    "project",
    "Resource-control projects (Solaris/illumos)",
    Category::Accounts,
    SOLARIS,
    &["etc/project"],
    parse,
);

#[derive(Serialize)]
struct Project<'a> {
    name: &'a str,
    id: Option<u32>,
    comment: &'a str,
    users: Vec<&'a str>,
    groups: Vec<&'a str>,
    attributes: &'a str,
}

impl Record for Project<'_> {}

fn names(list: &str) -> Vec<&str> {
    list.split(',').map(str::trim).filter(|p| !p.is_empty()).collect()
}

fn parse(input: &Input, sink: &mut Sink) -> Result<()> {
    for_each_line(input, |line| {
        let text = lossy(line.bytes);
        let text = text.trim();
        if text.is_empty() || text.starts_with('#') {
            return Ok(());
        }
        // The attribute list may contain `:` only inside parentheses in practice; the sixth field is the rest.
        let fields: Vec<&str> = text.splitn(6, ':').collect();
        let &[name, id, comment, users, groups, attributes] = &fields[..] else {
            sink.warn(format!("line {}: expected 6 fields, found {}", line.number, fields.len()));
            return Ok(());
        };
        let (users, groups) = (names(users), names(groups));
        sink.emit(
            Loc::Line(line.number),
            &Project { name, id: id.trim().parse().ok(), comment, users, groups, attributes },
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{fixture, run};

    #[test]
    fn a_real_project_file() {
        let out = run(&ARTIFACT, "etc/project", &fixture("project/project"), 0);
        insta::assert_snapshot!(out);
        // The harness wrote this line by hand with an empty field too many (`::alice::`): the fields are kept as found.
        assert!(out.contains(r#""name":"user.alice","id":5001,"comment":"NXMK_PROJECT example","users":[],"groups":["alice"],"attributes":":project.max-lwps=(privileged,100,deny)""#), "{out}");
        assert!(out.contains(r#""name":"default""#) && out.contains(r#""name":"system","id":0"#), "{out}");
    }

    #[test]
    fn a_well_formed_line_and_its_lists() {
        let out = run(
            &ARTIFACT,
            "etc/project",
            b"batch:10:Batch jobs:alice,bob,!eve:staff,*:project.pool=pool_default;rcap.max-rss=1gb\n",
            0,
        );
        assert!(out.contains(r#""users":["alice","bob","!eve"],"groups":["staff","*"],"attributes":"project.pool=pool_default;rcap.max-rss=1gb""#), "{out}");
    }

    #[test]
    fn short_lines_warn() {
        assert!(run(&ARTIFACT, "etc/project", b"a:1:c\n", 0).contains("expected 6 fields, found 3"));
        super::super::never_panics(&ARTIFACT, "etc/project", &fixture("project/project"));
    }
}
