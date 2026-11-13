//! `/etc/passwd`: local accounts. Format: passwd(5).

use crate::text::{for_each_line, lossy};
use crate::{Artifact, Category, Input, UNIX};
use nixcavate_core::{Loc, Record, Result, Sink};
use serde::Serialize;

pub const ARTIFACT: Artifact =
    Artifact::new("passwd", "Local user accounts", Category::Accounts, UNIX, &["etc/passwd", "etc/passwd-"], parse);

#[derive(Serialize)]
struct Account<'a> {
    user: &'a str,
    /// `x` means the hash is in `shadow`; anything else is unusual and worth a look.
    password_field: &'a str,
    uid: Option<u32>,
    gid: Option<u32>,
    gecos: &'a str,
    home: &'a str,
    shell: &'a str,
}

impl Record for Account<'_> {}

fn parse(input: &Input, sink: &mut Sink) -> Result<()> {
    for_each_line(input, |line| {
        let text = lossy(line.bytes);
        if text.trim().is_empty() || text.starts_with('#') {
            return Ok(());
        }
        let fields: Vec<&str> = text.split(':').collect();
        if fields.len() != 7 {
            sink.warn(format!("line {}: expected 7 fields, found {}", line.number, fields.len()));
            return Ok(());
        }
        sink.emit(
            Loc::Line(line.number),
            &Account {
                user: fields[0],
                password_field: fields[1],
                uid: fields[2].parse().ok(),
                gid: fields[3].parse().ok(),
                gecos: fields[4],
                home: fields[5],
                shell: fields[6],
            },
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{fixture, run};

    #[test]
    fn parses_accounts() {
        insta::assert_snapshot!(run(&ARTIFACT, "etc/passwd", &fixture("passwd/passwd"), 0));
    }
}
