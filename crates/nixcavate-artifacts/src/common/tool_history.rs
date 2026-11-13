//! Interactive-tool histories that carry no timestamps: `.python_history`, `.mysql_history`
//! and `.lesshst`. Formats: GNU readline / libedit history files (libedit's `_HiStOrY_V2_`
//! writes spaces and other characters as octal `\040`), and less(1) "HISTORY".

use super::home::user_from_path;
use crate::text::{for_each_line, lossy};
use crate::{Artifact, Category, Input, ANY_OS};
use nixcavate_core::{Loc, Record, Result, Sink};
use serde::Serialize;
use std::borrow::Cow;

pub const PYTHON: Artifact = Artifact::new(
    "python-history",
    "Python interactive history",
    Category::Execution,
    ANY_OS,
    &[
        "home/*/.python_history",
        "root/.python_history",
        "Users/*/.python_history",
        "private/var/root/.python_history",
        "var/root/.python_history",
    ],
    parse_command_history,
);

pub const MYSQL: Artifact = Artifact::new(
    "mysql-history",
    "MySQL client history",
    Category::Execution,
    ANY_OS,
    &[
        "home/*/.mysql_history",
        "root/.mysql_history",
        "Users/*/.mysql_history",
        "private/var/root/.mysql_history",
        "var/root/.mysql_history",
    ],
    parse_command_history,
);

pub const LESS: Artifact = Artifact::new(
    "less-history",
    "less search, shell and mark history",
    Category::Execution,
    ANY_OS,
    &["home/*/.lesshst", "root/.lesshst", "Users/*/.lesshst", "private/var/root/.lesshst", "var/root/.lesshst"],
    parse_less,
);

/// One artifact for the line-per-command histories of the other interactive tools. The file
/// name says which tool wrote it (see [`tool_name`]).
pub const TOOLS: Artifact = Artifact::new(
    "tool-history",
    "Interactive tool histories (node, psql, sqlite3, redis-cli, irb, php, gdb, mongo, PowerShell)",
    Category::Execution,
    ANY_OS,
    &[
        "home/*/.node_repl_history",
        "root/.node_repl_history",
        "Users/*/.node_repl_history",
        "var/root/.node_repl_history",
        "home/*/.psql_history",
        "root/.psql_history",
        "Users/*/.psql_history",
        "var/root/.psql_history",
        "home/*/.sqlite_history",
        "root/.sqlite_history",
        "Users/*/.sqlite_history",
        "var/root/.sqlite_history",
        "home/*/.rediscli_history",
        "root/.rediscli_history",
        "Users/*/.rediscli_history",
        "var/root/.rediscli_history",
        "home/*/.irb_history",
        "root/.irb_history",
        "Users/*/.irb_history",
        "var/root/.irb_history",
        "home/*/.local/share/irb/history",
        "root/.local/share/irb/history",
        "home/*/.php_history",
        "root/.php_history",
        "Users/*/.php_history",
        "var/root/.php_history",
        "home/*/.gdb_history",
        "root/.gdb_history",
        "Users/*/.gdb_history",
        "var/root/.gdb_history",
        "home/*/.dbshell",
        "root/.dbshell",
        "Users/*/.dbshell",
        "var/root/.dbshell",
        "home/*/.mongodb/mongosh/mongosh_repl_history",
        "root/.mongodb/mongosh/mongosh_repl_history",
        "Users/*/.mongodb/mongosh/mongosh_repl_history",
        "var/root/.mongodb/mongosh/mongosh_repl_history",
        "home/*/.local/share/powershell/PSReadLine/ConsoleHost_history.txt",
        "root/.local/share/powershell/PSReadLine/ConsoleHost_history.txt",
        "Users/*/.local/share/powershell/PSReadLine/ConsoleHost_history.txt",
        "var/root/.local/share/powershell/PSReadLine/ConsoleHost_history.txt",
    ],
    parse_tool_history,
);

const LIBEDIT_HEADER: &[u8] = b"_HiStOrY_V2_";

#[derive(Serialize)]
struct Command<'a> {
    user: &'a str,
    command: &'a str,
}

impl Record for Command<'_> {}

/// Replaces `\ooo` (three octal digits) with that byte. Other backslashes stay as they are.
fn decode_octal(bytes: &[u8]) -> Cow<'_, [u8]> {
    if !bytes.contains(&b'\\') {
        return Cow::Borrowed(bytes);
    }
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while let Some(&b) = bytes.get(i) {
        let octal = match bytes.get(i + 1..i + 4) {
            Some(d) if b == b'\\' && d[0] <= b'3' && d.iter().all(|c| (b'0'..=b'7').contains(c)) => {
                Some((d[0] - b'0') << 6 | (d[1] - b'0') << 3 | (d[2] - b'0'))
            }
            _ => None,
        };
        match octal {
            Some(byte) => {
                out.push(byte);
                i += 4;
            }
            None => {
                out.push(b);
                i += 1;
            }
        }
    }
    Cow::Owned(out)
}

/// Calls `f` for every command of a one-command-per-line history. Files in libedit's V2 form
/// (macOS Python, some MySQL clients) start with a marker line and escape their text.
fn for_each_command(input: &Input, mut f: impl FnMut(u64, &str) -> Result<()>) -> Result<()> {
    let mut escaped = false;
    for_each_line(input, |line| {
        if line.number == 1 && line.bytes == LIBEDIT_HEADER {
            escaped = true;
            return Ok(());
        }
        if line.bytes.is_empty() {
            return Ok(());
        }
        let decoded = if escaped { decode_octal(line.bytes) } else { Cow::Borrowed(line.bytes) };
        f(line.number, &lossy(&decoded))
    })
}

fn parse_command_history(input: &Input, sink: &mut Sink) -> Result<()> {
    let user = user_from_path(input.path);
    for_each_command(input, |number, command| sink.emit(Loc::Line(number), &Command { user, command }))
}

#[derive(Serialize)]
struct ToolCommand<'a> {
    user: &'a str,
    /// The program that wrote the file: `node`, `psql`, `sqlite3`, `redis-cli`, `irb`, `php`,
    /// `gdb`, `mongo`, `mongosh` or `powershell`.
    tool: &'static str,
    command: &'a str,
}

impl Record for ToolCommand<'_> {}

/// The tool behind a history file, from its name.
fn tool_name(path: &str) -> &'static str {
    match path.rsplit('/').next().unwrap_or("") {
        ".node_repl_history" => "node",
        ".psql_history" => "psql",
        ".sqlite_history" => "sqlite3",
        ".rediscli_history" => "redis-cli",
        ".irb_history" | "history" => "irb",
        ".php_history" => "php",
        ".gdb_history" => "gdb",
        ".dbshell" => "mongo",
        "mongosh_repl_history" => "mongosh",
        "ConsoleHost_history.txt" => "powershell",
        _ => "",
    }
}

/// One command per line, as written by readline or libedit. node and mongosh write the
/// newest command first; PowerShell's PSReadLine continues a multi-line command with a trailing
/// backtick, which is not joined here (each line is one record).
fn parse_tool_history(input: &Input, sink: &mut Sink) -> Result<()> {
    let user = user_from_path(input.path);
    let tool = tool_name(input.path);
    for_each_command(input, |number, command| sink.emit(Loc::Line(number), &ToolCommand { user, tool, command }))
}

#[derive(Serialize)]
struct Item<'a> {
    user: &'a str,
    /// `search`, `shell` or `mark`.
    kind: &'static str,
    text: &'a str,
}

impl Record for Item<'_> {}

fn parse_less(input: &Input, sink: &mut Sink) -> Result<()> {
    let user = user_from_path(input.path);
    let mut section: &'static str = "";
    for_each_line(input, |line| {
        let text = lossy(line.bytes);
        let (kind, text) = match (section, &*text) {
            (_, header) if header.starts_with('.') => {
                section = match header {
                    ".search" => "search",
                    ".shell" => "shell",
                    ".mark" => "mark",
                    _ => "",
                };
                return Ok(());
            }
            ("search" | "shell", entry) if entry.starts_with('"') => (section, &entry[1..]),
            ("mark", entry) if entry.starts_with("m ") => (section, &entry[2..]),
            _ => return Ok(()),
        };
        sink.emit(Loc::Line(line.number), &Item { user, kind, text })
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{fixture, run};

    #[test]
    fn python_history() {
        let data = fixture("python-history/.python_history");
        insta::assert_snapshot!(run(&PYTHON, "home/alice/.python_history", &data, 0));
    }

    #[test]
    fn mysql_history_v2_is_decoded() {
        let data = fixture("mysql-history/.mysql_history");
        insta::assert_snapshot!(run(&MYSQL, "root/.mysql_history", &data, 0));
    }

    #[test]
    fn mysql_history_plain_and_crlf() {
        insta::assert_snapshot!(run(&MYSQL, "home/bob/.mysql_history", b"select 1;\r\nshow\\040tables;\r\n\r\n", 0));
        // Octal escapes are only meaningful after the V2 marker; the last one is not octal.
        let v2 = b"_HiStOrY_V2_\nselect\\040\\134\\18\\777;\n";
        insta::assert_snapshot!(run(&MYSQL, "home/bob/.mysql_history", v2, 0));
    }

    /// Files the real tools wrote (Debian 12: node's REPL, sqlite3, gdb and PHP, each typed on a pty).
    /// node writes the newest command first; PHP's libedit escapes spaces as `\040`.
    #[test]
    fn real_tool_histories() {
        let commands = |path: &str, name: &str| -> Vec<(String, String)> {
            let out = run(&TOOLS, path, &fixture(&format!("tool-history/debian12/{name}")), 0);
            out.lines()
                .filter(|l| l.starts_with('{'))
                .map(|l| {
                    let v: serde_json::Value = serde_json::from_str(l).unwrap();
                    (v["tool"].as_str().unwrap().to_string(), v["command"].as_str().unwrap().to_string())
                })
                .collect()
        };
        let pairs = |tool: &str, list: &[&str]| -> Vec<(String, String)> {
            list.iter().map(|c| (tool.to_string(), c.to_string())).collect()
        };
        assert_eq!(
            commands("home/alice/.node_repl_history", ".node_repl_history"),
            pairs("node", &["console.log(\"hello world\")", "const x = 41 + 1"])
        );
        assert_eq!(
            commands("home/alice/.sqlite_history", ".sqlite_history"),
            pairs(
                "sqlite3",
                &[
                    ".open /tmp/test.db",
                    "create table t(a text);",
                    "insert into t values('it works');",
                    "select * from t;"
                ]
            )
        );
        assert_eq!(
            commands("home/alice/.gdb_history", ".gdb_history"),
            pairs("gdb", &["info registers", "show version"])
        );
        assert_eq!(commands("root/.php_history", ".php_history"), pairs("php", &["echo 1+1;", "echo \"hi there\";"]));
        insta::assert_snapshot!(run(&TOOLS, "root/.php_history", &fixture("tool-history/debian12/.php_history"), 0));
    }

    #[test]
    fn every_listed_file_names_its_tool() {
        for path in TOOLS.paths {
            assert!(!tool_name(path).is_empty(), "{path}");
        }
        assert_eq!(tool_name("home/a/.local/share/irb/history"), "irb");
    }

    #[test]
    fn less_history() {
        let data = fixture("less-history/.lesshst");
        insta::assert_snapshot!(run(&LESS, "Users/sam/.lesshst", &data, 0));
    }

    #[test]
    fn empty_and_garbage_do_not_panic() {
        let garbage: Vec<u8> = (0..=255u8).cycle().take(2000).collect();
        for artifact in [&PYTHON, &MYSQL, &LESS, &TOOLS] {
            assert_eq!(run(artifact, "root/.x", b"", 0), "");
            run(artifact, "root/.x", &garbage, 0);
            run(artifact, "root/.x", b"_HiStOrY_V2_\n\\", 0);
        }
    }
}
