//! systemd unit files and drop-ins. Formats: systemd.syntax(7), systemd.unit(5),
//! systemd.service(5), systemd.timer(5), systemd.socket(5), systemd.path(5).
//!
//! Limits: enablement is expressed as symlinks (`*.wants/`, `*.requires/`, masking by a link
//! to `/dev/null`), and links are not parsed here. A unit's `[Install]` section says what
//! enabling it would do, not that it is enabled. `.target` units run nothing and are left
//! out, as are file times as timeline events: they are not reliable enough to assert on.
//! `modified` is the file's mtime from collection metadata, not an event recorded in the
//! unit; no timeline event is built from it.

use crate::logical_lines::{for_each_logical, Dialect};
use crate::{Artifact, Category, Input, LINUX};
use nixcavate_core::{Basis, Loc, Record, Result, Sink, Timestamp};
use serde::Serialize;

macro_rules! unit_paths {
    ($($root:literal),*) => {
        &[$(
            concat!($root, "/**/*.service"),
            concat!($root, "/**/*.timer"),
            concat!($root, "/**/*.socket"),
            concat!($root, "/**/*.path"),
            concat!($root, "/**/*.mount"),
            concat!($root, "/**/*.automount"),
            concat!($root, "/**/*.d/*.conf"),
        )*]
    };
}

pub const ARTIFACT: Artifact = Artifact::new(
    "systemd-units",
    "systemd service, timer, socket and path units and their drop-ins",
    Category::Persistence,
    LINUX,
    unit_paths!(
        "etc/systemd/system",
        "usr/lib/systemd/system",
        "usr/local/lib/systemd/system",
        "lib/systemd/system",
        "run/systemd/system",
        "etc/systemd/user",
        "usr/lib/systemd/user",
        "home/*/.config/systemd/user",
        "home/*/.local/share/systemd/user",
        "root/.config/systemd/user"
    ),
    parse,
);

/// Repeated keys make lists, so every list value is joined with ` ; `.
#[derive(Serialize)]
struct Unit<'a> {
    /// The unit the file defines; for a drop-in, the unit it modifies.
    unit: &'a str,
    drop_in: bool,
    unit_type: Option<&'a str>,
    description: Option<String>,
    exec_start: Option<String>,
    exec_start_pre: Option<String>,
    exec_start_post: Option<String>,
    exec_stop: Option<String>,
    exec_stop_post: Option<String>,
    /// `ExecCondition=`: runs before `ExecStart` and gates it.
    exec_condition: Option<String>,
    exec_reload: Option<String>,
    run_user: Option<String>,
    run_group: Option<String>,
    working_directory: Option<String>,
    environment: Option<String>,
    environment_file: Option<String>,
    wanted_by: Option<String>,
    required_by: Option<String>,
    also: Option<String>,
    on_calendar: Option<String>,
    on_boot_sec: Option<String>,
    on_active_sec: Option<String>,
    on_startup_sec: Option<String>,
    on_unit_active_sec: Option<String>,
    /// `Unit=` in `[Timer]`: the unit the timer starts.
    timer_unit: Option<String>,
    /// `Service=` in `[Socket]` and `Unit=` in `[Path]`: the unit that is started.
    activates: Option<String>,
    /// All `Listen*=` of `[Socket]`.
    listen: Option<String>,
    /// All `Path*=` of `[Path]`, and `DirectoryNotEmpty=`.
    path_triggers: Option<String>,
    restart: Option<String>,
    service_type: Option<String>,
    modified: Option<Timestamp>,
}

impl Record for Unit<'_> {}

const DESCRIPTION: usize = 0;
const EXEC_START: usize = 1;
const EXEC_START_PRE: usize = 2;
const EXEC_START_POST: usize = 3;
const EXEC_STOP: usize = 4;
const EXEC_RELOAD: usize = 5;
const RUN_USER: usize = 6;
const RUN_GROUP: usize = 7;
const WORKING_DIRECTORY: usize = 8;
const ENVIRONMENT: usize = 9;
const ENVIRONMENT_FILE: usize = 10;
const WANTED_BY: usize = 11;
const REQUIRED_BY: usize = 12;
const ALSO: usize = 13;
const ON_CALENDAR: usize = 14;
const ON_BOOT_SEC: usize = 15;
const ON_UNIT_ACTIVE_SEC: usize = 16;
const TIMER_UNIT: usize = 17;
const LISTEN: usize = 18;
const PATH_TRIGGERS: usize = 19;
const RESTART: usize = 20;
const SERVICE_TYPE: usize = 21;
const EXEC_STOP_POST: usize = 22;
const EXEC_CONDITION: usize = 23;
const ON_ACTIVE_SEC: usize = 24;
const ON_STARTUP_SEC: usize = 25;
const ACTIVATES: usize = 26;
const SLOTS: usize = 27;

/// Which output field a `Key=` in a section feeds.
fn slot(section: &str, key: &str) -> Option<usize> {
    Some(match (section, key) {
        ("Unit", "Description") => DESCRIPTION,
        ("Service", "ExecStart") => EXEC_START,
        // `[Socket]` has its own hooks; they run commands just the same.
        ("Service" | "Socket", "ExecStartPre") => EXEC_START_PRE,
        ("Service" | "Socket", "ExecStartPost") => EXEC_START_POST,
        ("Service", "ExecStop") | ("Socket", "ExecStopPre") => EXEC_STOP,
        ("Service" | "Socket", "ExecStopPost") => EXEC_STOP_POST,
        ("Service", "ExecCondition") => EXEC_CONDITION,
        ("Socket", "Service") | ("Path", "Unit") => ACTIVATES,
        ("Timer", "OnActiveSec") => ON_ACTIVE_SEC,
        ("Timer", "OnStartupSec") => ON_STARTUP_SEC,
        ("Service", "ExecReload") => EXEC_RELOAD,
        ("Service", "User") => RUN_USER,
        ("Service", "Group") => RUN_GROUP,
        ("Service", "WorkingDirectory") => WORKING_DIRECTORY,
        ("Service", "Environment") => ENVIRONMENT,
        ("Service", "EnvironmentFile") => ENVIRONMENT_FILE,
        ("Service", "Restart") => RESTART,
        ("Service", "Type") => SERVICE_TYPE,
        ("Install", "WantedBy") => WANTED_BY,
        ("Install", "RequiredBy") => REQUIRED_BY,
        ("Install", "Also") => ALSO,
        ("Timer", "OnCalendar") => ON_CALENDAR,
        ("Timer", "OnBootSec") => ON_BOOT_SEC,
        ("Timer", "OnUnitActiveSec") => ON_UNIT_ACTIVE_SEC,
        ("Timer", "Unit") => TIMER_UNIT,
        ("Socket", k) if k.starts_with("Listen") => LISTEN,
        ("Path", k) if k.starts_with("Path") || k == "DirectoryNotEmpty" => PATH_TRIGGERS,
        _ => return None,
    })
}

fn joined(values: &[String]) -> Option<String> {
    (!values.is_empty()).then(|| values.join(" ; "))
}

fn parse(input: &Input, sink: &mut Sink) -> Result<()> {
    let mut parts = input.path.rsplit('/');
    let file = parts.next().unwrap_or_default();
    let dir = parts.next().unwrap_or_default();
    let (unit, drop_in) = match dir.strip_suffix(".d") {
        Some(unit) => (unit, true),
        None => (file, false),
    };
    let unit_type = unit.rsplit_once('.').map(|(_, ext)| ext);

    let mut lists: [Vec<String>; SLOTS] = Default::default();
    let mut section = String::new();
    for_each_logical(
        input,
        Dialect::Systemd,
        |t| t.starts_with(['#', ';']).then_some(0),
        |logical| {
            let line = logical.text.trim();
            if logical.truncated {
                sink.warn(format!("line {}: logical line longer than 1 MiB was cut", logical.number));
            }
            if let Some(name) = line.strip_prefix('[').and_then(|l| l.strip_suffix(']')) {
                section = name.to_string();
            } else if let Some((key, value)) = line.split_once('=') {
                if let Some(slot) = slot(&section, key.trim()) {
                    let value = value.trim();
                    // An empty assignment resets the list built so far.
                    if value.is_empty() {
                        lists[slot].clear();
                    } else {
                        lists[slot].push(value.to_string());
                    }
                }
            } else {
                sink.warn(format!("line {}: neither a section nor an assignment", logical.number));
            }
            Ok(())
        },
    )?;

    let get = |slot: usize| joined(&lists[slot]);
    sink.emit(
        Loc::None,
        &Unit {
            unit,
            drop_in,
            unit_type,
            description: get(DESCRIPTION),
            exec_start: get(EXEC_START),
            exec_start_pre: get(EXEC_START_PRE),
            exec_start_post: get(EXEC_START_POST),
            exec_stop: get(EXEC_STOP),
            exec_stop_post: get(EXEC_STOP_POST),
            exec_condition: get(EXEC_CONDITION),
            exec_reload: get(EXEC_RELOAD),
            run_user: get(RUN_USER),
            run_group: get(RUN_GROUP),
            working_directory: get(WORKING_DIRECTORY),
            environment: get(ENVIRONMENT),
            environment_file: get(ENVIRONMENT_FILE),
            wanted_by: get(WANTED_BY),
            required_by: get(REQUIRED_BY),
            also: get(ALSO),
            on_calendar: get(ON_CALENDAR),
            on_boot_sec: get(ON_BOOT_SEC),
            on_active_sec: get(ON_ACTIVE_SEC),
            on_startup_sec: get(ON_STARTUP_SEC),
            on_unit_active_sec: get(ON_UNIT_ACTIVE_SEC),
            timer_unit: get(TIMER_UNIT),
            activates: get(ACTIVATES),
            listen: get(LISTEN),
            path_triggers: get(PATH_TRIGGERS),
            restart: get(RESTART),
            service_type: get(SERVICE_TYPE),
            modified: (input.mtime > 0).then(|| Timestamp::from_secs(input.mtime, Basis::Recorded)),
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{fixture, run};
    use nixcavate_source::glob::Pattern;

    fn unit(name: &str, path: &str) -> String {
        run(&ARTIFACT, path, &fixture(&format!("systemd-units/{name}")), 1_700_000_000)
    }

    #[test]
    fn distro_units() {
        insta::assert_snapshot!("ssh_service", unit("ssh.service", "lib/systemd/system/ssh.service"));
        insta::assert_snapshot!("cron_service", unit("cron.service", "lib/systemd/system/cron.service"));
        insta::assert_snapshot!("apt_daily_timer", unit("apt-daily.timer", "lib/systemd/system/apt-daily.timer"));
        insta::assert_snapshot!("ssh_socket", unit("ssh.socket", "lib/systemd/system/ssh.socket"));
    }

    #[test]
    fn suspicious_service_with_continuations_and_resets() {
        insta::assert_snapshot!(unit("evil.service", "etc/systemd/system/evil.service"));
    }

    #[test]
    fn user_unit_and_drop_in() {
        insta::assert_snapshot!(unit("updater.service", "home/alice/.config/systemd/user/updater.service"));
        insta::assert_snapshot!(unit("override.conf", "etc/systemd/system/ssh.service.d/override.conf"));
    }

    #[test]
    fn comment_ending_in_backslash_does_not_hide_the_next_directive() {
        let data = b"[Service]\n# note \\\nExecStartPre=/tmp/implant\nExecStart=/usr/bin/true\n";
        let out = run(&ARTIFACT, "etc/systemd/system/x.service", data, 0);
        assert!(out.contains("\"exec_start_pre\":\"/tmp/implant\""), "{out}");
    }

    #[test]
    fn socket_hooks_service_and_extra_timer_keys_are_read() {
        let data = b"[Socket]\nExecStartPre=/tmp/a\nExecStopPost=/tmp/b\nService=x.service\n[Timer]\nOnActiveSec=5\nOnStartupSec=6\n[Service]\nExecCondition=/tmp/c\n";
        let out = run(&ARTIFACT, "etc/systemd/system/x.socket", data, 0);
        for want in [
            "\"exec_start_pre\":\"/tmp/a\"",
            "\"exec_stop_post\":\"/tmp/b\"",
            "\"activates\":\"x.service\"",
            "\"on_active_sec\":\"5\"",
            "\"on_startup_sec\":\"6\"",
            "\"exec_condition\":\"/tmp/c\"",
        ] {
            assert!(out.contains(want), "{want} in {out}");
        }
    }

    #[test]
    fn path_unit() {
        insta::assert_snapshot!(unit("watch.path", "etc/systemd/system/watch.path"));
    }

    #[test]
    fn empty_and_garbage_do_not_panic() {
        let out = run(&ARTIFACT, "etc/systemd/system/masked.service", b"", 0);
        assert!(out.contains("\"unit\":\"masked.service\""));
        let _ = run(
            &ARTIFACT,
            "etc/systemd/system/x.service",
            b"\xff\x00\n[\n=\n]\nExecStart\n\\\n[Service]\nExecStart=\\",
            0,
        );
    }

    #[test]
    fn patterns_cover_units_and_drop_ins_but_not_targets() {
        let matches = |path: &str| ARTIFACT.paths.iter().any(|p| Pattern::new(p).matches(path));
        assert!(matches("etc/systemd/system/multi-user.target.wants/x.service"));
        assert!(matches("etc/systemd/system/ssh.service.d/override.conf"));
        assert!(matches("home/alice/.config/systemd/user/a.timer"));
        assert!(matches("usr/lib/systemd/system/foo.service"));
        assert!(matches("usr/local/lib/systemd/system/foo.service"));
        assert!(matches("home/alice/.local/share/systemd/user/foo.service"));
        assert!(!matches("etc/systemd/system/multi-user.target"));
        assert!(!matches("etc/systemd/system/system.conf"));
    }
}
