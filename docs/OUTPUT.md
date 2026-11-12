# Output contract

What a pipeline can rely on. Field names are stable within a major version; every change is
listed in [CHANGELOG.md](../CHANGELOG.md).

## Layout of an `auto-parse` run

```
<output>/
  manifest.json
  <host>/
    <Category>/<artifact>/<input>.<csv|json|jsonl>     records
    _timeline/<artifact>/<input>.<n>.run               sorted timeline runs (binary)
  timeline.<csv|json|jsonl>                            written by super-timeline
```

- `<host>` is the host name made file-system-safe. Two collections of the same host become
  `name` and `name-2`.
- `<Category>` is one of `Accounts`, `Logs`, `Execution`, `Persistence`, `Software`,
  `Network`, `Filesystem`, `Containers`, `Activity`, `Security`, `System`, `Live`.
- `<input>` is the source path with `/` replaced by `_`. One file is written per task, so one
  per input file, or one per chunk for a split log (`name@<byte offset>`). Glob
  `<artifact>/*.csv` to read an artifact.
- A task that produced no records writes no file.

## Records

Every row starts with the same four columns:

| Column | Meaning |
|---|---|
| `host` | The host the record belongs to |
| `artifact` | The artifact id |
| `source_path` | The input path relative to the host root. `../` marks a file beside the root (UAC `live_response/`) |
| `source_line` or `source_offset` | 1-based line, or byte offset in the (decompressed) input. An artifact uses one of the two |

The remaining columns belong to the artifact. They are snake_case and identical in CSV headers
and JSON keys. Shared names mean the same thing everywhere:

| Name | Meaning |
|---|---|
| `time` | The record's primary timestamp. Other times are `<what>_time` |
| `time_basis` | Present when the basis can differ between rows of one artifact |
| `user`, `uid`, `gid`, `pid`, `ppid` | Account and process identity |
| `command` | A command line |
| `path` | A file path named by the record |
| `message` | Free log text |
| `remote_address`, `remote_port`, `remote_host` | The other end of a connection |

Formats:

- **Timestamps** are RFC 3339 in UTC: `2024-03-10T01:02:03.123456Z`. The number of fraction
  digits is the precision of the source (none, 3, 6 or 9).
- **CSV**: RFC 4180 quoting, `\n` line ends, one header row per file. An absent value is an
  empty cell. A nested value (a list or map) is a JSON string in one cell.
- **JSONL**: one object per line. **JSON**: one array per file. An absent value is `null`;
  nested values stay nested.
- Text that is not valid UTF-8 in the source has its bad bytes replaced with U+FFFD.

## `manifest.json`

```json
{
  "schema_version": 1,
  "tool_version": "0.1.0",
  "started": "2026-11-11T20:15:00Z",
  "duration_ms": 612,
  "threads": 12,
  "format": "csv",
  "hosts": [
    { "name": "web01", "os": "linux", "os_version": "Debian GNU/Linux 12 (bookworm)",
      "source": "evidence/uac-web01.tar.gz", "root": "[root]",
      "timezone": "Europe/Berlin (zone data from the evidence)", "output_dir": "web01" }
  ],
  "tasks": [
    { "host": "web01", "artifact": "wtmp", "input": "var/log/wtmp", "input_offset": 0,
      "input_bytes": 768, "status": "succeeded", "error": null, "duration_ms": 1,
      "records": 2, "records_per_sec": 1914, "events": 2,
      "first_event": "2023-11-14T22:13:20.000000Z", "last_event": "2023-11-14T22:15:00.000000Z",
      "input_modified": "2023-11-14T22:13:20Z", "warnings": [],
      "outputs": ["web01/Accounts/wtmp/var_log_wtmp.csv"],
      "timeline_runs": ["web01/_timeline/wtmp/var_log_wtmp.0.run"] }
  ]
}
```

- `status` is `succeeded`, `skipped` (nothing to parse: an empty file, a format variant the
  parser does not handle; `error` says why) or `failed` (`error` says why; whatever was parsed
  before the failure is still in `outputs`).
- `first_event` and `last_event` are the earliest and latest timeline events the task
  produced; `input_modified` is the input file's modification time as collected. For a log
  that failed part-way (cut by `--max-expansion`, damaged), the unparsed part lies between
  `last_event` and `input_modified`. For an input that was skipped, only `input_modified` is
  known. The run summary prints this for every failed task and every skipped input that
  holds data.
- `warnings` holds up to 20 messages per task, then a count of the rest.
- `timezone` says how zone-less times were converted, so an analyst can judge every
  `assumed_zone` timestamp of that host.
- Paths are relative to the manifest.

Notes on single artifacts:

- **`unified-log`**: `source_offset` is the file offset of the chunk set an entry sits in,
  shared by many entries; `chunk_offset` locates the entry inside the decompressed chunk
  set. `time_estimated` is true when no time-sync record matched and the time was derived
  from the file header. `ttl_days` is the entry's retention class when it has one.
- **`bodyfile`**: also produced for disk images, from the filesystem itself.
- A record never holds a secret: `shadow` and `dslocal-users` give hash types only,
  `networkmanager` gives `has_secret`.

## Limits on input

`--max-expansion <RATIO>` (default 100, `0` for none) bounds how far compressed evidence may
expand: a compressed log to RATIO times its size (at least 16 MiB), an archive's kept entries
to RATIO times the archive (at least 1 GiB). A task that hits the limit fails, keeps the
records it parsed, and names the flag in its error.

## Timeline

`super-timeline -d <output>` writes one row per event, ordered by time:

| Column | Meaning |
|---|---|
| `timestamp` | RFC 3339, UTC |
| `precision` | `nanos`, `micros`, `millis`, `seconds` or `day` |
| `basis` | `recorded`, `assumed_zone`, `inferred_year` or `inferred_year_assumed_zone` |
| `host`, `artifact` | Where the event comes from |
| `event` | What the time means: `login`, `executed`, `package_installed`, `m.c.` (file times) |
| `message` | One line for a human |
| `source_path`, `source_line`, `source_offset` | Where to find the source record |
| `rule`, `level` | Sigma rule title and level, for imported detections; otherwise empty |

Events with the same timestamp keep a fixed order (by run, then by position in the source), so
the same run always gives the same timeline.

`--start <TIME>` and `--end <TIME>` keep only the events in a window: `--start` is inclusive,
`--end` is exclusive. A time is RFC 3339 (`2026-03-01T08:00:00Z`); without an offset it is
UTC, and a date alone (`2026-03-01`) is midnight UTC. Events outside the window are skipped
through each run's index, not read. Imported Sigma detections are filtered the same way.

`--sigma <FILE>` merges ChopChopGo (`-out json`) or Zircolite (`detected_events.json`)
results. Their rows have `artifact` `sigma-chopchopgo` or `sigma-zircolite`, `event`
`detection`, and `source_path` set to the results file. ChopChopGo output carries no rule
level. Detections whose time cannot be read are counted and reported, not guessed.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | The run completed; every task succeeded or was skipped |
| 1 | The run completed; at least one task failed (see the manifest) |
| 2 | The run could not start: bad arguments, unreadable evidence, an output directory that already holds a run and no `--clobber`, or output and evidence directories that contain each other |
