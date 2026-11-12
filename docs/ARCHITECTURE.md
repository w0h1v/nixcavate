# Architecture

How nixcavate is put together, and why.

## The shape of a run

```
evidence ──► Source ──► Host ──► plan ──► tasks ──► worker pool ──► Sink ──► records
(dir, tar,   list once   root,    one per   largest     N threads    per     <host>/<Category>/<artifact>/*.csv
 zip, image)             OS,      file or   first       pull tasks   task    <host>/_timeline/<artifact>/*.run
                         zone     chunk                                       manifest.json
                                                                                  │
                                              super-timeline ◄── parallel merge ──┘
```

1. **Source** (`nixcavate-source`). A directory, an archive or a disk image is listed once
   into a sorted table of entries. Nothing is extracted: a directory entry is memory-mapped
   when read, a zip or plain-tar entry is a range of the mapped archive, an image entry is
   read through a filesystem reader.
2. **Host**. Discovery finds each host root inside a source (`[root]` in a UAC collection,
   `/` in a mounted volume) and reads its name, OS and time zone.
3. **Plan** (`plan.rs`). Each artifact lists path patterns. Every matching file becomes one
   task. A large plain-text file whose parser works line by line is cut at newlines into
   64 MiB chunks, each its own task. Tasks are sorted by estimated work, largest first.
4. **Execute** (`exec.rs`). A fixed pool of threads pulls tasks from an atomic index. Each
   task owns its `Sink` and its output files, so nothing on the hot path is shared or locked.
   A parser panic is caught at the task boundary and becomes a failed task.
5. **Sink** (`nixcavate-core`). The parser hands records to the sink. The sink writes each
   record as a CSV row or JSON object and, in the same pass, appends the record's timeline
   events to a buffer that is written out as a sorted run.
6. **Manifest**. One entry per task: status, duration, bytes, records, warnings, outputs.
7. **super-timeline**. Memory-maps the runs and merges them in parallel. No artifact is parsed
   a second time.

## Crates

| Crate | Holds | Depends on |
|---|---|---|
| `nixcavate-core` | `Timestamp`, the row serializer, `Sink`, timeline runs and their merge, the manifest | serde, memchr, itoa, ryu |
| `nixcavate-fs` | Read-only ext4, XFS and APFS readers | nothing |
| `nixcavate-source` | Directories, archives, disk images (E01, partition tables), host discovery, zones, path patterns | core, fs |
| `nixcavate-artifacts` | One module per artifact, under `linux/`, `macos/`, `common/` | core, source |
| `nixcavate` | The commands, the planner, the executor, the summary | all of the above |

## Where the speed comes from

| Choice | Effect |
|---|---|
| One task per file, and per 64 MiB chunk of a big text log | The slowest task no longer sets the wall time; a 2 GiB log uses every core |
| Largest task first | No long task is left running alone at the end |
| Threads, not child processes | No process start per task; the host listing is shared read-only |
| Each task owns its output | No lock, no contention |
| Memory-mapped input, `memchr` line splitting | No copy of the input; no per-line allocation |
| Records borrow from the input | A parser allocates only for values it has to build |
| A row serializer written for this job (`row.rs`) | One pass into one buffer: `itoa`/`ryu` numbers, a fixed RFC 3339 formatter, JSON keys built once per record type |
| Timeline events written during the parse | `super-timeline` only merges; it never re-reads CSV |
| A sparse index in each run | The merge cuts all runs at the same instants and merges the pieces on all cores |
| `mimalloc` | Required for static musl builds, whose allocator is slow under threads |
| `lto = "fat"`, `codegen-units = 1` | Whole-program inlining of the parser and sink hot paths |

Measured numbers and how to reproduce them are in [PERFORMANCE.md](PERFORMANCE.md).

## The artifact contract

```rust
pub const ARTIFACT: Artifact =
    Artifact::new("wtmp", "Logins, logouts and boots", Category::Accounts, LINUX, &["var/log/wtmp*"], parse);

fn parse(input: &Input, sink: &mut Sink) -> Result<()>
```

An artifact is a value: an id, a category, the OSes it applies to, path patterns, and a parse
function. The registry is a list per OS folder. A parser sees one input (`data`, the path, the
file's metadata, the host) and one sink. It never opens a file or chooses a format.
[ADDING_AN_ARTIFACT.md](ADDING_AN_ARTIFACT.md) is the guide.

## Timestamps

```rust
pub struct Timestamp { pub utc: i64, pub precision: Precision, pub basis: Basis }
```

`utc` is nanoseconds since the Unix epoch, so sorting and merging compare integers. A
timestamp cannot be built without saying how precise the source was and how the instant was
obtained:

| Basis | Meaning |
|---|---|
| `recorded` | The source holds a complete instant: an epoch value or a date with a zone |
| `assumed_zone` | The source has no zone; the host zone was applied (UTC when the host zone is unknown) |
| `inferred_year` | The source has no year; it was inferred from the file's modification time |
| `inferred_year_assumed_zone` | Both (classic syslog) |

The host zone comes from the evidence's own `/etc/localtime`. When the evidence only names the
zone, the analyst machine's zone database supplies the rules, and the manifest says so.
A year is inferred per line with one rule: the latest year that does not put the line more
than a day after the file's last modification. The rule needs no state from other lines, so
chunks of a split file agree.

## Timeline runs

Each task buffers its events encoded, and writes them as a run: a header (host, artifact,
source path), the events in time order, and a sparse index (one entry per 64 KiB). Logs are
already in time order, so the usual run is written without sorting. A task that produces more
than 16 MiB of events writes several runs, which keeps memory flat.

The merge reads every run's index, picks cut instants so that each partition holds about
8 MiB, and gives partitions to worker threads. A worker finds its slice of every run through
the index, merges the slices with a heap, and formats the rows. A writer emits partitions in
order. Ties are broken by run order, so the output is identical for any thread count.

## Hostile input

Evidence is attacker-controlled. The rules:

- **No path from the evidence is ever used as a path on the analyst's machine.** Entry names
  are only matched and displayed. Output names are rebuilt from a safe character set.
- **Symlinks are never followed out of the evidence.** The directory walk does not follow
  links; a link inside a host root is resolved against that root only.
- **Special files are never opened.** Sockets, FIFOs and devices in a mounted volume are skipped.
- **Parsers do not panic.** Lengths and offsets from input are bounds-checked; loops over
  on-disk links have guards. Fuzz targets cover the binary formats. If a parser panics anyway,
  `catch_unwind` at the task boundary turns it into one failed task.
- **Sizes are not trusted.** Decompression and allocation are capped by limits and by the
  bytes actually present.
- **One `unsafe` block**: the read-only memory map in `nixcavate-source`. If another process
  truncates an evidence file during a run, the OS raises `SIGBUS` and the run aborts.
  Evidence is expected to be static; this is the accepted cost of zero-copy reads.
- **SQLite never opens evidence in place.** The database and its write-ahead log are copied
  to a scratch directory and opened there, so no `-shm` file appears beside the evidence and
  rows still in the WAL are read.
- **Secrets are not output.** Shadow hashes, Wi-Fi keys and password verifiers are reduced to
  their type.
