# Adding an artifact

An artifact is one module that exports one `Artifact` value. Adding one touches that module,
its fixtures, and one line in the OS registry (`linux/mod.rs`, `macos/mod.rs`, `bsd/mod.rs` or `common/mod.rs`).

Read `crates/nixcavate-artifacts/src/linux/passwd.rs` (text) and `linux/utmp.rs` (binary)
first. They are the reference parsers.

## The clean-room rule

Write every parser from published format documentation and from test data. Do not copy code
from other forensic tools. Name the format reference in the module comment (man page, RFC,
vendor documentation).

## Shape of a module

```rust
//! `/etc/passwd`: local accounts. Format: passwd(5).

pub const ARTIFACT: Artifact =
    Artifact::new("passwd", "Local user accounts", Category::Accounts, LINUX, &["etc/passwd"], parse);

#[derive(Serialize)]
struct Account<'a> { user: &'a str, uid: Option<u32>, /* ... */ }

impl Record for Account<'_> {}          // or implement `events` for timeline entries

fn parse(input: &Input, sink: &mut Sink) -> Result<()> { /* sink.emit(loc, &record)? */ }
```

- **id**: lowercase kebab-case, stable forever. It is a CLI argument and an output folder.
- **paths**: glob patterns relative to the host root (`*`, `?`, `**`; `../` reaches beside the
  root, e.g. `../live_response/...`). Prefer `home/*/.x` plus `root/.x` over `**/.x`.
  One task runs per matching file.
- **companions**: patterns for extra files the parser reads through `input.host.read(path)`.
- **`.split_lines()`**: only when every line parses on its own. Large files are then split at
  newlines and parsed in parallel, so the parser must not keep state between lines.
- **`.cost(x)`**: relative work per input byte; leave the default unless a benchmark says otherwise.

## Records

- A flat struct deriving `Serialize`. Field names are snake_case and become CSV headers and
  JSON keys. They are an output contract: choose them carefully.
- Never use `skip_serializing_if`, `flatten`, or enums with data: every row must have the same
  columns. `Option<T>` is fine (empty cell, JSON `null`). Nested `Vec` or map fields are
  allowed; CSV stores them as a JSON string.
- `host`, `artifact`, `source_path`, `source_line` and `source_offset` are written by the sink.
  Do not declare fields with those names (the sink rejects them).
- Borrow from the input (`&str`, `Cow<str>`) instead of allocating. Use `text::lossy` for bytes
  that may not be UTF-8.
- Pass `Loc::Line(n)` for small line-oriented files and `Loc::Offset(n)` for binary files and
  for every `.split_lines()` artifact (`line.offset`). Use one variant per artifact.

## Timestamps

A `Timestamp` states its precision and its basis. Be honest about both.

| Source value | Build with |
|---|---|
| Epoch value, or a date with a zone | `Timestamp::from_secs(..., Basis::Recorded)` and friends; `time::parse_iso8601(..)?.recorded()` |
| Wall-clock time with no zone | `input.local_time(wall_secs, nanos, precision)` (marks `AssumedZone`) |
| No year (classic syslog) | `common::syslog` helpers (mark `InferredYear...`) |

When a record's basis can vary, add a `time_basis: Basis` field so the record says so itself.
Never invent a timestamp from the file's own mtime and present it as recorded.

## Timeline events

Implement `Record::events` when a record has a time an analyst would want on a timeline.
`kind` says what the time means (`login`, `installed`, `executed`); `message` is one short
human sentence. Records with no time keep the default (no events).

## Errors

| Situation | Do |
|---|---|
| One bad line or record | `sink.warn(...)` and continue |
| The file is valid but holds nothing for this parser | `Err(Error::skipped("why"))` |
| The file is not in the expected format at all | `Err(Error::format("why"))` |

A parser must never panic on any input. Evidence is hostile by assumption.

- No indexing or slicing with lengths read from the input unless bounds were checked
  (`data.get(a..b)`).
- No `unwrap`/`expect` on anything derived from input.
- Checked or saturating arithmetic on sizes and offsets read from the input.
- Never allocate by a size field alone; cap it by the bytes actually present.
- Loops over on-disk structures must make progress and must end (guard against cycles).

## Performance

Speed is the main feature. Text parsers should exceed 300 MiB/s per core.

- No `regex`. Split with `memchr` and byte comparisons.
- No per-line `String` or `Vec` allocations on the common path; a `format!` for a timeline
  message is acceptable.
- Read text with `text::for_each_line`, which also handles `.gz`, `.zst` and `.xz` rotations.
  Binary formats that may be rotated use `text::decompressed`.
- SQLite goes through `sqlite::open(input)`, never by opening evidence paths directly.

## Tests

- One fixture per stated behavior under `test_files/<artifact-id>/`, and an `insta` snapshot
  test built with `testing::run` (records as JSONL, then the timeline, then warnings).
- Fixtures are small and synthetic, or generated in a throwaway container. Never commit data
  from a real person or a real host.
- Cover: a normal file, the edge cases the format documents, a truncated or corrupt input
  (it must not panic), and an empty input.
- Review each new snapshot by eye before accepting it: a snapshot only proves the output did
  not change, not that it was right.

Run `cargo test -p nixcavate-artifacts <module>` and `cargo clippy --workspace --all-targets`.
