# Benchmarks

Performance claims are accepted only with numbers from these collections.

## The corpus

| Name | What | Where it comes from |
|---|---|---|
| `uac-debian12` | Small Linux server: a real UAC 3.4 collection of a Debian 12 container (2 MiB) | `uac -p ir_triage` in a throwaway container |
| `synth-linux-<MiB>` | Large Linux host: syslog, auth, audit, nginx, Docker JSON and dpkg logs plus a body file | `bench/gen_corpus.py`, deterministic for a size and seed |
| `macos-unified` | macOS laptop: a Unified Log archive (`tracev3`, `uuidtext`, `timesync`) | built from a real system's log store |

The corpus lives **outside the repository**, by default in `../nixcavate-corpus/`. The real
collections describe real machines and must never be committed. `corpus.sha256` holds the
checksums of the reproducible corpus files, so a changed generator is noticed.

The synthetic collection has no journald files because writing them needs systemd tooling. To
add some, run `test_files/journald/generate.sh` (Docker) and copy the result to
`[root]/var/log/journal/<machine-id>/` inside the collection.

## Running

```sh
cargo build --release -p nixcavate
python3 bench/gen_corpus.py ../nixcavate-corpus/synth-linux-2048 --mib 2048
python3 bench/bench.py synth-linux-2048 ../nixcavate-corpus/synth-linux-2048
python3 bench/bench.py uac-debian12 ../nixcavate-corpus/uac-debian12/uac-*.tar.gz
```

`bench.py` runs `auto-parse` and `super-timeline` three times each and keeps the best wall
time. It prints the throughput, the timeline's share of the parse time and the five slowest
tasks, then compares the run with `baseline.json`.

For one parser on one file, `nixcavate parse <artifact> -f <file> -t csv -T 1 > /dev/null`
under `time` gives single-core throughput. Profile a slow task with `samply record` or
`cargo flamegraph`; the release profile keeps line tables for that.

## The gate

A run fails when, against the baseline for the same machine and collection:

- `auto-parse` throughput is more than 15% lower,
- `super-timeline` takes more than 15% (plus 50 ms) longer, or
- the record count, event count or failed-task count differs at all.

A count that changes is either a parser fix or a regression. If it is a fix, re-record the
baseline (`--record`) and explain the change in `CHANGELOG.md`. An unexplained drop blocks a
release.

Baselines are per machine (`NIXCAVATE_BENCH_MACHINE`, default host name and architecture)
because throughput is. CI uses the key `github-ubuntu-latest`; until a baseline is recorded
under that key the CI job only reports.
