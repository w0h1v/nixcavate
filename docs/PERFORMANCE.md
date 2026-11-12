# Performance

Measured numbers against the design targets. Reproduce them with
[bench/README.md](../bench/README.md).

Machine: a 12-core laptop with an SSD. Release build
(`lto = "fat"`). Best of three runs. Measured 2026-11-11 on the build that closes this work.

## Whole runs

| Collection | Input | Tasks | Records | `auto-parse` | Throughput | `super-timeline` | Timeline share |
|---|---|---|---|---|---|---|---|
| `synth-linux-2048`: text logs plus one 880 MiB journal | 2.9 GiB | 38 | 19.0 M | 3.3 s | 887 MiB/s | 0.70 s (22.5 M events) | 21% |
| `macos-unified`: a real Unified Log archive | 826 MiB | 534 | 26.2 M | 4.5 s | 184 MiB/s | 1.05 s (26.2 M events) | 23% |
| `uac-debian12`: a real UAC collection (tar.gz) | 2.1 MiB | 65 | 18,574 | 0.04 s | — | 0.01 s | — |

## Against the targets

| Target | Result | Met |
|---|---|---|
| Text log parsers ≥ 300 MiB/s per core | Records only, CSV: syslog 409, docker-logs 407, audit 359, web-access 338, bodyfile 310, auth-log 271, dpkg-log 218 | 5 of 7 |
| Binary parsers ≥ 200 MiB/s per core | journald 344 (CSV), 466 (JSONL). Unified Log about 33 MiB/s | journald yes; Unified Log no |
| `super-timeline` ≤ 25% of the `auto-parse` time | 21% and 23% | Yes |
| `auto-parse` within 1.5× of reading the input once | 3.3 s against 0.28 s to read the same 2.9 GiB from the page cache | No |
| Memory flat with input size | Peak 0.8 GB on the Unified Log archive (input is memory-mapped, so mapped pages count) | Yes, with the notes below |

### Where targets are missed, and why

- **auth-log and dpkg-log.** auth-log classifies each line (SSH, sudo, PAM, account
  changes), which costs several substring searches. dpkg-log lines are short (about 75
  bytes), so per-record cost dominates: it parses 2.9 million records a second.
- **Unified Log.** One MiB of `tracev3` holds about 31,000 entries, each needing LZ4
  decompression, a format-string lookup and `printf`-style rendering. 33 MiB/s per core is
  about one million entries a second. The run is output-bound: 826 MiB of input becomes
  21 GB of CSV.
- **1.5× of a read.** The comparison is against a read from the page cache, which is
  unrealistically fast. The wall time of the Linux run is set by one task: the 880 MiB
  journal takes 3.3 s on one core while everything else finishes in under a second. A
  journal file cannot be split safely, so the rule holds: the wall time of a run
  is the time of its slowest task.
- **Timeline events cost throughput.** The per-core figures above are for `parse`, which
  writes records only. In `auto-parse` every log line also becomes a timeline event, and
  per-core throughput drops by a third to a half (syslog about 270 MiB/s, audit 170,
  auth-log 120). That work is what makes `super-timeline` a merge instead of a second parse.

## What was done to get here

| Change | Effect |
|---|---|
| Own row serializer with prebuilt JSON keys, replacing `serde_json` on the hot path | JSONL: syslog 243 → 291, docker-logs 359 → 437 MiB/s |
| Events not built when no timeline is wanted (`parse`) | syslog CSV 307 → 385 MiB/s |
| Runs written without sorting when events arrive in order | Removes a sort and a copy per run for every log |
| Zone rule transitions precomputed at load | Zone conversion became a binary search; dpkg-log parse 175 → 413 MiB/s before output |
| Parallel timeline merge over indexed runs | 6.5 M events: 1.34 s → 0.27 s; 26 M events: 4.0 s → 1.05 s |
| Disk-image volumes kept open for the run | ext4 on E01: 542 µs → about 0.2 µs per file open |

## Not done

- **Profile-guided optimization.** Deferred until the corpus is stable.
- **A baseline in the repository.** Baselines are per machine and none is committed. The CI
  job reports until someone records one on the CI runner class (`bench.py --record`).
- **An official corpus.** The intent is three fixed collections including a large real
  Linux host. The Linux collection here is synthetic (plus one real 880 MiB journal written
  by journald), and the UAC collection is a small container.
- **hyperfine and samply.** Timing uses `bench/bench.py`; profiling used a sampling profiler.
