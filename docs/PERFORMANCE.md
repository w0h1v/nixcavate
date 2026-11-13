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
| Binary parsers ≥ 200 MiB/s per core | journald 344 (CSV), 466 (JSONL). Unified Log about 33 MiB/s. `pacct`: a 200 MiB file of 3.3 million records in 0.85 s, 235 MiB/s end to end (CSV, 514 MB of output, one task: a binary file is not split) | journald and `pacct` yes; Unified Log no |
| `super-timeline` ≤ 25% of the `auto-parse` time | 21% and 23% | Yes |
| `auto-parse` within 1.5× of reading the input once | 3.3 s against 0.28 s to read the same 2.9 GiB from the page cache | No |
| Memory flat with input size | Anonymous memory (the "peak memory footprint" `time -l` reports) is flat: 0.5 to 0.65 GB for a 1.0 GB and a 2.9 GB `.tar.gz` collection, 0.8 GB on the Unified Log archive. Peak resident size is not: it counts file-backed pages of mapped inputs, and grows with them (2.2 GB and 4.3 GB for the two collections) | Footprint yes; resident size no, see below |

### Service log parsers

200 MiB files made by repeating real log lines, one thread, `parse <artifact> -f <file> -t csv`
to a file, release build (12-core laptop). The output is written too, and is as large as the
input for most of these, which is why they are slower than `syslog` on the same lines (435
MiB/s, 248 MiB out).

| Artifact | Input | MiB/s | Output |
|---|---|---|---|
| `mail-log` (Postfix and Dovecot) | 200 MiB | 346 | 86 MiB |
| `haproxy-log` | 200 MiB | 213 | 216 MiB |
| `squid-access-log`, native and combined | 200 MiB | 244, 226 | 332, 277 MiB |
| `postgres-log` (stderr) | 200 MiB | 188 | 279 MiB |
| `vsftpd-log` | 200 MiB | 235 | 254 MiB |
| `mysql-general-log` | 200 MiB | 128 | 539 MiB |

Only `mail-log` meets the 300 MiB/s target; the others are bound by serialising their wide
records. `haproxy-log`, `squid-access-log` and `vsftpd-log` split a large file at newlines and
scale with threads; `mail-log`, `postgres-log` and `mysql-general-log` keep state between lines
(queue ids, continuation lines, connection ids) and read a file on one thread.

### Memory on a large `.tar.gz`

Measured on a real 2.9 GB UAC `.tar.gz` (4.4 million body-file entries, 20 GB of logs inside)
with `/usr/bin/time -l`, before and after the change below:

| | Peak resident size | Peak memory footprint | Wall time |
|---|---|---|---|
| Before (archive memory-mapped) | 7.1 GB | 0.60 GB | 36.8 s |
| After (archive streamed from the file) | 4.3 GB | 0.64 GB | 34.7 s |

What holds it. The kept entries are not the cause: of the 8.8 GB of log files the stream
kept for parsing, 15 MB stayed in memory and 8.8 GB went to scratch files in 89 spools. The
memory is **file-backed pages**, which `ru_maxrss` counts but the kernel can drop at any time:
the mapped archive (2.9 GB, resident after the one pass that lists it: streaming it
instead removed 2.8 GB from the peak) and the rest, about 3.7 GB, which is the mapped spool
files of the tasks running at once (by subtraction; the spools total 8.8 GB, and only the
files being parsed are mapped).
The anonymous memory, which is what the "footprint" column counts, measured 0.5 to 0.65 GB
on both collections; it was not broken down further.

Change: an archive of 2 GiB or more is read through a buffered file instead of a mapping,
since nothing in a compressed tar is later served from the mapping. Smaller archives keep
the mapping: on a 1 GB archive a buffered read costs about 0.9 s more of system time (copying
from the page cache) for 1 GB less resident size. Record counts, status and warnings of all
1,623 tasks of the large collection are identical before and after.

Not done: the spool files are still mapped whole while a task parses them. Releasing pages
as the parse advances needs `madvise`, which this project does not use (it has one `unsafe`
block, the mapping itself).

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
