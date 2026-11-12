#!/usr/bin/env python3
"""Times `auto-parse` and `super-timeline` on a corpus collection and gates on a baseline.

    bench.py NAME CORPUS [--bin PATH] [--runs 3] [--record] [--tolerance 0.15]

NAME labels the collection in bench/baseline.json. Without --record the run is compared with
the baseline for this machine: it fails (exit 1) when throughput drops by more than the
tolerance, or when the record or event count changes at all. A changed count is either a
parser fix (re-record and say why in CHANGELOG.md) or a regression.
Baselines are per machine because throughput is; a machine with no baseline only reports.
"""
import argparse
import json
import os
import platform
import shutil
import subprocess
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
BASELINE = os.path.join(HERE, "baseline.json")


def best_time(command, runs, prepare=lambda: None):
    best = None
    for _ in range(runs):
        prepare()
        start = time.perf_counter()
        result = subprocess.run(command, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        elapsed = time.perf_counter() - start
        if result.returncode not in (0, 1):  # 1 = some tasks failed; still a measurement
            sys.exit(f"{' '.join(command)}\n{result.stderr.decode()}")
        best = elapsed if best is None else min(best, elapsed)
    return best


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("name")
    parser.add_argument("corpus")
    parser.add_argument("--bin", default=os.path.join(HERE, "..", "target", "release", "nixcavate"))
    parser.add_argument("--runs", type=int, default=3)
    parser.add_argument("--record", action="store_true", help="store this run as the baseline for this machine")
    parser.add_argument("--tolerance", type=float, default=0.15)
    args = parser.parse_args()
    machine = os.environ.get("NIXCAVATE_BENCH_MACHINE", f"{platform.node()}-{platform.machine()}")

    out = tempfile.mkdtemp(prefix="nixcavate-bench-")
    try:
        flag = "-d" if os.path.isdir(args.corpus) else "-f"
        parse = best_time(
            [args.bin, "auto-parse", flag, args.corpus, "-o", out, "-q"],
            args.runs,
            prepare=lambda: shutil.rmtree(out, ignore_errors=True),
        )
        timeline = best_time([args.bin, "super-timeline", "-d", out, "-C", "-q"], args.runs)
        with open(os.path.join(out, "manifest.json")) as f:
            tasks = json.load(f)["tasks"]
    finally:
        shutil.rmtree(out, ignore_errors=True)

    mib = sum(t["input_bytes"] for t in tasks) / (1 << 20)
    result = {
        "input_mib": round(mib, 1),
        "tasks": len(tasks),
        "failed": sum(t["status"] == "failed" for t in tasks),
        "records": sum(t["records"] for t in tasks),
        "events": sum(t["events"] for t in tasks),
        "auto_parse_s": round(parse, 3),
        "auto_parse_mib_s": round(mib / parse, 1),
        "super_timeline_s": round(timeline, 3),
        "timeline_share": round(timeline / parse, 2),
    }
    print(f"{args.name} on {machine}")
    for key, value in result.items():
        print(f"  {key:18} {value}")
    slowest = sorted(tasks, key=lambda t: -t["duration_ms"])[:5]
    for t in slowest:
        rate = t["input_bytes"] / (1 << 20) / max(t["duration_ms"], 1) * 1000
        print(f"  slow: {t['duration_ms']:6} ms {rate:7.0f} MiB/s  {t['artifact']:16} {t['input']}")

    baselines = json.load(open(BASELINE)) if os.path.exists(BASELINE) else {}
    if args.record:
        baselines.setdefault(machine, {})[args.name] = result
        with open(BASELINE, "w") as f:
            json.dump(baselines, f, indent=2, sort_keys=True)
            f.write("\n")
        print(f"  recorded in {BASELINE}")
        return
    base = baselines.get(machine, {}).get(args.name)
    if base is None:
        print("  no baseline for this machine and collection; nothing to compare")
        return
    problems = []
    for key in ("records", "events", "failed"):
        if result[key] != base[key]:
            problems.append(f"{key} changed: {base[key]} -> {result[key]}")
    floor = base["auto_parse_mib_s"] * (1 - args.tolerance)
    if result["auto_parse_mib_s"] < floor:
        problems.append(f"auto-parse {result['auto_parse_mib_s']} MiB/s is below {floor:.1f} (baseline {base['auto_parse_mib_s']})")
    ceiling = base["super_timeline_s"] * (1 + args.tolerance) + 0.05
    if result["super_timeline_s"] > ceiling:
        problems.append(f"super-timeline {result['super_timeline_s']} s is above {ceiling:.2f} (baseline {base['super_timeline_s']})")
    for problem in problems:
        print(f"  FAIL {problem}")
    sys.exit(1 if problems else 0)


if __name__ == "__main__":
    main()
