#!/usr/bin/env python3
"""reduce.py DIR: keeps only the parts of sadf.json the tests compare (the file is 130 KB with
interrupts, paging and power management), and the sadf CSV, which is not needed."""
import json, os, sys
d = sys.argv[1]
j = json.load(open(os.path.join(d, "sadf.json")))
keep = ("timestamp", "cpu-load", "process-and-context-switch", "memory", "queue", "disk", "network")
host = j["sysstat"]["hosts"][0]
host["statistics"] = [{k: s[k] for k in keep if k in s} for s in host["statistics"]]
for s in host["statistics"]:
    if "network" in s:
        s["network"] = {"net-dev": s["network"].get("net-dev", [])}
    for entry in s.get("disk", []):
        for k in ("rd_sec", "wr_sec", "dc_sec", "dkB", "avgrq-sz", "avgqu-sz"):
            entry.pop(k, None)
with open(os.path.join(d, "sadf.json"), "w") as f:
    json.dump(j, f, separators=(",", ":"))
os.remove(os.path.join(d, "sadf-d.csv")) if os.path.exists(os.path.join(d, "sadf-d.csv")) else None
