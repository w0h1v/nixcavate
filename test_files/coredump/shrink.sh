#!/bin/sh
# Keeps the fixtures small: the journal's COREDUMP_* fields (kilobytes each, with the process
# maps and environment) are reduced to the ones the tests compare. The core files themselves
# are kept as systemd-coredump wrote them (about 16 KiB each for a sleeping process).
# Run from this folder after generate.sh.
set -eu
for d in */; do
    cd "$d"
    python3 -I - <<'PY'
import json
keep = ("COREDUMP_PID", "COREDUMP_UID", "COREDUMP_EXE", "COREDUMP_COMM", "COREDUMP_CMDLINE",
        "COREDUMP_SIGNAL", "COREDUMP_SIGNAL_NAME", "COREDUMP_FILENAME", "COREDUMP_TIMESTAMP")
with open("journal-fields.jsonl", "w") as out:
    for line in open("journal-coredump.json"):
        d = json.loads(line)
        if "COREDUMP_FILENAME" in d:
            out.write(json.dumps({k: d[k] for k in keep if k in d}, sort_keys=True) + "\n")
PY
    rm -f journal-coredump.json coredumpctl-list.json
    cd ..
done
