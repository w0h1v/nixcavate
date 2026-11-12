#!/bin/sh
# Regenerates the journald fixtures with the real systemd-journal-remote from the synthetic
# export stream of export.py, and dumps each with journalctl. systemd 252 writes the none and
# zstd variants, 257 the lz4 and xz ones (older versions ignore SYSTEMD_JOURNAL_COMPRESS and
# always use their build default), 249 and 245 are older writers (245: LZ4, no keyed hash). Fixtures are stored zstd-compressed (a journal file is mostly
# preallocated zeros); every variant holds the same entries, so one journalctl dump serves all.
#   ./generate.sh OUT_DIR          variants in OUT_DIR; copy *.journal.zst and journalctl.json here
#   ./generate.sh OUT_DIR big N    OUT_DIR/big.journal: N entries written by journald itself
#                                  (journal-remote rotates at ~48 MiB); 1500000 gives ~880 MiB
set -eu
out=$(cd "$1" && pwd)
here=$(cd "$(dirname "$0")" && pwd)
image() { # $1 base image, $2 tag
    printf 'FROM %s\nRUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends systemd-journal-remote python3 && rm -rf /var/lib/apt/lists/*\n' "$1" |
        docker build -q -t "$2" - >/dev/null
}
write() { # $1 image, $2 name, $3 compact 0|1, $4 compression (none|xz|lz4|zstd)
    docker run --rm -v "$here:/gen:ro" -v "$out:/out" -e SYSTEMD_JOURNAL_COMPACT="$3" \
        -e SYSTEMD_JOURNAL_COMPRESS="$(echo "$4" | tr a-z A-Z)" "$1" sh -c "
        python3 /gen/export.py | /lib/systemd/systemd-journal-remote --compress=$([ "$4" = none ] && echo no || echo yes) -o /out/$2.journal - &&
        journalctl --file /out/$2.journal -o json --all --no-pager > /out/$2.journalctl.json"
}
image debian:12 nixcavate-journal-252
image debian:13 nixcavate-journal-257
image ubuntu:22.04 nixcavate-journal-249
image ubuntu:20.04 nixcavate-journal-245
if [ "${2:-}" = big ]; then
    docker run --rm -v "$here:/gen:ro" -v "$out:/out" nixcavate-journal-252 sh -c "
        echo 0123456789abcdef0123456789abcdef >/etc/machine-id && mkdir -p /run/systemd/journal &&
        printf '[Journal]\nStorage=volatile\nRuntimeMaxFileSize=3G\nRuntimeMaxUse=20G\nRuntimeKeepFree=0\nRateLimitBurst=0\n' >/etc/systemd/journald.conf &&
        { /lib/systemd/systemd-journald 2>/dev/null & sleep 2; } &&
        python3 /gen/export.py feed $3 && sleep 3 &&
        cp /run/log/journal/*/system.journal /out/big.journal &&
        journalctl --file /out/big.journal -o json --all --no-pager >/out/big.journalctl.json"
    exit
fi
for c in none zstd; do
    write nixcavate-journal-252 "compact-$c" 1 "$c"
    write nixcavate-journal-252 "regular-$c" 0 "$c"
done
for c in lz4 xz; do
    write nixcavate-journal-257 "compact-$c" 1 "$c"
    write nixcavate-journal-257 "regular-$c" 0 "$c"
done
write nixcavate-journal-249 v249-zstd 0 zstd
write nixcavate-journal-245 v245-lz4 0 lz4
for f in "$out"/*.journal; do zstd -19 -q -f "$f" -o "$f.zst"; done
python3 -c '
import json, sys
for line in open(sys.argv[1]):
    entry = json.loads(line)
    entry.pop("__CURSOR")  # names the file it came from
    print(json.dumps(entry, sort_keys=True))
' "$out/compact-none.journalctl.json" >"$out/journalctl.json"
