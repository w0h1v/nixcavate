#!/bin/sh
# Regenerates the fixtures with Docker (privileged): real systemd-coredump and journald from
# Debian 12, fed core files made by gcore through its kernel-pipe interface, then shrink.sh.
set -eu
here="$(cd "$(dirname "$0")" && pwd)"
rm -rf "$here/debian12"; mkdir -p "$here/debian12"
docker run --rm --platform linux/arm64 --privileged -v "$here/inside.sh:/inside.sh:ro" -v "$here/launcher.py:/launcher.py:ro" \
    -v "$here/debian12:/o" debian:12 sh -c 'mkdir -p /out; sh /inside.sh; cp -r /out/. /o/ 2>/dev/null || true'
cd "$here" && sh shrink.sh
