#!/bin/sh
# Regenerates the fixtures: real interactive tools on a pty in a Debian 12 container.
set -eu
here="$(cd "$(dirname "$0")" && pwd)"
rm -rf "$here/debian12"; mkdir -p "$here/debian12"
docker run --rm --platform linux/arm64 -v "$here/inside.sh:/inside.sh:ro" -v "$here/drive.py:/drive.py:ro" \
    -v "$here/debian12:/out" debian:12 sh /inside.sh >/dev/null 2>&1
