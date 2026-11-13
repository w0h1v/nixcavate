#!/bin/sh
# Regenerates the fixture with Docker: a real pam_pwhistory history on Debian 12. On Rocky 9 and
# CentOS 7 pam_pwhistory kept no history for password changes made by root, so there is none.
set -eu
here="$(cd "$(dirname "$0")" && pwd)"
run() { # image tag [prep]
    rm -rf "$here/$2"; mkdir -p "$here/$2"
    docker run --rm --platform linux/arm64 --privileged -v "$here/inside.sh:/inside.sh:ro" -v "$here/$2:/out" "$1" sh -c "${3:-true}; sh /inside.sh" >/dev/null 2>&1
}
run debian:12 debian12
