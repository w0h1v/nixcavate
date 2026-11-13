#!/bin/sh
# Regenerates the fixtures with Docker (privileged: sadc reads /proc and /sys).
# Debian 12 and Ubuntu 24.04 write sysstat 12.6 files (format 0x2175); the older CentOS 7 and Rocky 9 files are kept to show the other versions are skipped.
set -eu
here="$(cd "$(dirname "$0")" && pwd)"
run() { # image tag [prep]
    rm -rf "$here/$2"; mkdir -p "$here/$2"
    docker run --rm --platform linux/arm64 --privileged -v "$here/inside.sh:/inside.sh:ro" -v "$here/$2:/out" "$1" sh -c "${3:-true}; sh /inside.sh" >/dev/null 2>&1
}
run debian:12 debian12
run ubuntu:24.04 ubuntu2404
run rockylinux:9 rocky9
run centos:7 centos7 "sed -i 's|^mirrorlist=|#mirrorlist=|; s|^#baseurl=http://mirror.centos.org|baseurl=http://vault.centos.org|' /etc/yum.repos.d/*.repo"
for d in "$here"/*/; do [ -f "$d/sadf.json" ] && python3 -I "$here/reduce.py" "$d"; done
