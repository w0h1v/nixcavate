#!/bin/sh
# Regenerates the fixtures with Docker (privileged). Each image has the failure-counting
# module of its time: Rocky 9 and Debian 12 pam_faillock, CentOS 7 pam_faillock and pam_tally2,
# Debian 9 (end of life, from archive.debian.org) pam_tally2 and pam_tally (shadow's faillog).
set -eu
here="$(cd "$(dirname "$0")" && pwd)"
run() { # image tag [prep] [platform]
    rm -rf "$here/$2"; mkdir -p "$here/$2"
    docker run --rm --platform "${4:-linux/arm64}" --privileged -v "$here/inside.sh:/inside.sh:ro" -v "$here/pamtry.py:/pamtry.py:ro" \
        -v "$here/$2:/out" "$1" sh -c "${3:-true}; sh /inside.sh" >/dev/null 2>&1
}
run rockylinux:9 rocky9
run debian:12 debian12
run debian:9 debian9 "sed -i 's|deb.debian.org|archive.debian.org|; s|security.debian.org|archive.debian.org|; /stretch-updates/d' /etc/apt/sources.list; echo 'Acquire::Check-Valid-Until false;' > /etc/apt/apt.conf.d/99old"
run centos:7 centos7 "sed -i 's|^mirrorlist=|#mirrorlist=|; s|^#baseurl=http://mirror.centos.org|baseurl=http://vault.centos.org|' /etc/yum.repos.d/*.repo"
# the same on 32-bit x86, whose faillog records have 4-byte times (24 bytes, not 32)
run debian:9 debian9-i386 "sed -i 's|deb.debian.org|archive.debian.org|; s|security.debian.org|archive.debian.org|; /stretch-updates/d' /etc/apt/sources.list; echo 'Acquire::Check-Valid-Until false;' > /etc/apt/apt.conf.d/99old" linux/386
