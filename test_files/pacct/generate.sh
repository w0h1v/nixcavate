#!/bin/sh
# Regenerates the fixtures with Docker (privileged: accton needs CAP_SYS_PACCT).
# The kernel is the Docker VM's; the distributions differ in userland (acct / psacct version).
# The CentOS 7 image is end of life: its repositories are pointed at vault.centos.org first.
set -eu
here="$(cd "$(dirname "$0")" && pwd)"
run() { # image tag [prep command]
    mkdir -p "$here/$2"
    docker run --rm -t --platform linux/arm64 --privileged -v "$here/inside.sh:/inside.sh:ro" -v "$here/$2:/out" "$1" \
        sh -c "${3:-true}; sh /inside.sh" >/dev/null 2>&1
}
run debian:12 debian12
run ubuntu:24.04 ubuntu2404
run rockylinux:9 rocky9
run centos:7 centos7 "sed -i 's|^mirrorlist=|#mirrorlist=|; s|^#baseurl=http://mirror.centos.org|baseurl=http://vault.centos.org|' /etc/yum.repos.d/*.repo; yum install -y -q psacct util-linux"
