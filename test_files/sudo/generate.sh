#!/bin/sh
# Regenerates the fixtures with Docker (privileged, with a tty so sudo logs ttyin/ttyout):
# sudo 1.9 on Debian 12 and Rocky 9, sudo 1.8 on CentOS 7 (end of life: vault repositories).
set -eu
here="$(cd "$(dirname "$0")" && pwd)"
run() { # image tag [prep]
    rm -rf "$here/$2"; mkdir -p "$here/$2"
    docker run --rm -t --platform linux/arm64 --privileged -v "$here/inside.sh:/inside.sh:ro" -v "$here/$2:/out" "$1" \
        sh -c "${3:-true}; sh /inside.sh" >/dev/null 2>&1
}
run debian:12 debian12
run rockylinux:9 rocky9
run centos:7 centos7 "sed -i 's|^mirrorlist=|#mirrorlist=|; s|^#baseurl=http://mirror.centos.org|baseurl=http://vault.centos.org|' /etc/yum.repos.d/*.repo"
