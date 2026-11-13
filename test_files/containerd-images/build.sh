#!/bin/sh
# Builds the containerd metadata fixture with a real daemon: dockerd (Docker 29, containerd
# image store, its default) in a privileged docker:dind container with --data-root
# /srv/data/docker, after pulling two images and tagging one of them again. Copies out
# containerd's BoltDB metadata file (gzip) and the daemon's own view (`ctr images ls`):
#   sh test_files/containerd-bolt/build.sh
# Needs Docker and network access. Output: ./meta.db.gz, ./ctr-images.txt and ./taken-at.txt (epoch seconds after the pulls)
set -eu
out="$(cd "$(dirname "$0")" && pwd)"
name=nxc-dind-bolt-$$
docker run -d --privileged --platform linux/arm64 --name "$name" -v "$name-data:/srv/data/docker" docker:dind \
  --data-root /srv/data/docker >/dev/null
trap 'docker rm -f "$name" >/dev/null 2>&1 || true; docker volume rm "$name-data" >/dev/null 2>&1 || true' EXIT
i=0; until docker exec "$name" docker info >/dev/null 2>&1; do i=$((i+1)); [ $i -gt 60 ] && exit 1; sleep 1; done
docker exec "$name" sh -c '
  docker pull -q alpine:3 >/dev/null
  docker pull -q busybox:1.36 >/dev/null
  docker tag busybox:1.36 myreg.example/team/app:v1
  ctr --address /var/run/docker/containerd/containerd.sock -n moby images ls | awk "{print \$1, \$2, \$3, \$4, \$5}" > /tmp/ctr-images.txt
  date -u +%s > /tmp/now.txt'
docker exec "$name" cat /tmp/ctr-images.txt > "$out/ctr-images.txt"
docker exec "$name" cat /tmp/now.txt > "$out/taken-at.txt"
docker exec "$name" gzip -9 -c /srv/data/docker/containerd/daemon/io.containerd.metadata.v1.bolt/meta.db > "$out/meta.db.gz"
