#!/bin/sh
# Builds the Docker data-root fixture with a real daemon: dockerd in a privileged
# docker:dind container, started with --data-root /srv/data/docker and the classic
# (graph driver) image store, running two containers. Copies out only the files the
# artifacts read, plus the daemon's own counts (`docker ps -a`, `docker logs | wc -l`):
#   sh test_files/docker-moved-root/build.sh
# Needs Docker and network access. Output: ./srv/data/docker/... and ./expected.txt
set -eu
out="$(cd "$(dirname "$0")" && pwd)"
name=nxc-dind-fixture-$$
docker run -d --privileged --platform linux/arm64 --name "$name" -v "$name-data:/srv/data/docker" docker:dind \
  --data-root /srv/data/docker --storage-driver overlay2 --feature containerd-snapshotter=false >/dev/null
trap 'docker rm -f "$name" >/dev/null 2>&1 || true; docker volume rm "$name-data" >/dev/null 2>&1 || true' EXIT
i=0; until docker exec "$name" docker info >/dev/null 2>&1; do i=$((i+1)); [ $i -gt 60 ] && exit 1; sleep 1; done
docker exec "$name" sh -c '
  docker pull -q alpine:3 >/dev/null
  docker run -d --name web -p 127.0.0.1:8080:80 -e APP_MODE=prod --label tier=front --restart unless-stopped \
    alpine:3 sh -c "echo web started; echo web warning >&2; echo \"two words\"; sleep 3600" >/dev/null
  docker run --name job --privileged alpine:3 sh -c "for n in 1 2 3 4 5 6 7; do echo job line \$n; done; echo job failed >&2; exit 3" >/dev/null 2>&1 || true
  sleep 2
  docker stop web >/dev/null
  {
    echo "containers $(docker ps -a -q | wc -l)"
    for n in web job; do echo "log_lines $n $(docker logs $n 2>&1 | wc -l)"; done
    echo "images $(docker images -q | sort -u | wc -l)"
  } > /tmp/expected.txt'
# (docker cp cannot read /tmp: it is a tmpfs in the container)
docker exec "$name" cat /tmp/expected.txt > "$out/expected.txt"
docker exec "$name" sh -c 'cd /srv/data/docker && find containers image/overlay2 -type f \( -name config.v2.json -o -name hostconfig.json -o -name "*-json.log*" -o -name repositories.json -o -path "*/imagedb/content/sha256/*" \) | tar -cf - -T -' \
  | { rm -rf "$out/srv"; mkdir -p "$out/srv/data/docker"; tar -C "$out/srv/data/docker" -xf -; }
