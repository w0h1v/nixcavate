#!/bin/sh
# Builds the Podman fixtures with the real tool in a throwaway privileged container (the
# quay.io/podman/stable image): a rootful store and a rootless one (user `podman`), each with
# two containers, plus podman's own counts:
#   sh test_files/podman-real/build.sh
# Needs Docker and network access. Output: ./var/lib/containers/storage/...,
# ./srv/data/containers/..., ./home/podman/.local/share/containers/storage/... and ./expected.txt
set -eu
out="$(cd "$(dirname "$0")" && pwd)"
name=nxc-podman-fixture-$$
docker run -d --privileged --platform linux/arm64 --name "$name" --user root --entrypoint sleep quay.io/podman/stable 600 >/dev/null
trap 'docker rm -f "$name" >/dev/null 2>&1 || true' EXIT
P="podman --storage-driver vfs"
run_as() { docker exec --user "$1" -e HOME="$2" "$name" sh -c "$3"; }
for who in root:/root podman:/home/podman; do
  user=${who%%:*}; home=${who##*:}
  run_as "$user" "$home" "$P pull -q alpine:3 >/dev/null 2>&1
    $P run -d --name $user-a alpine:3 sleep 600 >/dev/null
    $P run --name $user-b alpine:3 true >/dev/null"
  run_as "$user" "$home" "echo $user containers \$($P ps -a -q | wc -l) images \$($P images -q | sort -u | wc -l)" >> "$out/expected.txt.new"
done
# A graph root moved with `--root` (storage.conf `graphroot`).
C="podman --storage-driver vfs --root /srv/data/containers"
run_as root /root "$C pull -q alpine:3 >/dev/null 2>&1
  $C run -d --name moved-a alpine:3 sleep 600 >/dev/null"
run_as root /root "echo moved containers \$($C ps -a -q | wc -l) images \$($C images -q | sort -u | wc -l)" >> "$out/expected.txt.new"
mv "$out/expected.txt.new" "$out/expected.txt"
rm -rf "$out/var" "$out/home" "$out/root"
docker exec "$name" sh -c 'cd / && find var/lib/containers/storage srv/data/containers home/podman/.local/share/containers/storage -type f \( -name containers.json -o -name images.json \) | tar -cf - -T -' | tar -C "$out" -xf -
