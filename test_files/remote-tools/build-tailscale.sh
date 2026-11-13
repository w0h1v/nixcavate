#!/bin/bash
# Runs the real tailscaled and tailscale CLI against a real headscale control server (both in
# throwaway arm64 containers, user-space networking) so that tailscaled.state holds what a joined
# node holds, and copies the state and the tools' own view (`tailscale status --json`) out.
# Usage: build-tailscale.sh <output-dir>
set -uo pipefail
OUT=$(mkdir -p "$1" && cd "$1" && pwd)
docker rm -f l8s-headscale l8s-ts >/dev/null 2>&1; docker network rm l8s-net >/dev/null 2>&1; docker network create l8s-net >/dev/null
mkdir -p "$OUT/hs" && cat > "$OUT/hs/config.yaml" <<Y
server_url: http://l8s-headscale:8080
listen_addr: 0.0.0.0:8080
metrics_listen_addr: 127.0.0.1:9090
grpc_listen_addr: 127.0.0.1:50443
noise:
  private_key_path: /var/lib/headscale/noise_private.key
prefixes:
  v4: 100.64.0.0/10
  v6: fd7a:115c:a1e0::/48
derp:
  server:
    enabled: false
  urls:
    - https://controlplane.tailscale.com/derpmap/default
  paths: []
  auto_update_enabled: false
database:
  type: sqlite
  sqlite:
    path: /var/lib/headscale/db.sqlite
dns:
  magic_dns: false
  base_domain: example.test
  override_local_dns: false
  nameservers:
    global: []
Y
docker run -d --name l8s-headscale --platform linux/arm64 --network l8s-net -v "$OUT/hs:/etc/headscale" headscale/headscale:latest serve >/dev/null
sleep 8
docker exec l8s-headscale headscale users create demo > "$OUT/headscale.truth.txt" 2>&1
KEY=$(docker exec l8s-headscale headscale preauthkeys create --user 1 --reusable 2>&1 | tail -1)
echo "key created" >> "$OUT/headscale.truth.txt"
docker run -d --name l8s-ts --platform linux/arm64 --network l8s-net debian:12 sleep 3600 >/dev/null
x() { docker exec -i l8s-ts bash -c "$1"; }
x 'apt-get update -qq && apt-get install -y -qq curl ca-certificates iptables >/dev/null 2>&1; F=$(curl -s https://pkgs.tailscale.com/stable/ | grep -o "tailscale_[0-9.]*_arm64.tgz" | head -1); curl -sL https://pkgs.tailscale.com/stable/$F | tar xz -C /tmp && cp /tmp/tailscale_*/tailscale /tmp/tailscale_*/tailscaled /usr/local/bin/ && tailscale version | head -1' > "$OUT/tailscale.truth.txt" 2>&1
x 'mkdir -p /var/lib/tailscale /var/run/tailscale; (tailscaled --state=/var/lib/tailscale/tailscaled.state --tun=userspace-networking > /var/log/tailscaled.log 2>&1 &); sleep 4'
x "tailscale up --login-server http://l8s-headscale:8080 --auth-key $KEY --hostname alice-laptop --accept-dns=false; sleep 4; tailscale status --json" > "$OUT/tailscale-status.json" 2>"$OUT/tailscale-up.err"
x 'ls -la /var/lib/tailscale' >> "$OUT/tailscale.truth.txt" 2>&1
rm -rf "$OUT/tree"; mkdir -p "$OUT/tree/var/lib"
docker cp l8s-ts:/var/lib/tailscale "$OUT/tree/var/lib/tailscale"
docker rm -f l8s-headscale l8s-ts >/dev/null; docker network rm l8s-net >/dev/null
echo done
