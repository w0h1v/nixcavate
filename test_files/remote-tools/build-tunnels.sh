#!/bin/bash
# Installs the real ngrok, cloudflared and frp in a throwaway arm64 container, writes their
# configuration the documented way, validates it with the tool's own checker (the ground truth
# that the files are what the tool reads) and copies the files out. Example accounts only.
# Usage: build-tunnels.sh <output-dir>
set -uo pipefail
OUT=$(mkdir -p "$1" && cd "$1" && pwd)
rm -f "$OUT"/*.truth.txt
docker rm -f l8s-tunnels >/dev/null 2>&1
docker run -d --name l8s-tunnels --platform linux/arm64 debian:12 sleep 3600 >/dev/null
x() { docker exec -i l8s-tunnels bash -c "$1"; }
x 'apt-get update -qq && apt-get install -y -qq curl ca-certificates tar >/dev/null 2>&1; echo apt-done'
# ngrok 3: `config add-authtoken` writes the file itself.
x 'curl -sL https://bin.equinox.io/c/bNyj1mQVY4c/ngrok-v3-stable-linux-arm64.tgz | tar xz -C /usr/local/bin && ngrok version'
x 'ngrok config add-authtoken PLANTED-NGROK-AUTHTOKEN-0001 && cat >> /root/.config/ngrok/ngrok.yml <<Y
tunnels:
  ssh:
    proto: tcp
    addr: 22
  web:
    proto: http
    addr: 8080
    domain: demo.example.ngrok.app
Y
cat /root/.config/ngrok/ngrok.yml; ngrok config check' > "$OUT/ngrok.truth.txt" 2>&1
# cloudflared: the config is hand-written (named tunnels need an account); the tool's own
# `ingress validate` and `ingress rule` check it.
x 'curl -sL -o /usr/local/bin/cloudflared https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-arm64 && chmod +x /usr/local/bin/cloudflared && cloudflared --version'
x 'mkdir -p /root/.cloudflared /etc/cloudflared
cat > /etc/cloudflared/config.yml <<Y
tunnel: 6ff42ae2-765d-4adf-8112-31c55c1551ef
credentials-file: /root/.cloudflared/6ff42ae2-765d-4adf-8112-31c55c1551ef.json
ingress:
  - hostname: app.example.com
    service: http://localhost:8000
  - hostname: ssh.example.com
    service: ssh://localhost:22
  - service: http_status:404
Y
echo "{\"AccountTag\":\"0123456789abcdef0123456789abcdef\",\"TunnelSecret\":\"PLANTED-CLOUDFLARED-SECRET-0002\",\"TunnelID\":\"6ff42ae2-765d-4adf-8112-31c55c1551ef\"}" > /root/.cloudflared/6ff42ae2-765d-4adf-8112-31c55c1551ef.json
cloudflared tunnel --config /etc/cloudflared/config.yml ingress validate; cloudflared tunnel --config /etc/cloudflared/config.yml ingress rule https://ssh.example.com' > "$OUT/cloudflared.truth.txt" 2>&1
# frp
x 'V=$(curl -s https://api.github.com/repos/fatedier/frp/releases/latest | grep tag_name | sed "s/.*\"v\([0-9.]*\)\".*/\1/"); curl -sL https://github.com/fatedier/frp/releases/download/v$V/frp_${V}_linux_arm64.tar.gz | tar xz -C /tmp && cp /tmp/frp_*/frpc /tmp/frp_*/frps /usr/local/bin/ && frpc --version'
x 'mkdir -p /etc/frp
cat > /etc/frp/frpc.toml <<Y
serverAddr = "198.51.100.7"
serverPort = 7000
auth.token = "PLANTED-FRP-TOKEN-0003"

[[proxies]]
name = "ssh"
type = "tcp"
localIP = "127.0.0.1"
localPort = 22
remotePort = 6000

[[proxies]]
name = "web"
type = "http"
localPort = 80
customDomains = ["www.example.com"]
Y
cat > /etc/frp/frpc-old.ini <<Y
[common]
server_addr = 198.51.100.7
server_port = 7000
token = PLANTED-FRP-TOKEN-0003

[ssh]
type = tcp
local_ip = 127.0.0.1
local_port = 22
remote_port = 6000
Y
frpc verify -c /etc/frp/frpc.toml; frpc verify -c /etc/frp/frpc-old.ini' > "$OUT/frp.truth.txt" 2>&1
rm -rf "$OUT/tree"; mkdir -p "$OUT/tree/root/.config" "$OUT/tree/etc"
docker cp l8s-tunnels:/root/.config/ngrok "$OUT/tree/root/.config/ngrok"
docker cp l8s-tunnels:/root/.cloudflared "$OUT/tree/root/.cloudflared"
docker cp l8s-tunnels:/etc/cloudflared "$OUT/tree/etc/cloudflared"
docker cp l8s-tunnels:/etc/frp "$OUT/tree/etc/frp"
docker rm -f l8s-tunnels >/dev/null
echo done
