#!/bin/bash
# Installs the real TeamViewer Host, RustDesk and AnyDesk (arm64 packages) in throwaway containers
# and lets each service start, headless and without an account, then copies out their logs and
# configuration. Incoming-session records (which need a remote peer) are not produced here.
# Usage: build-remote-desktop.sh <output-dir>
set -uo pipefail
OUT=$(mkdir -p "$1" && cd "$1" && pwd)
run() {  # name, install script, run script, paths to copy
  docker rm -f l8s-rd >/dev/null 2>&1
  docker run -d --name l8s-rd --platform linux/arm64 --privileged debian:12 sleep 3600 >/dev/null
  docker exec -i l8s-rd bash -c 'apt-get update -qq && apt-get install -y -qq curl ca-certificates procps >/dev/null 2>&1'
  docker exec -i l8s-rd bash -c "$2" > "$OUT/$1.install.txt" 2>&1
  docker exec -i l8s-rd bash -c "$3" > "$OUT/$1.truth.txt" 2>&1
  rm -rf "$OUT/$1"; mkdir -p "$OUT/$1"
  for p in $4; do mkdir -p "$OUT/$1/$(dirname $p)"; docker cp l8s-rd:/$p "$OUT/$1/$p" 2>/dev/null; done
  docker rm -f l8s-rd >/dev/null
}
run teamviewer 'curl -sL -o /tmp/tv.deb https://download.teamviewer.com/download/linux/teamviewer-host_arm64.deb && apt-get install -y -qq /tmp/tv.deb 2>&1 | tail -3; ls /opt/teamviewer' \
  '(teamviewerd -d >/tmp/tvd.out 2>&1 &); sleep 15; teamviewer info 2>&1 | head -20; ls -la /var/log/teamviewer*/ /opt/teamviewer/config /opt/teamviewer/logfiles 2>&1 | head -30; ls /var/log; mkdir -p /tmp/keep; cp -a /var/log/teamviewer15 /etc/teamviewer /tmp/keep/' \
  'tmp/keep'
V=$(curl -s https://api.github.com/repos/rustdesk/rustdesk/releases/latest | grep -o '"browser_download_url": "[^"]*aarch64.deb"' | head -1 | cut -d'"' -f4)
echo "rustdesk url: $V" > "$OUT/rustdesk.url.txt"
run rustdesk "curl -sL -o /tmp/rd.deb '$V' && apt-get install -y -qq /tmp/rd.deb 2>&1 | tail -3; ls /usr/share/rustdesk 2>&1 | head" \
  '(timeout 30 rustdesk --service >/tmp/rd.out 2>&1 &); sleep 20; rustdesk --get-id 2>&1 | tail -2; find /root/.config/rustdesk /root/.local/share/logs /var/log/rustdesk* -type f 2>&1 | head -20; tail -5 /tmp/rd.out' \
  'root/.config/rustdesk root/.local/share/logs var/log'
run anydesk 'for v in 7.1.0 7.0.2 7.0.1 7.0.0 6.4.3 6.4.2 6.3.2; do curl -sfL -o /tmp/ad.deb https://download.anydesk.com/rpi/anydesk_${v}-1_arm64.deb && { echo got $v; break; }; done; apt-get install -y -qq /tmp/ad.deb 2>&1 | tail -3; apt-get install -y -qq -f libpolkit-gobject-1-0 libgtk-3-0 libgl1 libxkbcommon0 2>&1 | tail -3; ls /usr/bin/anydesk' \
  '(timeout 40 anydesk --service >/tmp/ad.out 2>&1 &); sleep 25; anydesk --get-id 2>&1 | tail -2; find /etc/anydesk /var/log /root/.anydesk -type f 2>&1 | head -20; tail -5 /tmp/ad.out; mkdir -p /tmp/keep; cp -a /etc/anydesk /root/.anydesk /var/log/anydesk* /tmp/keep/ 2>&1' \
  'tmp/keep'
echo done
