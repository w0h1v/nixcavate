#!/bin/bash
# Gathers the files the build-*.sh scripts produced into ./tree (a host-like root) and ./truth, and
# replaces the few secrets a real tool wrote (TeamViewer's private keys) with PLANTED-* strings.
# Usage: collect.sh <work-dir containing tunnels vpn ts rd2 vscode>
set -euo pipefail
cd "$(dirname "$0")"; W=$1
rm -rf tree truth; mkdir -p tree truth
cp -r "$W/tunnels/tree/." tree/
cp -r "$W/vpn/tree/." tree/
rm -f tree/etc/openvpn/update-resolv-conf
[ -d "$W/ts/tree" ] && cp -r "$W/ts/tree/." tree/
# AnyDesk and TeamViewer (the second build copies /tmp/keep)
mkdir -p tree/etc tree/root tree/var/log
cp -r "$W/rd2/anydesk/tmp/keep/anydesk" tree/etc/anydesk
rm -rf tree/etc/anydesk/cache tree/etc/anydesk/*.lock tree/etc/anydesk/.iid
mkdir -p tree/root/.anydesk && cp "$W/rd2/anydesk/tmp/keep/.anydesk/anydesk.trace" "$W/rd2/anydesk/tmp/keep/.anydesk/user.conf" tree/root/.anydesk/
cp "$W/rd2/anydesk/tmp/keep/anydesk.trace" tree/var/log/anydesk.trace
mkdir -p tree/etc/teamviewer tree/var/log/teamviewer15
cp "$W/rd2/teamviewer/tmp/keep/teamviewer15/TeamViewer15_Logfile.log" "$W/rd2/teamviewer/tmp/keep/teamviewer15/TVNetwork.log" tree/var/log/teamviewer15/
python3 - "$W/rd2/teamviewer/tmp/keep/teamviewer/global.conf" tree/etc/teamviewer/global.conf <<'Y'
import re, sys
s = open(sys.argv[1]).read()
n = [0]
def plant(m):
    n[0] += 1
    return f"{m.group(1)} = PLANTED-TV-{m.group(2).upper()}-{n[0]:04d}"
s = re.sub(r"(\[bin  \] (Certificate|CertificateKey|DataUploaderDbKey|PK|SK)) = .*", plant, s)
open(sys.argv[2], "w").write(s)
Y
# RustDesk
mkdir -p tree/root/.config/rustdesk tree/root/.local/share/logs
cp "$W/rd/rustdesk/root/.config/rustdesk/RustDesk.toml" tree/root/.config/rustdesk/
cp -r "$W/rd/rustdesk/root/.local/share/logs/RustDesk" tree/root/.local/share/logs/RustDesk
# VS Code server (extension list and the small top-level logs)
mkdir -p tree/home/alice/.vscode-server/extensions tree/home/alice/.vscode-server/data
cp "$W/vscode/tree/home/alice/.vscode-server/extensions/extensions.json" tree/home/alice/.vscode-server/extensions/
cp -r "$W/vscode/tree/home/alice/.vscode-server/data/logs" tree/home/alice/.vscode-server/data/logs
cp "$W"/tunnels/*.truth.txt "$W"/vpn/*.truth.txt "$W"/vpn/wireguard.planted-* truth/
[ -f "$W/ts/tailscale-status.json" ] && cp "$W/ts/tailscale-status.json" truth/
cp "$W"/vscode/*.truth.txt truth/; cp "$W"/rd/rustdesk.truth.txt truth/rustdesk.truth.txt; cp "$W"/rd2/teamviewer.truth.txt "$W"/rd2/anydesk.truth.txt truth/
find tree -type f | sort
