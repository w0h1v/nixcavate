#!/bin/bash
# Runs the real VS Code server (the one Remote-SSH installs) and the VS Code CLI (`code tunnel`)
# in a throwaway arm64 container as an ordinary user, installs one extension, and copies out
# ~/.vscode-server and ~/.vscode. The tunnel cannot finish (it needs a GitHub device login), so
# its state file is not produced here; see the artifact's module comment.
# Usage: build-vscode.sh <output-dir>
set -uo pipefail
OUT=$(mkdir -p "$1" && cd "$1" && pwd)
docker rm -f l8s-vscode >/dev/null 2>&1
docker run -d --name l8s-vscode --platform linux/arm64 debian:12 sleep 3600 >/dev/null
x() { docker exec -i l8s-vscode bash -c "$1"; }
as() { docker exec -i -u alice -e HOME=/home/alice l8s-vscode bash -c "$1"; }
x 'apt-get update -qq && apt-get install -y -qq curl ca-certificates tar gzip procps >/dev/null 2>&1; useradd -m alice; echo apt-done'
as 'cd ~ && J=$(curl -s "https://update.code.visualstudio.com/api/update/server-linux-arm64/stable/latest"); echo $J; C=$(echo $J | sed "s/.*\"version\":\"\([0-9a-f]*\)\".*/\1/"); echo commit $C
mkdir -p ~/.vscode-server/bin/$C && curl -sL "https://update.code.visualstudio.com/commit:$C/server-linux-arm64/stable" | tar xz -C ~/.vscode-server/bin/$C --strip-components=1 && ls ~/.vscode-server/bin/$C | head' > "$OUT/vscode.truth.txt" 2>&1
as 'C=$(ls ~/.vscode-server/bin | head -1); cd ~/.vscode-server/bin/$C
(timeout 25 ./bin/code-server --accept-server-license-terms --start-server --host 127.0.0.1 --port 8765 --connection-token example-token > /tmp/server.out 2>&1 &) ; sleep 14
curl -s "http://127.0.0.1:8765/version" ; echo
./bin/code-server --accept-server-license-terms --install-extension ms-python.python 2>&1 | tail -3
sleep 12; cat /tmp/server.out | head -8; find ~/.vscode-server -maxdepth 4 -not -path "*/bin/*" | head -40' >> "$OUT/vscode.truth.txt" 2>&1
x 'curl -sL "https://code.visualstudio.com/sha/download?build=stable&os=cli-alpine-arm64" -o /tmp/cli.tgz && tar xzf /tmp/cli.tgz -C /usr/local/bin && code --version; ls -l /usr/local/bin/code' > "$OUT/vscode-cli.truth.txt" 2>&1
as '(timeout 20 code tunnel --accept-server-license-terms --name l8s-example > /tmp/tunnel.out 2>&1); cat /tmp/tunnel.out | head; find ~/.vscode ~/.vscode-cli -maxdepth 3 2>/dev/null' >> "$OUT/vscode-cli.truth.txt" 2>&1
rm -rf "$OUT/tree"; mkdir -p "$OUT/tree/home/alice"
docker exec l8s-vscode bash -c 'cd /home/alice && tar cf - --exclude=bin .vscode-server .vscode .vscode-cli 2>/dev/null' | tar xf - -C "$OUT/tree/home/alice"
docker rm -f l8s-vscode >/dev/null
echo done
