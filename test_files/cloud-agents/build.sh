#!/bin/bash
# Installs the real AWS SSM agent, the Azure Linux agent (waagent) and the Google guest agent in
# a throwaway arm64 container and lets each run for a short time. None can reach its cloud, so
# each logs what it does at start-up and its failure to find the metadata service; the files
# are copied out as they are. (Files that only a cloud-delivered command creates are written by
# hand in the formats the vendors document; see the artifact's module comment.)
# Usage: build.sh <output-dir>
set -uo pipefail
OUT=$(mkdir -p "$1" && cd "$1" && pwd)
docker rm -f l8s-cloud >/dev/null 2>&1
docker run -d --name l8s-cloud --platform linux/arm64 --privileged debian:12 sleep 3600 >/dev/null
x() { docker exec -i l8s-cloud bash -c "$1"; }
x 'apt-get update -qq && apt-get install -y -qq curl ca-certificates gnupg python3 sudo procps >/dev/null 2>&1; echo apt-done'
# AWS
x 'curl -sL -o /tmp/ssm.deb https://s3.amazonaws.com/ec2-downloads-windows/SSMAgent/latest/debian_arm64/amazon-ssm-agent.deb && dpkg -i /tmp/ssm.deb >/dev/null 2>&1; amazon-ssm-agent -version' > "$OUT/ssm.truth.txt" 2>&1
x '(timeout 40 amazon-ssm-agent >/tmp/ssm.stdout 2>&1); sleep 1; ls -la /var/log/amazon/ssm /var/lib/amazon/ssm 2>&1; tail -5 /tmp/ssm.stdout' >> "$OUT/ssm.truth.txt" 2>&1
# Azure
x 'apt-get install -y -qq waagent >/dev/null 2>&1; waagent --version | head -2' > "$OUT/waagent.truth.txt" 2>&1
x '(timeout 60 waagent -daemon >/tmp/waagent.stdout 2>&1); ls -la /var/log/waagent.log /var/lib/waagent; tail -5 /tmp/waagent.stdout' >> "$OUT/waagent.truth.txt" 2>&1
# GCP
x 'curl -sL https://packages.cloud.google.com/apt/doc/apt-key.gpg | gpg --dearmor > /usr/share/keyrings/google-cloud.gpg
echo "deb [signed-by=/usr/share/keyrings/google-cloud.gpg] https://packages.cloud.google.com/apt google-compute-engine-bookworm-stable main" > /etc/apt/sources.list.d/gce.list
echo "deb [signed-by=/usr/share/keyrings/google-cloud.gpg] https://packages.cloud.google.com/apt google-guest-agent-bookworm-stable main" >> /etc/apt/sources.list.d/gce.list
apt-get update -qq 2>&1 | tail -3; apt-get install -y -qq google-guest-agent google-osconfig-agent 2>&1 | tail -3; dpkg -l | grep -i google; ls /etc/default /etc/google* 2>&1; dpkg -L google-guest-agent | head -30' > "$OUT/gce.truth.txt" 2>&1
x '(timeout 20 /usr/bin/google_guest_agent > /tmp/gga.out 2>&1); tail -20 /tmp/gga.out; ls -la /var/log /var/lib/google 2>&1 | head -40' >> "$OUT/gce.truth.txt" 2>&1
rm -rf "$OUT/tree"; mkdir -p "$OUT/tree/var/log" "$OUT/tree/var/lib"
docker cp l8s-cloud:/var/log/amazon "$OUT/tree/var/log/amazon"
docker cp l8s-cloud:/var/lib/amazon "$OUT/tree/var/lib/amazon"
docker cp l8s-cloud:/var/log/waagent.log "$OUT/tree/var/log/waagent.log"
docker cp l8s-cloud:/var/lib/waagent "$OUT/tree/var/lib/waagent"
docker cp l8s-cloud:/tmp/gga.out "$OUT/tree/gga.out"
docker rm -f l8s-cloud >/dev/null
echo done
