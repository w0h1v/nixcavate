#!/bin/bash
# Builds symlinks-1k.img: a v5 filesystem with 1 KiB blocks holding symlinks whose targets
# need one block and two blocks. A two-block target is one extent with ONE header.
#
#   docker run --rm --privileged -v "$PWD/test_files/fs/xfs":/out debian:13 bash /out/build-symlinks.sh
set -eu
apt-get -qq update >/dev/null && DEBIAN_FRONTEND=noninteractive apt-get -qq install -y xfsprogs zstd >/dev/null 2>&1
img=/tmp/symlinks-1k.img
truncate -s 300M $img
mkfs.xfs -q -b size=1024 $img
mkdir /mnt/x && mount -o loop $img /mnt/x
cd /mnt/x
# The target of length N is N copies of a letter that depends on N.
for n in 200 968 969 1000 1023; do
    ln -s "$(head -c $n /dev/zero | tr '\0' "$(printf "\\$(printf %o $((97 + n % 26)))")")" len$n
done
cd / && umount /mnt/x
zstd -q -19 --long=27 -f $img -o /out/symlinks-1k.img.zst
ls -l /out/symlinks-1k.img.zst
