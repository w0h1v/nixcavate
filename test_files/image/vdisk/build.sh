#!/bin/sh
# Builds the virtual-disk fixtures with the real tools (qemu-img from qemu-utils, Debian 12).
# Run from the repository root:
#   docker run --rm --platform linux/arm64 -v "$PWD/test_files/image:/w" debian:12 sh /w/vdisk/build.sh
# Source: the 8 MiB GPT/ext4 host disk of ../host, plus pseudo-random and text-like runs written
# OUTSIDE its partition (before 1 MiB and after 7 MiB) so that clusters of every size see allocated,
# compressible, incompressible and untouched ranges, and runs that straddle cluster boundaries.
# The host stays intact. Output goes to /w/vdisk/: disk.img.zst is the patterned raw disk, the
# rest are one fixture per format/variant. Flat extents are byte copies of the raw disk and are
# not stored (the tests recreate them); the script checks that with cmp.
set -eu
apt-get update -qq >/dev/null && apt-get install -y -qq qemu-utils zstd >/dev/null 2>&1
o=/w/vdisk; t=$(mktemp -d); cd $t
zstd -dqf /w/host/disk.img.zst -o disk.img
put() { head -c "$2" /dev/urandom | dd of=disk.img bs=1 seek="$1" conv=notrunc status=none; }
text() { yes 'nixcavate virtual disk fixture line' | head -c "$2" | dd of=disk.img bs=1 seek="$1" conv=notrunc status=none; }
put 102400 32768       # random, spans 512/4K/64K cluster boundaries
text 614400 24576      # compressible
put 7549747 1000       # odd offset, inside a 2 MiB cluster
put 8323072 20000      # random, near the end
zstd -q -19 -f disk.img -o $o/disk.img.zst
rm -f $o/*.qcow2 $o/*.vmdk $o/*.vhd $o/*.vhdx $o/*.vdi $o/*.raw

q() { qemu-img convert -f raw "$@" disk.img $o/$out; }
out=qcow2-v3.qcow2;          qemu-img convert -f raw -O qcow2 disk.img $o/$out
out=qcow2-v2.qcow2;          qemu-img convert -f raw -O qcow2 -o compat=0.10 disk.img $o/$out
out=qcow2-compressed.qcow2;  qemu-img convert -f raw -O qcow2 -c disk.img $o/$out
out=qcow2-compressed-4k.qcow2; qemu-img convert -f raw -O qcow2 -c -o cluster_size=4096 disk.img $o/$out
out=qcow2-zstd.qcow2;        qemu-img convert -f raw -O qcow2 -c -o compression_type=zstd disk.img $o/$out
out=qcow2-512.qcow2;         qemu-img convert -f raw -O qcow2 -o cluster_size=512 disk.img $o/$out
out=qcow2-2m.qcow2;          qemu-img convert -f raw -O qcow2 -o cluster_size=2M disk.img $o/$out
out=qcow2-2m-compressed.qcow2; qemu-img convert -f raw -O qcow2 -c -o cluster_size=2M disk.img $o/$out
out=qcow2-extl2.qcow2;       qemu-img convert -f raw -O qcow2 -o extended_l2=on,cluster_size=16384 disk.img $o/$out
out=qcow2-extl2-compressed.qcow2; qemu-img convert -f raw -O qcow2 -c -o extended_l2=on,cluster_size=16384 disk.img $o/$out

for sub in monolithicSparse streamOptimized twoGbMaxExtentSparse monolithicFlat twoGbMaxExtentFlat; do
    qemu-img convert -f raw -O vmdk -o subformat=$sub disk.img $o/vmdk-$sub.vmdk
done
# Flat extents are the raw disk: say so, then drop them (the tests recreate them).
for f in $o/vmdk-monolithicFlat-flat.vmdk $o/vmdk-twoGbMaxExtentFlat-f001.vmdk; do
    [ -f "$f" ] && cmp "$f" disk.img && rm "$f"
done
ls $o | grep -i vmdk

qemu-img convert -f raw -O vpc -o force_size=on disk.img $o/vpc-dynamic.vhd
qemu-img convert -f raw -O vpc -o subformat=fixed,force_size=on disk.img $o/vpc-fixed.vhd
qemu-img convert -f raw -O vpc disk.img $o/vpc-chs.vhd
qemu-img convert -f raw -O vhdx disk.img $o/vhdx-dynamic.vhdx
qemu-img convert -f raw -O vhdx -o block_size=1048576,log_size=1048576 disk.img $o/vhdx-1m.vhdx
qemu-img convert -f raw -O vhdx -o subformat=fixed disk.img $o/vhdx-fixed.vhdx
qemu-img convert -f raw -O vdi disk.img $o/vdi-dynamic.vdi
qemu-img convert -f raw -O vdi -o static=on disk.img $o/vdi-static.vdi

# A VHDX left with a non-empty log: SIGKILL qemu-io mid-write until the current header still names
# a log (qemu clears LogGuid when it flushes, so only a kill in the window leaves it set).
apt-get install -y -qq xxd >/dev/null 2>&1
n=0
while [ $n -lt 200 ]; do
    n=$((n + 1)); rm -f dirty.vhdx
    qemu-img create -q -f vhdx -o block_size=1048576 dirty.vhdx 8M
    qemu-io -f vhdx -c 'write -P 7 0 8M' -c 'write -P 8 1k 5M' dirty.vhdx >/dev/null 2>&1 &
    pid=$!; sleep 0.0$((n % 9)); kill -9 $pid 2>/dev/null; wait $pid 2>/dev/null || true
    # The current header is the one with the higher sequence number; it must name a log.
    s1=$(od -An -t u8 -j $((65536 + 8)) -N 8 dirty.vhdx); s2=$(od -An -t u8 -j $((131072 + 8)) -N 8 dirty.vhdx)
    if [ "$s1" -gt "$s2" ]; then at=65536; else at=131072; fi
    guid=$(xxd -p -s $((at + 48)) -l 16 dirty.vhdx)
    [ "$guid" != 00000000000000000000000000000000 ] && break
done
echo "dirty vhdx after $n tries: current header $at, log guid $guid"
cp dirty.vhdx $o/vhdx-dirty.vhdx

# Rejected inputs.
cp disk.img $o/base.raw
qemu-img create -q -f qcow2 -b base.raw -F raw $o/qcow2-backing.qcow2
qemu-img convert -f raw -O vmdk -o subformat=monolithicSparse disk.img $o/base.vmdk
qemu-img create -q -f vmdk -b base.vmdk -F vmdk $o/vmdk-child.vmdk
rm -f $o/base.raw $o/base.vmdk
echo secret > pw
qemu-img create -q -f qcow2 --object secret,id=s,file=pw -o encrypt.format=luks,encrypt.key-secret=s,encrypt.iter-time=10 $o/qcow2-luks.qcow2 1M
truncate -s 65536 $o/qcow2-luks.qcow2   # only the header matters; the LUKS header would make it 2 MiB
qemu-img create -q -f qcow2 -o data_file=ext.raw $o/qcow2-external.qcow2 1M 2>/dev/null || true
# Keep the repository small: every fixture except the script is stored zstd-compressed.
for f in $o/*; do
    case "$f" in */build.sh|*.zst) ;; *) zstd -q -19 -f --rm "$f" ;; esac
done
ls -la $o
