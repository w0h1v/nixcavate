#!/bin/bash
# Builds disk.img.zst with the real tools: a GPT disk with the volumes of one Linux host and an
# /etc/fstab that mounts them:
#   p1 vfat  /boot/efi  by UUID  (not opened by nixcavate: the entry is ignored)
#   p2 ext4  /boot      by UUID
#   p3 ext4  /          the root (`graftbox`)
#   p4 XFS   /var       by LABEL (/var/log/... lives here)
#   p5 LVM   /home      as /dev/mapper/vgx-home (plus an unused swap volume)
# The root also has files under /boot and /var/log that a real system hides under the mounts.
# truth.tsv is made from a real mount of the volumes at the fstab's mount points: the path, size
# and sha256 of every regular file. Run as root on Linux:  bash build.sh
set -eu
export DEBIAN_FRONTEND=noninteractive
W=$(cd "$(dirname "$0")" && pwd)
OUT=${OUT:-$W}
cfg='devices{use_devicesfile=0} activation{udev_sync=0 udev_rules=0} backup{backup=0 archive=0}'
ROOT_UUID=4b0c6a6e-0000-4000-8000-000000000003
BOOT_UUID=4b0c6a6e-0000-4000-8000-000000000002
img=$OUT/disk.img; rm -f $img; truncate -s 345M $img
sgdisk -n 1:2048:10239 -t 1:ef00 -n 2:10240:22527 -t 2:8300 -n 3:22528:38911 -t 3:8300 \
    -n 4:38912:657407 -t 4:8300 -n 5:657408:681983 -t 5:8e00 -c 4:varpart $img >/dev/null
part() { losetup -f --show -o $(($1 * 512)) --sizelimit $((($2 - $1 + 1) * 512)) $img; }
p1=$(part 2048 10239); p2=$(part 10240 22527); p3=$(part 22528 38911); p4=$(part 38912 657407); p5=$(part 657408 681983)
cleanup() { umount -R /mnt/g 2>/dev/null || true; lvm vgchange -q --config "$cfg" -an vgx >/dev/null 2>&1 || true; losetup -d $p1 $p2 $p3 $p4 $p5 2>/dev/null || true; }
trap cleanup EXIT

mkfs.vfat -F 12 -i ABCD1234 $p1 >/dev/null
lvm pvcreate -q --config "$cfg" --metadatasize 128k $p5 >/dev/null
lvm vgcreate -q --config "$cfg" -s 1M vgx $p5 >/dev/null
lvm lvcreate -q --config "$cfg" -Zn -Wn -l 8 -n home vgx >/dev/null 2>&1
lvm lvcreate -q --config "$cfg" -Zn -Wn -l 2 -n swap vgx >/dev/null 2>&1
dmsetup mknodes
mkfs.xfs -q -f -b size=1024 -m crc=1 -L varvol $p4

boot=$(mktemp -d); root=$(mktemp -d); home=$(mktemp -d); var=$(mktemp -d)
mkdir -p $boot/grub $boot/loader/entries
echo 'kernel image placeholder' > $boot/vmlinuz-6.1.0
echo 'set default=0' > $boot/grub/grub.cfg
echo 'title Test Linux' > $boot/loader/entries/test.conf
mkdir -p $var/log $var/lib
printf '2024-03-10T01:02:03.000000+00:00 graftbox sshd[42]: Accepted password for alice from 203.0.113.9 port 50000 ssh2\n' > $var/log/secure
printf 'Mar 10 01:02:04 graftbox kernel: boot\n' > $var/log/messages
echo state > $var/lib/state.txt
mkdir -p $home/alice
echo 'ls -la' > $home/alice/.bash_history
echo 'notes' > $home/alice/notes.txt
mkdir -p $root/etc $root/boot $root/var/log $root/home
echo graftbox > $root/etc/hostname
printf 'PRETTY_NAME="Rocky Linux 9.4 (Blue Onyx)"\n' > $root/etc/os-release
printf 'root:x:0:0:root:/root:/bin/bash\nalice:x:1000:1000::/home/alice:/bin/bash\n' > $root/etc/passwd
printf 'Etc/UTC\n' > $root/etc/timezone
echo 'under the /boot mount point' > $root/boot/shadowed.txt
echo 'under the /var mount point' > $root/var/log/rootvar.txt
cat > $root/etc/fstab <<FSTAB
# /etc/fstab
UUID=$ROOT_UUID / ext4 defaults 0 1
UUID=$BOOT_UUID /boot ext4 defaults 0 2
UUID=ABCD-1234 /boot/efi vfat umask=0077,shortname=winnt 0 2
LABEL=varvol /var xfs defaults 0 0
/dev/mapper/vgx-home /home ext4 defaults 0 2
/dev/vgx/swap none swap sw 0 0
tmpfs /tmp tmpfs defaults 0 0
/dev/sdb9 /srv ext4 defaults 0 2
FSTAB
touch -d '2024-03-10 01:02:03 UTC' $var/log/secure $root/etc/passwd $boot/vmlinuz-6.1.0

mkfs.ext4 -q -b 1024 -O ^has_journal -U $BOOT_UUID -d $boot -E root_owner=0:0 $p2
mkfs.ext4 -q -b 1024 -O ^has_journal -U $ROOT_UUID -d $root -E root_owner=0:0 $p3
mkfs.ext4 -q -b 1024 -O ^has_journal -d $home -E root_owner=0:0 /dev/mapper/vgx-home
# XFS has no -d: copy the files through a real mount.
mkdir -p /mnt/x && mount $p4 /mnt/x && cp -a $var/. /mnt/x/ && umount /mnt/x

# The truth: the volumes mounted where the fstab says.
mkdir -p /mnt/g && mount -o ro $p3 /mnt/g
mount -o ro $p2 /mnt/g/boot; mount -o ro $p4 /mnt/g/var 2>/dev/null || { mkdir -p /mnt/g/var; }
mount -o ro /dev/mapper/vgx-home /mnt/g/home
(cd /mnt/g && find . -type f ! -path '*/lost+found/*' -printf '%P\t%s\t' -exec sha256sum {} \; | awk -F'\t' '{split($3,a," "); print $1 "\t" $2 "\t" a[1]}' | LC_ALL=C sort) > $OUT/truth.tsv
umount -R /mnt/g
cleanup; trap - EXIT
zstd -q -19 -f --long=27 $img -o $OUT/disk.img.zst; rm $img
ls -l $OUT/disk.img.zst; cat $OUT/truth.tsv
