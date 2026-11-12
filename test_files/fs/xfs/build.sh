#!/bin/bash
# Builds the XFS test images and their ground truth. Run from the repository root:
#
#   docker run --rm --privileged --platform linux/amd64 -v "$PWD/test_files/fs/xfs":/out \
#       debian:12 bash /out/build.sh
#
# Images (xfsprogs 6.1 needs at least 300 MiB; mostly-empty images compress to a few KiB):
#   v5.img       default v5 filesystem: CRCs, ftype, bigtime, 4 KiB blocks
#   v5-1k.img    v5 with 1 KiB blocks and bigtime=0: leaf and node directories, a two-level
#                bmbt, legacy timestamps in v3 inodes
#   v4.img       v4 (crc=0, ftype=0). The host kernel cannot mount v4, so this one is
#                populated by `mkfs.xfs -p` (proto file) and its ground truth comes from xfs_db.
#
# Ground truth per image, all produced by the real tools:
#   <name>.stat.tsv.zst  path, inode, raw mode (hex), uid, gid, size, links, atime, mtime, ctime,
#                     crtime (nanosecond-precision seconds, `-` when absent)
#   <name>.sha256.zst sha256sum of every regular file
#   <name>.links.tsv  path and target of every symlink
set -euo pipefail

apt-get update -qq >/dev/null
apt-get install -y -qq xfsprogs zstd perl >/dev/null 2>&1
export TZ=UTC
OUT=/out
WORK=$(mktemp -d)

# Position-tagged, highly compressible content: every 64-byte record names its file and offset,
# so a block read from the wrong place is detected.
gen() { # gen <bytes> <tag>
    perl -e 'my ($n, $t) = @ARGV; my $o = ""; my $i = 0;
             while (length($o) < $n) { $o .= sprintf("%-12s%010d", $t, $i * 64) . ("." x 41) . "\n"; $i++ }
             print substr($o, 0, $n)' "$1" "$2"
}

# populate <dir> <block size> <big dir entries> <hardlinks: 1|0>
populate() {
    local d=$1 bs=$2 big=$3 hard=$4
    cd "$d"
    mkdir -p a/b/c/d/e
    : >empty
    printf 'hello, xfs\n' >small.txt
    gen 100000 large >a/b/large.bin
    gen 4096 deep >a/b/c/d/e/deep.txt
    # Sparse: data at 0 and at 10 MiB, size 20 MiB.
    gen 4096 sparse0 >sparse.bin
    gen 4096 sparse1 | dd of=sparse.bin bs=4096 seek=2560 conv=notrunc status=none
    truncate -s 20M sparse.bin

    # Directory forms: shortform, block, leaf, and a large node directory with freed entries.
    mkdir dir_sf dir_block dir_leaf big
    for i in 1 2 3; do printf 'sf %s\n' $i >dir_sf/f$i; done
    for i in $(seq 1 40); do : >dir_block/entry-$i; done
    for i in $(seq 1 300); do : >dir_leaf/leaf-entry-number-$i; done
    for i in $(seq 1 "$big"); do : >big/a-fairly-long-file-name-in-a-big-directory-$i; done
    for i in $(seq 7 7 "$big"); do rm big/a-fairly-long-file-name-in-a-big-directory-$i; done
    printf 'inside big\n' >big/zz-content.txt

    # Names.
    printf 'long name\n' >"$(printf 'L%.0s' $(seq 1 255))"
    printf 'unicode\n' >"café-日本語-ü.txt"

    # Links.
    ln -s small.txt link_short
    ln -s "$(printf 'a/%.0s' $(seq 1 300))target-that-does-not-exist" link_long
    if [ "$hard" = 1 ]; then ln small.txt a/hardlink.txt; fi

    # Owners, modes, special files.
    gen 3000 setuid >a/setuid-bin
    chmod 4755 a/setuid-bin
    chown 1234:5678 small.txt
    chown 4000000000:4000000001 a/b/large.bin
    chmod 0640 a/b/large.bin
    mkfifo a/fifo
    mknod a/null c 1 3
}

# Things that need a mounted filesystem: fragmentation, unwritten extents, timestamps.
finish_mounted() {
    local d=$1 bs=$2 frag=$3
    cd "$d"
    # Many extents: write contiguously, then punch every other block.
    gen $((frag * bs)) fragmented >fragmented.bin
    sync
    local args=() i
    for ((i = 1; i < frag; i += 2)); do args+=(-c "fpunch $((i * bs)) $bs"); done
    xfs_io "${args[@]}" fragmented.bin
    # Unwritten extents over blocks that held data: they must read as zeros.
    gen 1048576 victim >victim.bin
    sync
    rm victim.bin
    sync
    xfs_io -f -c "falloc 0 1m" -c "pwrite -q -S 0x7a 262144 4096" unwritten.bin
    sync

    touch -d '2001-02-03 04:05:06.123456789' small.txt
    touch -a -d '2002-03-04 05:06:07.987654321' small.txt
    touch -d '1960-06-01 12:00:00' a/b/c/d/e/deep.txt
    touch -d '2100-01-01 00:00:00.5' a/setuid-bin
    touch -h -d '2010-10-10 10:10:10' link_short
    touch -d '2015-05-05 05:05:05' a/b/c
}

truth_mounted() { # truth_mounted <mount> <name>
    cd "$1"
    find . -mindepth 1 -printf '%P\0' | sort -z |
        xargs -0 stat -c '%n	%i	%f	%u	%g	%s	%h	%.9X	%.9Y	%.9Z	%.9W' >"$OUT/$2.stat.tsv"
    find . -type f -printf '%P\0' | sort -z | xargs -0 sha256sum >"$OUT/$2.sha256"
    find . -type l -printf '%P\t%l\n' | sort >"$OUT/$2.links.tsv"
}

build_v5() { # build_v5 <name> <block size> <big> <frag> <mkfs options...>
    local name=$1 bs=$2 big=$3 frag=$4
    shift 4
    local img=$WORK/$name.img mnt=$WORK/mnt-$name
    truncate -s 300M "$img"
    mkfs.xfs -q -b size="$bs" "$@" "$img"
    mkdir -p "$mnt"
    mount -o loop "$img" "$mnt"
    populate "$mnt" "$bs" "$big" 1
    finish_mounted "$mnt" "$bs" "$frag"
    cd /
    umount "$mnt"
    mount -o loop,ro "$img" "$mnt"
    truth_mounted "$mnt" "$name"
    cd /
    umount "$mnt"
    xfs_info "$img" >"$OUT/$name.info"
    zstd -q -19 --long=27 -f "$img" -o "$OUT/$name.img.zst"
}

build_v5 v5 4096 3000 400 -m crc=1,bigtime=1
build_v5 v5-1k 1024 1500 3000 -m crc=1,bigtime=0

# v4: populate a source tree, describe it as a proto file, let mkfs copy it in.
build_v4() {
    local name=v4 img=$WORK/v4.img src=$WORK/src
    mkdir -p "$src"
    populate "$src" 4096 3000 0
    cd /
    perl - "$src" >"$WORK/proto" <<'EOF'
use strict;
my $src = shift;
sub mode_str { my ($m) = @_;
    my %t = (0040000 => 'd', 0100000 => '-', 0120000 => 'l', 0020000 => 'c', 0060000 => 'b', 0010000 => 'p');
    return $t{$m & 0170000} . (($m & 04000) ? 'u' : '-') . (($m & 02000) ? 'g' : '-') . sprintf('%03o', $m & 0777); }
sub walk { my ($dir, $ind) = @_;
    opendir(my $dh, $dir) or die; my @n = sort grep { $_ ne '.' && $_ ne '..' } readdir($dh); closedir $dh;
    for my $n (@n) { my $p = "$dir/$n"; my @s = lstat($p); my $m = $s[2]; my $ms = mode_str($m);
        my $line = "$ind$n $ms $s[4] $s[5]";
        if (($m & 0170000) == 0100000) { print "$line $p\n" }
        elsif (($m & 0170000) == 0120000) { print "$line ", readlink($p), "\n" }
        elsif (($m & 0170000) == 0020000) { print "$line ", ($s[6] >> 8) & 0xfff, " ", $s[6] & 0xff, "\n" }
        elsif (($m & 0170000) == 0040000) { print "$line\n"; walk($p, "$ind "); print "$ind\$\n" }
        else { print "$line\n" } } }
print "/dev/null\n0 0\nd--755 0 0\n"; walk($src, " "); print "\$\n";
EOF
    truncate -s 300M "$img"
    mkfs.xfs -q -m crc=0 -n ftype=0 -p "$WORK/proto" "$img"
    # Known timestamps. The kernel cannot mount v4 and xfs_db 6.1 cannot write time fields, so
    # the big-endian seconds/nanoseconds pairs go straight into the v2 inode core (no CRC in v4):
    # atime at byte 32, mtime at byte 40.
    settime() { # settime <path> <core offset> <seconds> <nanoseconds>
        local ino off
        ino=$(xfs_db -r -c "path $1" -c 'inode' "$img" | sed -n 's/.*current inode number is \([0-9]*\).*/\1/p')
        off=$(xfs_db -r -c "convert inode $ino byte" "$img" | sed -n 's/.*(\([0-9]*\)).*/\1/p')
        perl -e 'print pack("l>l>", $ARGV[0], $ARGV[1])' -- "$3" "$4" |
            dd of="$img" bs=1 seek=$((off + $2)) conv=notrunc status=none
    }
    settime /small.txt 40 981173106 123456789
    settime /small.txt 32 1015218367 987654321
    settime /a/b/c/d/e/deep.txt 40 -302443200 0

    # Ground truth from xfs_db: list every directory of the image (`ls` prints raw names and
    # inode numbers), then print each inode's core by number. xfs_db's command line drops
    # non-ASCII bytes, so names are only ever read from its output, never passed to it.
    cd "$src"
    find . -type d -printf '%P\n' | sort >"$WORK/dirs"
    perl -ne 'chomp; print "ls /$_\n"' "$WORK/dirs" >"$WORK/ls.cmd"
    xfs_db -r -c "source $WORK/ls.cmd" "$img" >"$WORK/ls.out"
    perl -e 'my $dir; my @out;
        while (<STDIN>) { chomp;
            if (m{^/(.*):$}) { $dir = $1; next }
            next unless /^\s*\d+\s+(\d+)\s+\S+\s+0x[0-9a-f]+\s+(\d+)\s(.*)\s\((?:good|bad)\)$/;
            my ($ino, $len, $name) = ($1, $2, $3); $name = substr($name, 0, $len);
            next if $name eq "." || $name eq "..";
            push @out, ($dir eq "" ? $name : "$dir/$name") . "\t$ino" }
        print "$_\n" for sort @out' <"$WORK/ls.out" >"$WORK/paths"
    cut -f2 "$WORK/paths" | perl -ne 'chomp; print "inode $_\nprint core.mode core.uid core.gid core.size core.nlinkv2 core.atime.sec core.atime.nsec core.mtime.sec core.mtime.nsec core.ctime.sec core.ctime.nsec\n"' >"$WORK/inode.cmd"
    xfs_db -r -c "source $WORK/inode.cmd" "$img" >"$WORK/db.out"
    perl - "$WORK/paths" "$WORK/db.out" >"$OUT/v4.stat.tsv" <<'EOF'
use strict;
use Time::Local;
my %mon = (Jan=>0,Feb=>1,Mar=>2,Apr=>3,May=>4,Jun=>5,Jul=>6,Aug=>7,Sep=>8,Oct=>9,Nov=>10,Dec=>11);
open(my $pf, '<', $ARGV[0]) or die; my @paths = map { chomp; [split /\t/] } <$pf>;
open(my $df, '<', $ARGV[1]) or die; my @recs; my %cur;
while (<$df>) {
    if (/^core\.mode = /) { push @recs, {%cur} if %cur; %cur = (); }
    if (/^core\.(\S+) = (.*)$/) { $cur{$1} = $2; } }
push @recs, {%cur} if %cur;
die "count mismatch" unless @recs == @paths;
sub secs { my ($s) = @_; return $s if $s =~ /^-?\d+$/;
    my ($w, $m, $d, $t, $y) = split ' ', $s; my ($H, $M, $S) = split /:/, $t;
    return timegm($S, $M, $H, $d, $mon{$m}, $y); }
sub ts { my ($r, $k) = @_; return sprintf('%d.%09d', secs($r->{"$k.sec"}), $r->{"$k.nsec"}); }
for my $i (0..$#paths) { my $r = $recs[$i];
    print join("\t", $paths[$i][0], $paths[$i][1], sprintf('%x', oct($r->{mode})), $r->{uid}, $r->{gid},
        $r->{size}, $r->{nlinkv2}, ts($r, 'atime'), ts($r, 'mtime'), ts($r, 'ctime'), '-'), "\n"; }
EOF
    # Content and symlink targets: what mkfs copied in, from the source tree.
    find . -type f -printf '%P\0' | sort -z | xargs -0 sha256sum >"$OUT/v4.sha256"
    find . -type l -printf '%P\t%l\n' | sort >"$OUT/v4.links.tsv"
    cd /
    xfs_info "$img" >"$OUT/v4.info"
    zstd -q -19 --long=27 -f "$img" -o "$OUT/v4.img.zst"
}
build_v4

# The listings are large and repetitive (thousands of empty files in big/).
zstd -q -19 --rm -f "$OUT"/*.stat.tsv "$OUT"/*.sha256
ls -l "$OUT"
