#!/bin/bash
# Builds the APFS test images with macOS hdiutil/diskutil, without root, and records ground
# truth from the mounted volumes with stat(1), readlink(1) and shasum(1).
#
#   basic.dmg.zst   case-insensitive APFS "TestVol" with the tree below (truth: basic.tsv.zst)
#   cs.dmg.zst      case-sensitive APFS "CaseVol" (truth: cs.tsv)
#   multi.dmg.zst   1.1 GiB container: "Main", "Second" (role Data) and an encrypted "Locked"
#                   volume (truth: multi-main.tsv, multi-second.tsv). diskutil mounts "Second"
#                   with ownership ignored, so its truth has the mounting user as owner.
#
# Usage: build.sh [work-dir]. Images are attached only under the work dir and always detached.
# Truth lines: path, type, octal mode, uid, gid, size, links, mtime, birthtime (seconds with
# nanoseconds), symlink target, SHA-256 of regular files' content (as the kernel reads it,
# decompressing transparently compressed files).
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
WORK=${1:-$(mktemp -d)}
mkdir -p "$WORK" && WORK=$(cd "$WORK" && pwd)
MNT=$WORK/mnt
mkdir -p "$MNT"
trap 'diskutil unmount "$WORK/mnt2" >/dev/null 2>&1; hdiutil detach "$MNT" >/dev/null 2>&1 || true' EXIT

create() { # image fs volname size
    rm -f "$WORK/$1"
    hdiutil create -quiet -size "$4" -fs "$2" -volname "$3" -type UDIF -layout GPTSPUD "$WORK/$1"
    hdiutil attach "$WORK/$1" -mountpoint "$MNT" -nobrowse -owners on >/dev/null
}

finish() { # image truth-file
    truth "$MNT" >"$HERE/$2"
    hdiutil detach "$MNT" >/dev/null
    zstd -q -19 -f "$WORK/$1" -o "$HERE/$1.zst"
}

truth() { # mount point
    (cd "$1" && find . -mindepth 1 -path ./.fseventsd -prune -o -print | sed 's#^\./##' | LC_ALL=C sort |
        while IFS= read -r p; do
            line=$(stat -f '%HT	%p	%u	%g	%z	%l	%Fm	%FB' "$p")
            target='' sum=''
            [ -L "$p" ] && target=$(readlink "$p")
            [ -f "$p" ] && [ ! -L "$p" ] && sum=$(shasum -a 256 "$p" | cut -d' ' -f1)
            printf '%s\t%s\t%s\t%s\n' "$p" "$line" "$target" "$sum"
        done)
}

text() { # lines prefix: deterministic, compressible content
    python3 -c "import sys; sys.stdout.write(''.join('%s line %06d of the fixture\n' % (sys.argv[2], i) for i in range(int(sys.argv[1]))))" "$1" "$2"
}

# --- basic: every feature the reader handles -------------------------------------------------
create basic.dmg APFS TestVol 20m
cd "$MNT"
mkdir -p dir1/dir2/dir3 largedir sticky
text 3 deep >dir1/dir2/dir3/deep.txt
: >empty
printf 'hello apfs\n' >small.txt
text 4000 big >big.bin                                   # ~140 KiB, many blocks
python3 - <<'EOF'
import os
# Sparse: data, a 2 MiB hole, data, a hole to 5 MiB, data.
with open("sparse.bin", "wb") as f:
    f.write(b"head" * 1024)
    f.seek(2 << 20); f.write(b"middle")
    f.seek(5 << 20); f.write(b"tail")
# Fragmented: alternate 4 KiB writes to two files, syncing each, so their extents interleave.
a, b = open("frag-a.bin", "wb"), open("frag-b.bin", "wb")
for i in range(48):
    for f, tag in ((a, b"A"), (b, b"B")):
        f.write((tag + b"%05d" % i) * 682 + tag * 4)
        f.flush(); os.fsync(f.fileno())
a.close(); b.close()
# Large directory: several thousand entries span many B-tree nodes.
for i in range(3000):
    open("largedir/entry-%05d-with-a-longer-name" % i, "wb").close()
open("largedir/entry-01500-with-a-longer-name", "w").write("middle entry\n")
EOF
printf 'long name\n' >"$(python3 -c 'print("L" * 251 + ".txt")')"
printf 'unicode\n' >"Ünïcödé-文件-ñ.txt"
ln -s small.txt link-short
ln -s "$(python3 -c 'print("long/" * 160 + "target")')" link-long
ln -s dir1/dir2 link-dir
ln small.txt hardlink.txt
ln small.txt dir1/hardlink2.txt
cp -c big.bin clone.bin                                   # clone shares extents...
printf 'CLONE' | dd of=clone.bin bs=1 seek=8192 conv=notrunc 2>/dev/null   # ...then diverges
printf '#!/bin/sh\n' >setuid.sh && chmod 4755 setuid.sh
printf 'g\n' >setgid.bin && chmod 2750 setgid.bin
printf 'p\n' >private.txt && chmod 600 private.txt
printf 'r\n' >readonly.txt && chmod 444 readonly.txt
chmod 1777 sticky
# Transparent compression: ditto compresses a large file into the resource fork (LZVN, type 8:
# listed, not readable); decmpfs.py writes types 1, 3 and 9, which the kernel reads back below.
text 5000 lz >c-src && ditto --hfsCompression c-src comp-large.txt && rm c-src
text 300 zlib >comp-zlib.txt && python3 "$HERE/decmpfs.py" 3 comp-zlib.txt
text 20 stored >comp-type1.txt && python3 "$HERE/decmpfs.py" 1 comp-type1.txt
text 5 marked >comp-type9.txt && python3 "$HERE/decmpfs.py" 9 comp-type9.txt
# Distinct times last, so nothing above touches them.
/usr/bin/touch -t 200102030405.06 small.txt
/usr/bin/touch -t 199912312359.59 big.bin
/usr/bin/touch -d 2015-06-07T08:09:10.123456789 dir1/dir2/dir3/deep.txt
/usr/bin/touch -h -t 202203040506.07 link-short
/usr/bin/touch -t 201001010000.00 dir1/dir2
cd "$WORK"
finish basic.dmg basic.tsv
zstd -q -19 -f --rm "$HERE/basic.tsv"                    # 3000 lines for largedir

# --- cs: case-sensitive volume ----------------------------------------------------------------
create cs.dmg "Case-sensitive APFS" CaseVol 20m
cd "$MNT"
mkdir Dir dir
printf 'upper\n' >Dir/File
printf 'lower\n' >dir/file
printf 'Mixed\n' >dir/FILE
cd "$WORK"
finish cs.dmg cs.tsv

# --- multi: three volumes, one encrypted ------------------------------------------------------
create multi.dmg APFS Main 1100m
printf 'main volume\n' >"$MNT/main.txt"
DISK=$(diskutil info "$MNT" | awk '/Part of Whole/ {print $4}')
CONTAINER=$(diskutil info "$MNT" | awk '/APFS Container:/ {print $3}')
truth "$MNT" >"$HERE/multi-main.tsv"
diskutil apfs addVolume "$CONTAINER" APFS Second -role D -nomount >/dev/null
mkdir -p "$WORK/mnt2"
diskutil mount -mountPoint "$WORK/mnt2" "$(diskutil list "$CONTAINER" | awk '/ Second / {print $NF}')" >/dev/null
printf 'second volume\n' >"$WORK/mnt2/second.txt"
mkdir "$WORK/mnt2/sub" && printf 'nested\n' >"$WORK/mnt2/sub/n.txt"
truth "$WORK/mnt2" >"$HERE/multi-second.tsv"
diskutil unmount "$WORK/mnt2" >/dev/null
diskutil apfs addVolume "$CONTAINER" APFS Locked -passphrase throwaway-test-pass -nomount >/dev/null
hdiutil detach "$MNT" >/dev/null
hdiutil detach "$DISK" >/dev/null 2>&1 || true
zstd -q -19 -f "$WORK/multi.dmg" -o "$HERE/multi.dmg.zst"
ls -l "$HERE"
