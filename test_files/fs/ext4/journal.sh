#!/usr/bin/env bash
# Builds ext3/ext4 images captured while mounted, whose newest changes are only in the journal,
# and their ground truth from the kernel's own journal replay.
#
#   test_files/fs/ext4/journal.sh    # run from anywhere; needs Docker (privileged)
#
# Each image is made with mke2fs and loop-mounted. Metadata writeback is held off
# (vm.dirty_writeback_centisecs=0, restored on exit), so a change committed to the journal by
# fsync stays out of its home block. The backing file is copied while still mounted: that copy
# has "needs_recovery" set and is NAME.img.zst. The truth is taken from a second copy mounted
# read-only, which makes the kernel replay the journal into it: NAME.truth.zst and NAME.sha256
# in the layout of build.sh. Each image is checked to differ when mounted with `noload` (no
# replay), so the fixture really needs the replay.
#
#   journal-csum3    ext4 defaults (64bit, metadata_csum: journal tags v3 with checksums), 4 KiB
#   journal-ext3     ext3, 1 KiB blocks: indirect maps, 32-bit journal tags without checksums
#   journal-wrap     a 1024-block journal written round more than once: the log wraps
#   journal-revoke   a directory deleted and its blocks reused for file data: revoke records
#   journal-nocommit journal-csum3 with its last commit block zeroed: that transaction is dropped
#   journal-badcsum  journal-csum3 with its last commit block's checksum damaged
set -eu  # no pipefail: `yes | head` ends with SIGPIPE

if [[ "${1:-}" != inside ]]; then
    here="$(cd "$(dirname "$0")" && pwd)"
    exec docker run --rm --privileged --platform linux/arm64 -v "$here:/out" debian:12 bash /out/journal.sh inside
fi

apt-get update -qq >/dev/null
apt-get install -y -qq e2fsprogs zstd >/dev/null 2>&1
mkdir -p /m /t

expire=$(cat /proc/sys/vm/dirty_expire_centisecs)
writeback=$(cat /proc/sys/vm/dirty_writeback_centisecs)
restore() {
    echo "$expire" > /proc/sys/vm/dirty_expire_centisecs
    echo "$writeback" > /proc/sys/vm/dirty_writeback_centisecs
    umount /m 2>/dev/null || true
    umount /t 2>/dev/null || true
}
trap restore EXIT
echo 0 > /proc/sys/vm/dirty_writeback_centisecs
echo 360000 > /proc/sys/vm/dirty_expire_centisecs

# path, file-type/mode hex, inode, links, size, uid, gid, atime, mtime, ctime, crtime, target
listing() {
    (cd "$1" && find . -mindepth 1 -print0 | sort -z | while IFS= read -r -d '' p; do
        printf '%s\t%s\t%s\n' "${p#./}" \
            "$(stat -c '%f	%i	%h	%s	%u	%g	%.9X	%.9Y	%.9Z	%.9W' "$p")" \
            "$(readlink "$p" || true)"
    done)
}

sums() {
    (cd "$1" && find . -type f -size +0 -print0 | sort -z | xargs -0 -r sha256sum | sed 's#  \./#  #')
}

fresh() {
    local mib=$1
    shift
    umount /m 2>/dev/null || true
    rm -f /tmp/live.img
    yes "stale data " | head -c $((mib * 1024 * 1024)) > /tmp/live.img
    mke2fs -q -F -E nodiscard "$@" /tmp/live.img
    # ext3 allocates at write time already, and refuses the option.
    extra=,nodelalloc
    [[ " $* " == *" ext3 "* ]] && extra=
    mount -o loop,noatime,commit=600$extra /tmp/live.img /m
}

# Unmounts (which checkpoints the journal: everything so far is in place) and mounts again.
settle() {
    umount /m
    mount -o loop,noatime,commit=600$extra /tmp/live.img /m
}

# fsync of each named file: commits the running transaction without writing metadata in place.
# Mounted with nodelalloc, so the commit also holds the blocks of every file written before it.
commit() {
    sync "$@"
}

# Copies the mounted image: its committed changes are in the journal only.
capture() {
    cp --sparse=always /tmp/live.img "/tmp/$1.img"
}

# Mounts a copy read-only on a writable loop device: the kernel replays the journal into it.
replay_mount() {
    loop=$(losetup -f --show "$1")
    mount -o ro,noatime "$loop" /t
}

replay_umount() {
    umount /t
    losetup -d "$loop"
}

# The journal's last commit block, as "journal-block filesystem-block".
last_commit() {
    local jblk
    jblk=$(debugfs -c -R logdump "$1" 2>/dev/null | awk '/type 2 \(commit block\)/ {b=$NF} END {print b}')
    echo "$jblk $(debugfs -c -R "bmap <8> $jblk" "$1" 2>/dev/null)"
}

# Writes the fixture and its truth. With `e2fsck` as $2 the replay is e2fsck's
# (`-E journal_only`) instead of the kernel's: the kernel refuses to mount a journal whose
# commit block checksum is wrong, and e2fsck replays the transactions before it.
finish() {
    local name=$1 by=${2:-kernel}
    local img=/tmp/$name.img
    dumpe2fs -h "$img" 2>/dev/null | grep -q needs_recovery || { echo "$name: needs_recovery is not set"; exit 1; }
    echo "== $name: $(debugfs -c -R logdump "$img" 2>/dev/null | grep -c 'commit block') commit blocks in the log," \
        "$(debugfs -c -R 'logdump -a' "$img" 2>/dev/null | grep -cE 'logged at .*flags 0x[0-9a-f]*[13579bdf]\)') escaped," \
        "$(dumpe2fs -h "$img" 2>/dev/null | grep -E '^Journal features' | tr -s ' ')"
    mount -o loop,ro,noload "$img" /t
    # Without the replay the metadata is out of date: reading it may fail.
    listing /t > /tmp/noload.list 2>/dev/null
    sums /t > /tmp/noload.sums 2>/dev/null
    umount /t
    cp --sparse=always "$img" /tmp/replayed.img
    if [[ $by == e2fsck ]]; then
        if replay_mount /tmp/replayed.img 2>/dev/null; then
            echo "$name: the kernel replayed a journal it should refuse"
            exit 1
        fi
        losetup -d "$loop"
        e2fsck -p -E journal_only /tmp/replayed.img 2>&1 | sed 's/^/   e2fsck: /'
        mount -o loop,ro,noload /tmp/replayed.img /t
        listing /t > /tmp/truth.list
        sums /t > "/out/$name.sha256"
        umount /t
    else
        replay_mount /tmp/replayed.img
        listing /t > /tmp/truth.list
        sums /t > "/out/$name.sha256"
        replay_umount
    fi
    if cmp -s /tmp/noload.list /tmp/truth.list && cmp -s /tmp/noload.sums "/out/$name.sha256"; then
        echo "$name: the replayed volume equals the volume without replay"
        exit 1
    fi
    echo "   $(wc -l < /tmp/truth.list) paths after replay, $(wc -l < /tmp/noload.list) without;" \
        "$(diff /tmp/noload.sums "/out/$name.sha256" | grep -c '^>') checksums differ or are new"
    e2fsck -fn /tmp/replayed.img >/dev/null 2>&1 || echo "   e2fsck -fn on the replayed copy reported problems"
    zstd -19 -q -f -o "/out/$name.truth.zst" /tmp/truth.list
    zstd -19 -q -f "$img" -o "/out/$name.img.zst"
}

# A tree written and checkpointed, then changed with each change committed to the journal.
changes() {
    cd /m
    mkdir -p base/keep log
    for i in $(seq 1 20); do printf 'base file %s\n' "$i" > "base/keep/f$i"; done
    printf 'to be changed\n' > base/changed.txt
    printf 'to be deleted\n' > base/deleted.txt
    printf 'to be renamed\n' > base/renamed-from
    seq 1 5000 > base/grows.txt
    printf 'first line\n' > log/app.log
    cd /
    settle
    cd /m
    printf 'changed in the journal\n' > base/changed.txt
    commit base/changed.txt
    rm base/deleted.txt
    mv base/renamed-from base/renamed-to
    seq 5001 9000 >> base/grows.txt
    commit base/grows.txt
    mkdir -p new/a/b
    printf 'new file\n' > new/a/b/file.txt
    seq 1 30000 > new/medium.txt
    ln -s ../base/changed.txt new/link
    ln -s "$(printf 'x/%.0s' $(seq 1 40))long_target" new/longlink
    chmod 640 base/keep/f1
    chown 1000:1000 base/keep/f2
    touch -d '2020-02-02T02:02:02.5Z' base/keep/f3
    # Data journaled too (chattr +j); a block that starts with the journal magic is escaped.
    touch new/journaled new/escaped
    chattr +j new/journaled new/escaped
    seq 1 3000 > new/journaled
    printf '\xc0\x3b\x39\x98 starts with the journal magic\n' > new/escaped
    mkdir new/many
    for i in $(seq 1 300); do printf '%s\n' "$i" > "new/many/entry_$(printf %04d "$i")_with_a_longer_name"; done
    commit new/medium.txt
    for i in $(seq 1 40); do
        printf 'log line %s\n' "$i" >> log/app.log
        commit log/app.log
    done
    printf 'only in the last transaction\n' > last-transaction
    commit last-transaction
    cd /
}

# (1) ext4 defaults, 4 KiB blocks
fresh 16 -t ext4 -b 4096 -N 2000
changes
capture journal-csum3
finish journal-csum3

# (5) and (6): the same image with its last transaction cut off or damaged
read -r jblk fblk <<< "$(last_commit /tmp/journal-csum3.img)"
echo "   last commit: journal block $jblk, filesystem block $fblk"
cp --sparse=always /tmp/journal-csum3.img /tmp/journal-nocommit.img
dd if=/dev/zero of=/tmp/journal-nocommit.img bs=4096 seek="$fblk" count=1 conv=notrunc status=none
finish journal-nocommit
cp --sparse=always /tmp/journal-csum3.img /tmp/journal-badcsum.img
# h_chksum[0] is at byte 16 of the commit block.
printf '\xa5' | dd of=/tmp/journal-badcsum.img bs=1 seek=$((fblk * 4096 + 17)) conv=notrunc status=none
finish journal-badcsum e2fsck

# (2) ext3, 1 KiB blocks
fresh 16 -t ext3 -b 1024 -N 2000
changes
capture journal-ext3
finish journal-ext3

# (3) a small journal written round more than once
fresh 16 -t ext4 -b 1024 -N 2000 -J size=1
cd /m
mkdir spin
cd /
settle
cd /m
wrapped=no
for i in $(seq 1 3000); do
    printf 'transaction %s\n' "$i" >> spin/log
    printf '%s\n' "$i" > "spin/file_$((i % 50))"
    commit spin/log "spin/file_$((i % 50))"
    if (( i % 50 == 0 && i >= 300 )); then
        capture journal-wrap
        # Wrapped when a block of the log comes after (in log order) a lower-numbered one.
        if debugfs -c -R logdump /tmp/journal-wrap.img 2>/dev/null \
            | awk '/^Found expected sequence/ {b=$NF; if (p != "" && b+0 < p+0) w=1; p=b} END {exit !w}'; then
            wrapped=yes
            break
        fi
    fi
done
cd /
[[ $wrapped == yes ]] || { echo "journal-wrap: the log never wrapped"; exit 1; }
debugfs -c -R logdump /tmp/journal-wrap.img 2>/dev/null | grep -E '^Journal starts' | sed 's/^/   /'
finish journal-wrap

# (4) a directory's blocks journaled, the directory deleted (revoke), the blocks reused for data
fresh 16 -t ext4 -b 1024 -N 2000 -m 0
cd /m
head -c $((64 * 1024)) /dev/zero | tr '\0' 'r' > reserve
dd if=/dev/zero of=filler bs=1k status=none 2>/dev/null || true
rm reserve
cd /
settle
cd /m
mkdir victim
for i in $(seq 1 400); do : > "victim/entry_$(printf %04d "$i")_with_a_name_long_enough_to_fill_blocks"; done
printf 'a\n' > marker1
commit marker1 victim
rm -r victim
printf 'b\n' > marker2
commit marker2
# Fills the free space, so the blocks the directory freed hold this file's data now.
yes 'reused block data' | head -c $((60 * 1024)) > reused 2>/dev/null || true
commit reused
cd /
capture journal-revoke
revoked=$(debugfs -c -R 'logdump -a' /tmp/journal-revoke.img 2>/dev/null | awk '/Revoke FS block/ {print $NF}' | sort -u)
logged=$(debugfs -c -R 'logdump -a' /tmp/journal-revoke.img 2>/dev/null | awk '/FS block [0-9]+ logged at/ {print $3}' | sort -u)
cp --sparse=always /tmp/journal-revoke.img /tmp/replayed.img
replay_mount /tmp/replayed.img
replay_umount
data=$(debugfs -c -R 'blocks /reused' /tmp/replayed.img 2>/dev/null | tr ' ' '\n' | sort -u)
both=$(comm -12 <(echo "$revoked") <(echo "$logged") | comm -12 - <(echo "$data") | wc -l)
echo "   $(echo "$revoked" | wc -w) revoked blocks, $both of them logged earlier and now data of /reused"
(( both > 0 )) || { echo "journal-revoke: no revoked block was logged earlier and reused"; exit 1; }
finish journal-revoke
