#!/bin/sh
# Runs every fuzz target for a time budget each (default 30 s): `fuzz/run.sh [seconds] [target...]`.
# Seeds each corpus from the test fixtures first. Needs `cargo install cargo-fuzz` and nightly.
set -eu
cd "$(dirname "$0")/.."
seconds="${1:-30}"
[ $# -gt 0 ] && shift
targets="${*:-$(cargo +nightly fuzz list)}"
for target in $targets; do
    mkdir -p "fuzz/corpus/$target"
    # Fixture folders are named after artifact ids (dashes); targets use underscores.
    for dir in "test_files/$(echo "$target" | tr _ -)" "test_files/$target"; do
        [ -d "$dir" ] && find "$dir" -type f -size -256k -exec cp {} "fuzz/corpus/$target/" \;
    done
    # Targets whose fixtures live in a folder named after the tool that made them.
    case "$target" in
        faillock | tallylog | faillog) extra=test_files/failed-logins ;;
        sudo_log | sudo_io) extra=test_files/sudo ;;
        *) extra= ;;
    esac
    [ -n "$extra" ] && find "$extra" -type f -size -256k -exec cp {} "fuzz/corpus/$target/" \;
    # Filesystem targets start from the real fixture images (those that are small enough).
    max_len=65536
    if [ -d "test_files/fs/$target" ]; then
        max_len=16777216
        for image in test_files/fs/"$target"/*.img.zst test_files/fs/"$target"/*.dmg.zst; do
            [ -f "$image" ] || continue
            seed="fuzz/corpus/$target/$(basename "$image" .zst)"
            zstd -dqf "$image" -o "$seed" && [ "$(wc -c < "$seed")" -le "$max_len" ] || rm -f "$seed"
        done
    fi
    # The virtual disk target starts from the small virtual disk fixtures (stored zstd-compressed).
    if [ "$target" = vdisk ]; then
        max_len=1048576
        for image in test_files/image/vdisk/*.zst; do
            seed="fuzz/corpus/$target/$(basename "$image" .zst)"
            zstd -dqf "$image" -o "$seed" && [ "$(wc -c < "$seed")" -le "$max_len" ] || rm -f "$seed"
        done
    fi
    echo "== $target"
    cargo +nightly fuzz run "$target" -- -max_total_time="$seconds" -max_len="$max_len" -rss_limit_mb=4096 -print_final_stats=1 2>&1 |
        grep -E "stat::number_of_executed_units|SUMMARY|panicked|ERROR|Test unit written" || true
    ls fuzz/artifacts/"$target"/crash-* >/dev/null 2>&1 && { echo "CRASH in $target"; exit 1; }
done
echo "no crashes"
