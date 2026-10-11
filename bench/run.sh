#!/bin/sh
set -eu

repo=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
slangc=${SLANGC:-slangc}
go_cmd=${GO:-go}
run_dir=$(mktemp -d "${TMPDIR:-/tmp}/argon-bench.XXXXXX")
if [ "${KEEP_RESULTS:-0}" = "1" ]; then
    trap 'printf "raw benchmark output: %s\n" "$run_dir"' EXIT HUP INT TERM
else
    trap 'rm -rf "$run_dir"' EXIT HUP INT TERM
fi

"$slangc" "$repo/bench/main.sl" -o "$run_dir/slang-bench"
(cd "$repo/bench/go" && "$go_cmd" build -o "$run_dir/go-bench" .)

run_timed() {
    program=$1
    output=$2
    timing=$3
    if [ "$(uname -s)" = "Darwin" ]; then
        /usr/bin/time -l "$program" >"$output" 2>"$timing"
    else
        /usr/bin/time -v "$program" >"$output" 2>"$timing"
    fi
}

set --
for round in 1 2 3 4; do
    s1="$run_dir/slang-a1-$round.txt"
    g1="$run_dir/go-b1-$round.txt"
    g2="$run_dir/go-b2-$round.txt"
    s2="$run_dir/slang-a2-$round.txt"
    run_timed "$run_dir/slang-bench" "$s1" "$s1.time"
    run_timed "$run_dir/go-bench" "$g1" "$g1.time"
    run_timed "$run_dir/go-bench" "$g2" "$g2.time"
    run_timed "$run_dir/slang-bench" "$s2" "$s2.time"
    if [ "$round" = "1" ]; then
        slang_raw=$(sed -n '1s/^RAW //p' "$s1")
        go_raw=$(sed -n '1s/^RAW //p' "$g1")
        if [ -z "$slang_raw" ] || [ "$slang_raw" != "$go_raw" ]; then
            printf '%s\n' "Slang and Go Argon2id tags differ" >&2
            printf '%s\n' "slang: $slang_raw" "Go:    $go_raw" >&2
            exit 1
        fi
        printf '%s\n' "cross-language Argon2id tag match ok"
    fi
    set -- "$@" "slang_a1_$round=$s1" "go_b1_$round=$g1" \
        "go_b2_$round=$g2" "slang_a2_$round=$s2"
done

python3 "$repo/bench/summarize.py" "$@"
