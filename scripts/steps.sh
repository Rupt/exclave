# scripts/steps.sh — the step runner scripts/gate and scripts/extra share: steps run in the background, N at a time,
# each with its status and time kept under $out, and reported one line each at the end. Sourced after lib.sh with
# $out (the log directory) and $jobs set.
# shellcheck disable=SC2154  # out and jobs are the sourcing script's

started=0
step() { # step NAME CMD...: in the background once fewer than $jobs run, its status and log kept
    name=$1
    shift
    while [ $((started - $(find "$out" -maxdepth 1 -name '*.rc' | wc -l))) -ge "$jobs" ]; do sleep 1; done
    started=$((started + 1))
    (
        # a name no step's function uses for its own, since a function shares the shell's variables
        step_started=$(date +%s)
        "$@" >"$out/$name.log" 2>&1
        echo "$? $(($(date +%s) - step_started))" >"$out/$name.rc"
    ) &
}

# shellcheck disable=SC2329  # run by the unit and fuzz steps
sanitized() { # sanitized OUT ARGS...: a host program built under ASan and UBSan, a finding fatal (test/sanitize.c)
    o=$1
    shift
    host_cc -fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer -o "$o" "$@" "$ROOT/test/sanitize.c"
}

# report WHAT START: one line per step, ok, SKIP (an oracle that could not run here, or the
# compatibility test before a baseline release) or FAIL with its last line; prints
# the count and the time since START; returns the number of failed steps
report() {
    fails=0 skips=0
    for rc in "$out"/*.rc; do
        name=$(basename "$rc" .rc)
        read -r r secs <"$rc"
        last=$(grep -v '^$' "$out/$name.log" | tail -1 | cut -c1-110)
        if [ "$r" != 0 ]; then
            printf '%-22s FAIL %4ss  %s\n' "$name" "$secs" "$last"
            fails=$((fails + 1))
        elif case $name in resolve-* | ns-* | syscalls-* | docker-* | nss | compat) grep -q 'cannot run' "$out/$name.log" ;; *) false ;; esac then
            printf '%-22s SKIP %4ss  %s\n' "$name" "$secs" "$last"
            skips=$((skips + 1)) # an oracle without bwrap, namespaces or openat2; no baseline yet
        else printf '%-22s ok   %4ss  %s\n' "$name" "$secs" "$last"; fi
    done
    echo "$1: $fails failed, $skips skipped, $(($(date +%s) - $2)) s"
    return $fails
}
