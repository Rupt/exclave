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

# cannot_run WHY...: the command of a step that cannot run here, for want of an input: it says why and returns the
# status a driver exits with when it cannot run (test/harness.py), which report prints as SKIP.
# shellcheck disable=SC2329  # run through step, by name
cannot_run() {
    echo "$*"
    return 77
}

# report WHAT START: one line per step, ok, SKIP (status 77: the step said it cannot run here, an oracle without
# bwrap, namespaces or openat2, the compatibility test before a baseline release, a step whose input was not
# given) or FAIL with its last line; prints the count and the time since START; returns the number of failed steps
report() {
    fails=0 skips=0
    for rc in "$out"/*.rc; do
        name=$(basename "$rc" .rc)
        read -r r secs <"$rc"
        last=$(grep -v '^$' "$out/$name.log" | tail -1 | cut -c1-110)
        if [ "$r" = 77 ]; then
            printf '%-22s SKIP %4ss  %s\n' "$name" "$secs" "$last"
            skips=$((skips + 1))
        elif [ "$r" != 0 ]; then
            printf '%-22s FAIL %4ss  %s\n' "$name" "$secs" "$last"
            fails=$((fails + 1))
        else printf '%-22s ok   %4ss  %s\n' "$name" "$secs" "$last"; fi
    done
    echo "$1: $fails failed, $skips skipped, $(($(date +%s) - $2)) s"
    return $fails
}
