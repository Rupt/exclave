#!/bin/sh
# test/gate.sh EXCLAVE... — the commit gate (PROPOSAL.md 17): the unit tests, the stack budget, and for every exclave
# given the suite in the given and a random order (and, for the first exclave, under the plain terminal's AppArmor label), the
# resolution oracle, the namespace oracle, the syscall probe and the Docker profile; dogfood when EXCLAVE_TEST_CACHE names a package cache. Every step runs in parallel; every driver
# runs build/launcher on a copy of its own (the suite wraps one from the exclave's tree, the others take test/tree.py's
# fresh_exclave), so the exclaves given are never run as they are nor written. One line per step; logs under build/gate/. Exit status: the number of failed steps.
set -u
here=$(cd "$(dirname "$0")" && pwd)
repo=$(dirname "$here")
out=$repo/build/gate
[ $# -ge 1 ] || { echo "usage: test/gate.sh EXCLAVE..." >&2; exit 2; }
[ -x "$repo/build/launcher" ] || { echo "build/launcher missing: run make" >&2; exit 2; }
rm -rf "$out" && mkdir -p "$out" || exit 2
start=$(date +%s)

step() {                                                    # step NAME CMD...: in the background, its status and log kept
    name=$1; shift
    ( "$@" > "$out/$name.log" 2>&1; echo $? > "$out/$name.rc" ) &
}
unit() {
    cc -std=gnu11 -O1 -g -Wall -fno-builtin -fno-tree-loop-distribute-patterns -DHOST_TEST -o "$out/manifest_test" "$here/manifest_test.c" "$repo/src/manifest.c" "$repo/src/str.c" \
        && "$out/manifest_test" && python3 "$here/grammar_test.py" --c-parser "$out/manifest_test" \
        && cc -std=gnu11 -O1 -g -Wall -fno-builtin -fno-tree-loop-distribute-patterns -DHOST_TEST -o "$out/filter_test" "$here/filter_test.c" "$repo/src/filter.c" "$repo/src/str.c" \
        && "$out/filter_test" && python3 "$here/syscalls.py" \
        && cc -std=gnu11 -O1 -g -Wall -fno-builtin -fno-tree-loop-distribute-patterns -DSCRATCH_TEST -o "$out/scratch_test" "$here/scratch_test.c" "$repo/src/scratch.c" \
        && "$out/scratch_test"   # the parser, the filter and the scratch pool just built, not stale builds
}
stack() {
    python3 "$here/stackcheck.py" "$repo"/build/launcher.debug-*.ci || return 1
    if ls "$repo"/build/launcher-aarch64.debug-*.ci > /dev/null 2>&1; then python3 "$here/stackcheck.py" "$repo"/build/launcher-aarch64.debug-*.ci; fi
}

step unit unit
step stack stack
for ex in "$@"; do
    n=$(basename "$ex" .exclave)
    step "suite-$n" python3 "$here/run.py" --exclave "$ex" --work "$out/w-$n"
    step "suite-$n-random" python3 "$here/run.py" --exclave "$ex" --work "$out/w-$n-random" --order random
    if [ "$ex" = "$1" ] && command -v aa-exec > /dev/null 2>&1 && aa-exec -p unconfined true 2> /dev/null; then   # the plain terminal's
        step "suite-$n-plain" aa-exec -p unconfined python3 "$here/run.py" --exclave "$ex" --work "$out/w-$n-plain"   # AppArmor label (12), once
    fi
    step "resolve-$n" python3 "$here/oracle_resolve.py" --exclave "$ex" --work "$out/r-$n"
    step "ns-$n" python3 "$here/oracle_ns.py" --exclave "$ex" --work "$out/n-$n"
    step "syscalls-$n" python3 "$here/oracle_syscalls.py" --exclave "$ex" --work "$out/s-$n"
    step "docker-$n" python3 "$here/docker_profile.py" --exclave "$ex" --profile "$here/docker-seccomp.json" --work "$out/d-$n"
done
if [ -n "${EXCLAVE_TEST_CACHE:-}" ]; then
    step dogfood python3 "$here/dogfood.py" --cache "$EXCLAVE_TEST_CACHE" --work "$out/dogfood"
else
    echo "dogfood: EXCLAVE_TEST_CACHE not set; skipped"
fi
wait

fails=0
for rc in "$out"/*.rc; do
    name=$(basename "$rc" .rc)
    r=$(cat "$rc")
    last=$(grep -v '^$' "$out/$name.log" | tail -1 | cut -c1-110)
    if [ "$r" = 0 ]; then printf '%-22s ok    %s\n' "$name" "$last"; else printf '%-22s FAIL  %s\n' "$name" "$last"; fails=$((fails + 1)); fi
done
echo "gate: $fails failed, $(( $(date +%s) - start )) s"
exit $fails
