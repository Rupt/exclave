#!/bin/sh
# test/examples.sh EXCLAVE — the example runs (DESIGN.md 17): what needs inputs the user supplies and time the gate
# cannot afford. Each runs when its input is set, and says so when it is not:
#   EXCLAVE_TEST_SRC=DIR         test/realsoft.py: zlib, Lua, SQLite and re2c built inside and outside (needs g++, make, python3 in the exclave)
#   EXCLAVE_TEST_SQLITE=FILE     test/bench.py: the performance table (16), best of three
#   EXCLAVE_TEST_RPMS=DIR        test/sysroot.py: a CentOS 7 glibc as a data directory, its output run inside and out
#   EXCLAVE_TEST_DEBS_ARM64=DIR  test/matrix.py --only noble-arm64: the emulated aarch64 row (12), about an hour
#   EXCLAVE_TEST_DOCKER=FILE     Docker's default seccomp profile, which the arm64 row then runs under too
# The x86-64 kernel matrix is test/matrix.py --exclave EXCLAVE --docker-profile FILE on its own, about ten minutes.
set -u
here=$(cd "$(dirname "$0")" && pwd)
repo=$(dirname "$here")
[ $# -eq 1 ] || { echo "usage: test/examples.sh EXCLAVE" >&2; exit 2; }
ex=$1; fails=0
run() { echo "== $1"; shift; "$@" || fails=$((fails + 1)); }
[ -n "${EXCLAVE_TEST_SRC:-}" ] && run realsoft python3 "$here/realsoft.py" --exclave "$ex" --src "$EXCLAVE_TEST_SRC" || echo "realsoft: EXCLAVE_TEST_SRC not set"
[ -n "${EXCLAVE_TEST_SQLITE:-}" ] && run bench python3 "$here/bench.py" --exclave "$ex" --sqlite "$EXCLAVE_TEST_SQLITE" || echo "bench: EXCLAVE_TEST_SQLITE not set"
[ -n "${EXCLAVE_TEST_RPMS:-}" ] && run sysroot python3 "$here/sysroot.py" --exclave "$ex" --rpms "$EXCLAVE_TEST_RPMS" --out "$repo/build/sysroot-hello" || echo "sysroot: EXCLAVE_TEST_RPMS not set"
[ -n "${EXCLAVE_TEST_DEBS_ARM64:-}" ] && run arm64 python3 "$here/matrix.py" --exclave "$ex" --only noble-arm64 --debs-arm64 "$EXCLAVE_TEST_DEBS_ARM64" ${EXCLAVE_TEST_DOCKER:+--docker-profile "$EXCLAVE_TEST_DOCKER"} || echo "arm64 row: EXCLAVE_TEST_DEBS_ARM64 not set"
exit $fails
