#!/bin/sh
# test/examples.sh CAN — the example runs (PROPOSAL.md 17): what needs inputs the user supplies and time the gate
# cannot afford. Each runs when its input is set, and says so when it is not:
#   CONT_SRC=DIR         test/realsoft.py: zlib, Lua, SQLite and re2c built inside and outside (needs g++, make, python3 in the can)
#   CONT_SQLITE=FILE     test/bench.py: the performance table (16), best of three
#   CONT_RPMS=DIR        test/sysroot.py: a CentOS 7 glibc as a data prefix, its output run inside and out
#   CONT_DEBS_ARM64=DIR  test/matrix.py --only noble-arm64: the emulated aarch64 row (12), about an hour
# The x86-64 kernel matrix is test/matrix.py --can CAN on its own, eight minutes.
set -u
here=$(cd "$(dirname "$0")" && pwd)
repo=$(dirname "$here")
[ $# -eq 1 ] || { echo "usage: test/examples.sh CAN" >&2; exit 2; }
can=$1; fails=0
run() { echo "== $1"; shift; "$@" || fails=$((fails + 1)); }
[ -n "${CONT_SRC:-}" ] && run realsoft python3 "$here/realsoft.py" --can "$can" --src "$CONT_SRC" || echo "realsoft: CONT_SRC not set"
[ -n "${CONT_SQLITE:-}" ] && run bench python3 "$here/bench.py" --can "$can" --sqlite "$CONT_SQLITE" || echo "bench: CONT_SQLITE not set"
[ -n "${CONT_RPMS:-}" ] && run sysroot python3 "$here/sysroot.py" --can "$can" --rpms "$CONT_RPMS" --out "$repo/build/sysroot-hello" || echo "sysroot: CONT_RPMS not set"
[ -n "${CONT_DEBS_ARM64:-}" ] && run arm64 python3 "$here/matrix.py" --can "$can" --only noble-arm64 --debs-arm64 "$CONT_DEBS_ARM64" || echo "arm64 row: CONT_DEBS_ARM64 not set"
exit $fails
