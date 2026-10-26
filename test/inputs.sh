#!/bin/sh
# test/inputs.sh DIR — the development inputs, remade from the network (PROPOSAL.md 17): the cans the gate
# runs on and the files the examples take. Nothing is kept anywhere but DIR and the fetchers' caches under
# ~/.cache, and both may be empty at any time: whatever is missing is fetched again, and an item DIR already
# has is skipped, so a rerun costs nothing. Afterwards:
#   EXCLAVE_TEST_CACHE=$HOME/.cache/exclave-debs test/gate.sh DIR/gcc13.exclave DIR/alpine.exclave DIR/f42.exclave DIR/clang.exclave
#   EXCLAVE_TEST_SRC=DIR/src EXCLAVE_TEST_SQLITE=DIR/src/sqlite3.c EXCLAVE_TEST_RPMS=DIR/el7 EXCLAVE_TEST_DEBS_ARM64=DIR/debs-arm64 test/examples.sh DIR/realsoft.exclave
# The package sets are the ones the proposal measures (10.1, 12, 16.3): the noble gcc-13 and clang-18 closures,
# Alpine 3.21's gcc, Fedora 42's gcc, the noble gcc, g++, make and python3 that test/realsoft.py builds with,
# CentOS 7's glibc for the sysroot of 9, the noble arm64 gcc-13 closure for the emulated row, and the four
# projects of test/realsoft.py with the SQLite amalgamation of test/bench.py.
set -u
here=$(cd "$(dirname "$0")" && pwd)
repo=$(dirname "$here")
[ $# -eq 1 ] || { echo "usage: test/inputs.sh DIR" >&2; exit 2; }
[ -x "$repo/build/launcher" ] || { echo "build/launcher missing: run make" >&2; exit 2; }
dir=$(mkdir -p "$1" && cd "$1" && pwd) || exit 2
mkdir -p "$dir/log" "$dir/src" || exit 2
fails=0

exclave() { python3 "$repo/exclave/exclave.py" "$@"; }

fetch() {                                   # fetch NAME FETCHER ARGS...: package files into DIR/NAME through the fetcher's cache
    name=$1; tool=$2; shift 2
    if [ -n "$(ls "$dir/$name" 2>/dev/null)" ]; then echo "$name: present"; return 0; fi
    rm -rf "$dir/$name"
    if python3 "$repo/tools/$tool" --out "$dir/$name" "$@" > "$dir/log/$name.log" 2>&1; then
        echo "$name: $(ls "$dir/$name" | wc -l) files"
    else
        echo "$name: FAIL, see $dir/log/$name.log"; rm -rf "$dir/$name"; fails=$((fails + 1)); return 1
    fi
}
can() {                                     # can NAME PKGDIR: unpack the package files into DIR/NAME.exclave and close it
    name=$1; pkgs=$2
    if grep -q '^tree ' "$dir/$name.exclave/.exclave/hashes" 2>/dev/null; then echo "$name.exclave: present"; return 0; fi
    rm -rf "$dir/$name.exclave"
    if exclave unpack "$dir/$name.exclave" "$dir/$pkgs"/* > "$dir/log/$name.exclave.log" 2>&1 && exclave wrap "$dir/$name.exclave" >> "$dir/log/$name.exclave.log" 2>&1; then
        echo "$name.exclave: $(grep -c '^pkg ' "$dir/$name.exclave/.exclave/hashes") packages; $(tail -1 "$dir/log/$name.exclave.log")"
    else
        echo "$name.exclave: FAIL, see $dir/log/$name.exclave.log"; rm -rf "$dir/$name.exclave"; fails=$((fails + 1)); return 1
    fi
}
file() {                                    # file URL NAME HASH: one file into DIR/src, verified by its BLAKE2b-256
    url=$1; name=$2; hash=$3
    if [ "$(b2sum -l 256 "$dir/src/$name" 2>/dev/null | cut -d' ' -f1)" = "$hash" ]; then echo "src/$name: present"; return 0; fi
    rm -f "$dir/src/$name"
    if python3 -c 'import sys, urllib.request; urllib.request.urlretrieve(sys.argv[1], sys.argv[2])' "$url" "$dir/src/$name" > "$dir/log/$name.log" 2>&1 \
       && [ "$(b2sum -l 256 "$dir/src/$name" | cut -d' ' -f1)" = "$hash" ]; then
        echo "src/$name: fetched"
    else
        echo "src/$name: FAIL (download or hash), see $dir/log/$name.log"; rm -f "$dir/src/$name"; fails=$((fails + 1)); return 1
    fi
}

fedora=https://archives.fedoraproject.org/pub/archive/fedora/linux/releases/42/Everything/x86_64/os
centos=https://vault.centos.org/7.9.2009/os/x86_64
fetch debs-gcc13 fetch-debs.py gcc-13 libc6-dev && can gcc13 debs-gcc13
fetch apks fetch-apks.py gcc musl-dev binutils make linux-headers && can alpine apks
fetch rpms-f42 fetch-rpms.py --repo $fedora --choose glibc-langpack=glibc-minimal-langpack gcc glibc-devel binutils make && can f42 rpms-f42
fetch debs-clang fetch-debs.py clang-18 libc6-dev libgcc-13-dev libstdc++-13-dev binutils && can clang debs-clang
fetch debs-realsoft fetch-debs.py gcc g++ make libc6-dev python3 && can realsoft debs-realsoft
fetch el7 fetch-rpms.py --repo $centos --no-base glibc glibc-devel glibc-headers kernel-headers libgcc
fetch debs-arm64 fetch-debs.py --arch arm64 --mirror http://ports.ubuntu.com/ubuntu-ports gcc-13 libc6-dev
file https://github.com/madler/zlib/releases/download/v1.3.1/zlib-1.3.1.tar.gz zlib-1.3.1.tar.gz ac034b9c7bbd9f8cc38953efaac07145ce0c8993107a1594d5cedd08fdf2a2bc
file https://www.lua.org/ftp/lua-5.4.7.tar.gz lua-5.4.7.tar.gz 7a37bca67359c6917fd330eee4e5d9f50852c27a2f5bce4e40b2b3b02ce18830
file https://www.sqlite.org/2024/sqlite-autoconf-3460100.tar.gz sqlite-autoconf-3460100.tar.gz 12fab9a1ef11d6cb772b7b88ef73102a7c1e02f7ae35f4c2d3263fbe7af706d8
file https://github.com/skvadrik/re2c/releases/download/3.1/re2c-3.1.tar.xz re2c-3.1.tar.xz 24709a9a1658019d3590f2ceb32c6f0b1c16641f87c961e626a4793061efef02
file https://www.sqlite.org/2025/sqlite-amalgamation-3500400.zip sqlite-amalgamation-3500400.zip 96f33f65b7d2fbdfbb0b8261a85c31e0d72dc033da51dca5de1919a9175067c8 \
    && if [ ! -f "$dir/src/sqlite3.c" ]; then
        python3 -c 'import sys, zipfile; z = zipfile.ZipFile(sys.argv[1]); [open(sys.argv[2], "wb").write(z.read(n)) for n in z.namelist() if n.endswith("/sqlite3.c")]' \
            "$dir/src/sqlite-amalgamation-3500400.zip" "$dir/src/sqlite3.c" && echo "src/sqlite3.c: extracted" || { echo "src/sqlite3.c: FAIL"; fails=$((fails + 1)); }
    fi
echo "inputs: $fails failed"
exit $fails
