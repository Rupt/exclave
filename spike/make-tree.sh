#!/bin/sh
# Build a test root tree from Ubuntu/Debian packages, no root required.
# usage: make-tree.sh OUTDIR [packages...]   (default: gcc-13 libc6-dev dash coreutils)
set -e
OUT=${1:?outdir}; shift; PKGS="${*:-gcc-13 libc6-dev dash coreutils}"
TMP=$(mktemp -d); : > "$TMP/status"
CLOSURE=$(apt-get -s -o Dir::State::status="$TMP/status" -o Debug::NoLocking=1 --no-install-recommends install $PKGS | awk '/^Inst /{print $2}')
echo "closure: $(echo $CLOSURE | wc -w) packages"
mkdir -p "$OUT" "$TMP/debs"; (cd "$TMP/debs" && apt-get download $CLOSURE >/dev/null)
cd "$OUT"; mkdir -p usr/bin usr/sbin usr/lib usr/lib64 etc var
for d in bin sbin lib lib64; do [ -e $d ] || ln -s usr/$d $d; done
for f in "$TMP"/debs/*.deb; do dpkg-deb -x "$f" .; done
[ -e usr/bin/sh ] || ln -s dash usr/bin/sh
rm -rf "$TMP"; echo "tree at $OUT: $(du -sh . | cut -f1)"
