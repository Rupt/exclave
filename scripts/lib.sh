# Shared setup for the project's shell scripts. Source it; do not run it.
#
# Every script runs Python through the pinned uv in .uv/, never through the
# python3 on PATH, so a run depends neither on the caller's shell nor on what
# the machine has installed: uv provides the Python .python-version names and
# the tools pyproject.toml locks.
#
# A script elsewhere in the tree sources this with ROOT set to the repository
# root; scripts/ sets it from its own location.

if [ -z "${ROOT-}" ]; then
    ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
fi
UV_HOME="$ROOT/.uv"
UV="$UV_HOME/bin/uv"

# Everything uv downloads stays inside the repository: its cache and its
# Pythons. Only a Python uv installed is used, never one the machine has;
# pyproject.toml says the same for the project.
export UV_CACHE_DIR="$UV_HOME/cache"
export UV_PYTHON_INSTALL_DIR="$UV_HOME/python"
export UV_MANAGED_PYTHON=1

# Temporary files stay inside the repository too: what mktemp, Python's
# tempfile, Go's tests and the compilers make goes under build/tmp, not
# /tmp. A test that means the host's /tmp (DESIGN.md 8.1) names it.
# build/tmp outlives a reboot; scripts/clean-tmp empties it.
export TMPDIR="$ROOT/build/tmp"
mkdir -p "$TMPDIR"

# need_uv: the pinned uv is there, or the line that says how to get it. Asked where Python is run (py, py_exec) and
# by a script that runs uv itself, not where this file is sourced: the build, the install scripts and a build inside
# an exclave (scripts/reproduce) run none.
need_uv() {
    [ -x "$UV" ] || {
        echo "no uv at $UV; run scripts/install-uv" >&2
        return 1
    }
}

# The Go: the pinned toolchain scripts/install-go puts in .go/ builds the
# exclave command (DESIGN.md 10.5), never the go on PATH. Its module
# and build caches stay inside the repository too; a build is static, with
# every path in it relative and no version-control stamp, so the same sources
# give the same bytes anywhere, a checkout or a copy. The modules go.sum pins
# are fetched by scripts/install-go alone, so no build, check or test touches
# the network: to add or move one, run
#   GOPROXY=https://proxy.golang.org,direct .go/go/bin/go get MODULE@VERSION
# then scripts/install-go. scripts/build and scripts/check say when the
# toolchain is missing; nothing else needs it.
GO_HOME="$ROOT/.go"
# shellcheck disable=SC2034  # run by scripts/build, scripts/check and scripts/install-go
GO="$GO_HOME/go/bin/go"
# shellcheck disable=SC2034  # run by scripts/check
GOFMT="$GO_HOME/go/bin/gofmt"
export GOTOOLCHAIN=local
export GOMODCACHE="$GO_HOME/mod"
export GOCACHE="$GO_HOME/cache"
export GOPATH="$GO_HOME/path"
# staticcheck's cache and the go command's telemetry counters, which would otherwise go under the
# home directory: nothing the scripts run writes there
export STATICCHECK_CACHE="$GO_HOME/staticcheck"
export XDG_CONFIG_HOME="$GO_HOME/config"
export GOFLAGS="-trimpath -buildvcs=false"
export GOPROXY=off
export CGO_ENABLED=0

# go_build ARCH OUT PKG VERSION: the Go command PKG, a package path from the current directory, for ARCH, static
# (cgo off and the paths trimmed, above) and stripped, VERSION in it as `exclave version` prints it. scripts/build
# and scripts/reproduce call it.
go_build() {
    arch=$1 out=$2 pkg=$3 ver=$4
    case $arch in x86_64) goarch=amd64 ;; aarch64) goarch=arm64 ;; *) goarch=$arch ;; esac
    GOOS=linux GOARCH=$goarch "$GO" build -ldflags="-s -w -X main.version=$ver" -o "$out" "$pkg" || return 1
    # a static file, as the command is: no interpreter, so nothing of the machine's is loaded
    if readelf -l "$out" | grep -q 'interpreter'; then
        echo "build: $out asks for an interpreter: not static" >&2
        return 1
    fi
    echo "built $out ($(stat -c %s "$out") bytes, $arch)"
}

# go_notices OUT PKG...: the licence texts of Go itself, whose library and runtime every Go program links, and of
# every module linked into the PKGs, for a release to ship beside them (DESIGN.md 10.5), since their BSD licences
# ask a binary distribution to carry their notices. Go's from the pinned toolchain, then the modules in the order
# of their paths, each with the licence files at its root from the pinned cache, so the file is the same from the
# same go.sum and toolchain anywhere; a module without one fails the build, loudly.
go_notices() {
    out=$1
    shift
    mods=$("$GO" list -deps -f '{{if and .Module (not .Module.Main)}}{{.Module.Path}} {{.Module.Version}} {{.Module.Dir}}{{end}}' \
        "$@") || return 1
    [ -n "$mods" ] || {
        echo "build: $* link no module: no notices to write" >&2
        return 1
    }
    {
        echo "The exclave command and exclave-fetch link Go's standard library and runtime and these Go modules,"
        echo "the versions go.mod pins, each under the licence that follows its name. exclave itself is under the"
        echo "MIT licence (LICENSE)."
        printf '\n\n== Go %s, the standard library and runtime, LICENSE\n\n' "$(sed -n '1s/^go//p' "$GO_HOME/go/VERSION")"
        cat "$GO_HOME/go/LICENSE"
        printf '%s\n' "$mods" | LC_ALL=C sort -u | while read -r path ver dir; do
            found=false
            for f in "$dir"/LICENSE* "$dir"/LICENCE* "$dir"/COPYING* "$dir"/NOTICE*; do
                [ -f "$f" ] || continue
                found=true
                printf '\n\n== %s %s, %s\n\n' "$path" "$ver" "$(basename -- "$f")"
                cat "$f"
            done
            $found || {
                echo "build: $path $ver has no licence file in $dir" >&2
                exit 1
            }
        done
    } >"$out" || return 1
    echo "built $out ($(stat -c %s "$out") bytes)"
}

# The pinned Python, the project's environment brought up to date first:
# py script.py args. Quiet, so a script's output is its own.
py() {
    need_uv || return 1
    "$UV" run --quiet --project "$ROOT" python "$@"
}

# py_exec script.py args: the same in this shell's place, a wrapper's last line.
# shellcheck disable=SC2329  # called by the wrappers
py_exec() {
    need_uv || exit 1
    exec "$UV" run --quiet --project "$ROOT" python "$@"
}

# download URL FILE: through curl or wget, a connection that fails or stalls tried again, five times over about a
# minute, since GitHub has refused a runner's connection for two minutes at a time. scripts/inputs, the install
# scripts and scripts/example are the scripts that download.
# shellcheck disable=SC2329  # called by those scripts
download() {
    if command -v curl >/dev/null 2>&1; then
        curl -fsSL -A exclave --connect-timeout 30 --retry 5 --retry-delay 5 --retry-all-errors --retry-connrefused \
            -o "$2" "$1"
    elif command -v wget >/dev/null 2>&1; then
        wget -q -U exclave --timeout=30 --tries=5 --waitretry=5 -O "$2" "$1"
    else
        echo "neither curl nor wget is installed" >&2
        return 1
    fi
}

# The C: the flags every build of it shares, scripts/build's, scripts/check's
# and scripts/gate's, each a function that runs a compiler with them and then
# its own arguments.

# The architectures the launcher can be built for here: the machine's own, and
# aarch64 too where an x86-64 machine has the cross compiler (7.1, 12).
c_arches() {
    uname -m
    if [ "$(uname -m)" = x86_64 ] && command -v aarch64-linux-gnu-gcc >/dev/null 2>&1; then
        echo aarch64
    fi
}

# c_compile COMPILER ARGS...: COMPILER as C11 with GNU extensions and the
# strict warnings, then ARGS. The warnings are all clean, and scripts/check
# makes them errors; a build does not stop on one, since a newer gcc than the
# one the code was checked with may warn of something new.
c_compile() {
    compiler=$1
    shift
    "$compiler" -std=gnu11 -Wall -Wextra -Wshadow -Wconversion -Wcast-qual -Wwrite-strings -Wstrict-prototypes \
        -Wmissing-prototypes -Wmissing-declarations -Wredundant-decls -Wnested-externs -Wold-style-definition \
        -Wundef -Wformat=2 -Wnull-dereference -Wduplicated-cond -Wduplicated-branches -Wlogical-op \
        -Wjump-misses-init -Wvla -Wimplicit-fallthrough -Wunused-macros "$@"
}

# launcher_cc ARCH ARGS...: the launcher's compiler for ARCH, freestanding:
# no libc, no builtins, nothing gcc would call outside the launcher's own code.
# The handler reads its scratch buffers as whatever the syscall at hand
# fills, a stat, an iovec array, a vector, so type-based aliasing is off.
launcher_cc() {
    arch=$1
    shift
    compiler=${CC:-gcc}
    [ "$arch" = "$(uname -m)" ] || compiler=$arch-linux-gnu-gcc
    case $arch in
    # no vector or floating-point register, so that the state a program's
    # handler finds is the program's (7.5.7); r15 holds the trap's record
    # throughout the launcher's code (7.5.7)
    x86_64) set -- -fcf-protection=none -mno-red-zone -mgeneral-regs-only -ffixed-r15 "$@" ;;
    # atomics inline, no libgcc to call; x28 never touched, since a Go program
    # without cgo keeps its g there and its signal handler reads it as it finds
    # it, in the middle of the launcher's handler too (7.5.3); x18 never
    # touched, where a shadow call stack keeps its pointer; x27 holds the
    # trap's record (7.5.7); no BTI property, whatever the compiler's
    # default, since the trampolines' stubs carry no landing instruction
    aarch64) set -- -mgeneral-regs-only -mno-outline-atomics -ffixed-x28 -ffixed-x18 -ffixed-x27 -mbranch-protection=none "$@" ;;
    esac
    c_compile "$compiler" -O2 -g -nostdlib -nostartfiles -ffreestanding -fno-stack-protector -fno-builtin -fno-strict-aliasing \
        -fPIC -fvisibility=hidden -fno-plt -fno-asynchronous-unwind-tables -fno-tree-loop-distribute-patterns "$@"
}

# host_cc ARGS...: the unit tests' compiler, for the host on its libc, whose
# string.h declares again what sys.h declares.
host_cc() {
    c_compile "${CC:-gcc}" -O1 -g -Wno-redundant-decls -fno-builtin -fno-tree-loop-distribute-patterns "$@"
}

# unit_tests: the launcher's unit tests, one a line: the test's name, then the launcher's sources it is built with.
# test/NAME.c and those sources are compiled for the host with -DHOST_TEST, which turns on a source's test hooks.
# scripts/gate's unit step builds and runs each under the sanitisers, and scripts/check holds the same files,
# compiled the same way, to the warnings and the analyser.
unit_tests() {
    cat <<'EOF'
manifest_test src/manifest.c src/str.c
filter_test src/filter.c src/str.c
scratch_test src/scratch.c
cache_test src/cache.c src/str.c
isa_test src/isa.c src/str.c
str_test src/str.c
EOF
}

# release_head N: the checks scripts/release-prepare and scripts/release-publish share (docs/RELEASE.md): N is a whole
# number above 0, the machine is x86-64, the one a release carries (DESIGN.md 13 item 66), and the tree is main with
# no uncommitted change to a tracked file. Sets release_dir, where the release's files go.
release_head() {
    case $1 in '' | *[!0-9]* | 0*)
        echo "release: N is the release's number, a whole number above 0, not '$1'" >&2
        return 2
        ;;
    esac
    [ "$(uname -m)" = x86_64 ] || {
        echo "release: a release is made on x86-64, and this machine is $(uname -m)" >&2
        return 2
    }
    [ "$(git -C "$ROOT" symbolic-ref -q --short HEAD)" = main ] || {
        echo "release: a release is made on main" >&2
        return 1
    }
    git -C "$ROOT" diff-index --quiet HEAD -- || {
        echo "release: the tree has changes its commit does not hold" >&2
        return 1
    }
    release_dir=$ROOT/build/release-v$1
}

# release_commit N: HEAD is the commit that sets VERSION to N, from N-1, and changes nothing else.
release_commit() {
    [ "$(git -C "$ROOT" diff --name-only HEAD^ HEAD)" = VERSION ] &&
        [ "$(git -C "$ROOT" show HEAD:VERSION)" = "$1" ] &&
        [ "$(git -C "$ROOT" show HEAD^:VERSION)" = "$(($1 - 1))" ]
}

# release_files N: release_dir holds release N's files, built from HEAD: the two commands, the licences and the
# sums, each sum right, and the command naming itself exclave N+COMMIT, COMMIT as scripts/build names HEAD.
release_files() {
    [ "$(find "$release_dir" -mindepth 1 -maxdepth 1 -printf "%f\n" 2>/dev/null | LC_ALL=C sort | tr "\n" " ")" = \
        "LICENSE NOTICES SHA256SUMS exclave-fetch-x86_64 exclave-x86_64 " ] || {
        echo "release: $release_dir does not hold release $1's five files: run scripts/release-prepare $1" >&2
        return 1
    }
    (cd "$release_dir" && sha256sum --quiet -c SHA256SUMS) || {
        echo "release: a file in $release_dir does not match its sum" >&2
        return 1
    }
    release_name="exclave $1+$(git -C "$ROOT" describe --always --exclude='*')"
    [ "$("$release_dir/exclave-x86_64" version)" = "$release_name" ] || {
        echo "release: $release_dir is not of $release_name: run scripts/release-prepare $1" >&2
        return 1
    }
}
