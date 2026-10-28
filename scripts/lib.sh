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

# install-uv sets this, because it is the one script that runs before uv exists.
if [ -z "${UV_BOOTSTRAP-}" ] && [ ! -x "$UV" ]; then
    echo "no uv at $UV; run scripts/install-uv" >&2
    exit 1
fi

# The pinned Python, the project's environment brought up to date first:
# py script.py args. Quiet, so a script's output is its own.
py() {
    "$UV" run --quiet --project "$ROOT" python "$@"
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
    x86_64) set -- -fcf-protection=none -mno-red-zone "$@" ;;
    # atomics inline, no libgcc to call; x28 never touched, since a Go program
    # without cgo keeps its g there and its signal handler reads it as it finds
    # it, in the middle of the launcher's handler too (7.5.3)
    aarch64) set -- -mgeneral-regs-only -mno-outline-atomics -ffixed-x28 "$@" ;;
    esac
    c_compile "$compiler" -O2 -g -nostdlib -nostartfiles -ffreestanding -fno-stack-protector -fno-builtin -fno-strict-aliasing \
        -fPIC -fvisibility=hidden -fno-plt -fno-asynchronous-unwind-tables -fno-tree-loop-distribute-patterns "$@"
}

# tool_cc COMPILER ARGS...: the exclave command's compiler, ordinary C on the C
# library with its GNU extensions (memmem, pipe2); scripts/build links the
# command statically, so that the file runs with nothing beside it (DESIGN.md 10).
# Its automatic variables start as zero, so that a read of one before a write
# is the same wrong answer on every run, rather than whatever the stack held.
tool_cc() {
    compiler=$1
    shift
    c_compile "$compiler" -O2 -g -D_GNU_SOURCE -ftrivial-auto-var-init=zero "$@"
}

# host_cc ARGS...: the unit tests' compiler, for the host on its libc, whose
# string.h declares again what sys.h declares.
host_cc() {
    c_compile "${CC:-gcc}" -O1 -g -Wno-redundant-decls -fno-builtin -fno-tree-loop-distribute-patterns "$@"
}
