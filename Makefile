# exclave — build the launcher, run the checks.
#
# The launcher is a freestanding ET_DYN object with no PT_INTERP: it runs as a
# program (a wrapper, DESIGN.md 6.1) and loads programs itself (7.3).

CC      ?= gcc
SRC     := src/launcher.c src/manifest.c src/loader.c src/scratch.c src/vis.c src/canon.c src/cache.c \
           src/filter.c src/handler.c src/isa.c src/str.c src/log.c
HDR     := src/sys.h src/common.h src/elf.h src/gdb.py LICENSE
OUT     := build/launcher
OLD     := build/launcher-old

# Every warning here is clean, and scripts/check holds it so (make warnings); the build itself does not stop on
# one, since a newer gcc than the one the code was checked with may warn of something new.
WARNINGS := -Wall -Wextra -Wshadow -Wconversion -Wcast-qual -Wwrite-strings -Wstrict-prototypes \
           -Wmissing-prototypes -Wmissing-declarations -Wredundant-decls -Wnested-externs -Wold-style-definition \
           -Wundef -Wformat=2 -Wnull-dereference -Wduplicated-cond -Wduplicated-branches -Wlogical-op \
           -Wjump-misses-init -Wvla -Wimplicit-fallthrough -Wunused-macros
CFLAGS_COMMON := -std=gnu11 -O2 -g $(WARNINGS) \
           -nostdlib -nostartfiles -ffreestanding -fno-stack-protector -fno-builtin \
           -fPIC -fvisibility=hidden -fno-plt \
           -fno-asynchronous-unwind-tables -fno-tree-loop-distribute-patterns
CFLAGS  := $(CFLAGS_COMMON) -fcf-protection=none -mno-red-zone -fcallgraph-info=su   # the call graph and frames test/stackcheck.py reads
# the aarch64 launcher (7.1, 12): the same sources, the cross compiler when the machine has one
AARCH64_CC := $(shell command -v aarch64-linux-gnu-gcc 2>/dev/null)
# atomics inline, no libgcc to call; x28 never touched, since a Go program without cgo keeps its g there and its
# signal handler reads it as it finds it, in the middle of the launcher's handler too (7.5.3)
CFLAGS_AARCH64 := $(CFLAGS_COMMON) -mgeneral-regs-only -mno-outline-atomics -ffixed-x28 -fcallgraph-info=su
LDFLAGS := -shared -nostdlib -Wl,-e,_start -Wl,--no-relax -Wl,-z,noexecstack -Wl,-z,norelro \
           -Wl,-z,nopack-relative-relocs -Wl,-Bsymbolic -Wl,--build-id=none

# a freestanding link binds nothing: no PLT and no undefined symbol (an outline atomic helper of libgcc, say)
define linkcheck
	@$(1)readelf -d $@.debug | grep -q JMPREL && (echo "$@ has a PLT: a call left for a libc or libgcc" && false) || true
	@$(1)nm -u $@.debug | grep . && (echo "$@ has undefined symbols" && false) || true
endef

.PHONY: all clean debug unit warnings

all: $(OUT) $(OLD) $(if $(AARCH64_CC),build/launcher-aarch64 build/launcher-old-aarch64)

# build/launcher is stripped for shipping (every wrapper is a link to it); build/launcher.debug keeps the symbols.
# The strip keeps .debug_gdb_scripts, the script gdb auto-loads (7.6), .dynsym, the six names it reads, and
# .exclave.license, the licence's text, which goes with every copy of the launcher.
$(OUT): $(SRC) $(HDR) Makefile
	@mkdir -p build
	@rm -f build/*.su build/launcher.debug-*.ci
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@.debug $(SRC)
	@mv -f *.ci build/ 2>/dev/null || true
	$(call linkcheck,)
	objcopy --strip-all --keep-section=.debug_gdb_scripts --keep-section=.exclave.license $@.debug $@
	@readelf -n $@ | grep -Eq '^ +exclave +0x' && readelf -n $@ | grep -Eq '^ +cont +0x' || (echo "a note was stripped: the launcher carries exclave and cont (7.4.5)" && false)
	@readelf -S -W $@ | grep -q debug_gdb_scripts || (echo "the gdb script was stripped" && false)
	@readelf -p .exclave.license $@ | grep -q 'MIT License' || (echo "the licence was stripped" && false)
	@readelf --dyn-syms $@ | grep -q exclave_debug_hook || (echo "the gdb hook is not exported" && false)
	@readelf -h $@ | grep -q 'DYN' && echo "built $@ ($$(stat -c %s $@) bytes stripped, ET_DYN; symbols in $@.debug)"

# an older launcher for the nesting regression of 17.4: the same sources at filter version 3, without the syscalls
# version 4 added (version 5 added none, only an ioctl request every handler answers alike), so that a trap for
# one of them reaches a handler that must answer ENOSYS rather than re-issue it
$(OLD): $(SRC) $(HDR) Makefile
	@mkdir -p build
	$(CC) $(filter-out -fcallgraph-info=su,$(CFLAGS)) -DFILTER_VERSION=3 -DEXCLAVE_TEST_OLD $(LDFLAGS) -o $@.debug $(SRC)
	$(call linkcheck,)
	objcopy --strip-all --keep-section=.debug_gdb_scripts --keep-section=.exclave.license $@.debug $@

build/launcher-aarch64: $(SRC) $(HDR) Makefile
	@mkdir -p build
	@rm -f build/launcher-aarch64.debug-*.ci
	$(AARCH64_CC) $(CFLAGS_AARCH64) $(LDFLAGS) -o $@.debug $(SRC)
	@mv -f *.ci build/ 2>/dev/null || true
	$(call linkcheck,aarch64-linux-gnu-)
	aarch64-linux-gnu-objcopy --strip-all --keep-section=.debug_gdb_scripts --keep-section=.exclave.license $@.debug $@
	@aarch64-linux-gnu-readelf -n $@ | grep -Eq '^ +exclave +0x' && aarch64-linux-gnu-readelf -n $@ | grep -Eq '^ +cont +0x' || (echo "a note was stripped: the launcher carries exclave and cont (7.4.5)" && false)
	@aarch64-linux-gnu-readelf -S -W $@ | grep -q debug_gdb_scripts || (echo "the gdb script was stripped" && false)
	@aarch64-linux-gnu-readelf -p .exclave.license $@ | grep -q 'MIT License' || (echo "the licence was stripped" && false)
	@aarch64-linux-gnu-readelf --dyn-syms $@ | grep -q exclave_debug_hook || (echo "the gdb hook is not exported" && false)
	@aarch64-linux-gnu-readelf -h $@ | grep -q 'AArch64' && echo "built $@ ($$(stat -c %s $@) bytes stripped, ET_DYN aarch64)"

build/launcher-old-aarch64: $(SRC) $(HDR) Makefile
	@mkdir -p build
	$(AARCH64_CC) $(filter-out -fcallgraph-info=su,$(CFLAGS_AARCH64)) -DFILTER_VERSION=3 -DEXCLAVE_TEST_OLD $(LDFLAGS) -o $@.debug $(SRC)
	$(call linkcheck,aarch64-linux-gnu-)
	aarch64-linux-gnu-objcopy --strip-all --keep-section=.debug_gdb_scripts --keep-section=.exclave.license $@.debug $@

# every source compiled with the warnings as errors: the launcher's for each architecture there is a compiler for, and
# as build/launcher-old; the unit tests' for the host, on its libc, whose string.h declares again what sys.h declares.
# Nothing is kept.
UNIT_FLAGS := -std=gnu11 -O1 -g $(WARNINGS) -Wno-redundant-decls -fno-builtin -fno-tree-loop-distribute-patterns
warnings:
	@s=0; for f in $(SRC); do $(CC) $(filter-out -fcallgraph-info=su,$(CFLAGS)) -Werror -c -o /dev/null $$f || s=1; \
	    $(CC) $(filter-out -fcallgraph-info=su,$(CFLAGS)) -DFILTER_VERSION=3 -DEXCLAVE_TEST_OLD -Werror -c -o /dev/null $$f || s=1; done; \
	$(if $(AARCH64_CC),for f in $(SRC); do $(AARCH64_CC) $(filter-out -fcallgraph-info=su,$(CFLAGS_AARCH64)) -Werror -c -o /dev/null $$f || s=1; done;) \
	for f in test/*_test.c test/sanitize.c src/manifest.c src/filter.c src/isa.c src/str.c; do \
	    $(CC) $(UNIT_FLAGS) -Werror -DHOST_TEST -c -o /dev/null $$f || s=1; done; \
	$(CC) $(UNIT_FLAGS) -Werror -DSCRATCH_TEST -c -o /dev/null src/scratch.c || s=1; \
	exit $$s

# The unit tests, scripts/gate's unit step: the manifest parser, the filter, the scratch pool and the CPU check, built
# for the host under AddressSanitizer and UndefinedBehaviorSanitizer, a finding fatal (test/sanitize.c).
SANITIZE := -fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer
UNIT := build/unit/manifest_test build/unit/filter_test build/unit/scratch_test build/unit/isa_test
unit: $(UNIT)
build/unit/manifest_test: test/manifest_test.c src/manifest.c src/str.c
build/unit/filter_test: test/filter_test.c src/filter.c src/str.c
build/unit/isa_test: test/isa_test.c src/isa.c src/str.c
build/unit/scratch_test: test/scratch_test.c src/scratch.c
build/unit/manifest_test build/unit/filter_test build/unit/isa_test: UNIT_DEFINE := -DHOST_TEST
build/unit/scratch_test: UNIT_DEFINE := -DSCRATCH_TEST
$(UNIT): test/sanitize.c src/sys.h src/common.h Makefile
	@mkdir -p build/unit
	$(CC) $(UNIT_FLAGS) $(SANITIZE) $(UNIT_DEFINE) -o $@ $(filter %.c,$^)

# build/launcher-debug: the launcher with gcc's undefined-behaviour checks, each a trap instruction, since the launcher
# links no runtime to report one. A failed check kills the program with SIGILL at the faulting instruction, which gdb
# places from build/launcher-debug.debug. The gate runs the suite on it (test/run.py --launcher build/launcher-debug).
DEBUG_FLAGS := -fsanitize=undefined -fsanitize-trap=undefined -fsanitize=bounds-strict
debug: build/launcher-debug
build/launcher-debug: $(SRC) $(HDR) Makefile
	@mkdir -p build
	$(CC) $(filter-out -fcallgraph-info=su,$(CFLAGS)) $(DEBUG_FLAGS) $(LDFLAGS) -o $@.debug $(SRC)
	$(call linkcheck,)
	objcopy --strip-all --keep-section=.debug_gdb_scripts --keep-section=.exclave.license $@.debug $@

# the tests are scripts/gate EXCLAVE... (the commit gate) and scripts/examples EXCLAVE (the example runs); see README.md

clean:
	rm -rf build
