# cont — build the opener, run the checks.
#
# The opener is a freestanding ET_DYN object with no PT_INTERP: it runs as a
# program (a wrapper, PROPOSAL.md 6.1) and loads programs itself (7.3).

CC      ?= gcc
SRC     := src/opener.c src/manifest.c src/loader.c src/scratch.c src/vis.c src/canon.c src/cache.c \
           src/filter.c src/handler.c src/isa.c src/str.c src/log.c
HDR     := src/sys.h src/common.h src/elf.h src/gdb.py
OUT     := build/opener
OLD     := build/opener-old

CFLAGS_COMMON := -std=gnu11 -O2 -g -Wall -Wextra -Wno-unused-parameter -Wno-unused-function \
           -nostdlib -nostartfiles -ffreestanding -fno-stack-protector -fno-builtin \
           -fPIC -fvisibility=hidden -fno-plt \
           -fno-asynchronous-unwind-tables -fno-tree-loop-distribute-patterns
CFLAGS  := $(CFLAGS_COMMON) -fcf-protection=none -mno-red-zone -fstack-usage
# the aarch64 opener (7.1, 12): the same sources, the cross compiler when the machine has one
AARCH64_CC := $(shell command -v aarch64-linux-gnu-gcc 2>/dev/null)
CFLAGS_AARCH64 := $(CFLAGS_COMMON) -mgeneral-regs-only -mno-outline-atomics -fstack-usage   # atomics inline: no libgcc to call
LDFLAGS := -shared -nostdlib -Wl,-e,_start -Wl,--no-relax -Wl,-z,noexecstack -Wl,-z,norelro \
           -Wl,-z,nopack-relative-relocs -Wl,-Bsymbolic -Wl,--build-id=none

# a freestanding link binds nothing: no PLT and no undefined symbol (an outline atomic helper of libgcc, say)
define linkcheck
	@$(1)readelf -d $@.debug | grep -q JMPREL && (echo "$@ has a PLT: a call left for a libc or libgcc" && false) || true
	@$(1)nm -u $@.debug | grep . && (echo "$@ has undefined symbols" && false) || true
endef

.PHONY: all clean stack test unit oracles bench

all: $(OUT) $(OLD) $(if $(AARCH64_CC),build/opener-aarch64 build/opener-old-aarch64)

# build/opener is stripped for shipping (every wrapper is a link to it); build/opener.debug keeps the symbols.
# The strip keeps .debug_gdb_scripts, the script gdb auto-loads (7.6), and .dynsym, the six names it reads.
$(OUT): $(SRC) $(HDR) Makefile
	@mkdir -p build
	@rm -f build/*.su
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@.debug $(SRC)
	@mv -f *.su build/ 2>/dev/null || true
	$(call linkcheck,)
	objcopy --strip-all --keep-section=.debug_gdb_scripts $@.debug $@
	@readelf -n $@ | grep -q cont || (echo "the note was stripped" && false)
	@readelf -S -W $@ | grep -q debug_gdb_scripts || (echo "the gdb script was stripped" && false)
	@readelf --dyn-syms $@ | grep -q cont_debug_hook || (echo "the gdb hook is not exported" && false)
	@readelf -h $@ | grep -q 'DYN' && echo "built $@ ($$(stat -c %s $@) bytes stripped, ET_DYN; symbols in $@.debug)"

# the previous opener for the nesting regression of 17.4: the same sources with the filter version before this
# one and without the syscalls that version did not know, so that a trap for one of them reaches a handler
# that must answer ENOSYS rather than re-issue it
$(OLD): $(SRC) $(HDR) Makefile
	@mkdir -p build
	$(CC) $(filter-out -fstack-usage,$(CFLAGS)) -DFILTER_VERSION=1 -DCONT_TEST_OLD $(LDFLAGS) -o $@.debug $(SRC)
	$(call linkcheck,)
	objcopy --strip-all --keep-section=.debug_gdb_scripts $@.debug $@

build/opener-aarch64: $(SRC) $(HDR) Makefile
	@mkdir -p build
	@rm -f build/opener-aarch64.debug-*.su
	$(AARCH64_CC) $(CFLAGS_AARCH64) $(LDFLAGS) -o $@.debug $(SRC)
	@mv -f *.su build/ 2>/dev/null || true
	$(call linkcheck,aarch64-linux-gnu-)
	aarch64-linux-gnu-objcopy --strip-all --keep-section=.debug_gdb_scripts $@.debug $@
	@aarch64-linux-gnu-readelf -h $@ | grep -q 'AArch64' && echo "built $@ ($$(stat -c %s $@) bytes stripped, ET_DYN aarch64)"

build/opener-old-aarch64: $(SRC) $(HDR) Makefile
	@mkdir -p build
	$(AARCH64_CC) $(filter-out -fstack-usage,$(CFLAGS_AARCH64)) -DFILTER_VERSION=1 -DCONT_TEST_OLD $(LDFLAGS) -o $@.debug $(SRC)
	$(call linkcheck,aarch64-linux-gnu-)
	aarch64-linux-gnu-objcopy --strip-all --keep-section=.debug_gdb_scripts $@.debug $@

# stack budget (7.5.4): no frame on the handler path above 512 bytes, and the
# summed frames of the handler path under 2048; the aarch64 build's frames too when it is built.
stack: $(OUT) $(if $(AARCH64_CC),build/opener-aarch64)
	python3 test/stackcheck.py build/opener.debug-*.su
	$(if $(AARCH64_CC),python3 test/stackcheck.py build/opener-aarch64.debug-*.su)

# host-side unit tests: the manifest parser compiled with a libc
unit:
	@mkdir -p build
	$(CC) -std=gnu11 -O1 -g -Wall -fno-builtin -fno-tree-loop-distribute-patterns -DHOST_TEST -o build/manifest_test test/manifest_test.c src/manifest.c src/str.c
	build/manifest_test
	python3 test/grammar_test.py
	python3 test/syscalls.py

# the regression suite (17.4); needs a gcc tree: CONT_TREE=dir make test
test: $(OUT) $(OLD)
	python3 test/run.py --tree $(CONT_TREE)

# the oracles and the container profile (17.1, 17.2, 12); need a packaged gcc can: CONT_CAN=x.can make oracles
oracles: $(OUT)
	python3 cannery/cannery.py reopen $(CONT_CAN)
	python3 test/oracle_resolve.py --can $(CONT_CAN)
	python3 test/oracle_ns.py --can $(CONT_CAN)
	python3 test/docker_profile.py --can $(CONT_CAN) --profile test/docker-seccomp.json

# the performance table (16): CONT_CAN=x.can make bench
bench: $(OUT)
	python3 test/bench.py --can $(CONT_CAN) --sqlite $(CONT_SQLITE)

clean:
	rm -rf build
