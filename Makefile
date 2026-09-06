# cont — build the opener, run the checks.
#
# The opener is a freestanding ET_DYN object with no PT_INTERP: it runs as a
# program (a wrapper, PROPOSAL.md 6.1) and loads programs itself (7.3).

CC      ?= gcc
SRC     := src/opener.c src/manifest.c src/loader.c src/scratch.c src/vis.c src/canon.c src/cache.c \
           src/filter.c src/handler.c src/isa.c src/str.c src/log.c
HDR     := src/sys.h src/common.h src/elf.h
OUT     := build/opener

CFLAGS  := -std=gnu11 -O2 -g -Wall -Wextra -Wno-unused-parameter -Wno-unused-function \
           -nostdlib -nostartfiles -ffreestanding -fno-stack-protector -fno-builtin \
           -fPIC -fvisibility=hidden -fno-plt -fcf-protection=none -mno-red-zone \
           -fno-asynchronous-unwind-tables -fno-tree-loop-distribute-patterns -fstack-usage
LDFLAGS := -shared -nostdlib -Wl,-e,_start -Wl,--no-relax -Wl,-z,noexecstack -Wl,-z,norelro \
           -Wl,-z,nopack-relative-relocs -Wl,-Bsymbolic -Wl,--build-id=none

.PHONY: all clean stack test unit oracles bench

all: $(OUT)

# build/opener is stripped for shipping (every wrapper is a link to it); build/opener.debug keeps the symbols
$(OUT): $(SRC) $(HDR) Makefile
	@mkdir -p build
	@rm -f build/*.su
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@.debug $(SRC)
	@mv -f *.su build/ 2>/dev/null || true
	objcopy --strip-all $@.debug $@
	@readelf -n $@ | grep -q cont || (echo "the note was stripped" && false)
	@readelf -h $@ | grep -q 'DYN' && echo "built $@ ($$(stat -c %s $@) bytes stripped, ET_DYN; symbols in $@.debug)"

# stack budget (7.5.4): no frame on the handler path above 512 bytes, and the
# summed frames of the handler path under 2048.
stack: $(OUT)
	python3 test/stackcheck.py build/opener.debug-*.su

# host-side unit tests: the manifest parser compiled with a libc
unit:
	@mkdir -p build
	$(CC) -std=gnu11 -O1 -g -Wall -fno-builtin -fno-tree-loop-distribute-patterns -DHOST_TEST -o build/manifest_test test/manifest_test.c src/manifest.c src/str.c
	build/manifest_test
	python3 test/grammar_test.py
	python3 test/syscalls.py

# the regression suite (17.4); needs a gcc tree: CONT_TREE=dir make test
test: $(OUT)
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
