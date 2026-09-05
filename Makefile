# cont — build the opener, run the checks.
#
# The opener is a freestanding ET_DYN object with no PT_INTERP: it runs as a
# program (a wrapper, PROPOSAL.md 6.1) and loads programs itself (7.3).

CC      ?= gcc
SRC     := src/opener.c src/index.c src/loader.c src/scratch.c src/vis.c src/canon.c \
           src/filter.c src/handler.c src/isa.c src/str.c src/log.c
HDR     := src/sys.h src/common.h src/elf.h
OUT     := build/opener

CFLAGS  := -std=gnu11 -O2 -g -Wall -Wextra -Wno-unused-parameter -Wno-unused-function \
           -nostdlib -nostartfiles -ffreestanding -fno-stack-protector -fno-builtin \
           -fPIC -fvisibility=hidden -fno-plt -fcf-protection=none -mno-red-zone \
           -fno-asynchronous-unwind-tables -fno-tree-loop-distribute-patterns -fstack-usage
LDFLAGS := -shared -nostdlib -Wl,-e,_start -Wl,--no-relax -Wl,-z,noexecstack -Wl,-z,norelro \
           -Wl,-z,nopack-relative-relocs -Wl,-Bsymbolic -Wl,--build-id=none

.PHONY: all clean stack test unit

all: $(OUT)

$(OUT): $(SRC) $(HDR) Makefile
	@mkdir -p build
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $(SRC)
	@mv -f *.su build/ 2>/dev/null || true
	@readelf -h $@ | grep -q 'DYN' && echo "built $@ ($$(stat -c %s $@) bytes, ET_DYN)"

# stack budget (7.5.4): no frame on the handler path above 512 bytes, and the
# summed frames of the handler path under 2048.
stack: $(OUT)
	python3 test/stackcheck.py build/*.su

# host-side unit tests: the index parser compiled with a libc
unit:
	@mkdir -p build
	$(CC) -std=gnu11 -O1 -g -Wall -fno-builtin -fno-tree-loop-distribute-patterns -DHOST_TEST -o build/index_test test/index_test.c src/index.c src/str.c
	build/index_test

# the regression suite (17.4); needs a gcc tree: CONT_TREE=dir make test
test: $(OUT)
	python3 test/run.py --tree $(CONT_TREE)

clean:
	rm -rf build
