# cont

`cont` turns environment-dependent Linux software, compilers first, into
a directory that behaves like a single static executable: copy it
anywhere, run any program inside it by path, and it never touches a host
library, header, loader or configuration file. No daemon, no image store,
no privileges, no host binaries, no run-time options.

A **can** is that directory: an unmodified filesystem tree plus one
static, freestanding binary, the **opener**, which every executable in
the tree is a hard link to. The opener projects the tree onto `/` with a
seccomp filter and a resident `SIGSYS` handler that rewrites every
path-taking syscall inside the process, and loads the original program
and the can's own `ld.so` itself. The **cannery** builds cans; today from
a tree, later from packages and source, and eventually as a can itself.

## Status

Milestone 1a is built: the opener and a minimal cannery. A can made from
the stock Ubuntu 24.04 gcc 13 packages compiles and links C on this
machine with byte-identical objects and no host file touched, and the
regression suite (24 named tests, proposal section 17.4) passes. The
next milestones are 1b (the cannery from packages) and 1c (oracles,
kernel matrix, performance work). Section 18 of the proposal has the
table.

## Build, make a can, run

```
make                      # build/opener, a freestanding ET_DYN, x86-64 only for now
make unit                 # the index grammar tests, compiled with the host libc
make stack                # the handler's stack budget from gcc -fstack-usage
spike/make-tree.sh DIR    # a gcc 13 tree from Ubuntu packages, no root needed
cannery/cannery.py mkcan DIR mycan.can --link
mycan.can/root/usr/bin/gcc-13 -O2 hello.c -o hello     # any executable in root/ runs by path
CAN_EXEC=/path/to/host/program mycan.can/.can/opener args...   # a host program inside the can
CAN_LOG=/tmp/can.log ...  # the one knob: one line per translated operation
CONT_TREE=DIR make test   # the regression suite; makes its own can under build/test-work
```

`cannery.py check CAN` verifies wrappers, payloads and index agree;
`cannery.py fmt FILE` rewrites a manifest or index in canonical form.

## Read in this order

1. `docs/PROPOSAL.md`: the design, self-contained. Sections 6 to 8 are
   the specification; 17 the tests; 18 the milestones; 19 the decisions.
2. `src/`: the opener, one module per section of the proposal (below).
3. `docs/REVIEW-RESPONSE.md`: every review finding and where it landed.
4. `docs/PRIOR-ART.md`: twenty related systems and the primary sources
   for the kernel and loader facts relied on.
5. `spike/README.md`: the prototypes that preceded the opener, frozen.

## Layout

```
src/sys.h        syscall numbers, the syscall page, raw wrappers, a tiny libc subset
src/common.h     constants, the run-time state (struct can), every module's interface
src/opener.c     entry: syscall page, self-relocation, find the can, index, boundary, env, load
src/index.c      the strict grammar parser (6.2, 6.3); also built for the host by make unit
src/loader.c     userland ELF loader and the .note.cont probe (7.3)
src/filter.c     the seccomp program (7.4.2)
src/handler.c    the SIGSYS handler: translation, read-only rule, exec, signal masks (7.4.3, 7.5, 8.2)
src/canon.c      canonicalisation in virtual space (7.4.4)
src/vis.c        the visibility rule, identity files, wrapper redirect (8)
src/scratch.c    handler memory: mmap'd chunks with liveness reclamation (7.5.4)
src/isa.c        x86-64 psABI level check (7.7)
src/str.c        string helpers, arena, the shebang parser
src/log.c        CAN_LOG and fatal messages
cannery/cannery.py   grammar, wrap, index, mkcan, check, fmt (10, milestone 1a subset)
test/run.py      the regression suite; test/progs/ its C programs; test/index_test.c; test/stackcheck.py
docs/            proposal (revision 7), review response, prior art, review reports
spike/           frozen prototypes and their tests
```

## Names

`cont` is the codename and repository. `can` is the format and the
directory suffix. `opener` is the launcher. `cannery` is the build tool.
The environment knob is `CAN_LOG`; `CAN_EXEC` is the loader-mode target
and is set by the opener itself, or by hand to run a host program inside
a can.
