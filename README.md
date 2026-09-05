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

Milestones 1a to 1c are built and milestone 2 is under way. A gcc can
from the Ubuntu or Debian archive builds zlib, Lua, SQLite and re2c
from source with their configure scripts, at native speed for the
compiles and about a third more for the configure scripts. The
regression suite (41 named tests), the kernel oracles, Docker's default
seccomp profile and the plain-terminal AppArmor label all pass on the
reference machine, and the kernel matrix in QEMU virtual machines
passes on nine distributions from CentOS 7 at kernel 3.10 to Fedora 42,
Alpine's musl userland and SELinux included. The cannery ships as a can
and the gcc can it builds from inside its can reproduces the host-built
lockfile byte for byte. A third adversarial review, of the
implementation, found thirty-seven defects; thirty-four are fixed with
regressions. Section 18 of the proposal has the table; 16.2 and 16.3
the measurements; 12 the matrix; `docs/REVIEW-RESPONSE.md` the review.

## Build, make a can, run

```
make                      # build/opener, a freestanding ET_DYN, x86-64 only for now
make unit                 # the index grammar tests and the syscall table test
make stack                # the handler's stack budget from gcc -fstack-usage
cannery/cannery.py from-packages --entry gcc=/usr/bin/gcc-13 --out gcc.can gcc-13 libc6-dev
gcc.can/gcc -O2 hello.c -o hello                        # an entry symlink; any executable in root/ runs by path
gcc.can/root/usr/bin/sh -c 'cc1 --version'              # the can's own shell
CAN_EXEC=/path/to/host/program gcc.can/.can/opener args...   # a host program inside the can
CAN_LOG=/tmp/can.log ...  # the one knob: one line per trapped syscall
cannery/cannery.py check gcc.can --run gcc.can/gcc -c x.c    # static check of every ELF, dynamic check of a run
CONT_TREE=DIR make test   # the suite on a plain tree (spike/make-tree.sh makes one)
CONT_CAN=gcc.can make oracles   # bwrap and openat2 oracles, Docker's profile; needs user namespaces
CONT_CAN=gcc.can CONT_SQLITE=sqlite3.c make bench       # the performance table
test/realsoft.py --can dev.can --src DIR   # build zlib, Lua, SQLite, re2c inside and outside; dev.can needs g++, make, python3
test/matrix.py --can gcc.can              # the kernel matrix: cloud images under QEMU/KVM, one VM at a time
test/dogfood.py --cache DIR               # the cannery as a can, and a cross-can build that must reproduce
```

`from-packages` resolves the closure from the archive's `Packages`
index (with the Essential set unless `--no-essential`), verifies every
download against the index digests, extracts in Python, synthesises
what maintainer scripts would have done (alternatives, `ld.so.cache`
with the can's own `ldconfig`, the CA bundle, `/etc/passwd`), wraps,
checks, and writes the index and the lockfile. `--distro debian`,
`--suite`, `--mirror`, `--snapshot DATE` and `--cache DIR` select the
source. Other commands: `mkcan` from a plain tree, `wrap`, `index`,
`reopen` to swap a can's opener and relink its wrappers, `unwrap`,
`hash` for the lockfile's tree hash, `fmt`.

## Read in this order

1. `docs/PROPOSAL.md`: the design, self-contained. Sections 6 to 8 are
   the specification; 10 the cannery; 17 the tests; 18 the milestones;
   19 the decisions.
2. `src/`: the opener, one module per section of the proposal (below).
3. `docs/REVIEW-RESPONSE.md`: every review finding and where it landed.
4. `docs/PRIOR-ART.md`: twenty related systems and the primary sources
   for the kernel and loader facts relied on. `docs/reviews/`: the
   review reports; round 3 reviewed the code and is the best reading on
   where the implementation is subtle.
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
src/cache.c      the per-process component cache (7.4.4)
src/vis.c        the visibility rule, identity files, wrapper redirect (8)
src/scratch.c    handler memory: mmap'd chunks with liveness reclamation (7.5.4)
src/isa.c        x86-64 psABI level check (7.7)
src/str.c        string helpers, arena, the shebang parser
src/log.c        CAN_LOG and fatal messages
cannery/cannery.py   the command line: grammar, fmt, wrap, index, mkcan, from-packages, check, reopen, unwrap, hash
cannery/deb.py       ar, tar, compression, Packages stanzas, dependency fields, Debian version order
cannery/repo.py      indexes, closure resolution, fetch and verify
cannery/build.py     extraction rules, synthesis, placeholders, tree hash, lockfile, unwrap
cannery/elfcheck.py  the static and dynamic checks of 10.3
test/run.py          the regression suite; test/progs/ its C and Rust programs
test/oracle_ns.py    the namespace oracle (bwrap); test/oracle_resolve.py the openat2 oracle
test/docker_profile.py   a can under Docker's default seccomp profile; test/docker-seccomp.json the profile
test/syscalls.py     every kernel syscall classified; test/bench.py the performance table
test/realsoft.py     real projects built inside and outside a can; test/matrix.py the kernel matrix in VMs
test/dogfood.py      the cannery can building a can that must reproduce the host-built lockfile
test/index_test.c    grammar tests; test/stackcheck.py the stack budget
docs/            proposal (revision 9), review response, prior art, review reports
spike/           frozen prototypes and their tests
```

## Names

`cont` is the codename and repository. `can` is the format and the
directory suffix. `opener` is the launcher. `cannery` is the build tool.
The environment knob is `CAN_LOG`; `CAN_EXEC` is the loader-mode target
and is set by the opener itself, or by hand to run a host program inside
a can.
