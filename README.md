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
and the can's own `ld.so` itself. The **cannery** builds cans from files:
package files it is handed, or any root tree, and is itself a can.

## Status

Milestones 1a to 1c are built and milestone 2 has one item left, gdb.
Revision 10 of the proposal is a simplification: the cannery takes
files and never fetches, the lockfile records inputs and output by hash
and locates nothing, there is no generated index (the opener reads the
manifest and the tree), no from-source, no layers, no entries or
environment records, and a can is a directory at every stage. A gcc
can from Ubuntu or Debian packages builds zlib, Lua, SQLite and re2c
from source with their configure scripts, at native speed for the
compiles and about a third more for the configure scripts. The
regression suite (49 named tests), the kernel oracles, Docker's default
seccomp profile and the plain-terminal AppArmor label all pass on the
reference machine, and the kernel matrix in QEMU virtual machines
passes on nine distributions from CentOS 7 at kernel 3.10 to Fedora 42,
Alpine's musl userland and SELinux included. The cannery ships as a can
and the gcc can it builds from inside its can reproduces the host-built
lockfile byte for byte. Trace pruning keeps 120 of a gcc can's 4 851
files for a hello-world compile. Section 18 of the proposal has the
milestone table; 16.2 and 16.3 the measurements; 12 the matrix;
`docs/REVIEW-RESPONSE.md` every review finding, including the fourth
round's thirty-one against revision 10 itself.

## Build, make a can, run

```
make                      # build/opener, a freestanding ET_DYN, x86-64 only for now
make unit                 # the manifest grammar tests and the syscall table test
make stack                # the handler's stack budget from gcc -fstack-usage
tools/fetch-debs.py --out debs gcc-13 libc6-dev         # the step before the cannery: apt, a mirror, this tool, anything
cannery/cannery.py unpack gcc.can debs/*.deb            # package files -> an open can, a directory you may edit
cannery/cannery.py wrap gcc.can                         # close it: wrap, check, hash
ln -s root/usr/bin/gcc-13 gcc.can/gcc                   # an entry, if you want one
gcc.can/gcc -O2 hello.c -o hello                        # any executable in root/ runs by path
gcc.can/root/usr/bin/sh -c 'cc1 --version'              # the can's own shell
CAN_EXEC=/path/to/host/program gcc.can/.can/opener args...   # a host program inside the can
CAN_LOG=/tmp/can.log ...  # the one knob: one line per trapped syscall
cannery/cannery.py check gcc.can /tmp/can.log           # static check of every ELF, dynamic check of the logged run
cannery/cannery.py prune gcc.can /tmp/can.log           # keep what the logged runs touched
CONT_TREE=DIR make test   # the suite on a plain tree (spike/make-tree.sh makes one)
CONT_CAN=gcc.can make oracles   # bwrap and openat2 oracles, Docker's profile; needs user namespaces
CONT_CAN=gcc.can CONT_SQLITE=sqlite3.c make bench       # the performance table
test/realsoft.py --can dev.can --src DIR   # build zlib, Lua, SQLite, re2c inside and outside; dev.can needs g++, make, python3
test/matrix.py --can gcc.can              # the kernel matrix: cloud images under QEMU/KVM, one VM at a time
test/dogfood.py --cache DIR               # the cannery as a can, and a cross-can build that must reproduce
```

The cannery takes files and never fetches. `unpack` reads each
package's own control archive, reports dependencies the set does not
satisfy, extracts in Python, synthesises what maintainer scripts would
have done (alternatives, `ld.so.cache` with the can's own `ldconfig`,
the CA bundle, `/etc/passwd`), adds the placeholders and records every
input by hash in the lockfile. The result is a directory: copy a built
prefix in, add a manifest, delete what you do not want. `wrap` closes
it: wraps every executable, runs the static check, records the manifest
and tree hashes; `unwrap` opens it again; a bare directory holding a
`root/` becomes a can by `wrap` alone. `reopen` swaps a can's opener
and relinks its wrappers, `hash` prints the tree hash, `fmt`
canonicalises a manifest or lockfile.

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
src/opener.c     entry: syscall page, self-relocation, find the can, manifest, boundary, env, load
src/manifest.c   the strict grammar parser (6.2); also built for the host by make unit
src/loader.c     userland ELF loader and the .note.cont probe (7.3)
src/filter.c     the seccomp program (7.4.2)
src/handler.c    the SIGSYS handler: translation, read-only rule, exec, signal masks (7.4.3, 7.5, 8.2)
src/canon.c      canonicalisation in virtual space (7.4.4)
src/cache.c      the per-process component cache (7.4.4)
src/vis.c        the visibility rule, ownership read from the tree, identity files, wrapper redirect (8)
src/scratch.c    handler memory: mmap'd chunks with liveness reclamation (7.5.4)
src/isa.c        x86-64 psABI level check (7.7)
src/str.c        string helpers, arena, the shebang parser
src/log.c        CAN_LOG and fatal messages
cannery/cannery.py   the command line: grammar, unpack, wrap, unwrap, check, prune, fmt, hash, reopen
cannery/deb.py       ar, tar, compression, control stanzas, dependency fields, Debian version order
cannery/build.py     extraction rules, synthesis, placeholders, dependency report, pruning, tree hash, lockfile, unwrap
cannery/elfcheck.py  the static and dynamic checks of 10.3
tools/fetch-debs.py  an example of the step before the cannery: resolve a closure from an archive and download it
test/run.py          the regression suite; test/progs/ its C and Rust programs
test/oracle_ns.py    the namespace oracle (bwrap); test/oracle_resolve.py the openat2 oracle
test/docker_profile.py   a can under Docker's default seccomp profile; test/docker-seccomp.json the profile
test/syscalls.py     every kernel syscall classified; test/bench.py the performance table
test/realsoft.py     real projects built inside and outside a can; test/matrix.py the kernel matrix in VMs
test/dogfood.py      the cannery can building a can that must reproduce the host-built lockfile
test/manifest_test.c grammar tests; test/grammar_test.py the grammar properties; test/stackcheck.py the stack budget
docs/            proposal (revision 10), review response, prior art, review reports
spike/           frozen prototypes and their tests
```

## Names

`cont` is the codename and repository. `can` is the format and the
directory suffix. `opener` is the launcher. `cannery` is the build tool.
The environment knob is `CAN_LOG`; `CAN_EXEC` is the loader-mode target
and is set by the opener itself, or by hand to run a host program inside
a can. At the can boundary four variables are the can's, always the
same: `PATH=/usr/local/bin:/usr/bin:/bin`, `LANG=C.UTF-8`, `TZ=UTC0`
and `SHELL=/bin/sh`; the loader and libc variables are dropped;
everything else passes through, and inside the boundary nothing is
touched.
