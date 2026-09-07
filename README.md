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

Milestones 1a to 3 are built. The cannery takes files and never fetches, the
lockfile records inputs and output by hash and locates nothing, the
opener reads the manifest and the tree and nothing generated, and a
can is a directory at every stage. A gcc can from Ubuntu or Debian
packages builds zlib, Lua, SQLite and re2c from source with their
configure scripts, at native speed for the compiles and about a third
more for the configure scripts; an Alpine can from `.apk` files and a
Fedora can from `.rpm` files compile and run C inside; a clang can
compiles C and C++; a CentOS 7 glibc as a data prefix in the gcc can
gives outputs that run on every glibc since 2.17, which the kernel
matrix checks natively on each VM; the opener builds for aarch64 from
the same sources and the matrix has an emulated arm64 row. gdb debugs
a canned program with no manual command: the opener carries the script
gdb needs. The
regression suite (56 named tests), the kernel oracles and Docker's
default seccomp profile pass on the gcc, Alpine, Fedora and clang cans,
each pruned to what the suite touches, in one 30-second gate on the
reference machine, where the plain-terminal AppArmor label passes too, and the kernel matrix in QEMU
virtual machines passes on nine distributions from CentOS 7 at kernel
3.10 to Fedora 42, Alpine's musl userland and SELinux included. The
cannery ships as a can and the gcc can it builds from inside its can
reproduces the host-built lockfile byte for byte. Trace pruning keeps
120 of a gcc can's 4 851 files for a hello-world compile. Section 18
of the proposal has the milestone table; 16 the measurements; 12 the
matrix and the Alpine can; `docs/REVIEW-RESPONSE.md` every review
finding.

## Build, make a can, run

```
make                      # build/opener, a freestanding ET_DYN; build/opener-old for the nesting test; build/opener-aarch64 with aarch64-linux-gnu-gcc
test/gate.sh gcc.can alpine.can fedora.can clang.can   # the commit gate, 30 s: unit tests, stack budget, the suite on every can in two orders, the oracles; CONT_CACHE=DIR adds dogfood
tools/fetch-debs.py --out debs gcc-13 libc6-dev         # the step before the cannery: apt, a mirror, this tool, anything
tools/fetch-apks.py --out apks gcc musl-dev binutils     # the same for Alpine
tools/fetch-rpms.py --repo URL --out rpms gcc glibc-devel   # and for Fedora, Rocky, CentOS: any repository with repodata/
test/sysroot.py --can gcc.can --rpms el7/ --out hello     # a CentOS 7 glibc as a data prefix; the output runs on every glibc since 2.17
cannery/cannery.py unpack gcc.can debs/*.deb            # package files -> an open can, a directory you may edit; .apk files likewise
cannery/cannery.py wrap gcc.can                         # close it: wrap, check, hash
ln -s root/usr/bin/gcc-13 gcc.can/gcc                   # an entry, if you want one
gcc.can/gcc -O2 hello.c -o hello                        # any executable in root/ runs by path
gcc.can/root/usr/bin/sh -c 'cc1 --version'              # the can's own shell
gcc.can/.can/opener /path/to/host/program args...        # a program without a wrapper, a host tool or a built output, inside the can
gdb -iex 'set auto-load safe-path /' --args gcc.can/gcc -c x.c   # gdb: the opener carries the script; break, bt, source lines
CAN_LOG=/tmp/can.log ...  # the one knob: one line per trapped syscall
cannery/cannery.py check gcc.can /tmp/can.log           # static check of every ELF, dynamic check of the logged run
cannery/cannery.py prune gcc.can /tmp/can.log           # keep what the logged runs touched
test/run.py --can gcc.can                 # the suite alone; --tree DIR for a plain tree (spike/make-tree.sh makes one); -k NAME, --order random
test/matrix.py --can gcc.can              # the kernel matrix: cloud images under QEMU/KVM, one VM at a time, eight minutes
test/examples.sh gcc.can                  # the example runs, each when its input is set: CONT_SRC (realsoft), CONT_SQLITE (bench), CONT_RPMS (sysroot), CONT_DEBS_ARM64 (the emulated aarch64 row)
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
src/sys.h        syscall numbers and instruction per architecture, the syscall page, raw wrappers, a tiny libc subset
src/common.h     constants, the run-time state (struct can), every module's interface
src/opener.c     entry: syscall page, self-relocation, find the can, manifest, boundary, env, load
src/manifest.c   the strict grammar parser (6.2); also built for the host by the gate's unit step
src/loader.c     userland ELF loader and the .note.cont probe (7.3); the facts exported for gdb (7.6)
src/gdb.py       the script the opener carries in .debug_gdb_scripts and gdb auto-loads (7.6, 13.1)
src/filter.c     the seccomp program (7.4.2)
src/handler.c    the SIGSYS handler: translation, read-only rule, exec, signal masks (7.4.3, 7.5, 8.2)
src/canon.c      canonicalisation in virtual space (7.4.4)
src/cache.c      the per-process component cache (7.4.4)
src/vis.c        the visibility rule, ownership read from the tree, identity files, wrapper redirect (8)
src/scratch.c    handler memory: mmap'd chunks with liveness reclamation (7.5.4)
src/isa.c        the ISA check (7.7): x86-64 psABI levels by cpuid, aarch64 levels by AT_HWCAP
src/str.c        string helpers, arena, the shebang parser
src/log.c        CAN_LOG and fatal messages
cannery/cannery.py   the command line: grammar, unpack, wrap, unwrap, check, prune, fmt, hash, reopen
cannery/deb.py       ar, tar, compression, control stanzas, dependency fields, Debian version order
cannery/apk.py       the Alpine reader with deb.py's interface: gzip streams, .PKGINFO, apk's dependency and version syntax
cannery/rpm.py       the rpm reader with the same interface: lead and headers, the cpio payload, rpm's flags and version order
cannery/build.py     extraction rules, synthesis, placeholders, dependency report, pruning, tree hash, lockfile, unwrap
cannery/elfcheck.py  the static and dynamic checks of 10.3
tools/fetch-debs.py  an example of the step before the cannery: resolve a closure from an archive and download it
tools/fetch-apks.py  the same for an Alpine repository, verified as apk verifies
tools/fetch-rpms.py  the same for a yum or dnf repository, verified by the index's SHA-256
test/sysroot.py      a glibc sysroot as a data prefix and an output built against it, for the matrix to run natively
test/run.py          the regression suite; test/progs/ its C and Rust programs
test/oracle_ns.py    the namespace oracle (bwrap); test/oracle_resolve.py the openat2 oracle
test/docker_profile.py   a can under Docker's default seccomp profile; test/docker-seccomp.json the profile
test/syscalls.py     every kernel syscall classified; test/bench.py the performance table
test/realsoft.py     real projects built inside and outside a can; test/matrix.py the kernel matrix in VMs
test/dogfood.py      the cannery can building a can that must reproduce the host-built lockfile
test/gate.sh         the commit gate, every step in parallel on copies of the cans given; test/examples.sh the example runs
test/tree.py         what a tree says about itself: its compiler, its shell, where a tool lives, its libc; the suite and the oracles ask it
test/manifest_test.c grammar tests; test/grammar_test.py the grammar properties; test/stackcheck.py the stack budget
docs/            proposal (revision 14), review response, prior art, review reports
spike/           frozen prototypes and their tests
```

## Names

`cont` is the codename and repository. `can` is the format and the
directory suffix. `opener` is the launcher. `cannery` is the build tool.
The environment knob is `CAN_LOG`, the only one. `CAN_EXEC` is the
opener's own protocol: set by an opener when it re-execs itself for a
program on the loader path, removed before any program runs, never an
interface; `.can/opener PROGRAM ARGS...` is how a program without a
wrapper is run from outside. At the can boundary four variables are the can's, always the
same: `PATH=/usr/local/bin:/usr/bin:/bin`, `LANG=C.UTF-8`, `TZ=UTC0`
and `SHELL=/bin/sh`; the loader and libc variables are dropped;
everything else passes through, and inside the boundary nothing is
touched.
