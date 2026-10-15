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
a canned program once the can is in its auto-load safe-path: the opener
carries the script gdb needs. The
regression suite (69 named tests), the kernel oracles, a differential
syscall probe that agrees with the kernel on 19 093 cases per can, and
Docker's default seccomp profile pass on the gcc, Alpine, Fedora and
clang cans, each pruned to what the suite touches, in one gate of
about a minute on the reference machine, where the plain-terminal
AppArmor label passes too, and the kernel matrix in QEMU
virtual machines passes on nine distributions from CentOS 7 at kernel
3.10 to Fedora 42, Alpine's musl userland and SELinux included. The
cannery ships as a can and the gcc can it builds from inside its can
reproduces the host-built lockfile byte for byte. Trace pruning keeps
122 of a gcc can's 4 851 files for a hello-world compile. `example.sh`
walks the path from a clean checkout to a program built inside a can
that runs on any glibc since 2.17, in nine seconds once the packages
are cached. Section 18
of the proposal has the milestone table; 16 the measurements; 12 the
matrix and the Alpine can; `docs/REVIEW-RESPONSE.md` every review
finding.

## First run

You need an x86-64 Linux host with `gcc`, `make` and `python3` (3.6 or
later), and the network for one package fetch. No root, no container
runtime, no user namespaces: nothing here needs a privilege.

```bash
make
./example.sh ~/cont-example
```

`example.sh` runs the whole path under the directory you name and
prints each command as it runs, or for the long ones a line of summary
with the command and its output in a log under `log/`, so its output
and logs are the tutorial and each command is one you can run by hand:

1. `make` builds `build/opener`, the freestanding binary every
   executable in a can is a hard link to.
2. `tools/fetch-debs.py` downloads Ubuntu 24.04's `gcc-13` closure, 94
   packages, and `cannery unpack` makes an open can from the files:
   the tree under `gcc.can/root/`, the maintainer scripts' effects
   synthesised, every input recorded by hash in `gcc.can/.can/lock`.
3. `tools/fetch-rpms.py` downloads CentOS 7's glibc, headers and
   `libgcc`; unpacked into a can of their own, the tree is copied into
   the gcc can at `/opt/sysroot-el7`, and a two-line manifest says
   `data "/opt/sysroot-el7"`: nothing there is wrapped, checked or
   executed. `cannery wrap` closes the can, and a symlink `gcc.can/gcc`
   names its compiler.
4. `hello.c` is compiled inside the can twice, plainly and with
   `--sysroot=/opt/sysroot-el7 -B/opt/sysroot-el7/usr/lib64/`, each
   with `CAN_LOG` on. `objdump` shows what each output binds: the plain
   one `GLIBC_2.34`, so it needs a glibc at least that new wherever it
   runs; the sysroot one `GLIBC_2.2.5` alone, so it runs on any glibc
   from 2.17 on, the oldest the kernel matrix has, which runs this same
   build natively on CentOS 7. It runs on this host and, through `.can/opener`,
   inside the can on the can's loader.
5. `cannery prune` keeps, in a copy, the 136 files that compile touched
   out of 9 567; the copy compiles the program again, and
   `cannery check` reads the new log: that copy is the can you would
   ship for that workload, and the check is the one you would run on
   it.

What it prints on the reference machine, abridged:

```
== 3. CentOS 7's glibc as a sysroot inside it
+ cp -a sysroot.can/root gcc.can/root/opt/sysroot-el7
  closed gcc.can (46 warnings; log/wrap.log)
== 4. a program built inside, run on this host and inside the can
+ env CAN_LOG=log/hello.log gcc.can/gcc --sysroot=/opt/sysroot-el7 -B/opt/sysroot-el7/usr/lib64/ -o hello hello.c
  log/hello.log: 1220 lines, one per trapped syscall; the first:
    opener 0 host path absent, using the can's /etc/pki/tls/certs/ca-bundle.crt
    opener 0 cwd /home/me/cont/build/example
    opener 0 boundary /usr/bin/x86_64-linux-gnu-gcc-13
    load 0 /usr/bin/x86_64-linux-gnu-gcc-13
    access -2 /etc/ld.so.preload
    open 3 /etc/ld.so.cache
  glibc symbol versions bound: hello-plain: GLIBC_2.2.5 GLIBC_2.34  hello: GLIBC_2.2.5
+ ./hello
hello from a can
+ gcc.can/.can/opener /home/me/cont/build/example/hello
hello from a can
== 5. the can pruned to what the compile touched, and the checks on it
+ cannery prune hello.can log/hello.log
pruned hello.can: kept 136 files, removed 9431, 360514915 bytes freed
static check: 24 ELF files, 2 static executables, 0 warnings, 0 errors
+ cannery check hello.can log/pruned.log
0 wrapper problems
static check: 24 ELF files, 2 static executables, 0 warnings, 0 errors
warning: this host's nsswitch.conf names sss; the can has no libnss_sss.so.2
dynamic check: 1220 log lines, 0 errors
```

The 46 warnings of `wrap` are dangling symlinks: 45 are `coreutils`'
locale links, which point at translations Ubuntu moves into language
packs the package does not ship, and one is a man-page link to a page
no package in the set ships. The warning says the tree has a link to
nothing, which is true and harmless; an error would have stopped
`wrap`. Afterwards the directory holds `gcc.can`, a compiler
that touches nothing on the host, 264 MB with the sysroot; `hello`;
`hello.can`, the pruned copy, 50 MB; the fetched packages, which a
second run reuses; and `log/`, one file per step. A second run takes
nine seconds on the reference machine; the first also fetches 121 MB:
the 94 packages and 23 rpms, and the indexes that resolve them.

## Making your own can

The cannery takes files and never fetches. Whatever puts package files
in a directory is the step before it: apt, a mirror, the three fetchers
here. `unpack` reads each package's own control archive, reports
dependencies the set does not satisfy, extracts in Python, synthesises
what maintainer scripts would have done (alternatives, `ld.so.cache`
with the can's own `ldconfig`, the CA bundle, `/etc/passwd`), adds the
placeholders and records every input by hash in the lockfile. The
result is a directory. `wrap` closes it: wraps every executable, runs
the static check, records the manifest and tree hashes; `unwrap` opens
it again; a bare directory holding a `root/` becomes a can by `wrap`
alone. Every can has a `README` at its top for whoever finds it
without this repository: what it is, how to run its programs, what
it touches and how to check it. The cannery writes it where the can
has none, so a maker's own stays.

```
tools/fetch-debs.py --out debs gcc-13 libc6-dev make       # Ubuntu or Debian: the closure of the packages named, verified against the index
tools/fetch-apks.py --out apks gcc musl-dev binutils        # the same for Alpine
tools/fetch-rpms.py --repo URL --out rpms gcc glibc-devel   # and for Fedora, Rocky, CentOS: any repository with repodata/
cannery/cannery.py unpack gcc.can debs/*.deb               # package files -> an open can, a directory you may edit; .apk and .rpm files likewise
cannery/cannery.py wrap gcc.can                            # close it: wrap every executable, static check, hashes into the lock
ln -s root/usr/bin/gcc-13 gcc.can/gcc                      # an entry, if you want one
gcc.can/gcc -O2 hello.c -o hello                           # any executable in root/ runs by path
gcc.can/root/usr/bin/sh -c 'as --version'                  # the can's own shell, with the can's PATH
gcc.can/.can/opener /path/to/host/program args...           # a program without a wrapper, a host tool or a built output, inside the can
gdb -iex 'set auto-load safe-path /' --args gcc.can/gcc -c x.c   # gdb: the opener carries the script; break, bt, source lines
CAN_LOG=/tmp/can.log gcc.can/gcc -c x.c                    # the one knob: one line per trapped syscall
cannery/cannery.py check gcc.can /tmp/can.log              # static check of every ELF, dynamic check of the logged run
cannery/cannery.py prune gcc.can /tmp/can.log              # keep what the logged runs touched
cannery/cannery.py unwrap gcc.can                          # open a closed can to edit it; wrap closes it again
cannery/cannery.py reopen gcc.can build/opener             # swap the opener after rebuilding it; the wrappers are relinked
cannery/cannery.py hash gcc.can                            # the tree hash the lock records
cannery/cannery.py fmt gcc.can/.can/manifest               # the canonical spelling of a manifest or lock; --check only reports
```

Between `unpack` and `wrap` the open can is yours: copy a built prefix
in, delete what you do not want, add a data prefix, write the
manifest. The manifest is `gcc.can/.can/manifest`, `can 1` when nothing
is overridden, and has four other keys, each a string: `isa` names the
level the binaries need (`"x86-64-v3"`; x86-64 when absent); `data`
names a prefix that is never executed or loaded, not wrapped, not
checked, a sysroot or a second libc's world; `host` puts a host path
at its own name inside the can, `host "/usr/local/share/fonts"`; `own`
claims a path for the can, which removes one of the eight host
identity files below. That is the whole manifest. There is no way to
make the tree writable, remap a path, set a variable or put a directory
on `PATH`: a wrapper script inside the can sets variables, a symlink in
the tree does remapping, and a symlink in the can's own
`/usr/local/bin` puts a program on `PATH`.

A can of something you built is the same four lines, with the build
system's own installer doing the building:

```
gcc.can/root/usr/bin/sh -c './configure --prefix=/usr/local && make && make install DESTDIR=$PWD/stage'
cannery/cannery.py unpack tool.can runtime/*.deb          # libc6 and whatever else the result links against
cp -a stage/usr/local tool.can/root/usr/
cannery/cannery.py wrap tool.can                          # the static check says whether it all links inside
```

No recipe format and no closure copying: the runtime the result needs
is packages you already have, and the static check verifies that every
library resolves inside the can.

## The log and the checks

`CAN_LOG=<file>` is the opener's one knob. It appends one line per
trapped syscall, `<syscall> <result> <virtual path>`, the result being
the return value or the negative errno: `open 3 /etc/ld.so.cache` is
descriptor 3, `access -2 /etc/ld.so.preload` is `ENOENT`, which is what
a search looks like and is not a fault. Lines that begin `opener` are
the opener's own decisions: the working directory it started in and,
when that lies under a can-owned path, the subtree it claimed for the
host; the boundary program; an identity file the host lacks, answered
from the can's copy. Every process a workload spawns appends to the
same file, so a `make` writes one log. A newline in a path is written
`\n` and a backslash `\\`; nothing else is escaped.

`cannery check CAN [LOG...]` first verifies the wrappers and their
payloads and compares the tree with the lock's hash, then runs the
static check on every ELF file outside data
prefixes: every loader and every `DT_NEEDED` resolves inside the tree
by the loader's own search, to one libc, and nothing would resolve on
the host. Errors name the file and stop `wrap`; warnings are things
worth knowing that do not: a dangling symlink, a 32-bit or
foreign-machine object a package ships beside the real ones; static
executables are counted, having no loader to verify.
With logs it adds the dynamic check: every library the workload opened
resolved inside the can, and every NSS module this host's
`nsswitch.conf` names that the can lacks is a warning. glibc skips a
missing module, which is right for `hosts` and wrong for `passwd` on a
host whose users come from LDAP or `systemd-homed`, so the warning is
the one to read before shipping a can to such a host.

`cannery prune CAN LOG...` keeps every path a logged syscall touched,
the entries of any directory a program listed, the symlink chains that
reach kept files, the libraries kept programs need, the placeholders
and the identity files, and removes every other file and symlink;
directories stay, so `ls` and ownership do not change. It refuses a
log that names no program in the can. Afterwards a failed open in a
new log names what pruning removed, so the cycle is prune, run the
whole workload, add back from an unpruned copy. The suite runs on cans
pruned this way.

## What bites first

The proposal's section 13 lists every limitation. These are the ones a
first user meets, with the rule behind each and what to do:

- **Host tools are not found by name.** `PATH` inside a can is
  `/usr/local/bin:/usr/bin:/bin`, the can's. A host program runs inside
  by path, or through `.can/opener`, and only if the libraries it
  needs are in the can. A symlink in the can's own `/usr/local/bin`
  puts a name on `PATH`.
- **The tree is read-only.** A write anywhere the can owns is `EROFS`,
  as under a read-only mount, so a build that installs into `/usr` or
  `/usr/local` inside fails; install with `DESTDIR` or a prefix on the
  host. Outputs go to host paths: the working directory and its
  subdirectories, `/tmp`, `/home`, anything the tree does not ship.
  A working directory under a can-owned path is claimed for the host
  as a subtree, so `-o build/x.o` works from anywhere.
- **One libc per can.** A tree that mixes two, or that would load a
  host library, is refused by `wrap` with the file named. A second
  libc's world can ride along as a `data` prefix that is never
  executed, which is what a sysroot is.
- **Eight host files are the host's:** `/etc/passwd`, `/etc/group`,
  `/etc/nsswitch.conf`, `/etc/host.conf`, `/etc/resolv.conf`,
  `/etc/hosts`, `/etc/ssl/certs/ca-certificates.crt` and
  `/etc/pki/tls/certs/ca-bundle.crt`, read from the host where they
  exist and from the can's copy where not. `own` in the manifest takes
  one back. Everything else under `/etc` is the can's.
- **The locale, the time zone and the shell are the can's.** At the
  boundary `LANG=C.UTF-8`, `TZ=UTC0` and `SHELL=/bin/sh` replace the
  user's, `LANGUAGE` and every `LC_*` are dropped with them, and the
  variables that steer a loader or libc to host files
  (`LD_*`, `GCONV_PATH`, `LOCPATH` and the like) are dropped; every
  other variable passes through, and inside the can nothing is
  touched but the opener's own variables (below). `date` prints UTC, messages are English. A can that wants
  otherwise ships the data and a wrapper script that sets the variable.
- **From the host, every executable in a can is the opener.** `ldd`,
  `file` and `debsums` see the same small static binary at every
  wrapper path; the originals are beside them in `.real/`, byte for
  byte upstream's. `du` and `tar` differ by the opener's size times
  the wrappers, and a copy that breaks hard links (`cp -r`, `git`,
  `zip`) still works, each wrapper then being a copy of the opener.
  `/proc/<pid>/exe` of a built output or a host program run inside
  names `.can/opener` from outside, and a wrapped program's names its
  own path; from inside both are right.
- **Nothing elevates.** seccomp needs `no_new_privs`, which also
  disables setuid, file capabilities and AppArmor transitions on exec:
  `sudo`, `su`, `ping` and setcap binaries fail inside a can, from
  build scripts too.
- **Programs that need their own kernel features are refused:**
  `io_uring`, `clone3` extensions and a seccomp filter of their own,
  which rules out container runtimes, browsers and `rr` inside a can.
  `strace` works but shows a `SIGSYS` for every translated call.
- **A `noexec` filesystem** cannot hold a can: the kernel refuses to
  execute or map anything there, and a `noexec /tmp` in CI is the
  common case.
- **Compiler-identity caches** see every canned compiler as the same
  binary at the same mtime; ccache needs `compiler_check = %compiler% -v`.
- **Overhead** is per trapped syscall: about 9x on a tight `stat`
  loop, within noise on a compute-bound compile, about half again on
  thirty small compiles, where process start dominates. Section 16
  has the measurements.
- **A running program on a host path is not protected from another
  process's writes**, since the kernel executes the opener, not the
  file: natively `gcc -o prog` over a running `prog` fails, in a can
  it does not.
- **Not a sandbox.** The translation is bypassable by a program that
  wants to; it isolates software from the host's files, not the host
  from the software.

## The tests

```
test/inputs.sh ~/.cache/cont-inputs   # the development inputs from the network: the four cans of the gate, the examples' inputs; skips what is present
CONT_CACHE=~/.cache/cont-debs test/gate.sh ~/.cache/cont-inputs/*.can   # the commit gate, about a minute: unit tests, stack budget, the suite on every can in two orders and once under the plain terminal's label, the oracles, the syscall probe, the Docker profile; CONT_CACHE adds dogfood
test/run.py --can gcc.can                 # the suite alone; --tree DIR for a plain tree (spike/make-tree.sh makes one); -k NAME, --order random
test/matrix.py --can gcc.can              # the kernel matrix: cloud images under QEMU/KVM, one VM at a time, about ten minutes
test/exercise.py --can gcc.can test/progs/fexec.c HOSTDIR   # one program under bwrap, where the kernel answers, and under the opener, side by side
test/examples.sh gcc.can                  # the example runs, each when its input is set: CONT_SRC (realsoft), CONT_SQLITE (bench), CONT_RPMS (sysroot), CONT_DEBS_ARM64 (the emulated aarch64 row)
test/sysroot.py --can gcc.can --rpms el7/ --out hello     # the sysroot recipe as a test: symbol versions checked, the output run inside and out, then natively by the matrix
test/dogfood.py --cache DIR               # the cannery as a can, and a cross-can build that must reproduce
```

## Read in this order

1. `docs/PROPOSAL.md`: the design, self-contained. Sections 6 to 8 are
   the specification; 10 the cannery; 17 the tests; 18 the milestones;
   19 the decisions.
2. `src/`: the opener, one module per section of the proposal (below).
3. `docs/REVIEW-RESPONSE.md`: every review finding and where it landed.
4. `docs/PRIOR-ART.md`: the related systems and the primary sources
   for the kernel and loader facts relied on. `docs/reviews/`: the
   review reports; round 3 reviewed the code and is the best reading on
   where the implementation is subtle.
5. `docs/PERFORMANCE.md`: where a can's overhead goes, measured, what
   was done about it and what was deliberately left alone.
6. `spike/README.md`: the prototypes that preceded the opener, frozen.

## Layout

```
example.sh       the first run: from make to a program built inside a can that runs on any glibc since 2.17, every command shown
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
test/run.py          the regression suite; test/progs/ its C, Rust and Go programs
test/oracle_ns.py    the namespace oracle (bwrap); test/oracle_resolve.py the openat2 oracle
test/oracle_syscalls.py  the differential syscall probe: every trapped path and descriptor syscall with every path form under bwrap and under the opener; test/progs/probe.c its interpreter
test/inputs.sh       the development inputs, remade from the network through ~/.cache
test/exercise.py     one program run under bwrap and under the opener, the answers side by side: how a limitation is measured before it is fixed
test/docker_profile.py   a can under Docker's default seccomp profile; test/docker-seccomp.json the profile
test/syscalls.py     every kernel syscall classified; test/bench.py the performance table
test/realsoft.py     real projects built inside and outside a can; test/matrix.py the kernel matrix in VMs
test/dogfood.py      the cannery can building a can that must reproduce the host-built lockfile
test/gate.sh         the commit gate, every step in parallel on copies of the cans given; test/examples.sh the example runs
test/tree.py         what a tree says about itself: its compiler, its shell, where a tool lives, its libc; the suite and the oracles ask it
test/manifest_test.c grammar tests; test/grammar_test.py the grammar properties; test/filter_test.c the filter against its rule; test/stackcheck.py the stack budget
docs/            proposal (revision 17), review response, prior art, performance, review reports
spike/           frozen prototypes and their tests
```

## Names

`cont` is the codename and repository. `can` is the format and the
directory suffix. `opener` is the launcher. `cannery` is the build tool.
The environment knob is `CAN_LOG`, the only one. `CAN_EXEC`, `CAN_EXECFN`
and `CAN_COMM` are the opener's own protocol: set by an opener when it
execs a wrapper or re-execs itself for a program on the loader path,
the target and the identity the kernel would give it, removed before
any program runs, never an interface; `.can/opener PROGRAM ARGS...` is
how a program without a wrapper is run from outside. At the can boundary four variables are the can's, always the
same: `PATH=/usr/local/bin:/usr/bin:/bin`, `LANG=C.UTF-8`, `TZ=UTC0`
and `SHELL=/bin/sh`; `LANGUAGE`, every `LC_*` and the loader and libc
variables are dropped;
everything else passes through, and inside the boundary nothing else is
touched.
