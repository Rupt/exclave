# exclave

`exclave` turns environment-dependent Linux software, compilers first, into
a directory that behaves like a single static executable: copy it
anywhere, run any program inside it by path, and it never touches a host
library, header, loader or configuration file. No daemon, no image store,
no privileges, no host binaries, no run-time options.

An **exclave** is that directory: an unmodified filesystem tree plus
one static, freestanding binary, the **launcher**, which every
executable in the tree is a hard link to. The launcher projects the tree
onto `/` with a seccomp filter and a resident `SIGSYS` handler that
rewrites every path-taking syscall inside the process, and loads the
original program and the exclave's own `ld.so` itself. The **`exclave`
command** builds exclaves from files: package files it is handed, or
any filesystem tree, and is itself an exclave.

## Status

Milestones 1a to 3 are built. The `exclave` command takes files and
never fetches, the hashes file records inputs and output by hash and
locates nothing, the launcher reads the manifest and the tree and
nothing generated, and an exclave is a directory at every stage. A gcc
exclave from Ubuntu or Debian packages builds zlib, Lua, SQLite and re2c
from source with their configure scripts, at native speed for the
compiles and about a third more for the configure scripts; an Alpine
exclave from `.apk` files and a Fedora exclave from `.rpm` files compile
and run C inside; a clang exclave compiles C and C++; a CentOS 7 glibc
as a data directory in the gcc exclave gives outputs that run on every
glibc since 2.17, which the kernel matrix checks natively on each VM;
the launcher builds for aarch64 from the same sources and the matrix has
an emulated arm64 row. gdb debugs a program in an exclave once the
exclave is in its auto-load safe-path: the launcher carries the script
gdb needs. The regression suite (74 named tests), the kernel oracles, a
differential syscall probe that agrees with the kernel on 19 093 cases
per exclave, and Docker's default seccomp profile pass on the gcc,
Alpine, Fedora and clang exclaves, each pruned to what the suite
touches, in one gate of about a minute on the reference machine, where
the plain-terminal AppArmor label passes too, and the kernel matrix in
QEMU virtual machines passes on nine distributions from CentOS 7 at
kernel 3.10 to Fedora 42, Alpine's musl userland and SELinux included.
The tool ships as an exclave, and the gcc exclave it builds from inside
its exclave reproduces the host-built hashes file byte for byte. Trace
pruning keeps 122 of a gcc exclave's 4 851 files for a hello-world
compile. `example.sh` walks the path from a clean checkout to a program
built inside an exclave that runs on any glibc since 2.17, in nine
seconds once the packages are cached. Section 18 of the proposal has the
milestone table; 16 the measurements; 12 the matrix and the Alpine
exclave; `docs/REVIEW-RESPONSE.md` every review finding.

## First run

You need an x86-64 Linux host with `gcc`, `make` and `python3` (3.6 or
later), and the network for one package fetch. No root, no container
runtime, no user namespaces: nothing here needs a privilege.

```bash
make
./example.sh ~/exclave-example
```

`example.sh` runs the whole path under the directory you name and
prints each command as it runs, or for the long ones a line of summary
with the command and its output in a log under `log/`, so its output
and logs are the tutorial and each command is one you can run by hand:

1. `make` builds `build/launcher`, the freestanding binary every
   executable in an exclave is a hard link to.
2. `tools/fetch-debs.py` downloads Ubuntu 24.04's `gcc-13` closure, 94
   packages, and `exclave unpack` makes an unwrapped exclave from the
   files: the tree under `gcc.exclave/tree/`, the maintainer scripts'
   effects synthesised, every input recorded by hash in
   `gcc.exclave/.exclave/hashes`.
3. `tools/fetch-rpms.py` downloads CentOS 7's glibc, headers and
   `libgcc`; unpacked into an exclave of their own, the tree is copied
   into the gcc exclave at `/opt/sysroot-el7`, and a two-line manifest
   says `data "/opt/sysroot-el7"`: nothing there is wrapped, checked or
   executed. `exclave wrap` wraps the exclave, and a shortcut, the
   symlink `gcc.exclave/gcc`, names its compiler.
4. `hello.c` is compiled inside the exclave twice, plainly and with
   `--sysroot=/opt/sysroot-el7 -B/opt/sysroot-el7/usr/lib64/`, each
   with `EXCLAVE_LOG` on. `objdump` shows what each output binds: the plain
   one `GLIBC_2.34`, so it needs a glibc at least that new wherever it
   runs; the sysroot one `GLIBC_2.2.5` alone, so it runs on any glibc
   from 2.17 on, the oldest the kernel matrix has, which runs this same
   build natively on CentOS 7. It runs on this host and, through
   `.exclave/launcher`, inside the exclave on the exclave's loader.
5. `exclave prune` keeps, in a copy, the 136 files that compile touched
   out of 9 567; the copy compiles the program again, and
   `exclave check` reads the new log: that copy is the exclave you would
   ship for that workload, and the check is the one you would run on
   it.

What it prints on the reference machine, abridged:

```
== 3. CentOS 7's glibc as a sysroot inside it
+ cp -a sysroot.exclave/tree gcc.exclave/tree/opt/sysroot-el7
  gcc.exclave is wrapped (46 warnings; log/wrap.log)
== 4. a program built inside, run on this host and inside the exclave
+ env EXCLAVE_LOG=log/hello.log gcc.exclave/gcc --sysroot=/opt/sysroot-el7 -B/opt/sysroot-el7/usr/lib64/ -o hello hello.c
  log/hello.log: 1220 lines, one per trapped syscall; the first:
    launcher 0 host path absent, using the exclave's /etc/pki/tls/certs/ca-bundle.crt
    launcher 0 cwd /home/me/exclave/build/example
    launcher 0 border /usr/bin/x86_64-linux-gnu-gcc-13
    load 0 /usr/bin/x86_64-linux-gnu-gcc-13
    access -2 /etc/ld.so.preload
    open 3 /etc/ld.so.cache
  glibc symbol versions bound: hello-plain: GLIBC_2.2.5 GLIBC_2.34  hello: GLIBC_2.2.5
+ ./hello
hello from an exclave
+ gcc.exclave/.exclave/launcher /home/me/exclave/build/example/hello
hello from an exclave
== 5. the exclave pruned to what the compile touched, and the checks on it
+ exclave prune hello.exclave log/hello.log
pruned hello.exclave: kept 136 files, removed 9431, 360514915 bytes freed
static check: 24 ELF files, 2 static executables, 0 warnings, 0 errors
+ exclave check hello.exclave log/pruned.log
0 wrapper problems
static check: 24 ELF files, 2 static executables, 0 warnings, 0 errors
warning: this host's nsswitch.conf names sss; the exclave has no libnss_sss.so.2
dynamic check: 1220 log lines, 0 errors
```

The 46 warnings of `wrap` are dangling symlinks: 45 are `coreutils`'
locale links, which point at translations Ubuntu moves into language
packs the package does not ship, and one is a man-page link to a page
no package in the set ships. The warning says the tree has a link to
nothing, which is true and harmless; an error would have stopped
`wrap`. Afterwards the directory holds `gcc.exclave`, a compiler
that touches nothing on the host, 264 MB with the sysroot; `hello`;
`hello.exclave`, the pruned copy, 50 MB; the fetched packages, which a
second run reuses; and `log/`, one file per step. A second run takes
nine seconds on the reference machine; the first also fetches 121 MB:
the 94 packages and 23 rpms, and the indexes that resolve them.

## Making your own exclave

The `exclave` command takes files and never fetches. Whatever puts
package files in a directory is the step before it: apt, a mirror, the
three fetchers here. `unpack` reads each package's own control archive,
reports dependencies the set does not satisfy, extracts in Python,
synthesises what maintainer scripts would have done (alternatives,
`ld.so.cache` with the exclave's own `ldconfig`, the CA bundle,
`/etc/passwd`), adds the placeholders and records every input by hash in
the hashes file. The result is a directory. `wrap` wraps every
executable, runs the static check and records the manifest and tree
hashes; `unwrap` moves the originals back; a bare directory holding a
`tree/` becomes an exclave by `wrap` alone. Every exclave has a `README`
at its top for whoever finds it without this repository: what it is, how
to run its programs, what it touches and how to check it. The tool
writes it where the exclave has none, so a maker's own stays.

```
tools/fetch-debs.py --out debs gcc-13 libc6-dev make         # Ubuntu or Debian: the closure of the packages named, verified against the index
tools/fetch-apks.py --out apks gcc musl-dev binutils         # the same for Alpine
tools/fetch-rpms.py --repo URL --out rpms gcc glibc-devel    # and for Fedora, Rocky, CentOS: any repository with repodata/
exclave/exclave.py unpack gcc.exclave debs/*.deb             # package files -> an unwrapped exclave, a directory you may edit; .apk and .rpm files likewise
exclave/exclave.py wrap gcc.exclave                          # wrap every executable, static check, hashes into .exclave/hashes
ln -s tree/usr/bin/gcc-13 gcc.exclave/gcc                    # a shortcut, if you want one
gcc.exclave/gcc -O2 hello.c -o hello                         # any executable in tree/ runs by path
gcc.exclave/tree/usr/bin/sh -c 'as --version'                # the exclave's own shell, with the exclave's PATH
gcc.exclave/.exclave/launcher /path/to/host/program args...  # a program without a wrapper, a host tool or a built output, inside the exclave
gdb -iex 'set auto-load safe-path /' --args gcc.exclave/gcc -c x.c   # gdb: the launcher carries the script; break, bt, source lines
EXCLAVE_LOG=/tmp/exclave.log gcc.exclave/gcc -c x.c          # the one knob: one line per trapped syscall
exclave/exclave.py check gcc.exclave /tmp/exclave.log        # static check of every ELF, dynamic check of the logged run
exclave/exclave.py prune gcc.exclave /tmp/exclave.log        # keep what the logged runs touched
exclave/exclave.py unwrap gcc.exclave                        # the originals back over their wrappers, to edit; wrap again after
exclave/exclave.py relink gcc.exclave build/launcher         # swap the launcher after rebuilding it; the wrappers are relinked
exclave/exclave.py hash gcc.exclave                          # the tree hash the hashes file records
exclave/exclave.py format gcc.exclave/.exclave/manifest      # the canonical spelling of a manifest or hashes file; --check only reports
```

Between `unpack` and `wrap` the unwrapped exclave is yours: copy a
built prefix in, delete what you do not want, add a data directory,
write the manifest. The manifest is `gcc.exclave/.exclave/manifest`,
`exclave 1` when nothing is overridden, and has four other keys, each
a string: `cpu` names the level the binaries need (`"x86-64-v3"`;
x86-64 when absent); `data` names a directory that is never executed
or loaded, not wrapped, not checked, a sysroot or a second libc's
world; `host` puts a host path
at its own name inside the exclave, `host "/usr/local/share/fonts"`;
`own` makes a path the exclave's, which removes one of the eight host
identity files below. That is the whole manifest. There is no way to
make the tree writable, remap a path, set a variable or put a directory
on `PATH`: a wrapper script inside the exclave sets variables, a
symlink in the tree does remapping, and a symlink in the exclave's own
`/usr/local/bin` puts a program on `PATH`.

An exclave of something you built is the same four lines, with the
build system's own installer doing the building:

```
gcc.exclave/tree/usr/bin/sh -c './configure --prefix=/usr/local && make && make install DESTDIR=$PWD/stage'
exclave/exclave.py unpack tool.exclave runtime/*.deb         # libc6 and whatever else the result links against
cp -a stage/usr/local tool.exclave/tree/usr/
exclave/exclave.py wrap tool.exclave                         # the static check says whether it all links inside
```

No recipe format and no closure copying: the runtime the result needs
is packages you already have, and the static check verifies that every
library resolves inside the exclave.

## A can from before revision 18

Until revision 18 an exclave was a can: `.can/` for `.exclave/`,
`root/` for `tree/`, `opener` and `lock` for `launcher` and `hashes`.
A can still runs as it is, from anywhere, and runs an exclave's
programs as an exclave runs its own. The `exclave` command refuses one
by name; converting it is renames, two edits and three commands,
`exclave/exclave.py` standing for the command:

```
cd OLD.can && mv .can .exclave && mv root tree && mv .exclave/opener .exclave/launcher && mv .exclave/lock .exclave/hashes
sed -i -e 's/^can 1$/exclave 1/' -e 's/^isa /cpu /' .exclave/manifest
sed -i -e 's/^lock 1$/hashes 1/' -e 's/^cannery /tool /' -e 's/^opener /launcher /' .exclave/hashes
cd .. && mv OLD.can OLD.exclave                               # the suffix is a convention; any name works
exclave/exclave.py relink OLD.exclave build/launcher          # the current launcher behind every wrapper
exclave/exclave.py unwrap OLD.exclave && exclave/exclave.py wrap OLD.exclave   # the manifest's hash, recorded again
```

Measured on a gcc can of revision 17's inputs: the converted exclave's
hashes file equals the one a fresh `unpack` and `wrap` of the same
packages writes, apart from the launcher's hash. A launcher from before
the syscall page moved (revision 15 or earlier) refuses to run under
this one and points at this README.

## The log and the checks

`EXCLAVE_LOG=<file>` is the launcher's one knob. It appends one line per
trapped syscall, `<syscall> <result> <virtual path>`, the result being
the return value or the negative errno: `open 3 /etc/ld.so.cache` is
descriptor 3, `access -2 /etc/ld.so.preload` is `ENOENT`, which is what
a search looks like and is not a fault. Lines that begin `launcher`
are the launcher's own decisions: the working directory it started in
and, when that lies under an exclave path, the subtree it gave the
host; the border program; an identity file the host lacks, answered
from the exclave's copy. Every process a workload spawns appends to the
same file, so a `make` writes one log. A newline in a path is written
`\n` and a backslash `\\`; nothing else is escaped.

`exclave check EXCLAVE [LOG...]` first verifies the wrappers and their
originals and compares the tree with the hash the hashes file records,
then runs the static check on every ELF file outside data
directories: every loader and every `DT_NEEDED` resolves inside the tree
by the loader's own search, to one libc, and nothing would resolve on
the host. Errors name the file and stop `wrap`; warnings are things
worth knowing that do not: a dangling symlink, a 32-bit or
foreign-machine object a package ships beside the real ones; static
executables are counted, having no loader to verify.
With logs it adds the dynamic check: every library the workload opened
resolved inside the exclave, and every NSS module this host's
`nsswitch.conf` names that the exclave lacks is a warning. glibc skips a
missing module, which is right for `hosts` and wrong for `passwd` on a
host whose users come from LDAP or `systemd-homed`, so the warning is
the one to read before shipping an exclave to such a host.

`exclave prune EXCLAVE LOG...` keeps every path a logged syscall touched,
the entries of any directory a program listed, the symlink chains that
reach kept files, the libraries kept programs need, the placeholders
and the identity files, and removes every other file and symlink;
directories stay, so `ls` and ownership do not change. It refuses a
log that names no program in the exclave. Afterwards a failed open in a
new log names what pruning removed, so the cycle is prune, run the
whole workload, add back from an unpruned copy. The suite runs on
exclaves pruned this way.

## What bites first

The proposal's section 13 lists every limitation. These are the ones a
first user meets, with the rule behind each and what to do:

- **Host tools are not found by name.** `PATH` inside an exclave is
  `/usr/local/bin:/usr/bin:/bin`, the exclave's. A host program runs
  inside by path, or through `.exclave/launcher`, and only if the
  libraries it needs are in the exclave. A symlink in the exclave's own
  `/usr/local/bin` puts a name on `PATH`.
- **The tree is read-only.** A write to an exclave path is `EROFS`,
  as under a read-only mount, so a build that installs into `/usr` or
  `/usr/local` inside fails; install with `DESTDIR` or a prefix on the
  host. Outputs go to host paths: the working directory and its
  subdirectories, `/tmp`, `/home`, anything the tree does not ship.
  A working directory under an exclave path is given to the host as a
  subtree, so `-o build/x.o` works from anywhere.
- **One libc per exclave.** A tree that mixes two, or that would load a
  host library, is refused by `wrap` with the file named. A second
  libc's world can ride along as a `data` directory that is never
  executed, which is what a sysroot is.
- **Eight host files are the host's:** `/etc/passwd`, `/etc/group`,
  `/etc/nsswitch.conf`, `/etc/host.conf`, `/etc/resolv.conf`,
  `/etc/hosts`, `/etc/ssl/certs/ca-certificates.crt` and
  `/etc/pki/tls/certs/ca-bundle.crt`, read from the host where they
  exist and from the exclave's copy where not. `own` in the manifest
  takes one back. Everything else under `/etc` is the exclave's.
- **The locale, the time zone and the shell are the exclave's.** At the
  border `LANG=C.UTF-8`, `TZ=UTC0` and `SHELL=/bin/sh` replace the
  user's, `LANGUAGE` and every `LC_*` are dropped with them, and the
  variables that steer a loader or libc to host files
  (`LD_*`, `GCONV_PATH`, `LOCPATH` and the like) are dropped; every
  other variable passes through, and inside the exclave nothing is
  touched but the launcher's own variables (below). `date` prints UTC,
  messages are English. An exclave that wants otherwise ships the data
  and a wrapper script that sets the variable.
- **From the host, every executable in an exclave is the launcher.**
  `ldd`, `file` and `debsums` see the same small static binary at every
  wrapper path; the originals are beside them in `.real/`, byte for
  byte upstream's. `du` and `tar` differ by the launcher's size times
  the wrappers, and a copy that breaks hard links (`cp -r`, `git`,
  `zip`) still works, each wrapper then being a copy of the launcher.
  `/proc/<pid>/exe` of a built output or a host program run inside
  names `.exclave/launcher` from outside, and a wrapped program's names
  its own path; from inside both are right.
- **Nothing elevates.** seccomp needs `no_new_privs`, which also
  disables setuid, file capabilities and AppArmor transitions on exec:
  `sudo`, `su`, `ping` and setcap binaries fail inside an exclave, from
  build scripts too.
- **Programs that need their own kernel features are refused:**
  `io_uring`, `clone3` extensions and a seccomp filter of their own,
  which rules out container runtimes, browsers and `rr` inside an exclave.
  `strace` works but shows a `SIGSYS` for every translated call.
- **A `noexec` filesystem** cannot hold an exclave: the kernel refuses to
  execute or map anything there, and a `noexec /tmp` in CI is the
  common case.
- **Compiler-identity caches** see every compiler in an exclave as the same
  binary at the same mtime; ccache needs `compiler_check = %compiler% -v`.
- **Overhead** is per trapped syscall: about 9x on a tight `stat`
  loop, within noise on a compute-bound compile, about half again on
  thirty small compiles, where process start dominates. Section 16
  has the measurements.
- **A running program on a host path is not protected from another
  process's writes**, since the kernel executes the launcher, not the
  file: natively `gcc -o prog` over a running `prog` fails, in an
  exclave it does not.
- **Not a sandbox.** The translation is bypassable by a program that
  wants to; it isolates software from the host's files, not the host
  from the software.

## The tests

```
test/inputs.sh ~/.cache/exclave-inputs   # the development inputs from the network: the four exclaves of the gate, the examples' inputs; skips what is present
EXCLAVE_TEST_CACHE=~/.cache/exclave-debs test/gate.sh ~/.cache/exclave-inputs/*.exclave   # the commit gate, about a minute: unit tests, stack budget, the suite on every exclave in two orders and once under the plain terminal's label, the oracles, the syscall probe, the Docker profile; EXCLAVE_TEST_CACHE adds dogfood
test/run.py --exclave gcc.exclave     # the suite alone; --tree DIR for a plain tree (spike/make-tree.sh makes one); -k NAME, --order random
test/matrix.py --exclave gcc.exclave  # the kernel matrix: cloud images under QEMU/KVM, one VM at a time, about ten minutes
test/exercise.py --exclave gcc.exclave test/progs/fexec.c HOSTDIR   # one program under bwrap, where the kernel answers, and under the launcher, side by side
test/examples.sh gcc.exclave          # the example runs, each when its input is set: EXCLAVE_TEST_SRC (realsoft), EXCLAVE_TEST_SQLITE (bench), EXCLAVE_TEST_RPMS (sysroot), EXCLAVE_TEST_DEBS_ARM64 (the emulated aarch64 row)
test/sysroot.py --exclave gcc.exclave --rpms el7/ --out hello   # the sysroot recipe as a test: symbol versions checked, the output run inside and out, then natively by the matrix
test/dogfood.py --cache DIR           # the tool as an exclave, and a cross-exclave build that must reproduce
```

## Read in this order

1. `docs/PROPOSAL.md`: the design, self-contained. Sections 6 to 8 are
   the specification; 10 the `exclave` command; 17 the tests; 18 the
   milestones; 19 the decisions.
2. `src/`: the launcher, one module per section of the proposal (below).
3. `docs/REVIEW-RESPONSE.md`: every review finding and where it landed.
4. `docs/PRIOR-ART.md`: the related systems and the primary sources
   for the kernel and loader facts relied on. `docs/reviews/`: the
   review reports; round 3 reviewed the code and is the best reading on
   where the implementation is subtle.
5. `docs/PERFORMANCE.md`: where an exclave's overhead goes, measured, what
   was done about it and what was deliberately left alone.
6. `spike/README.md`: the prototypes that preceded the launcher, frozen.

## Layout

```
example.sh       the first run: from make to a program built inside an exclave that runs on any glibc since 2.17, every command shown
src/sys.h        syscall numbers and instruction per architecture, the syscall page, raw wrappers, a tiny libc subset
src/common.h     constants, the run-time state (struct exclave), every module's interface
src/launcher.c   entry: syscall page, self-relocation, find the exclave, manifest, border, env, load
src/manifest.c   the strict grammar parser (6.2); also built for the host by the gate's unit step
src/loader.c     userland ELF loader and the probe for a launcher's notes (7.3); the facts exported for gdb (7.6)
src/gdb.py       the script the launcher carries in .debug_gdb_scripts and gdb auto-loads (7.6, 13.1)
src/filter.c     the seccomp program (7.4.2)
src/handler.c    the SIGSYS handler: translation, read-only rule, exec, signal masks (7.4.3, 7.5, 8.2)
src/canon.c      canonicalisation in virtual space (7.4.4)
src/cache.c      the per-process component cache (7.4.4)
src/vis.c        the visibility rule, ownership read from the tree, identity files, wrapper redirect (8)
src/scratch.c    handler memory: mmap'd chunks with liveness reclamation (7.5.4)
src/isa.c        the CPU check (7.7): x86-64 psABI levels by cpuid, aarch64 levels by AT_HWCAP
src/str.c        string helpers, arena, the shebang parser
src/log.c        EXCLAVE_LOG and fatal messages
exclave/exclave.py   the command line: grammar, unpack, wrap, unwrap, check, prune, format, hash, relink
exclave/deb.py       ar, tar, compression, control stanzas, dependency fields, Debian version order
exclave/apk.py       the Alpine reader with deb.py's interface: gzip streams, .PKGINFO, apk's dependency and version syntax
exclave/rpm.py       the rpm reader with the same interface: lead and headers, the cpio payload, rpm's flags and version order
exclave/build.py     extraction rules, synthesis, placeholders, dependency report, pruning, tree hash, hashes file, unwrap
exclave/elfcheck.py  the static and dynamic checks of 10.3
tools/fetch-debs.py  an example of the step before the tool: resolve a closure from an archive and download it
tools/fetch-apks.py  the same for an Alpine repository, verified as apk verifies
tools/fetch-rpms.py  the same for a yum or dnf repository, verified by the index's SHA-256
test/sysroot.py      a glibc sysroot as a data directory and an output built against it, for the matrix to run natively
test/run.py          the regression suite; test/progs/ its C, Rust and Go programs
test/oracle_ns.py    the namespace oracle (bwrap); test/oracle_resolve.py the openat2 oracle
test/oracle_syscalls.py  the differential syscall probe: every trapped path and descriptor syscall with every path form under bwrap and under the launcher; test/progs/probe.c its interpreter
test/inputs.sh       the development inputs, remade from the network through ~/.cache
test/exercise.py     one program run under bwrap and under the launcher, the answers side by side: how a limitation is measured before it is fixed
test/docker_profile.py   an exclave under Docker's default seccomp profile; test/docker-seccomp.json the profile
test/syscalls.py     every kernel syscall classified; test/bench.py the performance table
test/realsoft.py     real projects built inside and outside an exclave; test/matrix.py the kernel matrix in VMs
test/dogfood.py      the tool's exclave building an exclave that must reproduce the host-built hashes file
test/gate.sh         the commit gate, every step in parallel on copies of the exclaves given; test/examples.sh the example runs
test/tree.py         what a tree says about itself: its compiler, its shell, where a tool lives, its libc; the suite and the oracles ask it
test/manifest_test.c grammar tests; test/grammar_test.py the grammar properties; test/filter_test.c the filter against its rule; test/stackcheck.py the stack budget
docs/            proposal (revision 18), review response, prior art, performance, review reports
spike/           frozen prototypes and their tests
```

## Names

`exclave` is the project, its repository, the build command and the
format: a directory `name.exclave/`, whose own files are in
`name.exclave/.exclave/`. The **launcher** is `.exclave/launcher`, the
binary every wrapper is a hard link to; the **tree** is
`name.exclave/tree/`, what the software sees as `/`; **hashes** is
`.exclave/hashes`, every input, the launcher, the manifest and the tree
by hash; a **shortcut** is a symlink a maker puts at the top of an
exclave, pointing at a wrapper. The environment knob is `EXCLAVE_LOG`,
the only one. `EXCLAVE_EXEC`, `EXCLAVE_EXECFN` and `EXCLAVE_COMM` are
the launcher's own protocol: set by a launcher when it execs a wrapper
or re-execs itself for a program on the loader path, the target and the
identity the kernel would give it, removed from the environment a
program is given (the kernel's copy in `/proc/<pid>/environ` keeps
them), never an interface; `.exclave/launcher PROGRAM ARGS...` is how a
program without a wrapper is run from outside. At the border four
variables are the exclave's, always the same:
`PATH=/usr/local/bin:/usr/bin:/bin`, `LANG=C.UTF-8`, `TZ=UTC0` and
`SHELL=/bin/sh`; `LANGUAGE`, every `LC_*` and the loader and libc
variables are dropped; everything else passes through, and inside the
border nothing else is touched. Until revision 18 the project was
`cont`, the format a can, the launcher the opener and the tool the
cannery; section 5 of `docs/PROPOSAL.md` lists every earlier name
beside its new one.
