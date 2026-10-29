# exclave

`exclave` turns environment-dependent Linux software, compilers first, into
a directory that behaves like a single static executable: copy it
anywhere, run any program inside it by path, and it never touches a host
library, header or loader, and reads no host configuration but eight
identity files: who the users are, how names resolve, which certificate
authorities are trusted. No daemon, no image store, no privileges, no
host binaries, and one run-time knob, `EXCLAVE_LOG`, which only logs.

An **exclave** is that directory: an unmodified filesystem tree plus
one static, freestanding binary, the **launcher**, which every
executable in the tree is a hard link to. The launcher projects the tree
onto `/` with a seccomp filter and a resident `SIGSYS` handler that
rewrites every path-taking syscall inside the process, and loads the
original program and the exclave's own `ld.so` itself. The **`exclave`
command** builds exclaves from files: package files it is handed, or
any filesystem tree.

> **Experimental.** exclave works and is tested widely (below), but it
> has no release yet. The format is versioned (`exclave 1`, `hashes
> 1`), a build is named by the project's version and its commit
> (`exclave version`; the launcher and the hashes file carry the same
> name), and nothing else promises compatibility between commits.

## What works

- **Packages in, a directory out.** The `exclave` command builds
  exclaves from Debian and Ubuntu `.deb`, Alpine `.apk` and Fedora,
  Rocky or CentOS `.rpm` files, or from any filesystem tree. It takes
  files and never fetches; three small fetchers in `fetch/` are the
  step before it.
- **Compilers first.** A gcc exclave builds zlib, Lua, SQLite and re2c
  from source with their configure scripts: the builds within a fifth
  of native time, the configure scripts about a third slower. A clang
  exclave compiles C and C++; Alpine and Fedora exclaves compile and run
  C. A CentOS 7 glibc as a data directory gives outputs that run on
  every glibc since 2.17.
- **Where it runs.** x86-64 and aarch64 Linux, kernel 3.10 or later as
  tested, glibc or musl software inside, 4 KB pages (larger pages are
  untested). One source builds both launchers.
- **gdb** debugs a program in an exclave: the launcher carries the
  script gdb needs.
- **Tested against the kernel.** A suite of 78 named tests, oracles that
  compare the launcher's answers with the kernel's under a read-only
  bind mount, and a differential probe of 21 732 syscall cases pass on
  gcc, clang, Alpine and Fedora exclaves. An exclave also runs under
  Docker's default seccomp profile, and the gcc exclave passes the suite
  in virtual machines from CentOS 7 at kernel 3.10 to Fedora 42 and an
  emulated arm64 Ubuntu.

Figures here and in `docs/DESIGN.md` are measured on the reference
machine: an AMD Ryzen AI 7 350 (8 cores, 16 threads), Ubuntu 24.04,
kernel 7.0, glibc 2.39.

## First run

You need an x86-64 or aarch64 Linux host with `gcc` and its static C
library (Ubuntu's `libc6-dev`), `curl` or `wget`, and the network: `scripts/install-uv` fetches a pinned,
checksummed [uv](https://docs.astral.sh/uv/) into `.uv/`, which provides
the pinned Python and everything else Python the project uses; the
example then downloads Ubuntu's gcc packages and CentOS 7's glibc, 121
MB in all. No root, no container runtime, no user namespaces: nothing
here needs a privilege, and nothing is installed outside the checkout.

```bash
scripts/install-uv
scripts/build
scripts/example ~/exclave-example
```

`scripts/example` runs the whole path under the directory you name and
prints each command as it runs, or for the long ones a line of summary
with the command and its output in a log under `log/`, so its output
and logs are the tutorial and each command is one you can run by hand:

1. `scripts/build` builds `build/launcher`, the freestanding binary every
   executable in an exclave is a hard link to.
2. `fetch/debs.py` downloads Ubuntu 24.04's `gcc-13` closure, 94
   packages, and `unpack` makes an unwrapped exclave from the
   files: the tree under `gcc.exclave/tree/`, the maintainer scripts'
   effects synthesised, every input recorded by hash in
   `gcc.exclave/.exclave/hashes`.
3. `fetch/rpms.py` downloads CentOS 7's glibc, headers and
   `libgcc`; unpacked into a tree of their own, the tree is copied
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
5. `exclave prune` keeps, in a copy, the files that compile touched
   and the packages' licence texts: 226 of the 9 564 files and links
   under `tree/`; the copy compiles the program again, and
   `exclave check` reads the new log: that copy is the exclave you would
   ship for that workload, and the check is the one you would run on
   it.

What it prints on the reference machine, abridged; `exclave` in it is
`scripts/example`'s shorthand for `scripts/exclave`:

```
== 3. CentOS 7's glibc as a sysroot inside it
+ mkdir -p gcc.exclave/tree/opt
+ cp -a sysroot.exclave/tree gcc.exclave/tree/opt/sysroot-el7
  gcc.exclave is wrapped (46 warnings; log/wrap.log)
== 4. a program built inside, run on this host and inside the exclave
+ env EXCLAVE_LOG=/home/me/exclave/build/example/log/hello.log gcc.exclave/gcc --sysroot=/opt/sysroot-el7 -B/opt/sysroot-el7/usr/lib64/ -o hello hello.c
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
pruned hello.exclave: kept 226 files, removed 9338, 359454788 bytes freed
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

## What bites first

Section 13 of `docs/DESIGN.md` lists every limitation. These are the ones a
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
- **Overhead** is per trapped syscall: 6 to 10 times native on a tight
  `stat` loop, about a third more on thirty small compiles, where
  process start dominates, and within noise on a compute-bound compile.
  Section 16 of `docs/DESIGN.md` has the measurements.
- **A running program on a host path is not protected from another
  process's writes**, since the kernel executes the launcher, not the
  file: natively `cp new prog` over a running `prog` fails with "Text
  file busy"; in an exclave it succeeds, and the running program may
  take `SIGBUS`. (Linkers unlink their output first, so relinking is
  safe either way.)
- **Not a sandbox.** The translation is bypassable by a program that
  wants to; it isolates software from the host's files, not the host
  from the software.

## Making your own exclave

The `exclave` command is `build/exclave`, one static file that carries
its launcher and runs with nothing beside it; `scripts/exclave` runs it
from the checkout. It takes a directory holding `tree/` and never
fetches. Whatever made the tree is the step before it, and for package
files that is `scripts/unpack`, a program of its own beside the three
fetchers here: it reads each package's own control archive, reports
dependencies the set does not satisfy, extracts in Python, synthesises
what maintainer scripts would have done (alternatives, `ld.so.cache`
with the exclave's own `ldconfig`, the CA bundle, `/etc/passwd`) and
records every input by hash in the hashes file. The result is a
directory; `ar` and `tar`, `debootstrap` or a container export make
others (DESIGN.md 10.1). `wrap` adds the launcher and the placeholders,
wraps every executable, runs the static check and records the manifest
and tree hashes; `unwrap` moves the originals back. Every exclave has a `README`
at its top for whoever finds it without this repository: what it is, how
to run its programs, what it touches and how to check it. The tool
writes it where the exclave has none, so a maker's own stays.

```
scripts/fetch-debs --keyring /usr/share/keyrings/ubuntu-archive-keyring.gpg --out debs gcc-13 libc6-dev make   # Ubuntu or Debian: the closure of the packages named, InRelease checked against the keyring, every file against the index
scripts/fetch-apks --key alpine-devel@lists.alpinelinux.org-6165ee59.rsa.pub --out apks gcc musl-dev binutils  # the same for Alpine: the index checked against the key its signature names (https://alpinelinux.org/keys/)
scripts/fetch-rpms --keyring RPM-GPG-KEY-fedora-42-primary --repo URL --out rpms gcc glibc-devel   # and for Fedora, Rocky, CentOS: any repository with repodata/; every rpm checked against the key, repomd.xml where signed
scripts/unpack gcc.exclave debs/*.deb                     # package files -> an unwrapped exclave, a directory you may edit; .apk and .rpm files likewise
scripts/exclave wrap gcc.exclave                          # wrap every executable, static check, hashes into .exclave/hashes
ln -s tree/usr/bin/gcc-13 gcc.exclave/gcc                    # a shortcut, if you want one
gcc.exclave/gcc -O2 hello.c -o hello                         # any executable in tree/ runs by path
gcc.exclave/tree/usr/bin/sh -c 'as --version'                # the exclave's own shell, with the exclave's PATH
gcc.exclave/.exclave/launcher /path/to/host/program args...  # a program without a wrapper, a host tool or a built output, inside the exclave
gdb -iex 'set auto-load safe-path /' --args gcc.exclave/gcc -c x.c   # gdb: the launcher carries the script; break, bt, source lines
EXCLAVE_LOG=/tmp/exclave.log gcc.exclave/gcc -c x.c          # the one knob: one line per trapped syscall
scripts/exclave check gcc.exclave /tmp/exclave.log        # static check of every ELF, dynamic check of the logged run
scripts/exclave prune gcc.exclave /tmp/exclave.log        # keep what the logged runs touched
scripts/exclave unwrap gcc.exclave                        # the originals back over their wrappers, to edit; wrap again after
scripts/exclave relink gcc.exclave build/launcher         # swap the launcher after rebuilding it; the wrappers are relinked
scripts/exclave hash gcc.exclave                          # the tree hash the hashes file records
scripts/exclave version                                   # the build this command is from, which the launcher and the hashes file name too
scripts/exclave format gcc.exclave/.exclave/manifest      # the canonical spelling of a manifest or hashes file; --check only reports
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
`own` makes a path the exclave's: one of the eight host identity files
below, or any other path the rule would give the host. That is the whole manifest. There is no way to
make the tree writable, remap a path, set a variable or put a directory
on `PATH`: a wrapper script inside the exclave sets variables, a
symlink in the tree does remapping, and a symlink in the exclave's own
`/usr/local/bin` puts a program on `PATH`.

An exclave of something you built is the same four lines, with the
build system's own installer doing the building:

```
gcc.exclave/tree/usr/bin/sh -c './configure --prefix=/usr/local && make && make install DESTDIR=$PWD/stage'
scripts/unpack tool.exclave runtime/*.deb                 # libc6 and whatever else the result links against
cp -a stage/usr/local tool.exclave/tree/usr/
scripts/exclave wrap tool.exclave                         # the static check says whether it all links inside
```

No recipe format and no closure copying: the runtime the result needs
is packages you already have, and the static check verifies that every
library resolves inside the exclave.

## The log and the checks

`EXCLAVE_LOG=<file>` is the launcher's one knob. The file is a host file
named by its absolute path, outside the exclave; a launcher refuses a
relative path or a log inside its exclave by name. It appends one line
per trapped syscall, `<syscall> <result> <virtual path>`, the result
being the return value or the negative errno: `open 3 /etc/ld.so.cache`
is descriptor 3, `access -2 /etc/ld.so.preload` is `ENOENT`, which is
what a search looks like and is not a fault. Lines that begin `launcher`
are the launcher's own decisions: the working directory it started in
and, when that lies under an exclave path, the subtree it gave the host;
the border program; an identity file the host lacks, answered from the
exclave's copy. Every process a workload spawns appends to the same
file, so a `make` writes one log. A newline in a path is written `\n`
and a backslash `\\`; nothing else is escaped.

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

## Shipping an exclave, and taking one

An exclave is a directory, and `tar` makes it one file; `scripts/release`
makes a release of one or more, signed, with the `exclave` command
beside them so that whoever takes it needs nothing of this checkout:

```bash
scripts/release ~/.ssh/id_ed25519 release gcc.exclave    # release/: gcc.exclave.tar.xz, exclave, SHA256SUMS, B2SUMS, SHA256SUMS.sig
```

Taking one: with the release's files in a directory, and the releaser's
public key from a channel you trust (not the release itself):

```bash
echo "exclave-release $(cat releaser.pub)" > allowed_signers
ssh-keygen -Y verify -f allowed_signers -I exclave-release -n exclave -s SHA256SUMS.sig < SHA256SUMS
sha256sum -c SHA256SUMS                                   # or b2sum -c B2SUMS
tar -xJf gcc.exclave.tar.xz
chmod +x exclave && ./exclave check gcc.exclave           # the tree against the hashes file, the wrappers, the static check
./exclave version                                         # which build made it; the launcher inside says the same
```

The gate runs exactly this on a release of its first exclave
(`test/release_test.py`).

## Development

Every command is a POSIX shell script in `scripts/`, run from anywhere.
Python runs only through the pinned uv in `.uv/` (`scripts/install-uv`):
it installs the Python `.python-version` names and the tools `uv.lock`
pins, ruff and ty among them, inside the checkout, so a run depends on
neither the caller's shell nor what the machine has installed.

Requirements beyond the first run's: `bubblewrap` and unprivileged user
namespaces for the kernel oracles and the syscall probe; `strace`,
`gdb`, Go and `rustc` for the suite's regressions; `gpgv` and `openssl`
for the fetchers' signature checks, and `gpg` for their tests; optionally
`aarch64-linux-gnu-gcc` for the aarch64 launcher, and QEMU with KVM and
`cloud-image-utils` for the kernel matrix (`qemu-system-arm` and
`qemu-efi-aarch64` for its arm64 row). Where `bwrap` cannot create a
user namespace, as from a plain terminal on Ubuntu 23.10 and later, the
gate marks the oracle and probe steps SKIP rather than ok.

`scripts/inputs` downloads every development input, pinned or verified,
through caches under `~/.cache`; the tests take their inputs as paths,
and nothing else touches the network except the kernel matrix, which
downloads cloud images and whose VMs install packages. Section 17 of
`docs/DESIGN.md` describes what each test establishes, and section 19
the design decisions a change is expected to respect.

```
scripts/check                            # ruff, ty, shellcheck, shfmt, taplo, clang-format and clang-tidy from uv.lock, and gcc's strict warnings; --fix lets them correct
scripts/inputs ~/.cache/exclave-inputs   # the development inputs: the gate's four exclaves, Docker's seccomp profile, the examples' inputs; skips what is present
D=~/.cache/exclave-inputs; EXCLAVE_TEST_INPUTS=$D scripts/gate $D/gcc13.exclave $D/alpine.exclave $D/f42.exclave $D/clang.exclave   # the commit gate: the steps the change can affect, of the code checks, unit tests, stack budget, the suite in two orders and under the plain terminal's label, the oracles, the syscall probe and the Docker profile, four at a time (--jobs N); --full runs all of them, about 80 s
scripts/test --exclave gcc.exclave       # the suite alone; -k NAME, --order random
scripts/matrix --exclave gcc.exclave --docker-profile ~/.cache/exclave-inputs/src/docker-seccomp.json   # the kernel matrix, due when the gate says a change reaches the VMs: cloud images under QEMU/KVM, one at a time (--jobs N), about eleven minutes
scripts/exercise --exclave gcc.exclave test/progs/fexec.c HOSTDIR   # one program under bwrap, where the kernel answers, and under the launcher, side by side
scripts/examples ~/.cache/exclave-inputs/realsoft.exclave   # the example runs, each when its input is set: EXCLAVE_TEST_SRC (realsoft), EXCLAVE_TEST_SQLITE (bench), EXCLAVE_TEST_RPMS (sysroot), EXCLAVE_TEST_DEBS_ARM64 (the emulated aarch64 row), EXCLAVE_TEST_DOCKER (its Docker profile run)
```

The repository's layout:

```
scripts/install-uv   the pinned uv into .uv/, checked against a committed checksum per architecture; scripts/lib.sh what every script sources
scripts/exclave      the exclave command; scripts/unpack, fetch-debs, fetch-apks and fetch-rpms the steps before it
scripts/example      the first run: from the build to a program built inside an exclave that runs on any glibc since 2.17, every command shown
scripts/check        the code checks; scripts/gate the commit gate; scripts/inputs the development inputs; scripts/examples the example runs
scripts/release      a signed release of exclaves with the command beside them; test/release_test.py takes one as a consumer would
scripts/test         the suite; scripts/matrix, exercise and sysroot the other test drivers
pyproject.toml       the Python project, unpack: no dependencies, the dev tools, ruff's and ty's settings; uv.lock pins them; .python-version the Python
scripts/build        the launchers, build/launcher, build/launcher-old for the nesting regression and build/launcher-debug with UBSan's checks; the command, build/exclave, and build/exclave-asan for the gate; the aarch64 ones with a cross compiler; nothing when they are up to date
src/sys.h            syscall numbers and instruction per architecture, the syscall page, raw wrappers, a tiny libc subset
src/elf.h            the ELF structures the loader needs
src/common.h         constants, the run-time state (struct exclave), every module's interface
src/launcher.c       entry: syscall page, self-relocation, find the exclave, manifest, border, env, load
src/manifest.c       the strict grammar parser (6.2); also built for the host by the gate's unit step
src/loader.c         userland ELF loader and the probe for a launcher's notes (7.3); the facts exported for gdb (7.6)
src/gdb.py           the script the launcher carries in .debug_gdb_scripts and gdb auto-loads (7.6, 13.1)
src/filter.c         the seccomp program (7.4.2)
src/handler.c        the SIGSYS handler: translation, read-only rule, exec, signal masks (7.4.3, 7.5, 8.2)
src/canon.c          canonicalisation in virtual space (7.4.4)
src/cache.c          the per-process component cache (7.4.4)
src/vis.c            the visibility rule, ownership read from the tree, identity files, wrapper redirect (8)
src/scratch.c        handler memory: mmap'd chunks with liveness reclamation (7.5.4)
src/isa.c            the CPU check (7.7): x86-64 psABI levels by cpuid and XCR0, aarch64 levels by AT_HWCAP
src/str.c            string helpers, arena, the shebang parser
src/log.c            EXCLAVE_LOG and fatal messages
tool/tool.h          the exclave command (10), static C on the C library: every module's interface
tool/main.c          the command line, hash and format
tool/util.c          what every command shares: refusals, memory, byte strings, files
tool/grammar.c       the strict grammar of the manifest and the hashes file (6.2), and its canonical form
tool/tree.c          the walks of a tree in the order of its names' bytes, and the tree hash (6.4)
tool/layout.c        the launcher, the README and the hashes file; wrap, unwrap and relink
tool/paths.c         virtual paths resolved in the tree, and the visibility rule's prefixes (8.1)
tool/elf.c           the ELF headers, PT_INTERP, the dynamic section and ld.so.cache the checks read
tool/check.c         the static and dynamic checks of 10.3, the loader's library search, check
tool/prune.c         prune (10.4)
tool/blake2b.c       BLAKE2b, from RFC 7693
tool/blobs.S         the launcher and tool/README.txt, the README every exclave gets, carried as data
unpack/cli.py        the step before the tool: package files -> an unwrapped exclave (10.1)
unpack/steps.py      extraction rules, synthesis, the volatile directories, dependency report, the pkg records
unpack/reader.py     the interface every package reader provides, and the streams they read as they decompress
unpack/root.py       the tree as a root: every path resolved inside it, every write through a directory descriptor
unpack/deb.py        the Debian reader: ar, tar, compression, control stanzas, dependency fields, version order
unpack/apk.py        the Alpine reader: gzip streams, .PKGINFO, apk's dependency and version syntax
unpack/rpm.py        the rpm reader: lead and headers, the cpio payload, rpm's flags and version order
fetch/debs.py        resolve a closure from a Debian archive and download it: InRelease against the keyring, every file against the index
fetch/apks.py        the same for an Alpine repository: the index against the key its signature names, each package's checksums as apk checks them
fetch/rpms.py        the same for a yum or dnf repository: every rpm's own signatures as rpm checks them, repomd.xml's where the repository signs it
fetch/verify.py      the signature checks the fetchers share: gpgv for OpenPGP, openssl for Alpine's RSA, armoured keys decoded
test/run.py          the regression suite; test/progs/ its C, Rust and Go programs
test/unpack_test.py  unpack's rules on hostile .deb, .apk and .rpm files; test/packages.py builds them
test/fetch_test.py   the fetchers' signature checks, on repositories made and signed there
test/tree.py         what a tree says about itself: its compiler, its shell, where a tool lives, its libc; the suite and the oracles ask it
test/oracle_ns.py    the namespace oracle (bwrap); test/oracle_resolve.py the openat2 oracle
test/oracle_syscalls.py  the differential syscall probe: every trapped path and descriptor syscall with every path form under bwrap and under the launcher; test/progs/probe.c its interpreter
test/exercise.py     one program run under bwrap and under the launcher, the answers side by side: how a limitation is measured before it is fixed
test/docker_profile.py   an exclave under Docker's default seccomp profile, which scripts/inputs fetches
test/matrix.py       the kernel matrix in VMs, carrying the pinned Python for each; test/vm_run.py one VM
test/sysroot.py      a glibc sysroot as a data directory and an output built against it, for the matrix to run natively
test/realsoft.py     real projects built inside and outside an exclave; test/bench.py the performance table
test/syscalls.py     every kernel syscall classified; test/stackcheck.py the stack budget
test/affected.py     the gate's steps a change reaches, derived from what each step runs; test/figures.py the figures the documents quote, checked against the tree
test/tables_test.py  the tables the launcher, the command, unpack and the tests each carry, read from every source and compared
test/manifest_test.c grammar tests; test/grammar_test.py the grammar properties; test/filter_test.c the filter against its rule
test/scratch_test.c  the scratch pool's sweep under the interleaving that once shared a chunk; test/cache_test.c the cache's lock across fork
test/isa_test.c      the CPU level check against made-up cpuid and XCR0 values and against gcc's own answer
test/fuzz.c          mutation fuzzing of the parsers; test/tool_fuzz.c and test/launcher_fuzz.c its targets, test/fuzz.py the gate's step
LICENSE              the MIT licence; the launcher carries its text
docs/DESIGN.md       the design and specification
CLAUDE.md            working notes for contributors and coding agents
```

## Reporting problems and contributing

A problem report is most useful with the failing lines of an
`EXCLAVE_LOG=/tmp/x.log` run, `uname -r` and the distribution, the
exclave's `.exclave/hashes` file and the output of `exclave check` on
it. Contributions are welcome: a change passes the gate on the four
exclaves above, a launcher change the kernel matrix too, and the
design decisions in section 19 of `docs/DESIGN.md` stand unless the
change argues otherwise.

## Documentation

- `docs/DESIGN.md`: the design and specification, self-contained. 6 is
  the format, 7 the launcher, 8 the visibility rule, 10 the `exclave`
  command, 12 where it runs, 13 the limitations, 16 performance, 17
  the tests, 19 the decisions.
- `src/`: the launcher, one module per part of the design (below).

## Licence

exclave is under the MIT licence: `LICENSE`. The launcher is the part
of exclave that every exclave holds, so it carries the licence's text,
which the MIT licence asks to go with every copy; `readelf -p
.exclave.license .exclave/launcher` prints it, and the README the tool
writes says so. The software in an exclave's tree keeps its packages'
own licences, and an exclave passed on passes their terms on with it:
`exclave prune` keeps their texts, and an Alpine exclave has them only
if the packages' `-doc` packages went in.
