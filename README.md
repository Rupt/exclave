# exclave

`exclave` turns Linux software that depends on its environment, compilers
first, into a directory that behaves like one static executable. Copy the
directory anywhere and run any program in it by path. The program never
touches a host library, header or loader, and reads no host configuration
except eleven identity files and three directories: who the users are, how
names resolve, which certificate authorities are trusted, what the time
zone is. No daemon,
no image store, no
privileges, no host binaries. One run-time knob, `EXCLAVE_LOG`, which only
logs.

An **exclave** is that directory: an unmodified filesystem tree plus one
static, freestanding binary, the **launcher**, which every executable in
the tree is a hard link to. The launcher projects the tree onto `/`: a
seccomp filter and a resident `SIGSYS` handler rewrite every path-taking
syscall inside the process, and the launcher itself loads the program and
the exclave's own `ld.so`. The **`exclave` command** builds exclaves from
package files or from any filesystem tree.

> **Experimental.** exclave works and is tested widely (below), but has
> no release yet. Everything one build reads that another wrote is
> versioned, the format (`exclave 1`, `hashes 1`), the log and the
> launchers' nesting, and from the first release a later build reads
> what earlier builds of the same versions wrote (docs/DESIGN.md 6.7).
> A build is named by the project's version and commit (`exclave
> version`; the launcher and the hashes file carry the same name).
> Before the first release nothing promises compatibility between
> commits.

## What works

- **Packages in, a directory out.** The `exclave` command builds
  exclaves from Debian and Ubuntu `.deb`, Alpine `.apk`, and Fedora,
  Rocky or CentOS `.rpm` files, or from any filesystem tree. Its
  commands take files, and it holds no network code; `exclave-fetch`,
  a program of its own beside it, downloads a package closure with every
  file checked against the repository's signatures.
- **Compilers first.** A gcc exclave builds zlib, Lua, SQLite and re2c
  from source with their configure scripts: the builds within a fifth of
  native time, the configure scripts about a third slower. A clang
  exclave compiles C and C++; Alpine and Fedora exclaves compile and run
  C. A CentOS 7 glibc as a data directory gives outputs that run on every
  glibc since 2.17.
- **Where it runs.** x86-64 and aarch64 Linux, kernel 3.10 or later as
  tested, glibc or musl software inside, 4 KB and 64 KB pages (16 KB
  pages are untested). One source builds both launchers.
- **gdb** debugs a program in an exclave; the launcher carries the script
  gdb needs.
- **Tested against the kernel.** A suite of named tests, oracles that
  compare the launcher's answers with the kernel's under a read-only bind
  mount, and a differential probe of every trapped syscall pass on gcc,
  clang, Alpine and Fedora exclaves. An exclave also runs under Docker's
  default seccomp profile, and the gcc exclave passes the suite in
  virtual machines from CentOS 7 at kernel 3.10 to Ubuntu 26.10 at 7.3,
  and on an emulated arm64 Ubuntu.

Figures here and in `docs/DESIGN.md` are measured on the reference
machine: an AMD Ryzen AI 7 350 (8 cores, 16 threads), Ubuntu 24.04,
kernel 7.0, glibc 2.39.

## First run

You need an x86-64 or aarch64 Linux host with `gcc`, `curl` or `wget`,
Ubuntu's archive keyring at `/usr/share/keyrings/ubuntu-archive-keyring.gpg`,
which an Ubuntu host has and the `ubuntu-keyring` package gives another,
and the network. `scripts/install-go` fetches a pinned, checksummed
[Go](https://go.dev/dl/) into `.go/`, which builds the `exclave`
command, and `scripts/install-uv` a pinned, checksummed
[uv](https://docs.astral.sh/uv/) into `.uv/`, which provides the pinned
Python the tests and checks run on. The example then
downloads Ubuntu's gcc packages and CentOS 7's glibc. No
root, no container runtime, no user namespaces: nothing needs a
privilege, and nothing is installed outside the checkout.

```bash
scripts/install-go
scripts/install-uv
scripts/build
scripts/example build/example
```

`scripts/example` runs the whole path under the directory you name. It
prints each command as it runs; for the long ones it prints a summary
line and keeps the command and its output in a log under `log/`. Its
output and logs are the tutorial, and each command is one you can run by
hand:

1. `scripts/build` builds `build/launcher`, the freestanding binary every
   executable in an exclave is a hard link to.
2. `exclave-fetch debs` downloads Ubuntu 24.04's `gcc-13` closure, and
   `exclave unpack` makes an unwrapped exclave from the files: the tree under
   `gcc.exclave/tree/`, the maintainer scripts' effects synthesised,
   every input recorded by hash in `gcc.exclave/.exclave/hashes`.
3. `exclave-fetch rpms` downloads CentOS 7's glibc, headers and `libgcc`.
   Unpacked into a tree of their own, they are copied into the gcc
   exclave at `/opt/sysroot-el7`, and a two-line manifest says `data
   "/opt/sysroot-el7"`: nothing there is wrapped, checked or executed.
   `exclave wrap` wraps the exclave, and a symlink, `gcc.exclave/gcc`,
   names its compiler.
4. `hello.c` is compiled inside the exclave twice, plainly and with
   `--sysroot=/opt/sysroot-el7 -B/opt/sysroot-el7/usr/lib64/`, each with
   `EXCLAVE_LOG` on. `objdump` shows what each output binds: the plain
   one `GLIBC_2.34`, so it needs a glibc at least that new; the sysroot
   one `GLIBC_2.2.5` alone, so it runs on any glibc from 2.17 on, the
   oldest in the kernel matrix, where CentOS 7 runs this same build
   natively. The program runs on this host and, through
   `.exclave/launcher`, inside the exclave on the exclave's loader.
5. `exclave prune` keeps, in a copy, the files the compile touched and
   the packages' licence texts: a few hundred of the files and links
   under `tree/`. The copy compiles the program again, and `exclave
   check` reads the new log. That copy is the exclave you would ship for that
   workload, and the check is the one you would run on it.

What it prints on the reference machine, abridged (`exclave` here is
`scripts/example`'s shorthand for `scripts/exclave`):

```
== 3. CentOS 7's glibc as a sysroot inside it
+ mkdir -p gcc.exclave/tree/opt
+ cp -a sysroot.exclave/tree gcc.exclave/tree/opt/sysroot-el7
  gcc.exclave is wrapped (46 warnings; log/wrap.log)
== 4. a program built inside, run on this host and inside the exclave
+ env EXCLAVE_LOG=/home/me/exclave/build/example/log/hello.log gcc.exclave/gcc --sysroot=/opt/sysroot-el7 -B/opt/sysroot-el7/usr/lib64/ -o hello hello.c
  log/hello.log: 1508 lines, one per trapped syscall; the first:
    launcher 2 host path absent, using the exclave's /etc/pki/tls/certs/ca-bundle.crt
    launcher 2 cwd /home/me/exclave/build/example
    launcher 2 border /usr/bin/x86_64-linux-gnu-gcc-13
    load 0 /usr/bin/x86_64-linux-gnu-gcc-13
    access -2 /etc/ld.so.preload
    open 4 /etc/ld.so.cache
  glibc symbol versions bound: hello-plain: GLIBC_2.2.5 GLIBC_2.34  hello: GLIBC_2.2.5
+ ./hello
hello from an exclave
+ gcc.exclave/.exclave/launcher /home/me/exclave/build/example/hello
hello from an exclave
== 5. the exclave pruned to what the compile touched, and the checks on it
+ exclave prune hello.exclave log/hello.log
pruned hello.exclave: kept 226 files, removed 9340, 359535525 bytes freed
static check: 24 ELF files, 2 static executables, 0 warnings, 0 errors
+ exclave check hello.exclave log/pruned.log
0 wrapper problems
static check: 24 ELF files, 2 static executables, 0 warnings, 0 errors
warning: this host's nsswitch.conf names sss; the exclave has no libnss_sss.so.2, so what it looks up is unknown inside: add libnss-sss on Debian and Ubuntu, sssd-client on Fedora (8.4)
dynamic check: 1508 log lines, 0 errors
```

The warnings of `wrap` are dangling symlinks: `coreutils`' locale
links, which point at translations Ubuntu moves into language packs the
package does not ship, and a man-page link to a page no package in the
set ships. The warning says the tree has a link to
nothing, which is true and harmless; an error would have stopped `wrap`.

Afterwards the directory holds `gcc.exclave`, a compiler that touches
nothing on the host, its sysroot inside; `hello`; `hello.exclave`, the
pruned copy; the fetched packages and the indexes that resolve them,
which a second run reuses; and `log/`, one file per step.

## What bites first

Section 13 of `docs/DESIGN.md` lists every limitation. These are the
ones a first user meets, with the rule behind each and what to do:

- **Host tools are not found by name.** `PATH` inside an exclave is the
  exclave's: `/usr/local/bin:/usr/bin:/bin`. A host program runs inside
  by path or through `.exclave/launcher`, and only if the libraries it
  needs are in the exclave. A symlink in the exclave's own
  `/usr/local/bin` puts a name on `PATH`.
- **The tree is read-only.** A write to an exclave path fails with
  `EROFS`, as under a read-only mount, so a build that installs into
  `/usr` or `/usr/local` inside fails; install with `DESTDIR` or a prefix
  on the host. Outputs go to host paths: the working directory and its
  subdirectories, `/tmp`, `/home`, anything the tree does not ship. A
  working directory under an exclave path is given to the host as a
  subtree, so `-o build/x.o` works from anywhere.
- **One libc per exclave.** `wrap` refuses a tree that mixes two, or
  that would load a host library, and names the file. A second libc's
  world can ride along as a `data` directory that is never executed;
  that is what a sysroot is.
- **Eleven host files and three directories are the host's:**
  `/etc/passwd`, `/etc/group`, `/etc/nsswitch.conf`, `/etc/host.conf`,
  `/etc/resolv.conf`, `/etc/hosts`, `/etc/localtime`, the trust bundles
  `/etc/ssl/certs/ca-certificates.crt` and
  `/etc/pki/tls/certs/ca-bundle.crt`, Java's trust stores
  `/etc/ssl/certs/java/cacerts` and `/etc/pki/java/cacerts`, and the
  directories `/etc/ssl/certs` and `/etc/pki/tls/certs`, where the host
  keeps its trusted authorities one to a file, and `/var/lib/sss`,
  SSSD's. Each is read from the host where it exists, its links followed
  on the host, so a program that verifies through the certificate
  directory trusts what the host trusts; where the host lacks one, the
  exclave's copy answers. `own` in the manifest takes one back.
  Everything else under `/etc` is the exclave's.
- **The locale and the shell are the exclave's; the time zone is the
  host's.** At the border `LANG=C.UTF-8` and `SHELL=/bin/sh` replace the
  user's; `TZ`, `LANGUAGE`, every `LC_*` and the variables that steer a
  loader or libc to host files (`LD_*`, `GCONV_PATH`, `LOCPATH` and the
  like) are dropped. Every other variable passes through, and inside the
  exclave nothing is touched but the launcher's own variables. Messages
  are English, and `date` prints the host's local time, read from
  `/etc/localtime`, one of the eleven files above; a `TZ` zone name would
  need `tzdata` in the exclave. An exclave that wants another locale or
  shell ships the data and a wrapper script that sets the variable; one
  that wants a fixed zone takes `/etc/localtime` back with `own`.
- **From the host, every executable in an exclave is the launcher.**
  `ldd`, `file` and `debsums` see the same small static binary at every
  wrapper path; the originals are beside them in `.real/`, byte for byte
  upstream's. `du` and `tar` differ by the launcher's size times the
  wrappers. A copy that breaks hard links (`cp -r`, `git`, `zip`) still
  works; each wrapper is then a copy of the launcher. From outside,
  `/proc/<pid>/exe` of a built output or a host program run inside names
  `.exclave/launcher`, and a wrapped program's names its own path; from
  inside both are right. A copy of an original that a program inside
  makes at a host path, as `python3 -m venv --copies` does, is a plain
  host program from outside, which reads the tree's executable files
  as the launcher, and runs inside only through `.exclave/launcher`
  (`docs/DESIGN.md` 13 item 16).
- **Nothing elevates.** seccomp needs `no_new_privs`, which also
  disables setuid, file capabilities and AppArmor transitions on exec:
  `sudo`, `su`, `ping` and setcap binaries fail inside an exclave, from
  build scripts too.
- **Programs that need their own kernel features are refused:**
  `io_uring`, `clone3` extensions, and a seccomp filter of their own
  that traps, traces or asks a supervisor. That rules out container
  runtimes, browsers and `rr` inside an exclave. A filter that allows,
  logs, fails or kills, as `sshd`'s and `qemu -sandbox`'s do, is
  installed and applied by the kernel as natively. `strace` works but
  shows a `SIGSYS` for every translated call.
- **A `noexec` filesystem cannot hold an exclave.** The kernel refuses
  to execute or map anything there, and a `noexec /tmp` in CI is the
  common case.
- **Compiler-identity caches** see every compiler in an exclave as the
  same binary at the same mtime; ccache needs `compiler_check =
  %compiler% -v`.
- **Overhead is per trapped syscall:** 6 to 11 times native on a tight
  `stat` loop, a tenth to two fifths more on small compiles, where
  process start dominates, and within noise on a compute-bound compile.
  Section 16 of `docs/DESIGN.md` has the measurements.
- **A running program on a host path is not protected from another
  process's writes**, since the kernel executes the launcher, not the
  file. Natively `cp new prog` over a running `prog` fails with "Text
  file busy"; in an exclave it succeeds, and the running program may
  take `SIGBUS`. Linkers unlink their output first, so relinking is safe
  either way.
- **Not a sandbox.** A program that wants to can bypass the translation.
  An exclave isolates software from the host's files, not the host from
  the software. A program's own seccomp sandbox inside one confines the
  program's own calls, not an attacker who has gained code execution in
  it: the syscall page at a fixed address is a gadget its filter lets
  through.

## Making your own exclave

The `exclave` command is `build/exclave`, one static file that carries
its launcher and runs with nothing beside it; `scripts/exclave` runs it
from the checkout. Its `wrap` takes a directory holding `tree/` and
never fetches.

Whatever made the tree is the step before it. For package files that is
`exclave unpack`, beside the three fetchers of `exclave-fetch`, `debs`,
`apks` and `rpms` (from a checkout, `scripts/exclave` and
`scripts/exclave-fetch` run the two programs as `scripts/build` built
them):

- it reads each package's own control archive and reports the
  dependencies the set does not satisfy;
- it extracts, every path resolved inside the tree, and synthesises
  what the maintainer scripts
  would have done: alternatives, `ld.so.cache` as the exclave's own
  `ldconfig` would write it, the CA bundle, `/etc/passwd`;
- it records every input by hash in the hashes file.

The fetchers resolve hard dependencies alone, `Depends` and
`Pre-Depends`, `Requires` and `D:`, never the `Recommends` that apt and
dnf install by default; name a recommended package the program needs
along with it: `gcc` for Go's cgo and `-race`, `openssl` for its
`openssl.cnf`.

The result is a directory; `ar` and `tar`, `debootstrap` or a container
export make others (`docs/DESIGN.md` 10.1). `wrap` adds the launcher and
the placeholders, wraps every executable, runs the static check and
records the manifest and tree hashes; `unwrap` moves the originals back.
Every exclave has a `README` at its top for whoever finds it without
this repository: what it is, how to run its programs, what it touches
and how to check it. The tool writes one where the exclave has none, so
a maker's own stays.

```
scripts/exclave-fetch debs --keyring /usr/share/keyrings/ubuntu-archive-keyring.gpg --out debs gcc-13 libc6-dev make   # Ubuntu or Debian: the closure of the packages named; InRelease checked against the keyring, every file against the index
scripts/exclave-fetch apks --key alpine-devel@lists.alpinelinux.org-6165ee59.rsa.pub --out apks gcc musl-dev binutils  # Alpine: the index checked against the key its signature names (https://alpinelinux.org/keys/)
scripts/exclave-fetch rpms --keyring RPM-GPG-KEY-fedora-42-primary --repo URL --out rpms gcc glibc-devel   # Fedora, Rocky, CentOS: any repository with repodata/; every rpm checked against the key, repomd.xml where signed
scripts/exclave unpack gcc.exclave debs/*.deb                     # package files -> an unwrapped exclave, a directory you may edit; .apk and .rpm files likewise
scripts/exclave wrap gcc.exclave                          # wrap every executable, run the static check, record the hashes in .exclave/hashes
scripts/exclave caches py.exclave                         # Python bytecode, GSettings schemas, the MIME database, the GIO, gdk-pixbuf, icon, desktop and font caches, graphviz's plugin configuration and TeX Live's indexes and formats, made by the tree's own programs inside it
ln -s tree/usr/bin/gcc-13 gcc.exclave/gcc                    # a shortcut, if you want one
gcc.exclave/gcc -O2 hello.c -o hello                         # any executable in tree/ runs by path
gcc.exclave/tree/usr/bin/sh -c 'as --version'                # the exclave's own shell, with the exclave's PATH
gcc.exclave/.exclave/launcher /path/to/host/program args...  # a program without a wrapper, a host tool or a built output, inside the exclave
gdb -iex 'set auto-load safe-path /' --args gcc.exclave/gcc -c x.c   # gdb: the launcher carries the script; break, bt, source lines
EXCLAVE_LOG=/tmp/exclave.log gcc.exclave/gcc -c x.c          # the one knob: one line per trapped syscall
scripts/exclave check gcc.exclave /tmp/exclave.log        # the static check of every ELF file, the dynamic check of the logged run
scripts/exclave prune gcc.exclave /tmp/exclave.log        # keep what the logged runs touched
scripts/exclave unwrap gcc.exclave                        # the originals back over their wrappers, to edit; wrap again after
scripts/exclave relink gcc.exclave build/launcher         # swap the launcher after rebuilding it; the wrappers are relinked
scripts/exclave hash gcc.exclave                          # the tree hash the hashes file records
scripts/exclave version                                   # the build this command is from; the launcher and the hashes file name it too
scripts/exclave format gcc.exclave/.exclave/manifest      # the canonical spelling of a manifest or hashes file; --check only reports
```

Between `unpack` and `wrap` the unwrapped exclave is yours: copy a built
prefix in, delete what you do not want, add a data directory, write the
manifest.

The manifest is `gcc.exclave/.exclave/manifest`: `exclave 1` when
nothing is overridden, and four other keys, each a string:

- `cpu` names the level the binaries need (`"x86-64-v3"`; x86-64 when
  absent);
- `data` names a directory that is never executed or loaded, not
  wrapped, not checked: a sysroot, or a second libc's world;
- `host` puts a host path at its own name inside the exclave: `host
  "/usr/local/share/fonts"`;
- `own` makes a path the exclave's: one of the identity files or
  directories above, a path inside one, or any other path the rule
  would give the host.

That is the whole manifest. There is no way to make the tree writable,
remap a path, set a variable or put a directory on `PATH`. A wrapper
script inside the exclave sets variables, a symlink in the tree remaps,
and a symlink in the exclave's own `/usr/local/bin` puts a program on
`PATH`.

An exclave of something you built is the same four lines, with the
build system's own installer doing the building:

```
gcc.exclave/tree/usr/bin/sh -c './configure --prefix=/usr/local && make && make install DESTDIR=$PWD/stage'
scripts/exclave unpack tool.exclave runtime/*.deb                 # libc6 and whatever else the result links against
cp -a stage/usr/local tool.exclave/tree/usr/
scripts/exclave wrap tool.exclave                         # the static check says whether it all links inside
```

No recipe format and no closure copying: the runtime the result needs is
packages you already have, and the static check verifies that every
library resolves inside the exclave.

## The log and the checks

`EXCLAVE_LOG=<file>` is the launcher's one knob. The file is a host file
named by its absolute path, outside the exclave; the launcher refuses a
relative path or a log inside its exclave. It appends one line per
trapped syscall, `<syscall> <result> <virtual path>`, the result being
the return value or the negative errno: `open 3 /etc/ld.so.cache` is
descriptor 3; `access -2 /etc/ld.so.preload` is `ENOENT`, which is what
a search looks like and not a fault. Lines that begin `launcher` are the
launcher's own decisions: the working directory it started in and, when
that lies under an exclave path, the subtree it gave the host; the
border program; an identity file or directory the host lacks, answered
from the exclave's copy. Every process a workload spawns appends to the same
file, so a `make` writes one log. A newline in a path is written `\n`
and a backslash `\\`; nothing else is escaped.

`exclave check EXCLAVE [LOG...]` first verifies the wrappers and their
originals and compares the tree with the hash the hashes file records.
Then it runs the static check on every ELF file outside data
directories: every loader and every `DT_NEEDED` resolves inside the tree
by the loader's own search, to one libc, and nothing would resolve on
the host. Errors name the file and stop `wrap`; warnings are worth
knowing and do not: a dangling symlink, a 32-bit or foreign-machine
object a package ships beside the real ones. Static executables are
counted, having no loader to verify. With logs it adds the dynamic
check: every library the workload opened resolved inside the exclave,
and every NSS module this host's `nsswitch.conf` names that the exclave
lacks is a warning, naming the package that ships it. glibc skips a
missing module, which is right for `hosts` and wrong for `passwd` on a
host whose users come from LDAP, SSSD or `systemd-homed`; with the
module in the tree, `libnss-sss` for SSSD, the exclave finds them
through the host's daemon, whose socket is the host's.

`exclave prune EXCLAVE LOG...` keeps every path a logged syscall
touched, the entries of any directory a program listed, the symlink
chains that reach kept files, the libraries kept programs need, the
placeholders and the identity files, and removes every other file and
symlink. Directories stay, so `ls` and ownership do not change. It
refuses a log that names no program in the exclave. Afterwards a failed
open in a new log names what pruning removed, so the cycle is: prune,
run the whole workload, add back from an unpruned copy. The suite runs
on exclaves pruned this way.

## Shipping an exclave, and taking one

An exclave is a directory, and `tar` makes it one file. `scripts/release`
makes a signed release of one or more exclaves with the `exclave`
command beside them, so whoever takes it needs nothing of this checkout.
The command and the launcher a release ships are built inside a gcc
exclave, so anyone with that exclave builds the same bytes
(`scripts/reproduce`); an exclave to release is wrapped with that
launcher, which the command built there carries:

```bash
scripts/reproduce gcc.exclave build/reproduce               # build/reproduce/build/{launcher,exclave}, and their BLAKE3
build/reproduce/build/exclave relink app.exclave           # app.exclave wrapped with the reproducible launcher
scripts/release ~/.ssh/id_ed25519 release gcc.exclave app.exclave    # release/: app.exclave.tar.zst, exclave, exclave-fetch, NOTICES, SHA256SUMS, B3SUMS, SHA256SUMS.sig
```

Taking one, with the release's files in a directory and the releaser's
public key from a channel you trust (not the release itself):

```bash
echo "exclave-release $(cat releaser.pub)" > allowed_signers
ssh-keygen -Y verify -f allowed_signers -I exclave-release -n exclave -s SHA256SUMS.sig < SHA256SUMS
sha256sum -c SHA256SUMS                                   # or b3sum -c B3SUMS
tar --zstd -xf gcc.exclave.tar.zst                        # or, where tar has no --zstd: zstd -dc gcc.exclave.tar.zst | tar -xf -
chmod +x exclave && ./exclave check gcc.exclave           # the tree against the hashes file, the wrappers, the static check
./exclave version                                         # which build made it; the launcher inside says the same
```

The signature check needs an `ssh-keygen` with `-Y`: Ubuntu 20.04's
OpenSSH 8.2 has it, and CentOS 7's 7.4, Ubuntu 18.04's 7.6 and Rocky
Linux 8's 8.0 have none (measured November 2026), so on those hosts
verify the signature on another machine and carry `SHA256SUMS` across.
The archive is zstd only, for the reason `docs/DESIGN.md` 10.5 gives,
so unpacking it needs `zstd`, through `tar --zstd` where `tar` has that
option or piped into any `tar` where it has not.

The kernel matrix runs exactly this, with each host's own tools, on
every distribution it boots (`docs/DESIGN.md` 12.1), and
`test/release_test.py`, a step of `scripts/extra`, on the reference
machine, where a tampered archive and a tampered sums file are refused.

## Development

Every command is a POSIX shell script in `scripts/`, run from anywhere;
all but the wrappers of the two built programs source `scripts/lib.sh`,
which sets where everything is kept.
`unpack` and the fetchers are Go, built by the pinned toolchain in
`.go/` (`scripts/install-go`), their modules pinned by `go.sum`.
Python runs only through the pinned uv in `.uv/` (`scripts/install-uv`):
it installs the Python `.python-version` names and the tools `uv.lock`
pins, ruff and ty among them, inside the checkout, so a run depends on
neither the caller's shell nor what the machine has installed.

Beyond the first run's requirements:

- `bubblewrap` and unprivileged user namespaces, for the kernel oracles
  and the syscall probe. Where `bwrap` cannot create a user namespace,
  as from a plain terminal on Ubuntu 23.10 and later, the gate marks
  those steps SKIP rather than ok.
- `strace`, `gdb` and `rustc`, for the suite's regressions; the Go
  one is built by the pinned Go.
- `gpg` and `openssl`, for the fetchers' tests, which make keys and
  signatures with them.
- Optionally `aarch64-linux-gnu-gcc`, for the aarch64 launcher, and
  QEMU with KVM and `cloud-image-utils`, for the kernel matrix
  (`qemu-system-arm` and `qemu-efi-aarch64` for its arm64 row).

`scripts/inputs DIR` downloads every development input, pinned or
verified, and keeps everything in `DIR`, the fetchers' cache included.
Nothing the scripts make goes in the home directory: the pinned uv and
Go keep themselves and their caches in `.uv/` and `.go/`, uv keeps the
tools' environment in `.venv/`, and the rest is under `build/` or the
`DIR` given.
The tests take their inputs as paths; nothing else touches the network
except the kernel matrix, which downloads cloud images and whose VMs
install packages.

`docs/DESIGN.md` is the design and specification, self-contained: 6 is
the format, 7 the launcher, 8 the visibility rule, 10 the `exclave`
command, 12 where it runs, 13 the limitations, 16 performance, 17 what
each test establishes, 19 the decisions a change is expected to respect.
`CLAUDE.md` holds working notes for contributors and coding agents.

```
scripts/check                            # ruff, ty, shellcheck, shfmt, taplo, clang-format, clang-tidy, gcc's strict warnings and analyser, gofmt, go vet, staticcheck and deadcode; --fix lets the formatters correct
scripts/inputs build/inputs   # the test inputs: the four exclaves, the arm64 gcc exclave, the lookup, caches and gdb tests' exclaves, Docker's seccomp profile and the baseline release once one is recorded, from the package archives and GitHub; skips what is present
scripts/inputs build/inputs examples   # the examples' inputs too, some from their authors' sites
D=build/inputs; EXCLAVE_TEST_INPUTS=$D scripts/gate $D/gcc13.exclave   # the commit gate: of its steps (docs/DESIGN.md 17), the ones the change can affect, two at a time (--jobs N); --full runs all of them, and a step whose input $D lacks is a SKIP
D=build/inputs; EXCLAVE_TEST_INPUTS=$D scripts/extra $D/gcc13.exclave $D/alpine.exclave $D/f42.exclave $D/clang.exclave   # beyond the gate, when asked: the suite, the debug launcher, the oracles and the probe on every exclave given; the plain-label suite, the fuzz budget and the release test on the first
scripts/test --exclave gcc.exclave       # the suite alone; -k NAME runs one test
scripts/matrix --exclave gcc.exclave --docker-profile build/inputs/src/docker-seccomp.json   # the kernel matrix: cloud images under QEMU/KVM, one at a time (--jobs N); due when the gate says a change reaches the VMs
gh workflow run ci.yml -f matrix=true    # the gate on GitHub's x86-64 and aarch64 runners, then the x86-64 rows under KVM, for the pushed main; -f matrix=false the gate alone. gh run list --workflow ci.yml, gh run watch ID --exit-status, gh run view ID --log-failed
scripts/exercise --exclave gcc.exclave test/progs/fexec.c HOSTDIR   # one program under bwrap, where the kernel answers, and under the launcher, side by side
scripts/clean-tmp                        # empty build/tmp, the scripts' TMPDIR, which a reboot does not; when nothing runs
scripts/examples build/inputs/realsoft.exclave   # the example runs, each when its input is set: EXCLAVE_TEST_INPUTS (the workloads), EXCLAVE_TEST_SRC (realsoft), EXCLAVE_TEST_SQLITE (bench), EXCLAVE_TEST_RPMS (sysroot), EXCLAVE_TEST_ARM64 (the emulated aarch64 row), EXCLAVE_TEST_DOCKER (its Docker profile run)
```

The repository's layout, by directory; each file says what it is at its
head, and `test/run.py` what each kind of file in `test/` is:

```
src/        the launcher, freestanding C: one source for x86-64 and aarch64, and the script gdb reads from it
tool/       the exclave command, Go: its commands, and tool/format, the format's package
unpack/     exclave unpack, the step before: a reader for each package format, the rules, the tree, ld.so.cache
fetch/      exclave-fetch, the step before that: a fetcher for each kind of repository, and the signature checks
test/       the suite, the oracles and the other drivers, the unit tests, and progs/, the programs they compile
scripts/    every command: install-go, install-uv, build, check, gate, extra, matrix, inputs, test, exercise,
            example, examples, sysroot, figures, profile-spawn, release, reproduce, exclave, exclave-fetch,
            clean-tmp; lib.sh and steps.sh are sourced
docs/       DESIGN.md, the design and specification, and PLAN.md, the working plan
.github/    the workflow that runs the gate and the matrix on GitHub's runners, when dispatched by hand
build/      everything a script makes, with .uv/, .go/ and .venv/, the pinned tools; none of it is tracked
```

## Reporting problems and contributing

A problem report is most useful with the failing lines of an
`EXCLAVE_LOG=/tmp/x.log` run, `uname -r` and the distribution, the
exclave's `.exclave/hashes` file and the output of `exclave check` on
it.

Contributions are welcome. A change passes the gate on the gcc exclave
above; `scripts/extra` on the four exclaves and the kernel matrix are
the broader runs, made when a maintainer asks, and the gate says when a
change reaches the matrix's VMs. The gate and the matrix run on
GitHub's hosted runners when the workflow is dispatched. The design decisions in section
19 of `docs/DESIGN.md` stand unless the change argues otherwise.

## Licence

exclave is under the MIT licence: `LICENSE`. The launcher is the part of
exclave that every exclave holds, so it carries the licence's text,
which the MIT licence asks to go with every copy; `readelf -p
.exclave.license .exclave/launcher` prints it, and the README the tool
writes says so. The software in an exclave's tree keeps its packages'
own licences, and an exclave passed on passes their terms on with it:
`exclave prune` keeps their texts, and an Alpine exclave, as Alpine
does, names its packages' licences in apk's database, `/lib/apk/db/installed`,
and holds few texts. The Go modules `go.mod` pins
carry their own licences, BSD and MIT; `scripts/build` writes their
texts to `build/NOTICES`, and a release ships it beside the command.
