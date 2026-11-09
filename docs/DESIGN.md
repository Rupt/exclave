# exclave: design

This document is exclave's design and specification: the format of an
exclave, what the launcher does and why, the rules a program inside
sees, the `exclave` command, where it runs, its limitations, its
performance and how it is tested. `README.md` is the guide to using it;
this document is the reference behind it, and it reads on its own.

Source comments cite this document by section number, "(7.4.5)", and
by numbered item, "(13 item 31)", "(17 item 4)"; those numbers are
stable. Two short forms appear in the code: "8.1.N" means rule N of
8.1, and "17.N" means item N of section 17.

**Contents.** Sections 1 to 5 say what exclave is for and name its
parts; 6 to 10 specify it; 11 to 13 bound it; 14 to 19 justify and
measure it.

| Section | What it holds |
|---|---|
| 1. Summary | the design in a page |
| 2. Status | what exists, what is tested, the counts |
| 3. Goals and non-goals | what exclave is for, and what it will not do |
| 4. Problem analysis | why a program is bound to its host |
| 5. Concepts and names | the words the rest uses |
| 6. The exclave format | the directory, the manifest, the hashes file, their versions |
| 7. The launcher | the filter, the handler, the loader, exec |
| 8. Visibility rule | which paths are the exclave's and which the host's |
| 9. Compilers specifically | toolchains, sysroots and their outputs |
| 10. The `exclave` command | unpack, wrap, check, prune, release |
| 11. Layers | why there are none |
| 12. Portability envelope | the kernels and hosts it runs on, measured |
| 13. Limitations and risks | each numbered, each with its cause |
| 14. Alternatives considered | what was tried or weighed, and why not |
| 15. Related work | the relatives, each with what it shares |
| 16. Performance | where the time goes, measured |
| 17. Testing | the gate, the oracles, the matrix |
| 18. Roadmap | what is open |
| 19. Design decisions | what is settled, and where it is specified |

## 1. Summary

exclave turns Linux software that depends on its environment,
compilers included, into a directory that behaves like a single static
executable. The directory can be copied anywhere and any program in it
run by path. The software inside never touches a host library, header
or loader, and reads no host configuration but eleven identity files
and three identity directories: who the users are, how names resolve,
which certificate authorities are trusted, what the time zone is
(8.4). There is no daemon, no image store, no package
manager, no installation step, no host binary and no privilege of any
kind: no root, no setuid helper, no user or mount namespaces. There is
one run-time knob, `EXCLAVE_LOG`, and it only logs.

An **exclave** is that directory, `name.exclave/`:

```
name.exclave/
  tree/              the filesystem the software sees as /
  .exclave/
    launcher         one static, freestanding binary
    manifest         a short text file: CPU level, visibility overrides
    hashes           every input, the launcher, the manifest and the tree by hash
  README             what an exclave is, for whoever finds one
```

Every executable file in `tree/`, ELF or script, is a **wrapper**: a
hard link to the launcher standing at the program's own path, with the
**original** beside it in `.real/`. The launcher needs no libc and no
loader of its own (7.1), and a Linux kernel with seccomp filtering and
`/proc` is all it needs (12).

**What happens when a program runs.** Running
`name.exclave/tree/usr/bin/gcc` from any shell goes like this:

1. The kernel executes the launcher, since the wrapper is a hard link
   to it, under gcc's name, so the kernel, `ps` and `/proc` see gcc's
   process identity (7.2).
2. The launcher walks up from its own path, `/proc/self/exe`, to the
   directory that holds `.exclave/manifest`, parses the manifest and
   checks the CPU level (7.2, 7.7).
3. It reads the top level of `tree/` and compiles the **visibility
   rule**, which decides for every path whether the tree or the host
   answers for it (8).
4. It installs the **translator**: a `SIGSYS` handler, and a seccomp
   filter that traps every path-taking syscall (7.4).
5. It maps `.real/gcc` and the loader its `PT_INTERP` names, the
   exclave's own `ld.so`, into the process, and jumps to the loader
   (7.3).

From then on every path syscall of gcc traps, and the handler rewrites
the path so that `tree/` is projected onto `/`, or leaves it to the
host, and re-issues the call. The filter stays in force across `fork`
and `execve`, so `cc1`, `as`, `ld` and every other descendant is
translated too, whatever its file (7.4.5).

Inside an exclave there is one world and one libc: every program,
wherever its file lives, sees the exclave's tree and runs on the
exclave's loader. The exclave owns the top-level entries its tree
ships, such as `/usr` and `/etc`; the host owns everything else, such
as `/home`, the kernel's volatile directories (`/proc`, `/tmp` and the
rest), and the identity files and directories such as `/etc/passwd`,
`/etc/resolv.conf` and `/etc/ssl/certs` (8.1). Paths the exclave owns are read-only: the
handler refuses every write to them with the error the kernel gives on
a read-only bind mount (8.2). The manifest can move a path to either
side; anything the tree can say about itself the launcher reads from
the tree, so the manifest holds little else (6.2, 6.3).

The **`exclave` command** (10) is one static executable per
architecture that carries its launcher (10.5); its commands take
a directory, and it holds no network code. The fetchers, the step
before it, are a program of their own, **`exclave-fetch`** (10.1). Its input is an unwrapped exclave, a plain
directory holding `tree/` that ordinary tools can edit; `unpack`, the
step before it, makes one from `.deb`, `.apk` or `.rpm` packages, and
`tar` or `debootstrap` make others (10.1). `wrap` turns any such tree
into a runnable exclave: it puts the wrappers in place, checks
statically that every ELF file resolves inside the exclave and names
one loader, and records every input and the output by hash. It also
checks an exclave against the logs of real runs and prunes it to what
traced workloads touched.

exclave is not a security sandbox: a program that wants to escape the
translation can (3, 13). It is a way to make software hermetic and
relocatable without asking the host for anything.

**Reading this document.** To use exclave, start with `README.md`.
What a program inside sees is the format (6) and the visibility rule
(8); how the launcher achieves it is 7, and what compilers need is 9.
The command is 10, where exclaves run is 12, and what does not work
is 13. Why not another approach is 14 and 15, and the cost is 16. A
contributor wants 17, how a change is tested, and 19, what is settled.

## 2. Status

exclave is experimental software. It works and is tested as described
below, but it has not been released: there is no release, the commit
gate and the kernel matrix run on the reference machine or on GitHub's
hosted runners when a maintainer dispatches the workflow (17), and
nothing yet promises compatibility between one commit and the next.
From the first release on, what one build reads that another wrote is
versioned and kept as 6.7 says.

What is built and tested:

- **The launcher** for x86-64 and aarch64, from one freestanding C
  source (7).
- **The `exclave` command**, reading Debian and Ubuntu `.deb`, Alpine
  `.apk` and `.rpm` packages through one reader interface (10.1), and
  `exclave-fetch`, which downloads a package closure from a Debian,
  Ubuntu, Alpine or rpm repository, every file checked against the
  repository's signatures (10.1).
- **Four exclave kinds**, made from distribution packages: a gcc
  exclave from Ubuntu 24.04, which builds zlib, Lua, SQLite and re2c
  from source with their own configure scripts; an Alpine exclave on
  musl; a Fedora exclave; and a clang exclave that compiles C and C++
  (9, 17).
- **A glibc sysroot as a data directory**: CentOS 7's glibc inside the
  gcc exclave, never executed, links outputs against glibc 2.17, which
  run natively on any later glibc (9).
- **aarch64**: the launcher runs there, tested in emulated rows of the
  kernel matrix on kernels with 4 KB and with 64 KB pages (12.1, 13
  item 43); the exclave it runs is made on x86-64 (10.1).
- **gdb** debugs a program in an exclave through a script the launcher
  carries, once the exclave is in gdb's auto-load safe-path (7.6, 13.1).
- **The command as one file**: `build/exclave`, static Go carrying its
  launcher, unpacks packages and wraps, checks and prunes an exclave
  with nothing beside it, and `build/exclave-fetch` beside it fetches
  the packages (10.5).
- **Trace pruning**: in `scripts/example`, a hello-world compile against the
  CentOS 7 sysroot keeps a few hundred of the gcc exclave's files and
  symlinks, the originals in `.real/` included; the pruned copy
  compiles the program again (10.4).

`scripts/example` walks from a clean checkout to a program built inside an
exclave that runs on any glibc since 2.17, showing every command.

How it is tested (17):

- **The regression suite**: named tests, most of them programs that
  compute, run on the gcc, Alpine, Fedora and clang exclaves (17 item
  4).
- **Kernel oracles**, where user namespaces are available: the same
  workloads under `bwrap` with the tree bound read-only, and path
  resolution against `openat2` with `RESOLVE_IN_ROOT` (17 items 1
  and 2).
- **The syscall probe**: every trapped path and descriptor syscall,
  with every flag and path form, run under `bwrap` and under the
  launcher and compared case by case, each difference from the kernel
  fixed, accepted under a named reason or listed as an open defect (17
  item 7).
- **Docker's default seccomp profile**: a workload in each exclave runs
  under it, standing for a CI container where user namespaces are
  blocked (17 item 5).
- **The commit gate**, `scripts/gate`, which runs the unit tests, the
  suite, the oracles and the probe on the gcc exclave in under a
  minute, and `scripts/extra`, the broader and slower checks on the
  four exclaves, run when asked; an oracle that cannot run on the
  machine, for want of `bwrap` or user namespaces, is reported as
  SKIP, not as passing (17).
- **The kernel matrix**: the gcc exclave passes the suite in QEMU
  virtual machines of distributions from CentOS 7 at kernel 3.10
  to Ubuntu 26.10 at 7.3, Alpine 3.20's musl userland and Fedora's
  enforcing SELinux among them; an arm64 gcc exclave passes it in an
  emulated arm64 Ubuntu 24.04. Every oracle a row's kernel can run
  passes; CentOS 7, without user namespaces, runs none (12.1).

**The reference machine.** Figures in this document were measured,
unless a section says otherwise, in October 2026 on one machine: an
AMD Ryzen AI 7 350 (Zen 5, 8 cores, 16 threads), Ubuntu 24.04, kernel
7.0, glibc 2.39, a ZFS filesystem. From an ordinary terminal there,
AppArmor denies user namespaces (4.3).

## 3. Goals and non-goals

Goals:

1. **Isolation.** Programs see the exclave's files plus what the
   visibility rule allows. Host libraries and loaders are invisible,
   and so is host configuration, except the eleven identity files and
   three identity directories that describe the host (8.1 rule 5).
2. **Relocatability.** Any path, any filesystem, any machine of the same
   architecture and CPU level. An exclave moves with `cp -a`, `tar` or
   `rsync -aH`, and nothing in it names its location.
3. **No privileges.** No `sudo`, no setuid helper, no policy change, no
   kernel module, no daemon, on any host.
4. **No host binaries.** Not a container runtime, not FUSE, not the
   host's libc or loader.
5. **Programs are files.** Every executable in the tree is a path that
   can be run, symlinked or handed to another program, from anywhere.
6. **Software unmodified.** Compiled-in absolute paths, multi-process
   drivers, `dlopen`, locale and NSS loading, scripts and static
   binaries work without rebuilding or patching; originals stay
   byte-identical.
7. **Uniform behaviour.** One mechanism, one world, one libc, one shape
   of exclave, one code path. The same exclave behaves the same on
   every host and every medium. The launcher has one run-time knob,
   `EXCLAVE_LOG`, which only logs; the tool's commands take paths,
   and `format --check` is their one flag (`exclave-fetch`, the step
   before it, takes the arguments a download needs).
8. **Verifiability.** Isolation and libc homogeneity are checkable by
   the tool, statically and by trace.

Non-goals:

- **Security sandboxing.** The translation can be bypassed by a program
  that wants to; untrusted code needs a real sandbox. A program's own
  seccomp sandbox inside an exclave confines the program's own calls,
  not an attacker who has gained code execution in it: the syscall page
  at a fixed address holds `syscall; ret`, and the program's filter lets
  every call from it through (7.4.2, 13 item 5).
- **Resource control, networking and process namespaces.**
- **Anything but little-endian 64-bit Linux**, and cross-architecture
  emulation, including 32-bit programs in a 64-bit exclave.
- **GPU and other host-driver software** (13).

## 4. Problem analysis

### 4.1 Four bindings to the host

A Linux program is bound to the machine it was built for in four ways:

1. **The ELF interpreter.** `PT_INTERP` is an absolute path and cannot be
   relative to the executable. This is why AppImage borrows the host's
   loader and why Nix needs `/nix/store` at a fixed path.
2. **Shared libraries**, found through `RPATH`, `LD_LIBRARY_PATH`,
   `/etc/ld.so.cache` and compiled-in directories.
3. **Compiled-in data paths**: `cc1` under `/usr/libexec/gcc`, headers
   under `/usr/include`, startup objects under `/usr/lib/<triplet>`,
   glibc's locale, gconv and NSS files.
4. **The environment**: `PATH` for `as` and `ld`; `LD_*` and the
   handful of libc variables that name files.

Static linking addresses only the second. Modern software adds habits
of its own on top: glibc's `posix_spawn`, for one, asks the kernel
through `clone3` to reset signal handlers in the child, which a
translator in the process has to account for (7.5.5).

### 4.2 Existing approaches

| Approach | Fails on |
|---|---|
| Static linking | Only binding 2. |
| Docker, Podman | Daemon or system binary, global image store, root or user-namespace setup. |
| AppImage | Host loader and libc; FUSE or extraction. |
| Nix, Guix | A store at a fixed absolute path is global state. `guix pack -RR` picks the best of user namespaces, PRoot and fakechroot per host, a defensible design whose behaviour varies by host, the criticism 4.3 makes of a second backend. |
| Conda, Spack, Linuxbrew, uninative | Absolute paths patched in; a fixed prefix or re-patching on every move. |
| PRoot, CARE, CDE | A ptrace supervisor on every syscall; the ptrace slot taken. |
| Zig | Owns the compiler source. Not applicable to software one did not write. |

The generalisation: **an exclave is the tree the program expects, plus
a manifest, plus entry points; the design question is how that tree is
projected onto the paths the binaries contain.** Section 15 covers the
related systems in detail, including the precedents for shadow
wrappers.

### 4.3 The privilege constraint, measured

User plus mount namespaces would be the obvious projection. On the
reference machine, a test binary run from an ordinary terminal gets
`unshare(CLONE_NEWUSER)` accepted and then `EACCES` on
`/proc/self/setgroups`, `EPERM` on `uid_map` and `EPERM` on `mount`:
AppArmor moves an unconfined process that creates a user namespace into
a profile that denies all capabilities. Docker's default seccomp
profile blocks user namespaces inside containers. Many HPC clusters,
RHEL 7 and hardened kernels disable them. Escaping any of these needs
root, or a setuid helper such as the `bwrap` some distributions ship,
which the design declines to depend on.

A second backend for hosts that do allow namespaces would make
behaviour vary by machine and double the code, for no gain where it
matters most: a compute-bound compile already runs within noise of
native under the launcher (16). Namespaces are therefore not part of
the design. Where they are available they serve as the test oracle
(17 item 1).

## 5. Concepts and names

| Name | What it is |
|---|---|
| **exclave** | The project, its repository and the bundle format: a directory `name.exclave/`, the unit one copies, shares and runs. An exclave is a piece of one country inside another, whose own rules hold within its border and the host's everywhere else, as the visibility rule (8) does for paths. |
| **tree** | `name.exclave/tree/`, the tree the software sees as `/`. |
| **`.exclave/`** | The format's own files, in a hidden directory so that a shortcut never collides with one. |
| **manifest** | `.exclave/manifest`, the one file the launcher reads besides the tree: the CPU level (`cpu`) and the visibility overrides (`data`, `host`, `own`). `exclave 1` alone is a valid manifest (6.2). |
| **hashes** | `.exclave/hashes`: every input, the launcher, the manifest and the tree by hash; its records begin `hashes 1` and name the `tool` and the `launcher`. A record, not a locator (6.4). |
| **shortcut** | A symlink the maker puts at the top of the exclave, pointing at a wrapper in the tree; a convention, not a record. |
| **README** | `name.exclave/README`: what an exclave is and how to run it, for whoever finds one; the tool writes it where the exclave has none, and nothing reads it. |
| **launcher** | `.exclave/launcher`, one static freestanding `ET_DYN` binary: wrapper, loader and resident translator (7). |
| **wrapper** | A hard link to the launcher at an executable's own path in the tree. |
| **original** | The original executable, at `<dir>/.real/<name>` beside its wrapper. |
| **translator** | The launcher's resident part: the seccomp filter and the **handler**, its `SIGSYS` handler, together (7.4). |
| **syscall page** | The page at the fixed address `0x7fe00000` through which the launcher makes every syscall of its own; the filter allows a call from it untranslated (7.4.2). |
| **page generation** | The word in a launcher's ELF note that says which syscall page it uses, so that one launcher can refuse an incompatible other by name (7.4.2, 7.4.5). |
| **handler-call slot** | The slot of the syscall page from which a trampoline calls a program's handler, its return address at the restorer's instructions that the filter answers from there with an error (7.4.2, 7.5.7). |
| **re-issue slot** | The slot of the syscall page through which the handler makes every call on the program's behalf; it makes none once a program's handler has redirected the program (7.4.2, 7.5.7). |
| **trampoline** | The launcher's code that the kernel runs in place of a program's signal handler: outside a trapped call it jumps to the handler as the kernel would; inside one it gives the handler the trap site's frame and ends the call as the handler decides (7.5.7). |
| **version probe** | The `uname` with a magic argument that a launcher issues at startup: an inherited filter answers with its version, and `EFAULT` means none (7.2, 7.4.2). |
| **positional entry** | `name.exclave/.exclave/launcher PROGRAM ARGS...`, which runs a program that has no wrapper, a host tool or a built output, inside the exclave (7.2). |
| **loader path** | How a program without a wrapper runs inside an exclave: the handler, or the positional entry, re-execs the launcher with the target in `EXCLAVE_EXEC`, and that launcher loads it with the exclave's loader (7.4.5, 7.6). |
| **one-step host check** | One `openat2` with `RESOLVE_NO_SYMLINKS` standing in for the `lstat` of each of three or more plainly host-owned directories in a path walk, where the tree's mount allows it (7.4.4). |
| **exclave path** | A path the tree answers for, read-only (8.1, 8.2). |
| **host path** | A path the host answers for, as it would without the exclave (8.1). `host` and `own` records in the manifest move a path to either side. |
| **placeholder** | An empty top-level directory of the tree, which the exclave does not own; the tool ships placeholders for `/home`, `/tmp`, `/proc` and the other conventional host names (8.1). |
| **identity file** | One of eleven files, such as `/etc/passwd` and `/etc/resolv.conf`, that describe the host and are the host's by default (8.1 rule 5, 8.4). |
| **identity directory** | One of three directories, `/etc/ssl/certs`, `/etc/pki/tls/certs` and `/var/lib/sss`, that are the host's by default: the host's directory at its name, its links followed on the host at each call, as an identity file's chain is, with `..` at its root climbing in the exclave (8.1 rule 5, 8.4). |
| **border** | Where a program passes from the host into the exclave, its launcher finding no inherited filter; the environment is set there (6.2). |
| **data directory** | An exclave path that is never executed or loaded, named by a `data` record: a sysroot, headers, documentation (6.2). |
| **`exclave`** (command) | The build tool: `wrap`, `unwrap`, `check`, `prune`, `hash`, `relink` and `format`. Takes a directory holding `tree/`, fetches nothing (10). |
| **`unpack`** | The step before the tool: package files to an unwrapped exclave, run as `scripts/unpack` (10.1). |
| **unwrapped** | An exclave before `wrap`: a plain tree, editable with ordinary tools. After `wrap` it is wrapped. |
| **`EXCLAVE_LOG`** | The one run-time knob, which only logs (6.2). `EXCLAVE_EXEC`, `EXCLAVE_EXECFN` and `EXCLAVE_COMM` are the launcher's own protocol, never an interface; the test scripts' inputs are `EXCLAVE_TEST_…`. |
| **syscall probe** | The differential test of 17 item 7: every trapped syscall, flag and path form, run under `bwrap` and under the launcher and compared case by case. "The probe" always means this one. |
| **fixture** | The exclave the suite runs on: a copy of the given exclave pruned to what the suite touches, kept under `build/fixtures/` and remade when the exclave, the suite or the tool changes (17). |

## 6. The exclave format

An exclave is a directory. This section describes what it holds, the
grammar of its two text files, and what the launcher reads from it.

### 6.1 Layout

```
gcc-13.exclave/
  gcc             -> tree/usr/bin/gcc-13    shortcuts the maker added, conveniences
  g++             -> tree/usr/bin/g++-13
  README                                    for whoever finds the exclave; the tool's text unless the maker wrote one
  .exclave/
    launcher                                ET_DYN, one per architecture
    manifest                                edited by people, 6.2; `exclave 1` when nothing is overridden
    hashes                                  6.4
  tree/
    usr/bin/gcc-13                          hard link to .exclave/launcher: the wrapper
    usr/bin/.real/gcc-13                    the original, byte-identical to upstream
    usr/bin/which.debianutils               a script: wrapped the same way
    usr/bin/.real/which.debianutils         #!/bin/sh ...
    usr/libexec/gcc/x86_64-linux-gnu/13/cc1         wrapper
    usr/libexec/gcc/x86_64-linux-gnu/13/.real/cc1   original
    usr/lib/x86_64-linux-gnu/libc.so.6      wrapper (it is executable); original in .real/
    usr/lib/x86_64-linux-gnu/libgmp.so.10   plain library, untouched
    lib -> usr/lib   lib64 -> usr/lib64   bin -> usr/bin
    etc/  var/
    home/  root/  boot/  mnt/  media/  srv/  tmp/  proc/  dev/  sys/  run/   empty placeholders
    opt/                                    a placeholder too, unless the packages fill it
    opt/musl-sysroot/                       a data directory: nothing wrapped, nothing checked
```

`tree/` is what the software sees as `/`. A **wrapper** is a hard link
to `.exclave/launcher` at an executable's own path; the **original**
it stands for is at `<dir>/.real/<name>` beside it. A **shortcut** is a
symlink at the top of the exclave into the tree, which the maker adds
by hand; it is a convention, recorded nowhere.

- Every file with an executable bit outside data directories is
  wrapped, ELF or script. The tool refuses to wrap a file its user
  could not execute, since the wrapper's mode is the launcher's.
- A symlink in the tree whose text names the exclave's own location is
  refused by `wrap` and `check`, with the `ln` that fixes it: moving
  the exclave would break it (3, goal 2). Packages never make one.
- A shortcut must name its file by a relative path that begins
  `tree/` and resolve, as the host resolves it, to a file of the tree:
  `wrap` and `check` refuse one that is absolute, goes another way
  (`../x.exclave/tree/...` breaks when the exclave is renamed),
  dangling or leaves the tree, whatever the exclave's path is spelled. The
  kernel follows a shortcut by the host's resolution, so a shortcut to
  a link in the tree with an absolute target, dpkg's `/usr/bin/cc ->
  /etc/alternatives/cc` in a tree from `debootstrap`, would run the
  host's program (13 item 37), and nothing hashes the shortcuts.
- `.real/` is a hidden sibling: from the host, `find`, `du`, `tar` and
  directory scanners see it, and inside the exclave no listing of the
  tree shows it, so a program sees upstream's tree (8.3), though it
  opens by name. Hard links cost nothing; a copy that
  breaks them, `cp -r`, `git` or `zip -y`, makes each wrapper a copy of
  the launcher, larger by the launcher's size per wrapper. Whether a
  file is a wrapper is read from the file (7.4.4), so both forms run.
  `git` also drops the empty placeholders, which changes the tree hash
  (6.4), and `zip` without `-y` copies a symlinked directory's contents
  in its place.
- Nothing in `tree/` is patched. Verification against upstream compares
  the files in `.real/`. From the host, tools see the launcher at every
  executable path; from inside, they see the original (7.4.4).
- An original run directly from the host, `tree/usr/bin/.real/gcc-13`,
  runs on the host's loader and may half-work; the wrapper beside it is
  the supported way.
- `.real/` is the only reserved name in the tree. The tool refuses a
  package that ships one. A file under `.real/` with no wrapper beside
  it is refused by `wrap`, `unwrap` and `check`, left alone by
  `relink`, and hashed under its own name by the tree hash, so that
  nothing under the reserved name is ever invisible.
- There is no cache directory, at any stage.
- `README` explains the exclave to someone who has never heard of
  exclaves and finds the directory. It says:
  - what an exclave is and needs, that running it changes nothing and
    leaves nothing behind, and that it is not a sandbox;
  - what each name at the top is;
  - how to run a program: by path, by a symlink, or through
    `.exclave/launcher`;
  - which paths are the exclave's and which the host's, and the fixed
    locale and time zone;
  - that setuid programs and `noexec` mounts do not work;
  - how to move, copy and remove the exclave;
  - how `b3sum` checks the hashes file's hashes without the
    tool, and what the tool's `check`, `unwrap`, `wrap` and `relink`
    do;
  - where the packages' licence texts are, and how to print the
    launcher's own.

  Its text is the tool's, the same in every exclave, so it says nothing
  the tree or the hashes file could say and cannot go stale against
  them. `wrap` and `relink` write it where the exclave has
  none, and leave a maker's own, or a shortcut of that name, alone.
  Like the shortcuts it is not hashed, and the launcher never reads it.
  The launcher run with no arguments points to it; a launcher outside
  any exclave says what it is and where it runs.
- `.exclave/` is a hidden directory so that a shortcut can never
  collide with a format file. The `.exclave` suffix on the directory's
  name is a convention, as the shortcuts are.
- An **unwrapped** exclave is the same directory before its executables
  are wrapped: `tree/` holds the tree as it came from the packages or
  from the maker's hands, `.exclave/hashes` lists the inputs, and there
  is no wrapper to trip over. `exclave wrap` wraps it and `exclave
  unwrap` unwraps it again; both are idempotent. A plain directory
  holding only `tree/` becomes an exclave when it is wrapped.

### 6.2 Manifest grammar

Requirements: UTF-8 text; every byte sequence a Linux path or file name
can contain, including spaces, newlines, quotes and invalid UTF-8, must
be representable; exactly one canonical spelling, so that formatted
files are byte-comparable; parseable by a few hundred lines of
freestanding C.

Lexical structure, shared by the manifest and the hashes file:

```
file     = { line LF }                 ; at least one record, the first `exclave 1` or `hashes 1`
line     = record | comment | blank
blank    = ""                          ; an empty line
comment  = "#" { utf8-char except LF }
record   = key { " " field }           ; exactly one space between fields
key      = lowercase-letter { lowercase-letter | digit | "-" }
field    = string | token
token    = 1*( letter | digit | "_" | "." | "+" | "-" )   ; integers and keywords only
string   = '"' { raw | escape } '"'
raw      = utf8-char except '"', '\', LF, code points below U+0020,
           and U+007F to U+009F
escape   = '\\' | '\"' | '\n' | '\t' | '\x' hex hex        ; hex lowercase
```

`utf8-char` is a well-formed UTF-8 sequence as defined by Unicode
Table 3-7: no overlong forms, no surrogates, nothing above U+10FFFF, no
bytes C0, C1 or F5 to FF. A byte order mark is a parse error. A comment
block may precede a record, which it belongs to; a comment after the
last record is a parse error.

Field types are fixed per key: the format version of `exclave 1` and
`hashes 1` is a token, and every other field, a path, a name, a package
version or a hash, is a string. A string denotes a byte sequence
through this encoding:

```
encode(bytes):
    '"' -> \"    '\' -> \\    LF -> \n    TAB -> \t
    a maximal well-formed UTF-8 sequence encoding a code point >= U+0020
        other than U+007F to U+009F                -> emitted raw
    any other byte                                  -> \xHH
```

Properties, stated precisely: `encode` is injective and
`decode(encode(b)) = b` for every byte sequence `b`. The parser accepts
non-canonical spellings such as `\x41` for `A`; `format` normalises
them, and `format` is idempotent. The property tests are those three
statements plus malformed variants fed to both parsers, the launcher's
and the tool's, which must agree (17 item 3).

Strict parsing, in the launcher and the tool alike: reject CR, tabs
outside strings, leading or trailing whitespace, multiple spaces, an
unterminated string, an unknown escape, uppercase hex, a missing final
LF, malformed UTF-8 anywhere including comments, an unknown key, a
wrong field count, a wrong field type, a duplicate of a key that may
appear once, a path that is not absolute, contains NUL, ends in a
slash other than `/` itself or has an empty, `.` or `..` component,
more than 256 `own` records, more than 32 `host` records or more than
32 `data` records, which are the sizes of the launcher's tables (8.1),
and a field of more than 4095 bytes, a string's counted as it decodes:
a path that long is `ENAMETOOLONG` to the kernel anyway, and the bound
lets the launcher hold the largest manifest the limits allow. A path
has one spelling because the visibility rule matches a path by it and
would silently match nothing else (13 item 34). Any error names the
line and the column, counting characters from 1, so that a column is
the same whatever the bytes before it; a field too long is named by
the character that takes it past the bound. Records are checked in the
file's order, each as it is read, so the launcher and the tool name the
same place for every error; nothing is guessed.

Canonical form, produced by `exclave format`, required by `exclave
format --check`, and enforced by `exclave wrap` before it wraps an
exclave:

- Each key is its own group. Groups appear in the fixed order below,
  separated by exactly one blank line; there is no blank line
  elsewhere; the `exclave` record is the first record.
- Within a group, records are sorted by the bytes of their first string
  field, then the second.
- A comment block belongs to the record that follows it and moves with
  it; a comment block before the first record stays at the top.
- Strings are always quoted.

Manifest keys, in canonical order:

```
exclave 1                                      format version, first record

cpu "x86-64-v3"                                the CPU level the binaries need (7.7); the architecture's baseline when absent

data "/opt/musl-sysroot"                       never executed or loaded: exec there is EACCES, a loader there is refused; not wrapped, not checked

host "/usr/local/share/fonts"                  a host path, at its own path

own "/etc/hosts"                               a path the exclave owns (removes a default host file or directory)
```

`exclave` and `cpu` may appear once; `data`, `host` and `own` may
repeat, and `cpu` holds no NUL. Without a `cpu` record the level is the architecture's
baseline, `x86-64` or `aarch64`, so an exclave that says nothing runs
on any machine of its architecture.

That is the whole manifest, and `exclave 1` alone is a valid one. There
is no way to make the tree writable, remap a host path to another name,
set an environment variable, or put a directory on `PATH`: a wrapper
script inside the exclave sets variables; a symlink inside the tree
does remapping, since `data -> /srv/data` resolves to a host-owned path
by the ordinary rule; and a symlink in the exclave's own
`/usr/local/bin` puts a program on `PATH`. Everything else the launcher
needs it reads from the tree (6.3).

**Environment.** The **border** is where a program passes from the
host into the exclave: a process with no exclave filter of its own
starting a wrapper, which the version probe detects (7.4.2). At the
border the launcher passes the environment through unchanged except
for two groups, and for its own `EXCLAVE_EXEC`, `EXCLAVE_EXECFN` and
`EXCLAVE_COMM`, which every launcher removes before a program runs,
inside the exclave too (7.4.5).

It removes the variables which steer the loader or libc to host files:
`LD_*`, `GLIBC_TUNABLES`, `GCONV_PATH`, `LOCPATH`, `NLSPATH`,
`RESOLV_HOST_CONF`, `HOSTALIASES`, `TZDIR`, `GCC_EXEC_PREFIX`,
`COMPILER_PATH` and `LIBRARY_PATH`. It removes `TZ` as well: a zone
name in it selects data under `/usr/share/zoneinfo` that the exclave
may lack, where glibc keeps the name with an offset of zero, so that
`TZ=Europe/Paris date +%Z` prints `Europe` in a tree without `tzdata`,
while `/etc/localtime`, an identity file (8.4), is the host's TZif
file, which any libc reads with `TZ` unset. The time zone inside an
exclave is therefore the host's, as its users are.

And it replaces three variables that name what the exclave decides for
itself, the same in every exclave on every host:

| Variable | Value | Why |
|---|---|---|
| `PATH` | `/usr/local/bin:/usr/bin:/bin` | a host tool in the user's home directory is never found by name |
| `LANG` | `C.UTF-8`, with `LANGUAGE` and every `LC_*` dropped | one UTF-8 locale with code-point collation and English messages, whatever the user's; locale data is in a format tied to the glibc that wrote it, so it must be the exclave's, and a variable that selects data the exclave may lack is a promise it cannot keep |
| `SHELL` | `/bin/sh` | programs that spawn the user's shell find one |

These are the values reproducible builds fix by hand. An exclave that
wants another locale or shell ships the data and a wrapper script that
sets the variable before it execs the program, since inside the border
nothing is touched (13 item 35); one that wants a fixed zone takes
`/etc/localtime` back with `own` and ships the zone there. `C.UTF-8` needs no locale
files on musl, nor on the reference machine's glibc 2.39, which accepts
`setlocale(LC_ALL, "C.UTF-8")` with an empty `LOCPATH`. glibc's release
notes date the built-in locale to 2.35, so for a glibc older than that
the static check warns when the tree lacks the `C.utf8` locale
directory (10.3).

Path-valued variables the user passes, `CPATH` or `SSL_CERT_FILE`,
resolve inside the exclave like any other path, which is why passing
them is safe. `SOURCE_DATE_EPOCH`, `MAKEFLAGS` and `CFLAGS` pass
through because their values are the build's to know, not the
exclave's. Inside an exclave, exec passes the rest of the environment
through untouched, so `ldd`, libtool wrappers, `fakeroot` and sanitizer
runtimes that set `LD_*` for their children work. `EXCLAVE_LOG` passes
through everywhere and is visible to the program.

**`EXCLAVE_LOG=<file>`** is the one run-time knob. It names a host
file by its absolute path. Every launcher of a run opens it for
itself, untranslated, so a relative path would be read against each
process's working directory, often inside the tree: a launcher refuses
one by name. It refuses by name a log inside its exclave too, whether
the path names the tree or `.exclave/` or a symlink leads there, and
makes a new log only where no symlink stands, so the log leaves the
exclave as it was. A log that cannot be opened is not kept, and the
run goes on. The launcher appends its decisions, as lines beginning
`launcher 2`, where the 2 is the log format's version, and every
translated syscall as `<syscall> <result>
<virtual path>`: one line, in one write unless the path needs more
than two escapes. A syscall whose path could not be resolved is logged
with the path as the program gave it. An exec is logged as `exec 0`
when the handler hands it to the kernel, since one that succeeds never
returns; one that fails adds a second line with its error. A newline
in a path is written as `\n`, a backslash as `\\` and every other
control byte, below `0x20` or `0x7f`, as `\x` and two lowercase hex
digits, so that no name can end a line or move a terminal's cursor;
the tool undoes the escapes when it reads a log (10.3, 10.4). Format
1, which escaped the newline and the backslash alone, is read as
well, since a run's log may hold an older exclave's launcher's lines
beside a newer one's. The launcher at the border also logs the working directory
it started in. The log changes nothing else. Every launcher of a run
writes a line when it starts, so a log several launchers share says
each one's version; `check` and `prune` refuse by name a log with a
launcher line of a later version rather than misread it.

### 6.3 What the launcher reads

The manifest and the tree. The launcher finds its exclave as the
nearest directory above its own path that holds `.exclave/manifest`,
so the manifest must exist; `wrap` writes `exclave 1` where there is
none. There is no generated file between the manifest and the tree.
An index of what the tool computed from the tree would go stale
whenever the tree is edited, and every record such an index could hold
is either unused by the launcher or readable from the tree in
microseconds.

- **The ownership set** (8.1) is every top-level entry of `tree/` that
  is not an empty directory, read at startup with one directory
  listing per entry, plus the manifest's `own` records. An edited tree
  therefore needs nothing refreshed, and there is no stale-index state.
- **The loader** is each program's own `PT_INTERP`, resolved in the
  exclave as the kernel would resolve it in a chroot (7.3). That every
  ELF in an exclave names one loader, and so one libc, is the tool's
  static check (10.3), not a run-time rule.
- **The architecture** is the ELF header of the program, which the
  loader reads anyway. A foreign original fails with a message naming
  the file, and an exclave built for another architecture does not
  start at all, since its launcher is of that architecture too.
- **The host table** (8.4) is the eleven identity files and the three
  identity directories, compiled into the launcher, minus any that the
  manifest's `own` records name, plus the manifest's `host` records.

The `data` records are read for enforcement: no file under a data
directory is executed, and none is a loader (7.3, 7.4.5).

If the tree and the manifest disagree, there is nothing to decide: the
manifest holds only what the tree cannot say. Reading fails closed: a
top-level directory the launcher cannot list is the exclave's, and a
failure that is not the directory's own, no descriptor left or an I/O
error, is fatal with a message, never a silent answer of "the host's".

### 6.4 Hashes file

```
hashes 1

tool "0.0.1+1a2b3c4"

launcher "b3:<blake3-256 of .exclave/launcher>"

pkg "gcc-13" "13.3.0-6ubuntu2~24.04.1" "amd64" "b3:<blake3-256 hex of the .deb>"
pkg "libc6" "2.39-0ubuntu8.8" "amd64" "b3:..."

manifest "b3:<blake3-256 of the manifest bytes>"

tree "b3:<blake3-256 of the serialised listing>"
```

The hashes file uses the grammar of 6.2; its keys, in canonical order,
are `hashes`, `tool`, `launcher`, `pkg`, `manifest` and `tree`, each
once but for `pkg`, whose four strings are a package's name, version,
architecture and hash. `tool` names the build of the command that
wrote the file: the project's version and the commit it was built
from, `-dirty` when the checkout had uncommitted changes, as `exclave
version` prints it and the launcher's `.exclave.version` section
carries it (7). It is a record of an exclave's inputs and its
output, not a way to obtain either.

| Command | What it does to the hashes file |
|---|---|
| `unpack` (10.1) | writes the file with only the `pkg` records, one per package file it was given, with the name, version and architecture from the file's own control data and the hash of the file |
| `wrap` | adds the `launcher`, `manifest` and `tree` hashes |
| `unwrap` | drops those three, since an unwrapped exclave has no output yet |
| `prune`, `relink` | recompute the `launcher` and `tree` hashes from the exclave as it then stands and keep the `manifest` hash, which neither changes |
| `check` | compares the tree with the recorded hash and reports a difference |

Nothing reads the hashes file to rebuild: a rebuild is the same files
given to the same tool, and the hashes say whether the files were the
same and whether the tree came out the same. A hash verifies; a name
locates; and locating is the job of whatever fetched the files, whose
record of origin, mirror, snapshot date or checkout, lives outside the
exclave. An exclave wrapped from a tree made otherwise has no `pkg`
records and has a tree hash. A hashes file with no `tree` record marks
an unwrapped exclave.

All hashes are BLAKE3-256, written as `b3:` followed by lowercase hex,
so `b3sum` checks any of them without the tool. BLAKE3 hashes one file
on many cores, so a large file is not a tree hash's floor (10.5). The
`tree` hash is the BLAKE3-256 of a byte string built from every entry under
`tree/` except `.real/` directories, with originals in place of
wrappers and a `.real/` file with no wrapper beside it under its own
path (6.1), sorted by the bytes of the relative path. For each entry
the string holds:

```
relative path, NUL, one of f x d l, NUL,
    f, x: the lowercase hex BLAKE3-256 of the content
    l:    the link target bytes
    d:    nothing
NUL
```

`x` is a regular file with any executable bit. Other mode bits, mtimes,
ownership, xattrs and hard-link identity are excluded, so the hash
survives `cp -a`, `tar` and extraction, though not `git`, which drops
empty directories, and it is the same for an exclave wrapped or
unwrapped. Every file must be readable for the hash to be computed. The
launcher and `.exclave/` are excluded from the tree hash; the launcher
has its own record. `exclave hash` prints the tree hash of an exclave
as it stands, and given a file the file's hash as these records write
it, so the command checks any of them with nothing beside it.

### 6.5 The formatter

`exclave format` parses strictly, re-encodes every string, orders the
records, and writes the canonical file; it tells a hashes file from a
manifest by its first record, not by the file's name. `exclave format
--check` names each file that is not canonical and fails. `exclave
wrap` refuses a manifest that is not canonical, since its hash goes
into the hashes file. The launcher enforces the lexical and typing
rules on the manifest it reads, accepts non-canonical spellings and
order, and refuses to run on any error.

### 6.6 Single-file form

There is none. An exclave is a directory, and `tar` makes it one file.
A launcher with an appended archive that extracts itself on first run
would need a cache directory, which the format has none of (6.1), and
a `noexec` temporary directory would make its failure ugly.

### 6.7 Versions and compatibility

What one build of exclave reads that another build wrote carries a
version of its own, and from the first release on each version keeps
the promise below; builds before it promise nothing (2).

| What | Its version | Written by | Read by |
|---|---|---|---|
| The layout: `.exclave/` holding `launcher`, `manifest` and `hashes`, `tree/`, an original in `.real/` beside its wrapper (6.1) | the manifest's | `wrap`, `unwrap`, `relink`, `prune` | the launcher, every command |
| The manifest (6.2) | `exclave 1` | people, `wrap` | the launcher the exclave carries, every command |
| The hashes file and the tree hash (6.4) | `hashes 1` | `unpack`, `wrap`, `unwrap`, `relink`, `prune` | `check`, `hash`, anyone with `b3sum` |
| `EXCLAVE_LOG` (6.2) | the number in each `launcher` line, 2 | every launcher of a run | `check`, `prune`, which read 1 as well |
| One launcher running another's programs (7.4.2) | the filter version and the page generation, which the launcher's note carries (7) | each launcher | each launcher |
| The `exclave` command's commands and their arguments (10) | the project's, `VERSION`'s | | people and scripts |
| `exclave-fetch`'s commands, their arguments as `--help` lists them, its checks, and its cache's layout, `KIND/DIGEST` (10.1) | the project's, `VERSION`'s | `exclave-fetch` | people, scripts, a later `exclave-fetch` sharing the cache |

The rules every version keeps:

- **A reader refuses by name a version it does not know**, rather
  than reading it as one it does: both parsers refuse a manifest or
  hashes file of another version, `check` and `prune` a log whose
  launcher lines carry another number, and of two launchers of
  different page generations the later refuses the earlier, nested
  either way (13 item 45).
- **A later build reads what every earlier build of the same version
  wrote**: a later command checks, hashes, prunes, relinks, unwraps
  and wraps an earlier one's exclave, reads its launchers' logs, and a
  later launcher nests with an earlier one either way, the newer
  filter reused and the older stacked under it (7.4.2).
- **Within a version, only what an earlier reader passes over is
  added**: a log line of a new kind; a syscall the filter newly traps,
  which an older handler under a newer filter answers `ENOSYS`, so only
  one whose `ENOSYS` a library falls back from (7.4.2). A trap without
  that fallback moves the page generation instead, as does any change to the
  layout of the page's handler-call slot, whose return's address the
  filter names (7.4.2), so that the two
  launchers refuse each other's nesting by name rather than an older
  one failing the call: the listings version 7 traps and the `fstat`
  version 8 traps have none, and came before any release.
  Anything an earlier reader would refuse or read otherwise moves the
  version: a new manifest key is `exclave 2`, since the strict
  grammar refuses an unknown key, and a new hashes key, hash function
  or serialisation of the tree is `hashes 2`.
- **A later `wrap` or `relink` adds only its placeholders**: an
  earlier exclave wrapped again by a later build may gain the empty
  files a later build ships at its identity paths (8.4), and the
  directories that hold them, and every other path stays as the
  earlier build wrote it; adding an identity file moves no version.
- **The launcher reads only its own exclave's manifest**, wrapped with
  it, so a newer key reaches an older launcher only through `relink`
  with that launcher, which refuses the manifest by its version.
- **The command's version names a build, not a format**: `exclave
  version` and the hashes file's `tool` record give it with the commit
  (6.4), and the versions above say what the build reads.

The baseline is the first release: `scripts/inputs` records its
command and one exclave it ships by URL and BLAKE3-256 and puts them in
its `DIR/baseline`, and `test/compat_test.py`, a step of the commit
gate, holds every later build to these rules against them (17). Given an earlier build of another kind, it fails as
it should: against a build from before the log carried its version, on
the log.

## 7. The launcher

The launcher is one static, freestanding, `ET_DYN` binary with no
libc and no `PT_INTERP`; it relocates itself. Every
executable in an exclave's tree is a hard link to it, a *wrapper*, and
the program a wrapper stands for, its *original*, sits beside it in
`.real/` (6.1). Besides its code it carries:

- **An ELF note** in a `.note.exclave` section, `exclave`, holding two
  words, the *page generation* and the filter version (7.4.2), by which
  one launcher recognises another (7.4.5).
- **The MIT licence text**, in a `.exclave.license` section that is not
  loaded, since the licence's text goes with every copy.
- **Its version**, in `.exclave.version`: `exclave` and the build's
  name, the project's version and the commit it was built from, as
  `exclave version` prints it and the hashes file's `tool` record says
  it (6.4); `readelf -p .exclave.version` shows it.
- **gdb's script**, in `.debug_gdb_scripts`, and six exported names for
  it to read (7.6).

The build of either architecture strips everything else and fails if
any of these did not survive; `build/launcher.debug` and
`build/launcher-aarch64.debug` keep the symbols.

### 7.1 Why freestanding and why `ET_DYN`

Freestanding, because the `SIGSYS` handler (7.4) runs inside arbitrary
programs, whose thread-local storage, `errno` and stack canary belong
to another libc or to none, so it must make raw syscalls through the
syscall page (7.4.2); one discipline for the whole binary avoids an
invisible boundary, and the launcher runs whatever the host's libc.

`ET_DYN`, because the kernel then places the launcher at a random
base, so nested exclaves and one launcher loading another never
collide, and the loader (7.3) maps `ld.so` and originals without fixed
addresses around it. The syscall page is the one fixed address.

The build is `-nostdlib -ffreestanding -fno-stack-protector -fPIC
-fvisibility=hidden`, linked `-shared -e _start -Bsymbolic`, and fails
if the result has a PLT or an undefined symbol, a call left for a libc
or libgcc; startup applies the relative relocations from `_DYNAMIC`
itself. x86-64 adds `-mno-red-zone`, since every syscall is a `call`
into the page, which pushes below the stack pointer; aarch64 adds
`-ffixed-x28` (7.5.3). Architecture-specific code lives in `src/sys.h`,
`src/common.h` and a few `#if` blocks: the syscall instruction and
table, `_start`, the relocation type, the signal-frame offsets, the
restorer, the loader's final jump and the CPU check. x86-64 and aarch64
build from the same sources, and each launcher runs only programs of
its own machine (7.3).

### 7.2 Startup

The kernel has executed the launcher at some path. The launcher:

1. Maps the syscall page and relocates itself (7.4.2).
2. Runs the version probe for an inherited filter (7.4.2), and refuses
   by name one older than version 6, which would trap its every
   syscall.
3. Unblocks `SIGSYS` in the inherited mask, since a parent that blocks
   signals in its children would otherwise kill the first trap
   (7.5.1); raises a soft descriptor limit below 16 to the hard one for
   its own opens (7.4.5); opens `EXCLAVE_LOG` if set (6.2).
4. Reads `/proc/self/exe` and walks up until a directory holds
   `.exclave/manifest`; that directory is the exclave, and without one
   the launcher says so and exits.
5. Parses the manifest (6.2) and checks `cpu` (7.7).
6. Decides what it runs: a wrapper, if `/proc/self/exe` lies below
   `tree/`, the program's virtual path being the path below it;
   otherwise a program named by `EXCLAVE_EXEC` (7.4.5); otherwise the
   positional entry (below). The wrapper case is decided first, so the
   variable is inert in anyone's environment.
7. With no inherited filter, this process is the *border* and the
   environment policy of 6.2 applies; inside, only the launcher's own
   variables are removed (7.4.5).
8. Reads the top level of `tree/` for the ownership set (8.1), resolves
   the identity files and directories (8.4) and the working directory
   (8.1 rule 4), and
   compiles the visibility rule into one table.
9. Installs the `SIGSYS` handler, then the filter, unless one of this
   version or newer is inherited, which is reused (7.4.2).
10. Loads the original and its loader (7.3) and jumps. A wrapper whose
    original is a script parses its `#!` line as 7.4.5 does and loads
    the interpreter's original, after the checks an exec of the
    interpreter makes (below).

A wrapper run directly from outside any exclave goes through exactly
these steps; shortcuts (6.1) point at wrappers and add nothing.

**The positional entry.** `gcc.exclave/.exclave/launcher PROGRAM
ARGS...` runs a program without a wrapper, a host tool or a built
output, inside the exclave, from outside or inside. It re-execs itself
once as a handler does for such a program (7.4.5), with `PROGRAM`
taken as `execve` would take it, so that the program's `argv`,
`cmdline` and `comm` are its own. The re-exec'd launcher resolves the
target and makes an inside exec's checks in their order: a program in
a data directory, a directory or a special file is refused, and the
kernel's `X_OK` answer is final; each interpreter a script names is
checked the same way before it is loaded, as the kernel opens it to
run. The exit status is a shell's, 126 for a file that exists and
cannot run, 127 for one that does not. A target
that is a wrapper is exec'd as itself, by the name the caller spelt,
relative or absolute, through `./`, `../` or host symlinks, so that
the kernel gives the program its identity, when the kernel
would reach that wrapper by that name. An absolute link of the tree on
the way would lead the kernel to the host's file instead, so then the
wrapper is exec'd by its resolved path, and `comm` is the name the
link leads to. Only a program without a wrapper reaches the loader.
Without an argument the launcher says what it is; it takes no other
argument and no flag.

### 7.3 The loader

The loader replicates the kernel's `load_elf_binary` for the original
and its loader. It takes what the kernel takes, an `ET_EXEC` or an
`ET_DYN` whose `e_machine` is its own, the class byte not read, as the
kernel's `elf_check_arch` does not read it, with program headers of the
kernel's size. It maps each `PT_LOAD`, an `ET_EXEC` at its address with
`MAP_FIXED_NOREPLACE`, checked since an older kernel takes it as a hint,
an `ET_DYN` at a base chosen by reserving its span. Segments are rounded
to the kernel's page size from `AT_PAGESZ`, as the kernel rounds them,
16 or 64 KB on some aarch64 kernels (13 item 43). What the kernel meets
past its point of no return kills the new image with `SIGSEGV`
(`bprm_execve`), and so does the loader, with a message naming the
segment first: one with file bytes whose address and offset differ within
a page, which the kernel's own `mmap` refuses (a segment without file
bytes is memory at its page whatever its offset, as `elf_load` places it
since 6.7), one with more file than memory or past
the address space (`EINVAL` in `load_elf_binary`), one at an address the
kernel will not map, zero or one already in use, no `PT_LOAD` at all,
and a `.bss` the kernel cannot give; the oracle's `exec_elf` measures
each against the kernel (17 item 4). An address already in use is
refused on every machine, as x86-64's kernel refuses it; aarch64's
kernel maps a second, identical `PT_LOAD` over the first and runs the
image. The loader zeroes the tail of the last
file-backed page, maps anonymous memory for the rest of `.bss`, and
makes the stack executable where `PT_GNU_STACK` asks. It builds the
initial stack with `argc`, `argv`, `envp` and a copy of the launcher's
own auxiliary vector with `AT_PHDR`, `AT_PHENT`, `AT_PHNUM`, `AT_ENTRY`,
`AT_BASE` and `AT_EXECFN` overridden to describe the original, sets
`comm` (7.6), and jumps to the loader's entry, or the original's for a
static binary. `AT_EXECFN` is the name the program was exec'd by, as the
kernel spells it (7.4.5). It takes only 64-bit ELF of its own machine.

The loader is whatever the original's `PT_INTERP` names, resolved in
the exclave as the kernel would resolve it in a chroot and opened
through the wrapper redirect (7.4.4), since `ld.so` is itself a
wrapper; `ldd`'s `ld.so --verify` and a direct `ld.so --list` load it
as an original with no interpreter. The resolved loader must be the
exclave's own file, one whose virtual path is an exclave path outside
every data directory. An original naming a loader the exclave lacks, or
one on a host path (a Nix or Guix binary, anything linked with
`--dynamic-linker`), fails with a message naming it before anything
runs, so there is never a second loader in the world. That every ELF in
an exclave names the same loader is the static check's rule (10.3);
that the loader is the exclave's is the launcher's.

### 7.4 The resident translator

#### 7.4.1 Idea

Every fact a program learns about its filesystem arrives through a
path-taking syscall. A seccomp filter returns `SECCOMP_RET_TRAP` for
those; the `SIGSYS` handler, in the same process, canonicalises the path
in virtual space (7.4.4), applies the visibility rule (8.1) and the
read-only rules (8.2), re-issues the call through the syscall page, and
writes the result into the saved result register of the signal frame,
`rax` or `x0`. Syscalls without a path, the overwhelming majority,
never trap. With `EXCLAVE_LOG` set the handler writes one line per trap
(6.2).

#### 7.4.2 The filter

One classic-BPF program, installed at the border or over an older
version's, and inherited across `fork` and `execve`. A foreign syscall
ABI, an `arch` other than the launcher's own or the x32 bit, kills the
process: loud, never a silent host access.

**The syscall page.** A call whose instruction pointer lies in the page
at `0x7fe00000` is allowed, but for its judge slot (below). Before
anything else runs, every launcher maps that page with
`MAP_FIXED_NOREPLACE`, writes five slots into it and makes it
read-only and executable (on aarch64 after flushing the instruction
cache): at offset 0 `syscall; ret` (`svc #0; ret`), through which every
later syscall of the launcher is made by a `call` into the page, a
`blr` on aarch64; at 16 the same two instructions, the *judge slot*;
at 32 the signal restorer, `rt_sigreturn` by a bare instruction,
which the kernel jumps to after the handler and which a call would
break, since the kernel reads the frame from the stack; at 48 the
*handler-call slot*, 32 bytes, from which a trampoline calls a program's
handler: the call, then the restorer's own two instructions, which the
handler's return runs and the filter answers with an error for the one
instruction pointer after them, 60 bytes into the page on both
architectures, then a jump back into the trampoline (7.5.7); and at 80
the *re-issue slot*, 32 bytes, through which the handler makes every
call on the program's behalf: it reads the trap's record first and,
when a program's handler has redirected the program, makes no call and
answers `EINTR`, and after the call it stores the answer in the record
(7.5.7). A call's
instruction pointer, the address after its syscall instruction, lies in
its own slot on both architectures. Only the bootstrap that maps the
page and the version probe below use a bare syscall instruction in the
launcher's text; after an `execve` under a program's own filter the
bootstrap's `mmap` and `mprotect` are judged by that filter as a
native dynamic program's loader would be, and the probe is allowed by
the filter's prologue (below).

The address is a constant, so the filters of any number of ancestor
generations agree after `execve`. It lies above program images, which
linkers start low (GNU ld and Go's x86-64 linker at `0x400000`, Go's
aarch64 linker at `0x10000`); below `0x7fff8000`, where ASan's x86-64
shadow begins, so every sanitizer counts it as the program's own low
memory; outside the ranges Wine's preloader reserves; and 64
KB-aligned, for aarch64 kernels with 64 KB pages. If the page cannot be
mapped the launcher says so and exits (`EEXIST` meaning another
launcher is resident); a program whose image covers it cannot run in an
exclave (13 item 24). It is an address rather than a marker in a spare
register, which a signal handler interrupting a launcher syscall would
inherit, sending its own first path syscall to the host untranslated.
The page at a fixed address is a gadget: a program can trivially exempt
itself, from the translation and from its own seccomp filter alike, by
jumping through it, so neither contains an attacker with code execution
in the process; an exclave is not a security boundary (3, 13 item 5).

**No forced speculation mitigation.** The filter is installed with
`SECCOMP_FILTER_FLAG_SPEC_ALLOW`, or without it where a kernel before
4.17 answers `EINVAL`, since without the flag a filter forces
Speculative Store Bypass Disable on the process and its descendants
wherever the kernel's default is `spec_store_bypass_disable=seccomp`,
slowing code whose loads follow its stores by up to several times
(16.5). Installation sets `PR_SET_NO_NEW_PRIVS` first, as seccomp
requires without privilege (13 item 3), and falls back to
`prctl(PR_SET_SECCOMP)` before kernel 3.17.

**Refusals.**

- `clone3` returns `ENOSYS` (7.5.5). Honouring it is not an option:
  `CLONE_CLEAR_SIGHAND` removes the handler in the child, whose own
  `execve` then traps before any handler exists. Its own extensions,
  `CLONE_INTO_CGROUP` and `set_tid`, serve container runtimes, which
  are out of scope; `CLONE_PIDFD` is available through `clone` from 5.2.
- `io_uring_setup` returns `ENOSYS`, so file operations cannot bypass
  translation.
- A program's own filter is installed for it, below, or refused with
  `ENOSYS`.
- The rest are in the table of 7.4.3.

**A program's own filter.** `seccomp(2)` and `prctl(PR_SET_SECCOMP)`
trap, but for the two queries, `SECCOMP_GET_ACTION_AVAIL` and
`SECCOMP_GET_NOTIF_SIZES`, which stay allowed. The kernel runs every
filter of a thread on each call and takes the action of highest
precedence (`seccomp_run_filters`), and the launcher's trap outranks a
program's `ERRNO`, so the program's filter alone would never refuse a
call the launcher translates. The handler therefore installs, on the
program's behalf, a filter built around the program's, and lets the
kernel judge each trapped call by it:

- **The installed filter** is a prologue, the program's body and an
  epilogue. The prologue answers the probe, `uname` with the magic
  argument, before the body can: allowed from anywhere, so that the
  version probe of a launcher exec'd under the filter reads the
  launcher filter's answer, and `ERRNO(MARK_PRESENT)`, 4093, from the
  judge slot. It then clears A, as the kernel starts a program, with
  `and #0`, and falls into the body. The body is the program's, instruction for
  instruction, but for each return of an action other than `ALLOW`,
  which becomes a jump to a stub that loads the action into X and jumps
  to the epilogue: there a call from the syscall page, the launcher's
  own and its restorer's, is allowed, and one from the judge slot or
  from anywhere else gets the body's action. The instruction pointer is
  read only on that path, so a number the program's body allows by
  itself stays a constant for the kernel's action cache, as natively,
  but for `uname`, whose argument the prologue reads. The cache models
  only loads of the number and the architecture, jumps on constants,
  `and` with a constant and a constant return
  (`seccomp_is_const_allow`), which is why A is cleared with `and #0`:
  an `ld #0` would put every number out of its reach, in the process
  and its descendants. Jumps are
  relative and the kernel bounds them within the body, so each stays
  where the body put it; the handler checks those bounds itself, and
  that the body ends in a return, since inside a longer program the
  kernel's own check would not see a body that runs off its end.
- **The judge.** In a process where a program's filter may exist, the
  handler first re-issues each trapped call unchanged, its number and
  six arguments, from the judge slot. The launcher's filter answers any
  call from there with `ERRNO(MARK_NONE)`, 4094, ahead of the page's
  `ALLOW`, so a judge call never executes: the kernel evaluates the
  thread's whole chain, the program's filters, any outer filter such as
  Docker's, and the launcher's, and takes the action of highest
  precedence and, among `ERRNO` answers, the newest filter's. A
  program's filters are newer than the launcher's, so the judge returns
  `-MARK_NONE` when none of them refuses the call, and the handler
  translates it as for any program; otherwise the errno, or 0, of the
  refusal, which is returned to the program untranslated. Any `ERRNO`
  outranks an `ALLOW` in whichever filter, as natively. A `KILL` for
  the original call outranked the trap and the kernel killed the
  process before the handler ran; one that a concurrent install by
  `TSYNC` adds is the kernel's to apply. An outer filter's `ERRNO`
  applies to the re-issue as it did before.
- **The flag.** Whether to judge is one word of the launcher's data,
  copied by `fork` and shared by threads, set before an install, so
  that a thread a `TSYNC` install reaches is judged from its next trap,
  and never cleared: a thread whose own chain lacks the filter, or an
  install that fails, costs a judge call that answers `-MARK_NONE`. A
  process that installs no filter makes no judge call. After an
  `execve` the new launcher, under an inherited filter of version 10 or
  later, issues the probe from the judge slot, which a program filter's
  prologue answers `MARK_PRESENT`, and sets the flag. A launcher newer
  than the filter it finds stacks its own over the program's, whose
  judge answer would then be the newest and hide the program's
  refusals, so it refuses to start under one, by name; and while the
  flag is set, the handler refuses to exec a launcher whose note gives
  a filter version below 10, or none, since its handler would re-issue
  every trapped call through the page unjudged: `EACCES`, the kernel's
  answer for an exec a security policy refuses, and a line in the log.
- **Installed as given.** The re-issue is the form the program used,
  `seccomp` or `prctl`, so kernels before 3.17 keep working, with the
  program's flags: `TSYNC`, `TSYNC_ESRCH`, `LOG` and `SPEC_ALLOW`. Its
  answer is returned, `TSYNC`'s failure the offending thread's id. The
  kernel's refusals that do not depend on the body's instructions come
  first, in its order: the flags, by asking the kernel with no program
  (`EINVAL`, or `EFAULT` that the handler takes as their acceptance),
  the header's address (`EFAULT`), a
  length of 0 or above 4 096 or a null program (`EINVAL`), the
  program's address (`EFAULT`), the jump bounds and the final return
  (`EINVAL`); then the launcher's refusals below; then the kernel's
  checks of the instructions themselves, an opcode it does not admit, a
  misaligned load, a read of scratch memory before a write
  (`EINVAL`), on the installed filter, so a body with faults of both
  kinds is `ENOSYS` here where natively it is `EINVAL`. `LOG` on a
  kernel before 4.14, which kills on it, is refused as well, by asking
  the kernel whether the action is available. The body and the built
  filter live in a transient anonymous mapping, up to 64 KB, made and
  removed by the install.
- **Refused with `ENOSYS`**, visibly, at install: strict mode in either
  form; the flags `NEW_LISTENER`, `WAIT_KILLABLE_RECV` and any the
  launcher does not know; a return of A; any action but `ALLOW`, `LOG`,
  `ERRNO`, `KILL_PROCESS` and `KILL_THREAD` (`TRAP`'s `SIGSYS` is the
  launcher's, 13 item 23; `TRACE` and `USER_NOTIF` need a supervisor;
  an undefined action kills); `ERRNO(MARK_NONE)`; a read of the
  instruction pointer, which a judged call would see as the judge
  slot's; and a body longer than the room the prologue, 14
  instructions, the epilogue, 10, and two per distinct action left
  leave of 4 096 (13 item 5).

**Argument checks.** `rt_sigaction` traps only when it installs an
action; a query passes to the kernel (7.5.7). `rt_sigprocmask` and `rt_sigsuspend` always trap; `ppoll`,
`pselect6`, `epoll_pwait`, `epoll_pwait2` and `io_pgetevents` trap when
they carry a mask. `ioctl` traps for `FS_IOC_SETFLAGS` and
`FS_IOC_FSSETXATTR`, the `chattr` requests, and nothing else. `ptrace`
traps for `PTRACE_TRACEME`, request 0, and no other request: a check
by equality on the whole word, where the others trap on a non-zero
argument, for a `vfork` child's request, which waits for its exec
(7.4.5).

**Two stages.** The first is a binary tree on the syscall number alone,
whose leaf for every number the rule does not single out is `ALLOW`, so
the kernel's action cache (5.11) proves those syscalls allowed and
skips the filter, and a kernel without the cache runs about a dozen
instructions. The other numbers go to the second stage, the rule in
order: the argument checks that can only allow (an `ioctl` other than
`chattr`'s, a wait without a mask, a
`ptrace` request other than `PTRACE_TRACEME`, a `prctl` other than
seccomp's, the two `seccomp` queries) and the version
probe; an `rt_sigreturn` from the handler-call slot, answered with an
error, and every other `rt_sigreturn`, allowed; the judge slot and the
syscall page; the refusals; then the trap. On x86-64 the program is
291 instructions and 372 of the 472 numbers up to the ceiling are
allowed by number alone; `rt_sigreturn`, which the cache proves allowed
no longer, runs the second stage at every signal's return, the trap's
own included (16.2). 16.3 gives why a tree and what
an untrapped syscall costs. `test/filter_test.c` runs the program in an
interpreter against the rule written out on its own, for every number
and the arguments each check reads, and `test/syscalls.py` matches the
lists in `src/filter.c` against the running kernel's table, so a new
path-taking syscall is noticed rather than discovered (17).

**The ceiling.** A syscall numbered above the filter's table, whose
last entry is 471 (`rseq_slice_yield`), traps and is answered `ENOSYS`,
like any trap the handler does not know, so a path-taking syscall a
future kernel adds cannot reach the host untranslated. The table test
reads the running kernel's own table where its headers are installed,
and asks the running kernel above the table, rather than trusting a
userspace header, which lags the kernel by years: a syscall the
running kernel has and the table does not classify fails the gate's
unit step until it is.

**Versioned reuse.** The filter answers a `uname` whose argument is a
magic 64-bit value with `SECCOMP_RET_ERRNO` carrying `0x800` plus its
version. The *version probe* at startup issues that `uname` with a
bare syscall instruction, not through the page: an errno of that form
names the newest inherited filter, `EFAULT` none. Since every filter in
the stack runs on every syscall, a launcher installs its own only when
nothing equal or newer is inherited. A launcher under a newer filter
may then receive traps for syscalls it does not know; it answers them
`ENOSYS` and never re-issues them, since every path-taking syscall the
kernel has added has a libc fallback and a re-issue would be an
untranslated host access.

The version moves whenever the trap set grows or the syscall page
moves: 7 added the listings, `getdents64` and `getdents`,
8 `fstat`, for a directory's `.real/` (8.3), 9
`ptrace(PTRACE_TRACEME)`, for a `vfork` child's request (7.4.5), 10
the judge slot and the installs of a program's own filter, which
earlier versions refused in the filter, and 11 the page's handler-call
and re-issue slots and the error for an `rt_sigreturn` from the
handler-call slot (7.5.7); a launcher's note carries its
filter version as a second word from 10 on. The filter names the handler-call slot's instruction pointer, so
the slot's layout is fixed for the page generation, as the page's
address is. `test/syscalls.py`
records a digest of the set, the page and its judge slot each version
shipped with and fails when any changes under the same version.
Filters before 6 allow a page at another address, so
neither launcher can run under the other's filter: a launcher under a
filter older than 6 refuses by name at startup, and a handler sends a
launcher whose note carries a page generation older than its own, or
no word, to its own child, which refuses it by name (7.4.5, 13
item 45). `scripts/build` also builds `build/launcher-old`, the same sources at
version 3, without `bind` and `connect`, which version 4 added, and
without the judge slot's rule and the installs, which it refuses; the
regression of 17 item 4 nests it inside the current launcher, where it
answers `ENOSYS` for every trap a later version added, which version 3
shows as well as any later one would.

#### 7.4.3 Intercepted syscalls

| Group | Syscalls | Treatment |
|---|---|---|
| Path, follow final symlink | `openat`, `openat2` (below), `newfstatat`, `statx`, `faccessat`, `faccessat2`, `truncate`, `chdir`, `statfs`, `utimensat`, `fchmodat`, `fchmodat2`, `fchownat`, `*xattr` and the `*xattrat` family, `file_getattr`, `file_setattr`, `inotify_add_watch`, `fanotify_mark`, `execve`, `execveat`, and their legacy forms | translate, apply the read-only rules, re-issue |
| Path, no follow | `readlinkat`, `l*xattr`, `lchown`, `lstat`, `linkat`'s old name unless `AT_SYMLINK_FOLLOW`, `open` with `O_NOFOLLOW` | translate all but the final component, which a trailing slash follows, since the slash asks for a directory (`lookup_last`) |
| Path, on the parent | `unlinkat`, `mkdirat`, `mknodat`, `symlinkat` (the link's path; its target is stored verbatim), `renameat2`, `linkat`'s new name, `bind`, `open` with `O_CREAT` | translate all but the final component, which the kernel looks up by name in its parent and never follows (`filename_parentat`), a trailing slash included: the slash is the call's to judge, `EISDIR` for `O_CREAT` before any lookup, `EEXIST` for a create of what exists, a symlink included, `ENOENT` for a non-directory create of what does not, `ENOTDIR` for `rmdir` and `unlink` of what is not a directory, and `rename`'s own rules; `O_CREAT` without `O_EXCL` or `O_NOFOLLOW` then follows what the lookup found |
| Descriptor-addressed | any of the above with an empty path and `AT_EMPTY_PATH`; a NULL path where the kernel accepts one (`fstatat` and `statx` since 6.11, the `*xattrat` family, `file_getattr` and `file_setattr` under `AT_EMPTY_PATH`, `utimensat(fd, NULL, ...)` behind `futimens`) and `EFAULT` elsewhere (the empty-path forms are behind Rust's `File::metadata` and `fexecve`); and `fchmod`, `fchown`, `fsetxattr`, `fremovexattr`, `fstatfs` and the `chattr` ioctls (`ftruncate` needs a writable descriptor, which an exclave file never has) | resolve the descriptor through `/proc/self/fd`, no component walk, no trailing-slash rule, and re-issue the call through the descriptor as given, so that the kernel's rule for `AT_EMPTY_PATH` is its own (`linkat` wants `CAP_DAC_READ_SEARCH` before 6.10); `AT_FDCWD` is the working directory; apply the read-only rules; an `O_PATH` descriptor is `EBADF` for the five attribute calls, as natively; for `execveat` a descriptor on a symlink itself is `ELOOP`, and one on anything but a regular file, a pipe or a socket included, is `EACCES`; an original's descriptor given to `execveat` is mapped back to its wrapper; a descriptor whose file has no path (a pipe, a socket, a memfd, an unlinked file or directory) names nothing the exclave owns, so `linkat` with `AT_EMPTY_PATH` on one is the kernel's own through the descriptor, a link of the file, `EXDEV` or `EPERM`, after the read-only rule for the new name |
| A path inside a structure | `bind` and `connect` with an `AF_UNIX` address whose path is not abstract | below |
| A listing of the tree | `getdents64` and `getdents` on a directory of the tree | the kernel's listing, written into the program's buffer and rewritten without `.real/` (8.3) |
| A directory's stat | `fstat`, and every stat above, of a directory of the tree that holds `.real/` | the kernel's answer with a link fewer and, on ZFS, btrfs and tmpfs, a size an entry smaller (8.3) |
| Reverse-translate results | `getcwd`; `readlinkat` of `/proc/self/{exe,cwd,fd/*}` and of the process's own pid; `readlinkat` of an identity file; `statfs` and `fstatfs` on exclave paths | strip the tree's prefix, and the `.real/` of an original, which then names its wrapper; answer the program's virtual path for `exe` on the loader path (7.6); answer the host's link text for an identity file (8.4); report `ST_RDONLY`. Any other link's text is returned as stored, as the kernel returns it |
| Self-defence | `rt_sigaction` with a new action; the mask-carrying calls above | scrub `SIGSYS` from the mask (7.5.1), with no canonicalisation |
| Deferred to the exec | `ptrace(PTRACE_TRACEME)` in a `vfork` child | recorded and answered 0, `EPERM` for a second request, and made right before the exec's re-issue (7.4.5); in any other process re-issued at once |
| A program's own filter | `seccomp(SECCOMP_SET_MODE_FILTER)` and `prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER)`; every trapped call while one may be in force | install a filter built around the program's, through the page with the program's flags, or answer `ENOSYS` for what cannot be honoured, strict mode included; judge each trapped call first by re-issuing it from the judge slot, and return a refusal untranslated (7.4.2) |
| Denied | `clone3`, `io_uring_setup`, `uselib`, the mount API (`open_tree`, `open_tree_attr`, `move_mount`, `fsopen`, `fsconfig`, `fsmount`, `fspick`, `mount_setattr`) | `ENOSYS` |
| Denied | `mount`, `umount2`, `pivot_root`, `chroot`, `acct` | `EPERM` |
| Deferred | `name_to_handle_at` | `ENOSYS`; no program seen issues it, and a handle would name a real inode |
| Unknown | anything a newer ancestor filter traps | `ENOSYS`, logged |

Which error comes first on an exclave path, as the kernel orders them
on a read-only bind mount, is 8.2's.

**Relative paths.** A relative path begins with the kernel's own search
check on the directory it starts from, `faccessat(dfd, ".", X_OK)`,
which the kernel makes before any lookup (`link_path_walk`) and an
absolute re-issue would skip. A working directory that has lost its
execute bit answers `EACCES`, a descriptor that is not a directory
`ENOTDIR`, a closed one `EBADF`; the check costs one syscall per
relative path. The path is then resolved from the virtual working
directory, or from the descriptor's directory read through
`/proc/self/fd/<dfd>`, and re-issued absolute, which closes the
`..`-and-symlink escape from `tree/` (13 items 13 and 14).

The walk starts in that directory as the kernel names it, which holds
no symlink, and does not walk its ancestors again, as the kernel never
does. It walks them only where the name could mislead: a tree
directory known by a host name; a host name the rule does not plainly
give the host; `/proc`; a host directory on a filesystem that could
hold the tree's root under another name (the condition of the one-step
check, 7.4.4); and an `openat2` with `resolve` flags. A deleted
directory has no path to name, so the relative path is spelt through
its magic link, `/proc/self/fd/<dfd>/` or `/proc/self/cwd/`, and
resolved by the kernel; `.` and `..` keep working and a walk from
there stays the host's.

`chdir` is performed for real, so that `getcwd` has a real directory
to reverse-translate. A trailing slash is preserved through
translation, so that `stat("/file/")` fails as the kernel would.
`O_EXCL` without `O_CREAT` follows symlinks, as the kernel does.
`open` and `openat` make the kernel's checks on the flag word before
any lookup, as `openat2` does (`build_open_how`, `build_open_flags`):
a flag the kernel does not know is dropped, `O_PATH` drops every
companion but `O_DIRECTORY`, `O_NOFOLLOW` and `O_CLOEXEC`,
`O_DIRECTORY` with `O_CREAT` is `EINVAL`, and so is `O_TMPFILE`
without `O_DIRECTORY` or without write access. After the walk, a
directory wanted by `O_DIRECTORY` of what is not one is `ENOTDIR`
(`do_open`, `path_lookupat`) before `may_open`'s answers, a symlink's
`ELOOP` among them, and before the write access the read-only rule
refuses, the loaded program's `ETXTBSY` included.

A program on the loader path answers `ETXTBSY` when the process that
loaded it write-opens or truncates its file, before any read-only
answer, as the kernel answers for the programs it executes, and after
the permission the kernel checks first: `EACCES` where the file's mode
forbids the access (`may_open`, `vfs_truncate`), with `O_TRUNC` asking
for write access under any access mode (`build_open_flags`). A write by
another process is 13 item 29 on an exclave path (`EROFS`) and 13 item
40 on a host path (it succeeds).

**`openat2`** is the same open as `openat` after the kernel's checks on
`struct open_how`, made first and in the kernel's order: the struct's
size and its zero tail, the flag word against the set the kernel
accepts, the `resolve` bits, the exclusive scoping flags, the mode,
`O_DIRECTORY` with `O_CREAT`, then `O_TMPFILE`'s and `O_PATH`'s
companions. A walk that never touches the exclave's domain (it starts
in the host's, passes only host components, rewrites no magic link,
restarts at no root and climbs to none by `..`) is re-issued as given,
descriptor, path and struct, with `RESOLVE_CACHED` dropped, so that the
kernel applies the flags itself on the host's real mounts (13 item 22).
So is a walk scoped by `RESOLVE_IN_ROOT` or `RESOLVE_BENEATH` to a
descriptor whose file has no path, a removed directory, a memfd, an
`O_TMPFILE` file, a pipe or a socket: the handler cannot name that
scope, and the kernel's walk from the descriptor itself (`path_init`)
never reaches the exclave, since a removed directory is empty and the
rest is no directory at all, so it opens the removed directory as `.`
and as `..` in root, answers `EXDEV` for `..` beneath, `EISDIR` for a
write of it, `ENOENT` for a name in it and `ENOTDIR` for the rest.
Otherwise the walk of 7.4.4 honours the `resolve` flags, which are
dropped from the re-issue:

- `RESOLVE_IN_ROOT` and `RESOLVE_BENEATH` scope the walk to the
  descriptor's directory, where `..` stays or is `EXDEV`, and an
  absolute path or link target starts again at the scope or is `EXDEV`.
- `RESOLVE_NO_XDEV` is `EXDEV` where the walk crosses between the
  host's domain and the exclave's, at a component or at a `..` that
  climbs out of one into the other (`follow_dotdot`), which is where
  the kernel under a bind mount changes mounts; an identity symlink
  that is not followed is excepted, so is a last name with a trailing
  slash that `O_CREAT` refuses before looking it up (`EISDIR`, as under
  `RESOLVE_NO_SYMLINKS`), and the host's own mount boundaries are not
  seen (13 item 22).
- `RESOLVE_NO_SYMLINKS` is `ELOOP` at any link the walk would follow,
  the tree's own links, an identity file's host link and a link in an
  identity directory included, after
  `O_CREAT`'s `EISDIR` for a trailing slash, which comes before the last
  name is looked up at all (`lookup_fast_for_open`). A
  magic link, one below `/proc/<pid>/`, is `ELOOP` under
  `RESOLVE_NO_MAGICLINKS` and `RESOLVE_NO_SYMLINKS`, and otherwise
  `EXDEV` under the scoped flags, in the kernel's order
  (`nd_jump_link`).
- `RESOLVE_CACHED` with `O_CREAT`, `O_TRUNC` or `O_TMPFILE` is
  `EAGAIN` before any lookup, after the struct's other checks
  (`build_open_flags`), since no cached lookup can create or truncate.
  Otherwise it is dropped, since a resolved path is opened without it
  and openat2(2) permits a caller to see success where the kernel
  might have said `EAGAIN`.

The resolved path is re-issued as `openat2` itself, so that a kernel
without it answers `ENOSYS` as it would natively. The syscall probe
(17 item 7) measures every flag against the kernel.

**`bind` and `connect`.** The handler copies the `sockaddr_un` in, with
the kernel's length rules, and translates `sun_path` like any path, a
relative one from the working directory; an abstract name, an unnamed
address or another family is re-issued as given. At an exclave path the
read-only rules apply: a `bind` is a create, `EADDRINUSE` for an
existing name and `EROFS` otherwise; a `connect` answers from the
lookup, `ENOENT` or `ENOTDIR`, then `EACCES` without write permission,
and `ECONNREFUSED` for what exists, since nothing can bind there. A host
path whose walk never touched the exclave, a relative one from a host
directory of any depth included, is re-issued as given, so
`getsockname` answers the program's own name. The same rule serves
every path syscall: a path relative to a descriptor whose walk never
touched the exclave is re-issued as given, relative to that descriptor,
so the kernel resolves it from the directory itself and a rename of
the directory's ancestors meanwhile changes nothing, as it would not
natively. A walk from such a descriptor that fails at a host
component, with any error but a length's, is re-issued the same way,
spelt through the descriptor's magic link as a walk from a deleted
directory is: the launcher walked from its own reading of the
directory's name, which the rename can have made stale, and the
kernel's answer from the directory itself is the one the program
would get natively. A path relative to the working directory is re-issued as its
real path, since the working directory can change under the walk (13
item 14). Any other host path,
reached through an exclave symlink or a magic link, is re-issued as its
real path in a rebuilt structure, and a real path past `sun_path`'s 107
bytes as `/proc/self/fd/N/NAME` through an `O_PATH` descriptor of its
directory, which the kernel walks as it walks the path. A datagram
destination in `sendto` or `sendmsg` is not read (13 item 31).

#### 7.4.4 Canonicalisation

Translation works in virtual space and resolves symlinks there, as the
kernel would inside a bind-mounted root:

```
canon(path, dfd, follow_last):
    if path is NULL, or empty with AT_EMPTY_PATH: return virtual(dfd)
    parts = split(absolute ? path : virtual(dfd or cwd) + "/" + path)
    cur = "/"
    while parts:
        p = pop_front(parts)
        "." -> continue
        ".." -> if cur is an identity directory whose host name is a link and the walk is not
                    scoped, cur = from_real(the kernel's name for it, opened on the host) (8.4)
                cur = parent(cur); continue
        cand = cur + "/" + p
        if no parts left and (trailing slash ? on the parent : not follow_last): cur = cand; break
        if cand is an identity directory, the walk not scoped (below), and parts are left:
            cur = cand; continue                   # passed by name; the kernel follows a host link (8.4)
        if cand is one, or the host's below one, the walk not scoped, and lstat(cand) is a symlink:
            if no parts left: cur = cand; break    # re-issued following it: the kernel's, on the host
            h = the kernel's name for cand, opened as a directory on the host
            cur = (h is the host's or under tree) ? from_real(h) : cand; continue
        if lstat(to_real(cand)) is a symlink:
            t = readlink(to_real(cand))
            if cand under /proc: t = from_real(t)    # procfs reports real paths
            parts = split(t) + parts; cur = t absolute ? "/" : cur
            if ++hops > 40: ELOOP
        else cur = cand
    return cur, with the original trailing slash if any

to_real(v):   v host-owned (8.1) ? v : tree + v, or for an exclave path in an identity
              directory the tree's resolved directory + the rest (8.4)
              then wrapper -> original, except for execve and execveat
from_real(r): r under tree ? r without the prefix and a final .real/, or the virtual
              path of a resolved directory it lies in : r
```

An intermediate component must be a directory, so a textual `..`
cannot hide a missing one. A procfs magic link below `/proc/<pid>/` to
an object with no path ends the walk: a pipe, a socket or an anonymous
inode, whose link text is not a path, and an unlinked file, whose text
ends ` (deleted)` and leads nowhere else; a file that is really named
so is found by its name. A walk that ends there is re-issued on the
link, followed, as the kernel follows it, so that `stat` of
`/dev/stdin` finds the pipe and `linkat` with `AT_SYMLINK_FOLLOW`
links an `O_TMPFILE` file. An `openat2` walk (7.4.3) carries a scope
and its resolve flags: the scope replaces `/` for absolute paths and
link targets and stops `..`, and each flag is checked at the component
it concerns, in the order the kernel checks it. Such a walk counts as
scoped at and below an identity directory, where it follows the host's
links itself, when it carries `RESOLVE_NO_SYMLINKS`, `RESOLVE_NO_XDEV`,
`RESOLVE_BENEATH` whatever its scope, or `RESOLVE_IN_ROOT` with a scope
other than the root (8.4). A relative walk under `RESOLVE_NO_XDEV`
walks its starting directory's own components again without counting
a crossing there, since the kernel starts in that directory.

An identity directory the host has is a directory to the walk, decided
at startup, so a path through it costs no `lstat` of it; the names
below it are host names, `lstat`ed as any host component is. A walk
that ends at a link there is marked as one the re-issue follows, as for
an identity file, so the call keeps its own following of the last
component and the kernel follows the link on the host; the read-only
rules see a host path and leave it to the kernel. A link to a directory
with components after it costs an `open`, a `readlink` of its
descriptor and a `close`. A walk at or below an identity directory, or
one whose `..` lands on an exclave path, is not the kernel's own walk
from the program's descriptor (7.4.3), even from a descriptor in the
host's domain, so the path is re-issued as the walk resolved it.

A symlink's target is a virtual path whoever created the link. A host
link `/tmp/x -> /usr/bin/gcc` reaches the exclave's gcc, as it would
under bwrap; an exclave link `/var/run -> /run` reaches the host's
`/run` by 8.1 rule 3. The identity files and the links in the identity
directories of 8.4 are the one place a host symlink keeps its host
meaning, and the kernel follows them on the host, not here.

The real path of `tree/` is an alias of `/` (8.1 rule 6), and so is
any directory with the tree root's device and inode. A path that begins
with the tree's real path, as a program that finds its files from its
`argv[0]` spells it, starts at the root after one `faccessat(X_OK)` on
the exclave's directory, which answers for the directories above as
the walk would.

**Wrapper redirect.** A final real path is a wrapper if it is a regular
file with the launcher's inode or, for copied exclaves, the launcher's
size, and a `.real/` sibling of the same name exists, which
`.exclave/launcher` itself has not. For every syscall except `execve`
and `execveat`, the real path then becomes the original's, so `open`,
`stat`, `ldd`, checksum tools and `ld.so` see the original's bytes and
metadata, and only the kernel's exec sees the wrapper. `stat` of a
wrapper reports the original's mode and owner while the kernel's exec
check uses the launcher's; the tool's refusal to wrap files the user
could not execute keeps the two consistent (6.1).

**Cache.** Nothing inside an exclave modifies an exclave path (8.2), so
a per-process table of what each is (absent, a directory, a symlink and
its text, a file, a wrapper) never needs invalidation, and warm
translations cost hash lookups and no `lstat` walk. Readers never lock,
and an insert that finds the lock held is skipped, so a nested handler
cannot deadlock on it. The lock lives on a page the kernel wipes at
`fork` (`MADV_WIPEONFORK`, 4.14+), so a child forked while another
thread held it starts with it free, where an inherited copy would be
held for the child's life and every insert there skipped; a `vfork`
child shares the page, and the parent's release reaches it. Host-owned
paths are never cached. The assumption
is stated: nothing outside the exclave modifies the tree while an
exclave process runs.

**The one-step host check.** Host directories are not cached, so a walk
through them `lstat`s each, to follow a host symlink in virtual space
and to see the tree's root under another name. Where at least three
directories lie ahead of the final component and every one is plainly
the host's by the rule (not an identity file or directory, not on the
way to one, not the tree's root by name, not under `/proc`, no `.` or
`..`), one
`openat2` with `O_PATH`, `O_DIRECTORY` and `RESOLVE_NO_SYMLINKS` stands
in for their `lstat`s: it succeeds only if each is a directory reached
without a link.

Another spelling of the tree's root needs a bind mount or a second
mount of its filesystem, or a filesystem that folds case, where
`x.exclave/TREE` is the tree's root on the same mount. So the check is
used only where `/proc/self/mountinfo`, read when first needed and then
decided for the process, shows the tree's filesystem mounted once with
the tree's own device number; a btrfs subvolume and a chroot that does
not see the mount fail this. After the `openat2` succeeds, the kernel's
name for what it reached, read back from `/proc/self/fd`, must be the
path itself; a case-folded spelling of the tree's root fails this,
since the tree's root, pinned by the program's mappings, keeps its own
name. Any failure, a kernel before 5.6 included, leaves the
directories to the walk until it restarts at a link, and the final
component is always the walk's. The assumption is the cache's: no
second mount of the tree's filesystem appears while an
exclave process runs, by the host's hand or by a program's `setns` into
a namespace that has one; inside, `mount` is refused (7.4.3).

#### 7.4.5 `execve`: one world

The handler canonicalises the target and checks what the kernel would
check before loading anything: `EACCES` for a file without execute
permission, a directory, a special file or a `noexec` mount (the
kernel's own `X_OK` answer); `ENOEXEC` for a file that is neither ELF
nor `#!`; `ENOENT` and `ELOOP` from resolution. It parses `#!` as the
kernel does (interpreter, optional argument, the script's path as
given, the remaining arguments; five nested interpreters, the sixth
`ELOOP`), from the same 256 bytes: with no newline among them, an
interpreter path that no blank ends within the first 255 is `ENOEXEC`,
never a shorter path. An `execveat` flag the kernel does not know is
`EINVAL` before the name is read, and `AT_EXECVE_CHECK` (6.14), which
asks whether the file could be run and runs nothing, is re-issued on
the file the walk found, so the kernel answers it and the process is
never replaced. Then:

- **A target in a data directory** is `EACCES`, never executed (6.2).
- **A wrapper** is `execve`d: the kernel runs the launcher under the
  program's name, and identity is the kernel's.
- **A file carrying a launcher's note**, under either name, is another
  launcher and is `execve`d as it is, with the launcher's variables
  below as for a wrapper; one whose note names an older
  page generation goes to this launcher's child, which refuses it by
  name (7.4.2).
- **Anything else** re-execs the launcher with the original `argv`
  unchanged and the virtual target path in `EXCLAVE_EXEC`; the child
  launcher resolves the target as an exec would and loads it with
  whatever loader its own header names, resolved in the exclave (7.3).
  Before that exec the handler answers what `execve` itself would,
  `load_elf_binary`'s answers before its point of no return in its
  order: `ENOEXEC` for a header the loader cannot load, a type that is
  neither `ET_EXEC` nor `ET_DYN`, another machine, program headers of
  another size, none, or more than it holds, and for a `PT_INTERP` of
  under two bytes, over `PATH_MAX` or without its NUL, `EIO` for one
  the file does not hold whole; then, for the loader the first
  `PT_INTERP` names, the kernel's `open_exec` answer, `ENOENT` for one
  that is not there, `EACCES` for a directory, a special file or one
  without execute permission, then `EIO` for a header it does not hold
  whole and `ELIBBAD` for one that is not this machine's ELF, so that a
  shell's `execvp` fallback and a `posix_spawn` caller see the refusal
  rather than a child that dies. A loader that passes those checks but
  is not the exclave's own file, a host path or a data directory, is
  left to the child launcher, which refuses it by name (7.3), where the
  kernel would load it, an `ET_EXEC` included.

**A traced `vfork` child.** A debugger starts its program by `vfork`,
`ptrace(PTRACE_TRACEME)` and `execve`, as gdb's `fork_inferior` does.
A traced task's trapped `execve` stops for its tracer at the `SIGSYS`,
before the handler runs (`get_signal` calls `ptrace_signal` before any
handler), and the tracer, the parent, waits in `vfork` for that very
exec: both would wait for ever. So the handler does not make a `vfork`
child's request when it traps (7.4.2): it answers 0, or `EPERM` for a
second request as the kernel answers a task already traced, keeps the
request in the trap's scratch chunk (7.5.4) and makes it through the
syscall page right before it re-issues the exec, of a wrapper, of
another launcher or of the launcher itself, once it has answered what
`execve` would refuse without exec'ing. An exec that fails first, as
`execvp` tries each directory of `PATH`, leaves the request waiting
for the next; the kernel's `SIGTRAP` after the exec that runs stops the
new image for the tracer, as natively. Nothing but an exec or an exit
can follow the request in a `vfork` child, natively too, since its
parent is blocked until one of them, so the deferral changes no program
that runs natively. A child that exits without exec'ing leaves its
request to be dropped by the next search (7.5.4), and one whose parent
died meanwhile, which would have
detached its tracee, has none made for its new parent. A `vfork` child
is one whose memory is its parent's: `kcmp(KCMP_VM)` compares the two
address spaces, and where it is refused (Docker's default profile,
without `CAP_SYS_PTRACE`) the pid the launcher started as, on a page
wiped at fork, tells it: a `vfork` child reads its parent's pid there,
a `fork` child zero. In any other process, a `fork` child or a thread,
the request is re-issued at once, since such a child may stop for its
tracer before it execs, `raise(SIGSTOP)` after the request being the
classic pattern (13 item 54).

**The launcher's own protocol.** `EXCLAVE_EXEC`, `EXCLAVE_EXECFN` and
`EXCLAVE_COMM` are how one launcher tells the next what to run and under
what name, not an interface. `EXCLAVE_EXEC`, set by a handler or the
positional entry, is absolute and read only by a launcher run as a
program, never by a wrapper (7.2). The kernel spells the name a program
is exec'd by as given, or `/dev/fd/N` for a descriptor and
`/dev/fd/N/name` for a path relative to one (`alloc_bprm` in
`fs/exec.c`), and from it sets `AT_EXECFN`, `comm` as its last
component (from 6.12, for a bare descriptor the name of the file it
finally loads, a script's interpreter's) and a script's `$0`. The handler spells the name the same way and carries it,
with the `comm` it computed, in `EXCLAVE_EXECFN` and `EXCLAVE_COMM` on
every exec it makes, of a wrapper or of the launcher, dropping any
inherited copy of the three and of `EXCLAVE_TRACED`, which marks the
exec that leaves a process newly traced (7.6). The launcher it execs takes them for the
program's identity (7.6), a wrapper only when a filter is inherited, so
that from the host they are as inert as `EXCLAVE_EXEC`.
Every launcher removes all four from the environment a program is
given; the kernel's copy in `/proc/<pid>/environ` keeps them (13 item
46). A script's interpreter therefore receives the script's path as the
caller spelt it, for a wrapped script too, and a script behind a
close-on-exec descriptor is `ENOENT` before anything runs, as the kernel
answers (`BINPRM_FLAGS_PATH_INACCESSIBLE`); one spelling the positional
entry does not carry is 13 item 39.

**There is no other mode.** A program on a host path is an ordinary
file: it sees the exclave's tree and runs with the exclave's libraries.
A program the exclave's compiler just built runs inside the exclave
that built it, whether the exclave's libc is newer than the host's or
musl. A musl output in a glibc exclave fails with "interpreter not
found", which is the truth, and so does a program whose interpreter is
a host file (7.3). A tool in `~/bin` linked against host libraries runs
inside an exclave only if those libraries are in it, and fails visibly
otherwise; a tool not on the exclave's `PATH` is not found by name at
all, which is the hermeticity the design is for (13 item 7). A program
without a wrapper goes through the launcher rather than a plain
`execve`, because the inherited filter would trap the kernel-chosen
loader's first `openat` before any handler existed, killing it.

Argument vectors are copied into scratch memory (7.5.4), or a mapping
sized from their counts, never onto the program's stack, and are not
bounded.

The kernel's exec needs no descriptor, and the handler's does: it opens
the target to read its first bytes. A program at its soft descriptor
limit may still exec: the handler raises the soft limit to the hard one
for the open and puts it back, and a child launcher started under a
soft limit below 16 does the same for its own opens, the manifest, the
tree's top level, the program and its loader, and restores the limit
before the program runs. The soft limit is raised to the hard one rather
than by the few descriptors needed because the lowest free number may
lie anywhere above a limit a program lowered below its open
descriptors. From a soft limit of 16 up the child needs a free
descriptor, as a dynamically linked program's loader does natively. At
the hard limit the exec is `EMFILE` (13 item 12).

The launcher's variables go after the program's own in the environment
it is exec'd with, so that the kernel lays the program's strings
out contiguously after its arguments, as a program that writes its
title over them expects; where they end up is 13 item 50.

### 7.5 Signals, threads and memory

Each rule below comes from real software failing without it, not from
reasoning.

#### 7.5.1 `SIGSYS` must never be blocked

Seccomp delivers `SIGSYS` with `force_sig`: if the signal is blocked or
ignored at that moment, the kernel resets the handler to the default
and kills the process. The handler therefore scrubs `SIGSYS` from every
mask a program tries to set: `rt_sigprocmask`, the `sa_mask` of every
`rt_sigaction` that installs an action, the mask of every wait
that carries one (7.4.2), and the mask a program's handler leaves in a
frame the trampoline presented, before it reaches the trap's frame or
the launcher's (7.5.7). `rt_sigtimedwait` and `signalfd` name signals to
receive, not to block, and are left alone. The case is common: a
program installs a handler with `sigfillset` on `sa_mask`, a textbook
idiom, and touches a path inside it. The old action an install
replaces reports, for a handler, the mask the program wrote, which the
launcher keeps in the handler's slot (7.5.7); a query of an action,
which passes to the kernel, reports the mask without `SIGSYS`, as do
the mask in force while a handler runs and a query of the thread's (13
item 20).

The handler checks `si_code == SYS_SECCOMP`. A `SIGSYS` sent by `kill`
or `raise` restores the default disposition and re-raises, so the
process dies as it would natively.

#### 7.5.2 Masks are edited in the signal frame

`rt_sigprocmask` cannot be honoured by re-issuing it alone: the kernel
restores the mask from the frame at `sigreturn`. The handler re-issues
it with `SIGSYS` scrubbed from the set, which makes the kernel apply
block, unblock or set semantics and fill `oldset` with the pre-trap
mask, then copies the resulting mask into the frame's `uc_sigmask` so
that it survives the return, reading it by blocking every signal but
`SIGSYS` until the trap's return installs the frame's, so that no
program handler's mask (7.5.7) lands between the read and the copy; a
signal arriving then is delivered after the call, as natively. The mask-carrying waits are re-issued
through the page with a scrubbed copy of their mask, six arguments and
all. Each of these calls answers in the kernel's order: the timeout of
`ppoll`, `pselect6` and `epoll_pwait2` is read and checked before the
mask, as `poll_select_set_timeout` runs before `set_user_sigmask`, and
`io_pgetevents` reads its timeout before its mask pair; the old mask of
`rt_sigprocmask` is written after the new one is in force, so a bad
`oldset` is `EFAULT` with the mask changed, as `sys_rt_sigprocmask`
leaves it; and an install for `SIGSYS` reads its action before it is
ignored, so a bad pointer is `EFAULT`. `test/progs/sigcalls.c` holds the
cases and the kernel's answers (`test/kernel_answers.py`), which the
namespace oracle confirms under `bwrap`.
`rt_sigaction` on `SIGSYS` itself is accepted and ignored (13 item 23);
its `oldact` and every query of it report the truth, the launcher's
handler. Every other install puts a trampoline in the handler's place,
and its `oldact` reports the action it replaces as the program wrote it;
a query, which does not trap, reports what the launcher installed
(7.5.7). The frame is read at the offsets of the
architecture, `uc_sigmask` at 296, the registers at 40 and the pointer
to the floating-point save area at 224 on x86-64, `uc_sigmask` at 40
and the registers at 184 on aarch64, where `x0` is both the first argument and the
result and the handler copies the arguments before it writes. A
restorer of the launcher's own, in the syscall page (7.4.2), returns
through `rt_sigreturn` on both.

#### 7.5.3 The handler is interruptible, and nesting is legal

The handler is installed with `SA_SIGINFO`, `SA_ONSTACK`, `SA_NODEFER`
and an empty `sa_mask`. The program's own mask is in force during the
re-issued syscall, so a blocking `open` on a FIFO inside an exclave is
interrupted by Ctrl-C exactly as outside, and a program's own signal
handler may run inside the launcher's. It finds in its frame not the
launcher's registers but the trap site's, the call as it stands, and
what it decides there is what the program does (7.5.7). A signal already pending when the trap is
taken, a thread-directed one sent in the microsecond of the syscall's
entry, is delivered on top of the launcher's frame, since the kernel
dequeues `SIGSYS` first with the synchronous signals
(`SYNCHRONOUS_MASK` in `kernel/signal.c`): the program's handler runs
first, before the launcher's has run an instruction, finds the call
about to be made, and returns into the launcher's,
which finds the trap's registers intact. `test/progs/sigrain.c` rains
signals from a timer, a child process and a sibling thread on loops of
trapped calls, with every disposition and the restart rules, and every
answer is the kernel's. A Go program without cgo keeps its goroutine in
`x28` on aarch64 and its signal handler reads the register as it finds
it, so Go's preemption signal, landing in the launcher's handler, would
read the launcher's value and fault; the aarch64 launcher is therefore
built with `x28` reserved (`-ffixed-x28`). On x86-64 Go reloads it from
thread-local storage.

If the program's handler touches a path, its trap nests, and that is
legitimate: gcc's driver unlinks its temporary files from a `SIGTERM`
handler, crash reporters open files, shells run `trap` cleanups.
Nesting is allowed to a depth of 64, as a stack-exhaustion guard. The
case the design must catch is different and recognisable: a nested trap
whose `si_call_addr` lies inside the launcher's own text can only mean
a foreign filter or a bug in the launcher, and kills the process with a
message. `SA_ONSTACK` runs the handler on the program's alternate stack
where one exists, which keeps Go's small goroutine stacks and Rust's
guard pages safe; where none exists it is a no-op. A program's own
handler whose signal lands during a trap runs where the launcher's
handler is running, below its frames and the presented frame (7.5.7),
so on the alternate stack whether or not it asked for it (13 item 51).

#### 7.5.4 Scratch memory and the stack budget

The handler uses at most 3 KB of the program's stack beyond the
kernel's signal frame: 2 816 bytes on x86-64
and 2 736 on aarch64 for a five-deep chain of
host `#!` scripts, whose six nested exec frames keep their buffers in
scratch, the trap's record of 7.5.7 included. The kernel's frame is
`AT_MINSIGSTKSZ` bytes, about 3 KB on AVX-512 hardware and up to 11 KB
with AMX; a trap costs the two together, multiplied under nesting (13
item 30), and glibc's `posix_spawn` child runs on a 36 KB stack with
no guard page. `test/stackcheck.py` asserts the budget on the call
graph gcc writes with `-fcallgraph-info=su`: the deepest chain from
`on_sigsys`, `exec_target`'s recursion counted six deep and any other
recursion a failure. The launcher makes no call through a pointer,
which would have no edge, but the trampoline's call of a program's
handler, made in assembly, past which the stack is the program's
(7.5.7). The trampoline's C part is a second root with a budget of its
own, 512 bytes, of which its deepest chain takes 208 on x86-64 and 320
on aarch64, and which fails on any call out of the
trampoline's section, and the assembly of the handler's entry stub and
of the trampoline count as constants the check reads from beside their
source.

Path buffers, argument vectors and per-thread state live in scratch
chunks mapped on demand, since a fixed pool failed 40% of `stat` calls
under 64 threads when tried. A chunk records its owner's `(pid, tid)`
and the frame that claimed it, and is released when the handler
returns. Every copy from or into program memory names the pid recorded
in the trap's own chunk, never a process-wide value, which a `vfork`
child's handler, sharing the parent's memory, could overwrite. Each
buffer of a chunk has one role and is named for it: the path as the
program gave it, the walk's working buffers, the real path of a second
name, the `stat` the kernel's order asks for; none is cast to another
use, so no site depends on which buffer another is finished with.

A `vfork` child's deferred `PTRACE_TRACEME` (7.4.5) keeps its trap's
chunk past the handler's return, marked as holding the request and
named for the parent the child had: the frame comparison below passes
it by, the exec takes and releases it before its re-issue, and a sweep
releases it once its owner is gone, as any search for a request does,
so that a later child given the same pid finds none of its own once
any search has run (13 item 54).

Two ways of leaving a chunk busy are expected. A `vfork` child that
replaces its image from inside the handler leaves its chunk busy in the
parent until it exits (13 item 26). A program that `longjmp`s out of a
nested handler leaves its chunk busy in a live thread; the thread's
next trap releases it, since a chunk whose frame is at or below the
current handler's frame cannot be a live ancestor on that stack, so the
textbook `alarm` plus `siglongjmp` timeout runs for ever. A handler
that switches stacks between traps could confuse the comparison (13
item 27). Other threads' chunks are not reclaimed by stack position,
which means nothing across alternate stacks and coroutines.

When nothing is free the handler sweeps chunks whose owner no longer
exists, `tgkill(pid, tid, 0)` or `kill(pid, 0)` answering `ESRCH`, then
grows the pool: a slot reserved by an atomic add, a chunk mapped and
claimed, then published. Nothing takes a lock, since a lock held by the
interrupted frame, or by another thread at a `fork`, would never be
released. The pool holds 4 096 chunks; past that a trap answers
`ENOMEM` (13 item 26). A recycled identifier only delays reclamation,
the safe direction. No chunk is released before `execve`, since a
sibling thread could reuse it while the kernel still reads the argument
vectors it holds.

**The sequence rule.** Every claim and every release advances a
chunk's sequence, and a sweep releases a chunk only by advancing the
sequence it read before judging the owner, in one compare-and-swap. A
sweep overtaken by another sweep's release and a new claim finds the
sequence moved and leaves the new holder alone. Without the rule two
handlers could share a chunk, which `posix_spawn`'s `vfork` children,
leaving chunks with dead owners, make likely on two CPUs (13 item 44);
`test/scratch_test.c` forces the interleaving.

#### 7.5.5 Threads and `clone3`

`clone3` is refused with `ENOSYS` (7.4.2), so glibc, musl and Rust
create threads and spawn children with `clone`, which is not trapped.
glibc's `posix_spawn` fallback then resets the signal dispositions by
hand in the child: it queries every signal, which does not trap, and
installs only where the parent has a handler and for its own two
internal signals, which traps (7.5.7). That is the cost of refusing
`clone3`: a handful of traps per `posix_spawn`, two `rt_sigaction`s
and one `rt_sigprocmask` for a parent with no handlers.
What a spawn costs in all is the child launcher's start and the kernel's
work behind it (16.4). Honouring `clone3` would mean copying the
handler's signal frame onto the child's stack, and with it the FPU save
area, whose pointer in the frame names the parent's stack: a copy that
leaves the pointer there starts every new thread with a corrupt
`MXCSR`. The copy can be made, since the frame records the save area's
size, but it ties the handler to the kernel's frame layout on both
architectures, which grows with each new register set, to save
some sixty traps per spawn (14.3).

#### 7.5.6 `EFAULT`

Every read from program memory is a `process_vm_readv`, which returns
`EFAULT` for an invalid pointer instead of faulting in the handler, and
every write a `process_vm_writev`, since another thread may have
unmapped a buffer the kernel validated a moment earlier. Docker's
default profile allows both on kernels 4.8 and later. Where
they are refused, `EPERM` under a profile that gates them on a
capability, the handler copies through a pipe made for the copy alone,
whose `write` and `read` fault exactly as the kernel's own copy would;
the cost is 13 item 15.

The kernel checks a thread's access to memory against its protection
keys, x86-64's PKRU, and a signal handler starts with the kernel's own
PKRU, which denies keys a program may have opened for itself. The
handler loads the program's from the XSAVE area of the frame the kernel
saved, key 0, the launcher's memory, kept open, so that a syscall it
issues into the program's buffer is checked as the program's own would
be; and while the program has set keys of its own, a PKRU that denies
some key and is not the one a process starts with, it copies through
the pipe, since `process_vm_readv` and `process_vm_writev` reach
memory whatever its key, where `write` and `read` are checked, the
pipe's cost of 13 item 15 on that program alone. A buffer under
a key the program may write is written, and one under a key it denied
is `EFAULT`, as natively (`protection_keys`). aarch64's keys are 13
item 52.

#### 7.5.7 A program's handlers and the trap site's frame

A trapped call runs in two places: the program's syscall instruction
raises `SIGSYS`, and the launcher's handler walks the path and makes
the call again from the syscall page, with the program's mask in force
(7.5.3). A signal that lands meanwhile is delivered on top of the
launcher's frame, and the kernel's frame for it describes the launcher:
a counter in the page or the launcher's text, the launcher's registers.
A handler that reads its frame would be misled: musl's and glibc's
cancellation act only when the counter lies in their cancellable
syscall, Go's preemption asks whether it is a safe point, a sampling
profiler attributes the sample by it, and an unwinder walks from the
handler through the frame into the interrupted code. The launcher
therefore stands between the kernel and every handler a program
installs, and builds the frame the kernel would have built at the trap
site, as it already edits the mask in the trap's frame (7.5.2): one
more of the kernel's jobs, done by the same handler.

**Trampolines.** At every `rt_sigaction` that installs a handler, the
launcher's handler first checks the signal as the kernel does, so that
an install answered `EINVAL` takes nothing, then finds or takes a
*slot* for the program's handler and its `sa_mask` as the kernel stores
it, without `SIGKILL` and `SIGSTOP`, and installs that slot's *stub* in the handler's place,
with the program's flags, restorer and mask, less `SIGSYS` (7.5.1), as
given. The slots are 256 in the launcher's data, each filled once and
never rewritten: an install whose handler and mask a slot already holds
reuses it; any other claims the next by a compare-and-swap on the
count, bounded at 256, writes the mask, and publishes
the handler last with release order, and a reader acquires the handler
and takes a slot without one as empty. When none is left the handler is
installed directly and its frames are the launcher's (13 item 58). An
install of a stub's own address, an old action a program saved and puts
back, maps back to its slot. A stub is two instructions in a section of
the launcher's text of its own, which put the slot's number in a
scratch register, `r11` (`x16`), and jump to the *trampoline*. Since
the kernel's action names the slot and a slot never changes, a delivery
runs the handler the kernel delivered for, whatever another thread
installs meanwhile, and a `vfork` child's installs claim slots of their
own in the memory it shares with its parent, whose actions the kernel
keeps apart and whose slots stay as they were. `fork` copies the slots
with the memory, and `execve` starts a launcher with none, as the kernel
resets every caught signal to the default and keeps the ignored ones.

The kernel's action differs from the program's only in the handler's
address and `SIGSYS` in its mask, so the kernel applies the program's
flags itself: `SA_RESTART` to the restart of an interrupted re-issue,
`SA_NODEFER` and the mask to delivery, `SA_ONSTACK` to the stack,
`SA_RESETHAND` by resetting the action at delivery, which a later query
reports, and `SA_SIGINFO` to whether it writes the `siginfo` and, on
aarch64, passes the frame's address. The trampoline finds the frame
without it, at the stack pointer plus 8 on x86-64, past the restorer's
address, and plus 128 on aarch64, past the `siginfo`: the layout of
`rt_sigframe`, which unwinders rely on. The launcher carries no BTI
property by construction, built with `-mbranch-protection=none`
whatever the compiler's default, so its stubs need no landing
instruction, and a branch through `x16` to a program's handler is one
its `bti c` admits.

**Where the signal landed.** The trampoline reads the interrupted
counter from the frame:

- *Outside the launcher's text and the syscall page*, in the program's
  code, a library's or the vDSO: the trampoline restores the registers
  it used, `r11` and `rcx` from the frame and `rax` to the 0 the kernel
  leaves in it (`x15` from its own stack and `x17` from the frame on
  aarch64), and jumps to the program's
  handler, through `x16` on aarch64, the register the procedure call
  standard leaves to such veneers; only the arithmetic flags are not as
  the kernel left them. The handler starts with the stack, the frame
  and the return address into the program's restorer that the kernel
  gave, and no frame of the launcher's lies between.
- *At a stub's first instruction*: a second signal delivered before the
  first one's handler ran. The trampoline presents the frame with that
  handler's address as the counter, as natively, as it presents a trap
  site below, the frame the program resumes from being this one; if the
  handler leaves the counter as presented, the stub's address goes back.
- *In the trampoline itself*, its stubs past their first instruction
  and its code in the page included: as outside, the counter the
  trampoline's (13 item 58).
- *Anywhere else in the launcher's text or the page*: the signal landed
  during a trapped call, and the trampoline presents the trap site.

**The trap's record.** Every trap has a record of four words on the
launcher's stack, made by the handler's entry stub before anything
else: a magic word, the address of the trap's frame, the call's answer,
a sentinel until there is one, and a flag that a program's handler
redirected the program. A register holds the record's address
throughout the launcher's code (`r15`, `x27`, reserved by `-ffixed-`;
no C reads it, the entry stub passing the record to the handler as an
argument and the trampoline reading it from the frame, so clang, which
`scripts/check` runs without the flag, needs none), so a frame that
interrupts the launcher names its trap in that register, and the
trampoline asserts the magic word before it trusts it. The program's
value of the register is in the trap's frame. Where the record does not
exist, the trap's frame is found otherwise: in the entry stub's first
instructions it is the third argument the kernel passed the handler,
still in its register; in the stub's last instructions, after the
record is gone, and at the launcher's restorer, returning through the
trap's frame, it is found from the interrupted stack pointer, and the
call is made, its answer in the frame: on x86-64 the `ucontext` lies 8
bytes above the stack pointer before the stub's last `ret` and at it
after, at the restorer; on aarch64 128 bytes above it at each.

**The re-issue slot.** The call the handler makes on the program's
behalf, the re-issued syscall in whatever form, the exec, goes through
the page's re-issue slot (7.4.2), which reads the record's redirect
flag first and, when it is set, makes no call and answers `EINTR`, and
after the call stores the answer in the record. The launcher's own
calls do not wait but where a network or user-space filesystem makes a
lookup wait, and the log's writes, which follow the answer. The handler
stores its answer in the record before it does anything else with it,
an answer it made without a re-issue, `EROFS`, `ENOENT` or a judge's
refusal, included, and the entry stub writes it into the trap's frame
on the way out unless the flag is set; a redirect that lands between
the stub's test and its write moves the counter past the write.

**Where the call stands** is read in this order: the redirect flag; then
the counter of the re-issue slot, before its syscall instruction not
made, which is also where the kernel leaves a re-issue it will restart,
and after it made, the answer in the result register; then the
record's answer, made; else not made. Only the call itself goes through
the re-issue slot: the launcher's auxiliary calls on the way, a
deferred `PTRACE_TRACEME` before its `execve`, the availability query
before a filter's install, go through the page's first slot and leave
the call not made.

**What the trampoline presents.** It builds a frame of its own, laid out
as the kernel's `rt_sigframe`, below the kernel's frame, which stays as
the kernel made it and holds the launcher's state. The presented frame
has a fixed size on each architecture, so that the handler-call slot
finds the block above it at a fixed offset from the stack pointer: at
least the kernel's `rt_sigframe`, and room above the `ucontext` for a
whole `ucontext_t` of the program's libc, which a handler may write back
whole (glibc's is 968 bytes on x86-64, more than the kernel's
`ucontext` and `siginfo` together), so that no such write reaches the
block, which holds the address the trampoline is re-entered by:
1 040 bytes on x86-64 and 4 688 on aarch64, whose records' 4 096 bytes
it holds whole, with a block of 112 above it. Above it lies that block of the
trampoline's own: a magic word, the kernel's frame's address, the
record's, the slot, the re-entry address, on aarch64 the `x30` the
kernel set and a frame record. The handler's stack grows below the
presented frame. On x86-64 the presented `ucontext` is 16-byte aligned,
and the stack pointer at the handler's entry 8 modulo 16, as the
kernel's. The presented frame holds:

- the `siginfo` of this delivery;
- the general registers of the frame the program resumes from, on
  x86-64 the eighteen, `r8` to `r15`, `rdi`, `rsi`, `rbp`, `rbx`,
  `rdx`, `rax`, `rcx`, `rsp`, `rip` and `eflags`, on aarch64 the
  thirty-one, `sp`, `pc` and `pstate`, with the counter and the result
  register as the call stands. *Not made*: the counter at the program's
  syscall instruction, two bytes before the trap's on x86-64 and four on
  aarch64, and the result register as the kernel leaves it there, the
  syscall's number in `rax`, the first argument in `x0`: the kernel's
  frame for a signal that arrives just before a syscall instruction, and
  for one that interrupts a call the kernel will restart. *Made*: the
  counter after the syscall instruction and the answer in the result
  register, `-EINTR` where the kernel ended an interrupted re-issue
  with it. *Redirected* by an earlier handler in the same trap: the
  trap's frame as that handler left it. This delivery's own fields stay
  as the kernel made them: `csgsfs`, `err`, `trapno`, `oldmask` and
  `cr2` on x86-64, `fault_address` on aarch64;
- the floating-point state, the program's: on x86-64 the frame's
  pointer to its save area names the trap's frame's, so nothing is
  copied; on aarch64 the trap's frame's records, copied up to their
  terminator by one parser with one checked bound, the 4 096 bytes of
  `__reserved`, each record at least 16 bytes and 16-aligned, an
  `extra_context` record still naming the trap's frame's extra space,
  and this delivery's own syndrome written into the trap's `esr_context`
  where both frames carry one; a program using SVE across the copy and
  its copy back is **[measure]** on the arm64 row. The launcher depends on
  no save area's layout either way;
- `uc_stack` as the trap's frame's, the alternate stack as it stood at
  the trap site;
- the mask of this delivery's frame, the mask in force at the re-issue,
  which is the program's (7.5.3), or for a wait that carries a mask the
  mask from before it, as natively.

The trampoline then loads the trap site's callee-saved registers, and
`x18` on aarch64, from the trap's frame, the signal's number and the
addresses of the presented `siginfo` and `ucontext` into the argument
registers, `rax` 0 on x86-64, `x29` naming a frame record of the trap
site's `x29` and `x30` on aarch64, and calls the handler from the
page's *handler-call slot*, whose call is followed by the restorer's
own two instructions: `mov $15, %rax; syscall`, the bytes
`48 c7 c0 0f 00 00 00 0f 05`, on x86-64, `mov x8, #139; svc #0` on
aarch64. On x86-64 the call is made with the stack pointer at the
presented `ucontext`, so that the return address lands where the
kernel's frame keeps the restorer's address; on aarch64 with the stack
pointer at the presented frame and the return address in `x30`. The
handler thus starts as the kernel would start it, the stack pointer at
a frame of the kernel's layout and the return address at a restorer's
code, and an unwinder takes that return for the kernel's restorer:
libgcc's fallback (`config/i386/linux-unwind.h`,
`config/aarch64/linux-unwind.h`) reads the frame at the handler's
caller's frame address, which is the presented `ucontext` on x86-64
and the presented frame on aarch64, and gdb's signal-trampoline
recognition does the same, so a backtrace and an unwind walk from the
handler into the program's frames at the trap site. Measured with
libgcc 13 and gdb 15 on x86-64: a forced unwind from a handler called
so runs the trap site's caller's cleanup, as from a handler the kernel
called, and gdb's backtrace shows `<signal handler called>` above the
trap site; on aarch64 libgcc's fallback compares the same two words and
reads the frame at the frame address. When the handler returns, its
return runs the restorer's instructions in the page, and the filter
answers an `rt_sigreturn` from that one address with an error (7.4.2),
so that nothing is restored: the call returns, and the page's next
instructions jump back into the trampoline, whose address the block
above the presented frame holds.

**What the handler decides.** Back in the trampoline, the record is
reloaded from the block, not from the register, which holds what the
handler left, before any of its C runs. The trampoline compares the
presented general registers with the frame the program resumes from,
its counter and result register as the call stands, and copies into that
frame the mask the handler left, `SIGSYS` cleared (7.5.1), and its
`uc_stack`; on aarch64 the floating-point records go back, exactly the
bytes copied out and never a length read again from headers the
handler may have edited, so that a handler's edit reaches the program,
as on x86-64 it does through the pointer. The same mask, `SIGSYS` cleared, goes into the
kernel's frame for this delivery, so that the rest of the launcher's
handler runs with it, as the program would after the handler's return:
musl's handler, finding a call that is not its cancellable one, blocks
its cancel signal in the frame and sends it again, which must stay
blocked until the call is done.

Unchanged, the launcher's call goes on: the kernel restarts the
re-issue, or has ended it, as it decided before the handler ran, or the
walk continues to the call. Changed, the handler has redirected the
program, as musl's cancellation moves the counter to its cancel path, or
a single-stepping handler sets the trap flag: the trampoline writes the
registers into the trap's frame and sets the redirect flag, and if the
counter lies in the re-issue slot before its syscall instruction, moves
it past and puts `-EINTR` in the result register, so that no restart
follows. That edit is safe at any point: with a handler run, the kernel
leaves no `ERESTARTNOHAND` or `ERESTART_RESTARTBLOCK` in the frame,
having made them `EINTR`, and `rt_sigreturn` marks the thread as in no
syscall (`orig_ax` -1 on x86-64, `forget_syscall` on aarch64), so no
restart rule applies to the frame again. The flag stops any later call
through the re-issue slot, and the launcher's handler ends the trap
without writing its answer, so the program continues where its handler
sent it. A call that was made goes on to its end all the same: the
launcher finishes what it writes to program memory, the `.real/`
entries hidden from a listing, `ST_RDONLY`, a link's text, while the
result register stays as the handler left it. A handler that left the
counter at the syscall instruction and changed other registers makes
the program issue its call again with them, a fresh trap, as the kernel
would make the call with the registers the handler left.

The trampoline then returns through the kernel's frame for this
delivery as the kernel expects: on x86-64 by a `ret` with the stack
pointer at that frame's restorer address, into the program's restorer,
on aarch64 by a `ret` to the `x30` the kernel set, so that the entry the
kernel pushed at delivery on a shadow stack, x86-64's or aarch64's GCS,
is the one the return pops. A redirect in the entry stub, before the
record exists, ends the trap at once: the counter of this delivery's
frame goes to a `ret` in the page, two bytes into it on x86-64 and four
on aarch64, with the stack pointer at the trap's frame's restorer
address on x86-64, and on aarch64 the stack pointer at the trap's frame
and `x30` the launcher's restorer, which is what the shadow stack holds
there, so the trap's frame returns to the redirected program and no
call is made.

**Leaving otherwise.** A handler that `siglongjmp`s out, or an unwind
from it that lands in the program's frames, as glibc's cancellation
unwinds from its handler, leaves the presented frame, the kernel's
frame for its signal and the launcher's, with the trap's chunk, as a
`longjmp` out of a nested handler does, and the thread's next trap
releases the chunk (7.5.4), or a sweep does once the thread is gone.
What the launcher held at that point stays held: the descriptor of a
directory through which a long path is re-issued (`connect`, `bind`)
leaks, one per such leave, since no check can prove a number is still
the launcher's once a program may have closed and reopened it; and the
cache's lock, taken during an insert, stays taken, so that the process
makes no insert again, though a `fork` child starts with it free
(7.4.4); a release could not tell a lock left so from one a live insert
holds.
A handler that
issues an `rt_sigreturn` of its own on the presented frame resumes the
program at the presented state with its floating-point state, leaving
the launcher's frames as a `longjmp` does, but under a shadow stack,
whose token the presented frame lacks, or on aarch64 with an
`extra_context`, whose space the kernel requires right after the frame,
where the kernel refuses it with `SIGSEGV`.

**Queries and callable stubs.** An install traps; a query, an
`rt_sigaction` with no new action, passes to the kernel (7.4.2), which
answers with what the launcher installed: the stub as the handler, the
program's flags, the restorer installed with the stub, and the mask
without `SIGSYS` (13 item 20). An install's `oldact` is answered by the
handler, re-issued with the launcher's own buffer: where the kernel's
handler is a stub, the old action is the slot's handler and mask with
the kernel's flags and restorer; otherwise the kernel's answer as it
stands, the default, ignored, or the launcher's own handler for `SIGSYS`
(13 item 23). It is written to the program's buffer last, so a bad
`oldact` is `EFAULT` with the new action in force, as `sys_rt_sigaction`
leaves it. An install of a stub, which a program can only have from a
query, installs that stub's handler.

So a stub can be called as a function: Go's runtime queries each action
at its start, keeps a handler it finds, and on a fault in C code calls
the kept handler with the signal, its `siginfo` and its context; a
handler that queries an action before replacing it calls the old one
the same way. The slot keeps the restorer installed with the stub, the
program's, or on aarch64, where a program gives none and the kernel
would use the vDSO's, the launcher's own, the page's restorer, with
`SA_RESTORER` set for it and taken out again of an `oldact`. The stub
tells a delivery from a call by its return address, the word at the
stack pointer on x86-64 and `x30` on aarch64, which a delivery sets to
that restorer: equal, the trampoline runs as above; different, it jumps
to the program's handler with the arguments and the return address as
given, so the handler runs as if called directly.

**What it costs.** Outside a trapped call, a few instructions per
signal, and no stack but, on aarch64, one 16-byte slot for a register
it saves. Inside one, the presented frame and the block
above it, the copies and the comparison. On every trap, the record's
four words, the re-issue slot's check, the entry stub's write and the
filter's second stage for the `rt_sigreturn` of the trap's own return,
which the action cache no longer proves allowed (16.2). `test/progs/sigframe.c` reads the frame a handler
finds for a signal that lands during a blocking trapped open, with and
without `SA_RESTART`, outside any trap, and in a rain on stats of a
long path, and what a query and an install's `oldact` report, and a
handler called by another through a stub a query returned; the
kernel's answers are its expectation, but for the query. `test/stackcheck.py` walks the trampoline's C as a root of
its own, with a budget of its own, and fails on any call it makes out
of the trampoline's section, since that code runs where the reserved
register may hold the program's value (7.5.4).

### 7.6 Identity

For a wrapped program the kernel runs the launcher under the program's
own path, so `/proc/<pid>/exe`, `comm`, `cmdline`, audit records and
core-dump names are the program's for every observer. For a program on
the loader path, built outputs and host-path programs, the kernel's
`exe` and `maps` name the launcher and `.real/` files, which is 13 item
10 for observers outside the exclave; `cmdline` is the original `argv`,
and `comm` and `AT_EXECFN` are what the kernel would have set, carried
by the handler that exec'd it (7.4.5). From inside, `readlink` of
`/proc/self/exe` and of the process's own pid answers the program's
virtual path while `open` and `stat` of it reach the real file, and
another exclave process's `/proc/<pid>/exe` whose link is the launcher
answers, and resolves to, the program that process runs, read from the
`EXCLAVE_EXEC` the kernel keeps in its `environ` (13 item 46), so
glibc's `$ORIGIN`, Go's `os.Executable`, Rust's `current_exe` and
self-reading programs get the right file, and a built binary with
`RUNPATH=$ORIGIN/../lib` finds its libraries inside the exclave.

A program run from a descriptor that has no path, `fexecve` of a
`memfd` or of a file unlinked since it was opened, is a host program the
kernel would run from the descriptor. The handler dups the descriptor
without close-on-exec and execs the launcher with
`EXCLAVE_EXEC=/proc/self/fd/<dup>`; the child launcher loads the program
through that link, closes the dup once the segments are mapped, so that
the program's descriptor table is the kernel's, and answers the link's
text, `/memfd:name (deleted)`, for `/proc/self/exe`, as the kernel does.
Its `comm` is the file's own name, `memfd:name` or the unlinked file's,
and `AT_EXECFN` is `/dev/fd/N`. A script behind such a descriptor goes
to its interpreter as `/dev/fd/N`, the kernel's spelling, and a
close-on-exec script is `ENOENT`, as the kernel answers, since the
interpreter could not open it (13 item 25). For any program exec'd
through a bare descriptor, `comm` is the name of the file the kernel
finally loads, an ELF's own and a script's interpreter's, `dash` for
`#!/bin/sh` (`comm_from_dentry` in `fs/exec.c`, since 6.12; the
handler answers so on every kernel): the handler sets it where it finds
that file, and leaves it to the child launcher for a wrapped script,
whose interpreter the child resolves.

gdb sees the launcher, the executable of every wrapper, so the
launcher exports six names, the base, entry and real file of the
program it mapped, the base and file of the loader, and
`exclave_debug_hook`, which it calls once before the jump, and carries
a Python script, `src/gdb.py`, that gdb auto-loads from
`.debug_gdb_scripts` at launch and at every exec of a launcher. The
script adds the program's, the loader's and every library's symbols
from the tree, so a `break` in the program or the exclave's libc stops
with the right frames once the exclave is in gdb's auto-load safe-path;
13.1 gives the script's mechanics and the recipe, 13 item 1 what gdb
does not get, and 14.2 why gdb's JIT interface is not used.

A tracer is the one reader of another process's `exe` that gets the
kernel's text: gdb learns what it debugs from `/proc/<pid>/exe` at
every exec event, loads that file and auto-loads its script, so the
program's path, the answer every other reader gets, would hide the
launcher and its script from a gdb inside. The handler asks the
process's `/proc/<pid>/status` whether its `TracerPid` is the caller,
its process or one of its threads, only when the link is another
process's `exe`, and then answers the link as the kernel gives it: the
launcher for a program on the loader path, and for a wrapper of this
exclave the launcher's own path, the file the wrapper is, since an
open of the wrapper's path inside reaches its original (7.4.4). `open`
and `stat` of the link follow the same answer.

**The second exec.** gdb given a program, `gdb PROGRAM`, starts it by
`vfork`, `PTRACE_TRACEME` and an exec of `SHELL -c "exec PROGRAM"`
(`fork_inferior`), counts the execs that start expects, the shell's
and the program's or the program's alone (`startup_inferior`), takes
the image they leave for the file it was given, and reads
`/proc/<pid>/exe` only at an exec past that count (`follow_exec`).
Inside, that image is the launcher, so gdb would place the program's
breakpoints in the launcher's image and never load the script. So the
exec that makes a `vfork` child's deferred request (7.4.5) carries
`EXCLAVE_TRACED=1`, and the launcher it starts, of this exclave or
another, when its `TracerPid` is nonzero, execs its own file once
more, by its real path, with the same arguments and the variable set to
2: gdb meets an exec past its count, reads the launcher there, loads its
symbols and auto-loads the script, and a `break main` given before
`run` waits pending until the script adds the program.

gdb counts the shell's exec among its start's, and a second exec of the
shell would end the count early, with the shell's traps still to come.
So a launcher whose arguments are `-c` and a command beginning `exec `,
the shape of gdb's, makes no second exec but marks the next exec its
process makes, and that exec's launcher makes it. The rule reads the
arguments, not the program, so it holds for any shell and for a shell
of another exclave, and it matches any traced program run so: `gdb
--args sh -c 'exec PROGRAM'` with `startup-with-shell off` counts the
shell's exec alone, and meets the program's exec and its second after
it. With `set exec-wrapper` gdb counts the wrapper's exec too, which
the wrapper's second then ends, so the wrapper's first trap stops gdb
before the program's exec loads the script (13 item 1).

At the second exec the script reads the kernel's copy of the process's
environment, which holds `EXCLAVE_TRACED=2` and the name the program
was exec'd by, `EXCLAVE_EXECFN`, as gdb spelt it, and gives gdb that
name back as its file when the process exits (`exec-file`), so that
the next `run` starts the program as the first did and under the same
name, a link unresolved, which a program that reads its `argv[0]`
needs; a later exec of a launcher in the same run gives gdb that
program's name instead, as gdb's own following of an exec would. It
costs no syscall when nothing is traced: the handler's check is a
search of its own scratch chunks, and the launcher's a search of its
environment. Under a tracer that started its program so, it costs one
exec and one read of `/proc/self/status`, and the tracer meets one exec
stop more than the kernel gives (13 item 54). A `fork` child's request,
as strace makes it, is made at once and its exec carries no mark, and
an attached process or a fork child gdb follows needs none: gdb reads
the launcher at the attach or at the child's exec. A launcher older
than the variable passes it to its program and makes no second exec.

### 7.7 CPU check

The manifest's `cpu` (6.2) is compared on x86-64 with `cpuid` leaves 1,
7 and `0x80000001` for the `x86-64-v2`, `v3` and `v4` feature sets. The
vector levels also need the register state the kernel has enabled, read
from XCR0 with `xgetbv`, since a kernel booted with that state off
(`noxsave`, `clearcpuid`) leaves the instructions faulting on a CPU that
has them: SSE and AVX state for `v3`, and the AVX-512 opmask and both
ZMM halves too for `v4`, as glibc asks. `test/isa_test.c` checks the
decision against made-up `cpuid` and XCR0 values and against gcc's
`__builtin_cpu_supports` on the machine it runs on. On aarch64 the
levels are read from `AT_HWCAP`: `armv8.1-a` (LSE atomics and CRC32) and
`armv8.2-a` (with `DC CVAP`); `x86-64`, and `aarch64` or `armv8-a`, are
the baselines. Each launcher knows its own machine's names only. A
mismatch, or a `cpu` string the launcher does not know, is a clear
error before anything runs; since the launcher ships inside the
exclave, an unknown string means a damaged exclave. An exclave built
for two CPU levels is two exclaves: several roots chosen by this check
would be the one thing that made an exclave more than one tree.

### 7.8 `chroot`

Refused with `EPERM` (7.4.3), and stays refused. Re-rooting by
translation would have one use, running maintainer scripts in a scratch
copy of a tree, and that needs a writable root, which is a second world
(8.2); the tool synthesises what maintainer scripts would have done
instead (10.1).

## 8. Visibility rule

Every path a program names is either an **exclave path**, which the
tree answers for, read-only, or a **host path**, which the host answers
for as it would without the exclave. This section is the rule that
decides which, and what the exclave answers for its own paths.

### 8.1 Ownership

The rule has six parts. Code and other sections cite rule N of this
list as 8.1.N. A path with a trailing slash names the directory without
it, and every part rules it as it rules that directory.

1. **An exclave owns every top-level entry of its tree that is not an
   empty directory.** An empty directory is a placeholder, which the
   exclave does not own; a directory that cannot be listed is not a
   placeholder. The launcher reads the set from `tree/` at startup, one
   directory listing per top-level directory, so the tree is its only
   source; a volatile directory (rule 3) is the host's whatever it
   holds, so it is not read and is no entry of the set. The
   tool ships empty placeholders for `/home`, `/root`, `/boot`, `/mnt`,
   `/media`, `/opt`, `/srv`, `/tmp`, `/proc`, `/dev`, `/sys` and `/run`,
   and for `/var/tmp`, so that `ls /` lists them and `cd /home` works;
   a file dropped into a placeholder makes the directory the exclave's
   with nothing to refresh. The root directory itself is the tree's
   (8.3). The tables behind the rule are fixed: 256 top-level entries,
   a volatile one not counted, 256 `own` records, 32 `host` records
   and 32 `data` records. The launcher refuses to start beyond them
   and `exclave wrap` refuses to wrap, with the same numbers (13 item
   33).
2. **The host owns everything else.** `/srv`, `/mnt`, `/opt`, `/home`,
   whatever the host has. Reading data anywhere needs no configuration.
3. **The kernel's volatile directories are always the host's:** `/proc`,
   `/dev`, `/sys`, `/tmp`, `/var/tmp` and `/run`, whatever the tree
   ships, and whatever an `own` record says.
4. **The working directory.** At startup the launcher canonicalises the
   inherited working directory. Under `<exclave>/tree/` it becomes its
   virtual path and is given to no one, so a wrapper run from inside the
   tree does not hand `/usr/bin` to the host. Host-owned, it needs
   nothing. On an exclave path, the working directory is given to the
   host as a subtree, so relative paths into its subdirectories,
   `-o build/x.o` and `-I include`, resolve on the host. The directories
   on the way to it are the host's too, as directories, so that
   `realpath`, `pwd -P` and a compiler locating itself by an absolute
   path can walk them; their other entries are not, and `..` above the
   working directory otherwise stays in the exclave (13 item 14).
   Whether the working directory is an exclave path is decided by the
   other rules, without this one.
5. **Eleven host identity files and three identity directories are the
   host's by default.** The files: `/etc/passwd`, `/etc/group`,
   `/etc/nsswitch.conf`, `/etc/host.conf`, `/etc/resolv.conf`,
   `/etc/hosts`, `/etc/localtime`, the trust bundles
   `/etc/ssl/certs/ca-certificates.crt` and
   `/etc/pki/tls/certs/ca-bundle.crt`, and Java's trust stores
   `/etc/ssl/certs/java/cacerts` and `/etc/pki/java/cacerts`, each pair
   Debian's name and Red Hat's. The directories: `/etc/ssl/certs` and
   `/etc/pki/tls/certs`, the directories of the two bundles, where a
   host's trust tool keeps its authorities one to a name, by name and by
   subject hash, for a library that verifies through a directory
   (OpenSSL's `CApath`, which Debian's OpenSSL reaches through
   `/usr/lib/ssl/certs`, and the two directories Go's `crypto/x509`
   reads); and `/var/lib/sss`, SSSD's state, where SSSD's lookup module
   finds the daemon by its socket and its memory cache, as the host's
   other directory services keep theirs under `/run`. They describe who
   the user is, how names are looked up, DNS, the time zone and which
   authorities the machine trusts, all of which belong to the host, and
   they are data, read by libc, by TLS libraries, by a JDK or by SSSD's
   lookup module in formats those read whatever their version, not code:
   `/etc/localtime` is a TZif file, on most hosts a symlink into the
   host's `/usr/share/zoneinfo`, which the kernel follows on the host
   (8.4), so the zone needs no `tzdata` in the tree, and a certificate
   in the trust directory is a link into the host's
   `/usr/share/ca-certificates` or `/usr/local/share/ca-certificates`,
   followed there the same way. Seven of the files are on PRoot's
   default binding list. `own` on an identity file or directory removes
   it, and `own` on a path inside an identity directory makes that path
   the exclave's. One the host lacks falls through to the exclave's, an
   identity file inside an identity directory the host has included: Red
   Hat's hosts have `/etc/ssl/certs` and no `ca-certificates.crt` in it,
   so a Debian tree reads its own bundle there. Where the host's
   identity directory is a link at its name, as Fedora's and Red Hat's
   `/etc/ssl/certs` are, the directory the kernel resolves it to is an
   identity directory too, at its own name, so that the names the kernel
   gives a working directory or a descriptor there are the host's
   inside. The tool ships each of the eleven files as an empty
   placeholder when the tree lacks it, and the path walk treats the
   directories on the way to an identity file or directory as
   directories whether or not the exclave ships them (8.4).
6. **The exclave's own directory** is the host's, with the directories
   on the way to it, whatever prefix it lives under: a program that
   locates its files relative to its real executable path, as gcc does
   from `argv[0]`, must reach them. The tree itself is not made the
   host's by this: in the walk, the real path of `tree/` is an alias of
   `/`, so a path spelt through it is the same virtual path, an exclave
   path and read-only like any other, and the wrappers are reachable by
   the real paths the kernel reports for them because those paths
   resolve to themselves.

`host <path>` adds a host path at its own name; `own <path>` makes one
the exclave's. A `host` record whose host path is a directory gives
the host that subtree; one whose host path is a file or a symlink is
followed on the host like an identity file (8.4) and stands for that
one name; one whose host path does not exist is dropped, and
the exclave answers.

When several parts apply, the launcher decides in this order:

1. `/` itself is the tree's.
2. An identity file, or a `host` record naming a file, is the host's.
3. The working directory given to the host (rule 4) and the exclave's
   own directory (rule 6), each with the directories on the way to it,
   are the host's.
4. A volatile directory (rule 3) is the host's.
5. Otherwise the longest matching prefix among the `host` records and
   the identity directories, and the owned paths, rule 1's entries, the
   `own` records and the identity files inside an identity directory
   that the host lacks, wins; at equal length the `host` record wins.
6. A path no prefix matches is the host's (rule 2).

### 8.2 Read-only by refusal

Exclave paths cannot be written, and the handler alone enforces it:
the tree is not mounted read-only and its modes are not changed. The
rule is small enough to state in full. It answers what the kernel
answers on a read-only bind mount in a user namespace, which the
oracle of 17 item 1 measures and the syscall probe of 17 item 7 checks
syscall by syscall. `fs/namei.c`, `fs/open.c` and `fs/utimes.c` are
the references for the kernel's order.

- Write-mode opens, `O_TRUNC`, `O_TMPFILE`, creation, `mkdir`, `mknod`,
  `unlink`, `rmdir`, `rename`, `link`, `symlink`, `chmod`, `chown`,
  `utimensat`, `truncate`, attribute sets and removals, and the
  `chattr` ioctls on an exclave path or on a descriptor that refers to
  one, fail with `EROFS`. So does `bind` of a unix socket at an
  exclave path, the name looked up first as for any create, with
  `EEXIST` read as `EADDRINUSE`. `connect` to an exclave path answers
  from the lookup, then `EACCES` without write permission on what it
  found, as the kernel's `unix_find_bsd` does, and `ECONNREFUSED` for
  anything else that exists, since nothing can bind there.
- Where the kernel checks something before its write check, so does
  the handler, in the kernel's order, each case costing at most one
  `lstat` on the failing path.
  - The arguments the kernel checks before any lookup come first: the
    flags of `unlinkat`, `renameat2`, `linkat`, `fchmodat2`,
    `fchownat`, `faccessat2`, `newfstatat` and `statx`, the mode of
    `faccessat` and the mask of `statx`, a negative `truncate` length,
    the file type `mknod` is asked for, the target of `symlink`, an
    extended attribute's name, flags and size (`ERANGE` for an empty
    name), an `inotify` watch's mask and descriptor, and a `chattr`
    ioctl's argument. Where an older kernel looked the path up first,
    the handler answers as the newer kernels do (12.1).
  - A create (`mkdir`, `mknod`, `symlink`, `link`, `open` with
    `O_CREAT`) looks the name up first: an existing name is `EEXIST`,
    which `mkdir -p`, `install -d` and every configure script rely on;
    the name's own error, `ENAMETOOLONG`, `ENOTDIR`, a filesystem's
    `EILSEQ`, is reported as it is; a trailing slash, spelt in the path
    or ending the text of a final symlink that is followed (the kernel
    walks the text as the rest of the path), is `EISDIR` for
    `open` and `ENOENT` for a non-directory create, and a symlink
    before it is the existing name itself, never followed (7.4.3); a
    last name that is `.` or `..`, slash or not, is the directory
    itself, `EEXIST` under `O_EXCL` and `EISDIR` otherwise;
    and only then comes `EROFS`. `O_CREAT` without `O_EXCL` on an existing file opened
    read-only succeeds.
  - A write-open or `truncate` of a directory is `EISDIR`, `truncate`
    of a special file `EINVAL`, `O_TMPFILE` on anything but a directory
    `ENOTDIR`, and a non-creating write call on a missing path
    `ENOENT`, or the lookup's own error.
  - A delete, `unlink` and `rmdir`, is `EROFS` whether or not the name
    exists, since the kernel's `mnt_want_write` precedes its final
    lookup; an overlong last component under an exclave directory is
    `EROFS` too, for the same reason. Before that come the answers for
    a last component of `.`, `..` or `/`, which the kernel never looks
    up: `EINVAL`, `ENOTEMPTY` and `EBUSY` for `rmdir`, `EISDIR` for
    `unlink`. `rename` answers those with `EBUSY` on either side, or
    `EEXIST` for the new name under `RENAME_NOREPLACE`, for two names
    the exclave owns, after `EXDEV` for one of each domain; two names
    the host owns are the kernel's own, such a name kept after its
    resolved parent (`filename_parentat` leaves it to `do_renameat2`),
    since the host's mounts may differ among themselves, `/proc` or a
    tmpfs against the rest, and the kernel compares the parents' mounts
    before it refuses the name.
  - Two `UTIME_OMIT`s are a no-op before any lookup.
- `link` and `rename` between an exclave path and a host path fail with
  `EXDEV`, as they would across a mount boundary. Without this rule a
  hard link out of the tree would create a writable alias of an exclave
  file. The kernel's order, confirmed by the oracles: `rename` checks
  the mounts before it looks up the source, so a missing source across
  the border is `EXDEV`, not `ENOENT`; `link` looks the source up
  first, so there it is `ENOENT`, then the new name in either domain,
  so an existing one is `EEXIST` before `EROFS` or `EXDEV`.
- `install -d` on an existing directory succeeds only when the mode
  already matches, since it otherwise `chmod`s; the tool therefore
  keeps the archive's directory modes.
- Where the kernel checks a permission before the mount, so does the
  handler, on the real file:
  - `access(W_OK)` answers the lookup's own error, then `EACCES` for a
    file its owner cannot write, then `EROFS` for a regular file, a
    directory or a symlink, and succeeds on a special file, which the
    mount does not protect (`do_faccessat`).
  - A write-open without `O_TRUNC`, and `truncate`, answer `EACCES`
    before `EROFS` on a regular file; an open with `O_TRUNC` wants the
    mount first; and a socket or a FIFO in the tree is opened as the
    kernel opens it, `ENXIO` for a socket (`do_open`, `may_open`,
    `do_dentry_open`, `vfs_truncate`, measured on the reference
    kernel). Older kernels order two of these differently: on 6.1 and
    earlier `truncate` checks the mount before the permission (6.14
    checks the permission first), and before 5.9 `utimensat` refuses
    `AT_EMPTY_PATH` and checks the nanoseconds before the lookup. The
    handler answers as the newer kernels do, and the syscall probe
    accepts the older orders on the matrix rows that run such kernels.
  - `utimensat` answers a flag it does not take, or a NULL path with
    `AT_FDCWD`, before any lookup, with `EINVAL` and `EFAULT`, and a
    nanosecond out of range after the lookup and before the mount;
    `utimes` answers a microsecond out of range before the lookup.
  - `readlink` answers a size of zero with `EINVAL` before it reads the
    path.
  - `fchmod`, `fchown`, `fsetxattr`, `fremovexattr` and `ioctl` on an
    `O_PATH` descriptor are `EBADF`, before the descriptor's path is
    considered.
- `statfs` and `fstatfs` on an exclave path report `ST_RDONLY`, and
  `statvfs` follows on any glibc that trusts the kernel's `f_flags`
  (kernel 2.6.36 and later; measured on glibc 2.39). `/proc/mounts`
  shows the host's mounts (13 item 11).

A running program's file is the one case where the answer depends on
who writes. The process that loaded a program on the loader path gets
`ETXTBSY` for a write-open or `truncate` of that program's file, after
the permission and before any read-only answer, as the kernel answers
for the programs it executes (7.4.3). Another process's write-open
without `O_TRUNC` of an exclave file that is running answers `EROFS`
where the kernel answers
`ETXTBSY` (13 item 29); on a host path it succeeds (13 item 40).

Two orders the handler does not follow are stated in 13: that one,
and `fanotify_mark`'s flag bits (13 item 41). The oracles measure the
rest on the kernel matrix, since orderings differ between kernels.

There is no `chmod` of the tree: modes are fragile across copies and
version control, a write-protected tree resists `rm -r`, and the owner
could put the bits back. An exclave stays deletable and copyable with
ordinary tools, and behaves identically on writable and read-only
media. State that software insists on writing under an exclave path
gets a host directory through a symlink in the tree to a fixed host
path; per-user state has no expressible target (13 item 19).

### 8.3 What `ls` shows

The root directory is the tree's: no part of the visibility rule owns
`/` itself, so the launcher gives it to the tree, and `ls /` inside an
exclave lists the tree's top-level entries, which with the placeholders
of rule 1 are the conventional names. `cd` into a placeholder works
whether or not the host has a directory of that name. A host-owned file
inside an exclave-owned directory appears when opened but not in a
listing (13 item 6). `.real/` appears in no listing of a directory of
the tree, so that a program inside sees upstream's tree: `getdents64`
and `getdents` trap, the kernel writes its batch into the program's
buffer as it would, and the handler reads it back and, where it holds
the tree's `.real`, writes it again without the entry, the room filled
as the kernel fills a batch and a batch of nothing else followed by the
next. A refusal only `.real`'s record causes, a buffer too small for it
(`EINVAL`) or one the kernel cannot write it to (`EFAULT`), answers as
for the entry after it, so a listing of the tree names what upstream's
tree names at every buffer size (`listings_hide_real`), but for two
threads listing one descriptor at once, where the one entry after a
refusal so caused may come twice, since the kernel serialises one call
and that answer takes three; a batch holds
at most the scratch's 8 KB, as a listing may return fewer entries than
fit. A `.real/` the host has is listed as the host has it, and the
directory still opens by name. On the gcc exclave,
best of five, November 2026, `find /usr` takes 13 ms and `ls -lR /usr`
65 ms with the listings trapped, against 13 ms and 64 ms without.

A directory of the tree that holds `.real/` stats as upstream's too: a
link fewer, where links count subdirectories, so not on btrfs, which
gives a directory one, and a size an entry smaller on the filesystems
whose directory size counts entries, ZFS one an entry, btrfs twice the
name and tmpfs 20 bytes; another filesystem's size is 13 item 53. Every
stat corrects it, `fstat` among them, which the filter traps from
version 8 (`directory_stats_hide_real`); a path the canonicalisation
cache knows is no directory costs nothing more, and whether a directory
holds `.real/` is asked once a process and kept there (7.4.4). On the
gcc exclave, alternating the two launchers, best of seven, November
2026, `find /usr` takes about 15.5 ms and `ls -lR /usr` 71 ms with the
stats corrected, against 14 ms and 69 ms with the listings alone: a
stat of each directory a process has not stat'd before.

### 8.4 Host identity files and directories

At startup the launcher records in the host table each identity file
the host has: a file, or a symlink whose chain the host resolves, from
`/etc/resolv.conf` to `/run/systemd/resolve/stub-resolv.conf` for
instance. A call on an identity file is re-issued on its host name,
and the kernel follows the host's link, at the moment of the call and
in the host's space, as it follows it for the host's own programs. A
running program therefore sees the host retarget `/etc/resolv.conf`, as
a VPN client or a change of resolver does, or rename a file over the
link. Inside the exclave the identity file behaves as the host's link
does: `readlink` answers the host's link text, `lstat` and an
`O_PATH | O_NOFOLLOW` open see the host's symlink itself, and an
`O_NOFOLLOW` open fails with `ELOOP`. Every other call that does not
follow the last component is the host's own call on the host's link,
re-issued on the link by its host name with the no-follow flag kept, so
that the kernel answers for the link as it answers the host: `lchown`,
`fchownat`, `utimensat`, `faccessat2` and `fchmodat2` with
`AT_SYMLINK_NOFOLLOW` (`EOPNOTSUPP` for a link's mode), the `l*` and
`*at` attribute calls (`EPERM` for a user attribute set or removed on a
link, `ENODATA` for one read), `inotify_add_watch` with `IN_DONT_FOLLOW`
and `fanotify_mark` with `FAN_MARK_DONT_FOLLOW`, which watch the link,
`link` with the link as its old name, `rename` of either name and
`unlink`, which move or delete the link and leave its target, and
`execveat` with `AT_SYMLINK_NOFOLLOW`, `ELOOP`. The directories on the
way to an identity file or directory are traversable in the path walk
whether the exclave ships them or not (8.1 rule 5). Which identity
files and directories are the host's is fixed for the process's life
(13 item 18).

An identity directory is the host's directory at its name, its links
followed on the host at each call, as an identity file's chain is, with
`..` at its root climbing in the exclave. At startup the launcher
`lstat`s each one: a directory is the host's; a link at the name is the
host's too, opened as a directory, following links, and the directory
the kernel names for it, read back from `/proc/self/fd`, recorded as an
identity directory at its own name; anything else, no entry, a file, a
link that leads to no directory or to a name outside this root, is the
exclave's for the process's life (13 item 18), its links resolved in
virtual space like any of the tree's. Nothing new is logged: an absent
one is the same line as an absent identity file.

The walk (7.4.4) passes an identity directory by its name, whether the
host has it as a directory or as a link, so the kernel follows a host
link at the name, or above it, at each call as it reaches the names
below, and a `..` at a directory the host has as one climbs to its
parent in virtual space, as `..` at a bind mount's root climbs to its
mount point's parent. Where the host's name is a link, a `..` at the
name, however the path reaches it again (`certs/./..`,
`certs/sub/../..`), climbs from the directory the link reaches, opened
on the host and named as the kernel names it, as the kernel climbs after
following the link: Fedora's `/etc/ssl/certs/..` is `/etc/pki/tls`. The
rule is asked of every name below it before the host's entry is looked
at, so the exclave's names there, an identity file the host lacks or a
path an `own` record names, are the tree's, at the directory the tree
resolves for them, its links followed in the tree as a chroot would
follow them, a component the tree lacks taken as a directory, which is
where `wrap` places an identity file's copy: Fedora's tree has
`/etc/ssl/certs -> /etc/pki/tls/certs`, which the kernel would otherwise
follow on the host. A component that is a file, a loop, a link that
cannot be read, or a directory that resolves under a volatile one, which
is the host's, gives such a name no place: `wrap` places no copy there
and says so, and the launcher's answer for it is an error, as a chroot's
would be under a file. The directory holding such a name resolves
through the tree's links as a chroot would; below it the tree's links
are followed in virtual space, `..` and relative text by the virtual
parent; a working directory or a descriptor there is named by the tree's
plain name for it where that name is the tree's, and by the name the
rule maps where the plain name would be the host's, a name that would
outgrow `PATH_MAX` refused with `ENAMETOOLONG`. That costs an `lstat` at
startup for each directory on the way to such a name. A name below it
that the rule gives the host is `lstat`ed on the host. A link that is
the last component is the kernel's to follow: the call is re-issued on
the link's host name with the call's own following of it, so that the
kernel follows the link and every link after it on the host, at the
moment of the call. A link with components after it is opened on the
host as a directory, following links, and the walk goes on from the
directory the kernel names for it, by that name, where the rule gives
that name to the host or it is the tree's; otherwise it is passed by its
name as the directory itself is, the kernel following it at each call.
So `/etc/ssl/certs/<hash>.0 -> <name>.pem ->
/usr/share/ca-certificates/mozilla/<name>.crt` reads the host's
certificate whether or not the tree has `/usr/share/ca-certificates`, an
authority the host's administrator added under
`/usr/local/share/ca-certificates` is trusted inside as outside, and a
host whose trust tool links elsewhere, as Fedora's links into
`/etc/pki/ca-trust/extracted`, is followed there.

Every call on a path at or below an identity directory that the rule
gives the host is the host's own, re-issued on the host path, as a call
on an identity file is: a create, a write, a delete or a rename there
answers as the host answers the user, `EACCES` where root owns the
directory, not `EROFS`, and `rename` and `link` between it and an
exclave path are `EXDEV` first (8.2). Run as root inside,
`update-ca-certificates` therefore rewrites the host's directory, from
the tree's `/usr/share/ca-certificates`, as a root `passwd` inside
rewrites the host's `/etc/passwd`. `readlink` answers the host's link
text, and `lstat` and the no-follow calls see the host's link itself,
the directory's own name included where the host's is a link. A listing
of the directory is the host's, unaltered (8.3), so an exclave name
inside it that the host lacks opens and is not listed, the converse of a
host file in an exclave directory (13 item 6). `getcwd` there answers
the directory as the kernel names it, an identity directory at that
name, and a relative path from it is walked as from any directory.

Under `openat2`'s `RESOLVE_NO_SYMLINKS`, `RESOLVE_NO_XDEV`,
`RESOLVE_BENEATH` whatever its scope, or `RESOLVE_IN_ROOT` with a scope
other than the root, the walk hands no link at or below an identity
directory to the kernel, which would apply the flags on the host's
mounts or not at all: it follows the link itself, a host link at the
directory's name included, as the kernel would on a bind mount of the
host's directory or at the host's link laid at its name, so that a link
is `ELOOP` under `RESOLVE_NO_SYMLINKS`, an absolute target is `EXDEV`
beneath any scope, the root included (`nd_jump_root`), or across the
mount at the directory (`RESOLVE_NO_XDEV`, which a `..` out of it
crosses too), and under `RESOLVE_IN_ROOT` restarts at the scope (7.4.3).
A walk with `RESOLVE_NO_MAGICLINKS` alone, or `RESOLVE_IN_ROOT` at the
root, hands a final link to the kernel with `RESOLVE_NO_MAGICLINKS` kept
on its re-issue, since what a host link reaches may be one; a link with
components after it the handler opens on the host itself, following
magic links whatever the flag says. Identity directories add no trap, no
log line and no manifest key, so neither the filter's version nor the
page generation moves and launchers nest as before (6.7).

The translator never follows an identity file's host link, or a link in
an identity directory, in virtual space, where `/usr` is the exclave's;
the kernel follows it on the host, so `/etc/localtime ->
/usr/share/zoneinfo/Europe/London` reads the host's zone file whether or
not the tree has a `zoneinfo` directory. Nor do host symlinks in general
keep their host meaning: such a rule would let a host link into `/usr`
reach the host's `/usr`. The identity files and directories describe the
host and hold data, so what their links reach is the host's to say; no
other name is. Every other symlink, on a host path or an exclave path,
is resolved in virtual space (7.4.4).

The host's `nsswitch.conf` names NSS modules, `systemd`, `sss`,
`ldap`, `mdns4_minimal`, which a glibc exclave loads from its own tree,
since a module is code bound to its libc. Each is a client of a daemon
of the host's: `systemd`'s, `nslcd`'s, `winbindd`'s and `avahi`'s
sockets are under `/run`, a volatile directory, reached as well
through the `/var/run` link Debian's and Alpine's trees ship, and
SSSD's socket and memory cache under `/var/lib/sss`, the host's by
default (8.1 rule 5). The user records systemd reads from
`/etc/userdb` are the tree's, since `/etc` is.
So an exclave that ships a module finds the host's users through it,
whatever version the host's daemon is, as long as the protocol holds;
`test/nss_test.py` looks up a user served in SSSD's protocol, by name
and by uid, through Ubuntu's `libnss_sss.so.2` (17). glibc skips a
module the tree lacks, which is right for `hosts` and wrong for
`passwd` on a host whose users come from LDAP, SSSD or
`systemd-homed`, where `getpwuid` then fails inside (13 item 17).
`exclave check` given a log warns of each module the checking host's
`nsswitch.conf` names that the exclave lacks, naming the package that
ships the common ones (10.3), so an exclave's maker who checks on such
a host learns of it before a user does. musl loads no modules: for
users and groups it reads `nscd`'s socket, under `/var/run`, after
the files, and for host names it asks DNS alone, so `exclave check` on
a musl tree, one with musl's loader and not glibc's, says which of
the host's modules nscd could stand in for.

## 9. Compilers specifically

- **Hermetic sysroot by default.** A gcc exclave carries its own glibc
  headers, startup objects and `libc.so`. Its outputs name
  `/lib64/ld-linux-x86-64.so.2`, the host's loader outside the exclave,
  and run on any host whose glibc is at least as new. Inside the
  exclave they run on the exclave's glibc regardless of the host
  (7.4.5), so `make check` works. For wider portability, give a gcc
  exclave an older glibc or a musl sysroot as a data directory, or link
  `-static`.
- **Cross toolchains** are one exclave with one libc for the tools and a
  `data` sysroot for the target; their outputs run inside only when the
  target libc is the exclave's. A musl development exclave, such as
  the Alpine exclave below, runs musl outputs.
- **An older glibc as a sysroot.** CentOS 7's `glibc`, `glibc-devel`,
  `glibc-headers`, `kernel-headers` and `libgcc` rpms, unpacked by the
  rpm reader, are copied into the Ubuntu 24.04 gcc exclave at
  `/opt/sysroot-el7` and recorded as `data "/opt/sysroot-el7"`, so that
  nothing there is wrapped, checked or executed. The compile is
  `gcc --sysroot=/opt/sysroot-el7 -B/opt/sysroot-el7/usr/lib64/`: the
  sysroot for the headers, and `-B` for the start files and libc, since
  Debian's gcc searches its own multiarch directory before the
  sysroot's and would otherwise link the exclave's libc. The sysroot's
  `libc.so` linker script names `/lib64/libc.so.6`, which `ld` prefixes
  with the sysroot because the script lies inside it. The output binds
  `GLIBC_2.2.5` alone, and runs inside the exclave on the exclave's
  loader and natively on the reference machine. `test/sysroot.py`
  makes the exclave and the output, with gcc and, in the clang exclave,
  with `clang-18` under the same two flags, since clang finds
  `crtbegin.o` in the exclave's own libgcc development files; the
  kernel matrix runs the output natively on each glibc row, CentOS 7 at
  glibc 2.17 included (12.1); Alpine's musl has no loader for a glibc
  program. A static
  link made the same way needs `glibc-static` in the sysroot.
- **A clang exclave**: Ubuntu 24.04's `clang-18` closure with
  `libc6-dev`, `libgcc-13-dev`, `libstdc++-13-dev` and `binutils`,
  wrapped with no error. A maker who wants `cc` adds `cc -> ../../bin/clang-18` and
  `c++ -> ../../bin/clang++-18` in the exclave's own `/usr/local/bin`,
  which is what puts a name on the exclave's `PATH` (6.2). The test
  inputs' clang exclave has none, and the test suite finds its compiler
  as `clang-18`. C and C++ compile and run inside; the sanitizer
  runtimes are in a package that set does not include. It is one of
  the four test exclaves (17).
- **An Alpine exclave**: `gcc musl-dev binutils make linux-headers`
  and the base from Alpine 3.21, fetched with `scripts/fetch-apks`,
  unpacked and wrapped: no error from the static check, and a tree
  hash that reproduces from the same files. Its gcc 14.2 compiles and runs C inside, dynamically linked
  on musl 1.2.5 and statically linked. The static output runs on a
  glibc host; the dynamic one does not, since such a host has no musl
  loader. A compile touches no host path, and it is one of the four
  test exclaves (17).
- **A Fedora exclave**: `gcc glibc-devel binutils make` and the base
  from Fedora 42, fetched with `scripts/fetch-rpms`, with
  `glibc-minimal-langpack` chosen for the langpack, unpacked and
  wrapped: no error from the static check, and a tree
  hash that reproduces from the same files. Its gcc 15 compiles and
  runs C inside on glibc 2.41; a static link needs `glibc-static`,
  which the set does not include. A compile touches no host path, and
  it is one of the four test exclaves (17).
- **Targeting the host's own libraries** is not a manifest setting. A
  `host` record over the exclave's library directory takes the
  exclave's loader and libc with it, so no dynamic program in the
  exclave starts, which the static check reports (10.3); and the host's
  headers over the exclave's libc would compile against one glibc and
  link against another. A program for an older host is built against
  an older glibc as a sysroot, as above.
- **Two CPU levels**: what the compiler binaries need, `cpu`, checked
  at launch (7.7); and what the compiler targets by default,
  `--with-arch` at configure time, overridable with `-march`, including
  generic levels like `x86-64-v2`.
- **Multi-process drivers** need nothing special; verified with gcc's
  `cc1`, `as`, `collect2` and `ld`, including under `perf`.
- **32-bit outputs cannot run inside a 64-bit exclave**, since
  foreign-ABI syscalls are killed (13 item 4); a multilib toolchain's
  `-m32` tests must run outside.
- **Compiler-identity caches** see every compiler in an exclave as the
  same small binary at the same mtime, so ccache's default
  `compiler_check = mtime` would share entries between two different
  exclaves. ccache needs `compiler_check = %compiler% -v`.

## 10. The `exclave` command

The `exclave` command makes an exclave of a directory, and checks,
prunes and relinks it. It is Go, in `tool/`, built by `scripts/build`
with the pinned toolchain `scripts/install-go` puts in `.go/` as one
static file per architecture that carries its launcher (10.5), and run
from a checkout as `build/exclave` or `scripts/exclave`. The tests judge
it only through its commands. `unpack` (10.1), the step before it, is
its subcommand, `exclave unpack`, the package `unpack/`; the fetchers,
the step before that, are `exclave-fetch`, a program of their own built
the same way from `fetch/`, so that the command holds no network code.
The tests are Python, run by the
pinned Python: the uv that
`scripts/install-uv` puts in `.uv/` installs the version
`.python-version` names (3.15) into the checkout, and every script runs
through it (`scripts/lib.sh`), so nothing the machine has installed
decides which Go or Python runs.

The tool's input is an unwrapped exclave, a directory holding `tree/`.
What made the tree is the step before the tool: `unpack` from package
files (10.1), a build's staging directory (10.2), `debootstrap`, a
container export or `tar`. No command of the tool opens a network
connection, and the command holds no code that could: the files they
are given are their inputs, whoever fetched them, and any record of
where they came from is the fetcher's to keep; `exclave-fetch` is that
fetcher, a program of its own. Every command of the tool takes paths,
and `format --check` is the only flag; `exclave-fetch` takes the
arguments a download needs, which its `--help` lists:

```
exclave wrap EXCLAVE                wrap an exclave (idempotent; a bare directory holding tree/ becomes an exclave)
exclave unwrap EXCLAVE              unwrap an exclave again
exclave caches EXCLAVE              Python bytecode, GSettings schemas, the MIME database and GIO's, gdk-pixbuf's, icon, desktop and font caches, graphviz's plugin configuration and TeX Live's indexes and formats, made by the tree's own generators inside the wrapped exclave (10.1)
exclave check EXCLAVE [LOG...]      wrappers, the tree against the hashes file, the static check, and with EXCLAVE_LOG files the dynamic check
exclave prune EXCLAVE LOG...        drop what no logged workload touched
exclave format [--check] FILE...    canonical form of a manifest or hashes file; --check only reports
exclave hash EXCLAVE|FILE           the tree hash of 6.4, or a file's hash as the hashes file writes it
exclave relink EXCLAVE [LAUNCHER]   replace the launcher, relink every wrapper and ship the placeholders the tree lacks
exclave version                     the build this command is from: the project's version and the commit
exclave unpack OUT PKG...           an unwrapped exclave from package files (10.1); exclave unpack ldconfig TREE writes ld.so.cache for a tree made by hand
exclave-fetch debs|apks|rpms ...    a package closure from a repository, verified and downloaded (10.1)
exclave-fetch version               the build it is from, as exclave version
```

`wrap` and `relink` also write the exclave's `README` (6.1) where it
has none. Every command of the tool's own except `format` refuses,
before reading or writing anything, a directory without `tree/`, and
every one except `wrap` refuses one without `.exclave/`.

### 10.1 From packages

```
scripts/fetch-debs --keyring /usr/share/keyrings/ubuntu-archive-keyring.gpg --out debs gcc-13 libc6-dev   # or apt, a mirror, a hand-made directory
scripts/unpack gcc-13.exclave debs/*.deb
exclave wrap gcc-13.exclave
ln -s tree/usr/bin/gcc-13 gcc-13.exclave/gcc
```

**Unpack** is the step before the tool, as fetching is the step before
it: the command's `unpack` subcommand, `exclave unpack OUT PKG...`
(`scripts/unpack`), the package `unpack/`, which shares with the tool's
other commands only the layout of 6.1 and the hashes file of 6.4. It reads `.deb`, `.apk`
and `.rpm` files, each through a reader chosen by the file's suffix;
the three share one interface, and a set that mixes formats is
refused. From `.deb` files, in five steps:

1. **Read** every file's control archive: name, version, architecture,
   dependencies, maintainer scripts. Two files carrying one package
   name, or a set mixing architectures, are refused. Every `Depends` and
   `Pre-Depends` is checked within the set, honouring `Provides` and
   version constraints, and each one the set does not satisfy is
   reported by name: `tool needs absent-pkg, not in the set`. This is a
   report, not a refusal, because the set is its maker's choice; the
   static check (10.3) is the gate on correctness, and a missing data
   file shows up as a failed open in `EXCLAVE_LOG`. The Essential set, which every package assumes and none
   declares, is the fetcher's concern; `fetch debs` adds it
   unless given `--no-essential`.
2. **Extract** each `data.tar.*` into `tree/`, after creating the
   distribution's merged-`/usr` symlinks (`bin`, `sbin`, `lib`, `lib32`,
   `lib64`, `libx32` to their `usr/` counterparts). Directories and
   identical symlinks shipped by several packages are normal. A regular
   file shipped by two packages is an error unless one declares
   `Replaces` on the other; the merged-`/usr` spellings of a path count
   as one path. A diversion a package makes for itself, with
   `--package` naming it and both paths literal puts every other
   package's file at the path, in any of its merged-`/usr` spellings,
   under the diverted name, whichever package comes first, a hard link
   to the path linking to it there, and the package's own at the path, which is where dpkg leaves them;
   each file moved is named in the log. postgresql-common's, which
   diverts libpq-dev's `/usr/bin/pg_config` to
   `pg_config.libpq-dev`, is the case. Any other renaming diversion is
   refused with a message, since the tree would have to hold a file
   under a renamed name the rule cannot read, or the package's own
   file too (`--local`), but for one a package makes for itself of a
   path the rule cannot read, built from shell variables, which moves
   aside other packages' files at that path for the package's own:
   it is admitted with a note where no other package
   of the set ships a file the package ships, since then it has nothing
   to move, and refused where one does. vim-runtime's, which diverts
   vim-tiny's copies of its help files, is the case: `vim` unpacks
   without `vim-tiny`. Diversions with `--no-rename`, and the
   merged-`/usr` and `zutils` transitions that every Ubuntu 24.04
   closure carries, leave a fresh tree unchanged and are ignored.
   Every path, a member's, a hard link's target, and each one the next
   two steps read or write, resolves with the tree as its root, as dpkg
   resolves it in the root it installs into: an absolute symlink starts
   at the tree's root and `..` stops there, so a link that points out of
   the tree leads back into it, and nothing outside the tree is read,
   written or removed (`unpack/root` walks each path one directory
   descriptor at a time, no component followed but by reading it, at
   most 40 links). A hard link to a file the tree does not hold is
   refused, and so are `..` in a member's name and a member under the
   reserved name `.real` (6.1). Payloads are read as they decompress,
   never held whole, and a set whose files' declared sizes would leave
   the output's filesystem with less than 256 MiB free is refused before
   a byte of it is written. That first read of every payload, for the
   sizes and for the links other packages' files land under, runs on up
   to eight goroutines, a package to each, and is then taken in the
   packages' order, so what it decides, and the first failure it names,
   are those of one package read after another. A package file that cannot
   be read is refused in one line, and a failed unpack leaves no
   output behind. An archive ends where its format says: anything but
   NUL padding after a tar archive's last member, where a header that
   cannot be read stops the reader, or after a cpio payload's trailer
   is refused, since another reader could extract members hidden
   there; a cpio payload without its trailer, or with an entry running
   past its end, was cut short and is refused too.
   `ar` and `cpio` are read here; `tar`, gzip and bzip2 by Go's standard
   library, and xz and zstd by the pure-Go decoders `go.mod` pins. Modes
   and modification times come from the archive, with setuid and setgid
   bits dropped (they mean nothing under `no_new_privs`, 12) and every
   file made readable by its owner; special files are skipped with a
   note.
3. **Synthesise** the effects of maintainer scripts; the scripts are
   never run. The rules are a table, `unpack/rules.go`, each named,
   applied in order when the packages ask for it, and named in the log
   when it applied; they approximate dpkg's configure step for the case
   without privilege, and a tree whose scripts must really run comes
   from `debootstrap`, a container export or a chroot, and `wrap` makes
   an exclave of it. The rules: `alternatives`, every
   `update-alternatives --install` line in a `postinst`, with its
   slaves, the highest priority winning unless a `--set` names one,
   which yields `awk`, `which`, `pager`, `cc` and the rest without a
   per-package list, a `for` loop over literal words unrolled first,
   as ImageMagick installs `convert` and its other programs (a script
   whose loops would unroll past a megabyte or a thousand loops is
   refused, as nested loops multiply), each link written relative,
   `/usr/bin/awk -> ../../etc/alternatives/awk -> ../../usr/bin/mawk`,
   so that a name run from outside the exclave reaches the wrapper in
   the tree (13 item 37);
   `java-jinfo`, a Debian JDK's tool links from the
   `/usr/lib/jvm/.*.jinfo` file it ships for `update-java-alternatives`,
   since its `postinst` makes them in a loop, the highest priority
   winning, its links relative the same way; `busybox-applets`, Alpine's
   applet links from `/etc/busybox-paths.d`, relative as well; `apk-database`, apk's database of installed
   packages, `/lib/apk/db/installed`, as apk writes it, a record of
   each package's `.PKGINFO` keyed by its control section's checksum,
   its licence by name and its origin among the fields and the files
   it owns left out, with `/etc/apk/world` listing every package, so
   that `apk info` inside answers and a scanner reads the packages;
   `dpkg-database`, dpkg's database of installed packages,
   `/var/lib/dpkg/status`, each package's control file with `Status:
   install ok installed` after its `Package` field, in the order of the
   packages' names (one that is not a single stanza, repeats a field,
   its name's case aside, or carries a `Status` of its own is refused,
   as dpkg refuses such a database), so that `dpkg-query` inside answers, a script that
   asks whether a package is configured before it acts does (TeX's
   `update-language`), and a scanner reads the packages;
   `sbin-merge`, Fedora's `/usr/sbin` as a link
   to `bin`; `dash-sh`; `ca-certificates`, `ca-certificates.crt`
   concatenated as `update-ca-certificates` concatenates them from the
   certificates it enables: those `ca-certificates.conf` enables, in
   its order, or, where it is absent, as on a first install, whose
   `postinst` writes it from debconf's default of trusting them all,
   every `.crt` under `/usr/share/ca-certificates`, in the order of
   the paths' bytes, and then those under
   `/usr/local/share/ca-certificates`, a newline added to a file that
   lacks its last;
   `java-cacerts`, the Java keystore ca-certificates-java's `postinst`
   makes, `/etc/ssl/certs/java/cacerts`, to which a Debian JDK's
   `lib/security/cacerts` links and without which Java trusts no
   authority: a JKS keystore with the package's store password,
   `changeit`, of the same certificates as the bundle,
   each under the alias the package's own program gives it,
   `debian:` and the name of its link in `/etc/ssl/certs`, lowercased,
   and dated at the epoch, so that the tree is the same on every run:
   the first certificate of each file, PEM or, with none, the file
   as DER, as Java reads one; a file holding none, or whose name a
   keystore cannot hold, passed over with a note, since one entry
   Java cannot read makes it refuse the whole keystore; and of two
   files with one alias the later, as `update-ca-certificates`
   leaves the link. No rule makes Alpine's `java-cacerts` keystore
   or Fedora's `/etc/pki/ca-trust/extracted/java/cacerts`, so a JDK
   unpacked from those trusts no authority without a host's. The
   keystore holds the distribution's set, which answers where the host
   has none: `/etc/ssl/certs/java/cacerts` and `/etc/pki/java/cacerts`
   are identity files (8.1 rule 5), so a JDK inside reads the host's
   keystore where the host has one at the path the JDK reads;
   `ca-trust`, Fedora's bundle from the p11-kit trust source;
   `ssl-paths`, OpenSSL's compiled-in trust paths when a libssl is
   present, so that the host's bundle at the identity path (8.4) is
   consulted; `base-passwd`, `/etc/passwd` and `/etc/group` from its
   masters; `shells`, `/etc/shells` as debianutils' `update-shells`
   writes it from its template and the `shells.d` files packages ship,
   each shell with its merged-`/usr` spelling; `ucf`, each
   configuration file a `postinst` installs with `ucf SOURCE DEST` from
   a template the package ships, R's `/etc/R/Renviron` and PHP's
   `php.ini` and module files among them, the script read as far as
   literal words go (a loop over them unrolled, variables assigned them
   substituted, a file filled from a template by `cat TEMPLATE > FILE`
   or `cp` taken for the template, a trailing `|| true` or redirection
   passed over), a destination a package ships left as it is and one
   whose source the rule cannot read noted; no condition is evaluated,
   so every branch is read and the first line naming a destination
   wins, a second noted, and a template the script edits after filling
   it, as R's papersize, is installed without the edit, with a note; `php-modules`, each
   module in `/etc/php/VERSION/mods-available` enabled in every SAPI's
   `conf.d` under its `; priority=` line, as `phpenmod` enables it for
   the packages' scripts, without which PHP loads none of the modules
   it ships as shared objects; and `ldconfig`,
   `ld.so.cache` written as the exclave's own static `ldconfig` would
   write it, from the tree's files alone (`unpack/ldcache`, from
   glibc's `ldconfig` source): the directories
   `ld.so.conf` names and then the loader's trusted directories, read
   from the loader's own table (10.3), the soname links made and the
   dangling `.so.` links removed in them as `ldconfig` makes and removes
   them, the entries and the string table in `ldconfig`'s order and the
   generator string its binary carries; before wrapping, so that the
   cache never indexes the launcher, and with no `aux-cache`, which
   records inodes and modification times. The suite holds the writer
   to the tree's own `ldconfig`, byte for byte, on copies altered to
   exercise each rule (17). A new effect is a new rule in the table,
   never an option.

   What no rule makes is noted at unpack time. `unpack` reads each
   package's trigger interests, dpkg's `triggers` file and apk's
   `triggers` field, the paths whose caches and indexes a maintainer
   script would have built, and names what the tree lacks: Python
   bytecode (Python compiles each module on import where it cannot
   write), GSettings schemas, the MIME database, font and icon caches,
   the desktop database, GIO and gdk-pixbuf module caches, TeX's index
   and formats; an interest a rule or the extraction makes, or that
   nothing needs, a manual-page index, is passed over, and the notes
   of the caches `exclave caches` makes name it. A `postinst` that
   calls `update-alternatives` in a form the rule cannot read, from
   shell variables other than a literal loop's, is noted too, since
   its alternatives are not made. Failed opens in an
   `EXCLAVE_LOG` then show what an exclave tried and could not find.

   A cache only the tree's own binary can make is made after `wrap`,
   by `exclave caches EXCLAVE`, which runs the tree's own generators
   inside the exclave, under its launcher, and copies what they make
   into the tree; the maintainer script is still never run. It makes
   these, each where the tree holds its generator and something for
   it to index: Python's bytecode, by each `python3.N` the tree holds,
   with `compileall` over its standard library and the distribution's
   package directory; GSettings schemas, by `glib-compile-schemas`
   into `gschemas.compiled`; the MIME database, by
   `update-mime-database`; GIO's `giomodule.cache` in each module
   directory, by `gio-querymodules`, without which GIO loads every
   module to ask what it implements; gdk-pixbuf's `loaders.cache`,
   beside the loader directory `gdk-pixbuf-query-loaders` names on
   its standard output, without which gdk-pixbuf reads only the
   formats built into it; `icon-theme.cache` for each theme under
   `/usr/share/icons` with an `index.theme`, by `gtk-update-icon-cache
   -q -t -f`, none for one whose index names no directory (`Directories=`
   empty or absent), as the cursor theme `default`'s, which has no icons
   to index; the
   desktop database, `mimeinfo.cache`, by
   `update-desktop-database`; and fontconfig's caches of the system's
   font directories, by `fc-cache -s -f`, into the first cache
   directory the tree's `fonts.conf` names outside the home,
   `/var/cache/fontconfig`, so that `fc-list` inside finds them valid
   and writes none under the user's home; and graphviz's plugin
   configuration, `config6a` on Ubuntu 24.04 and `config6` on Alpine
   3.21, the plugins and the formats each provides, without which `dot`
   knows no output format, by `dot -c` with `GVBINDIR` naming a mirror
   of the plugin directory (`/usr/lib/TRIPLET/graphviz` on Debian,
   `/usr/lib/graphviz` on Alpine), since `dot -c` writes into the
   directory it takes its plugins from, which in place is read-only
   and is found from `/proc/self/maps`, which names the tree's host
   path (13 item 10); the file names each plugin relative to its
   directory, so it is valid at the directory's virtual path; and
   TeX Live's configuration, `ls-R` indexes, font maps and formats,
   by the steps of tex-common's `postinst` in its order where the
   tree holds them and the directories they write, `update-texmf`,
   `update-updmap`, `update-fmtutil`, `update-language`, `mktexlsr`
   over `/var/lib/texmf` and the distribution's trees, `updmap-sys
   --nohash`, `mktexlsr /var/lib/texmf` and `fmtutil --sys --all`,
   then `mktexlsr /var/lib/texmf` once more (ConTeXt's `mtxrun
   --generate`, which the `postinst` runs when `context` is
   configured, is not run), without which `pdflatex`
   finds no format and kpathsea, which searches the distribution's
   trees only through their `ls-R`, no file. A
   generator runs by its
   virtual path from the exclave's shell, itself run by the name
   `sh`, since a multi-call shell such as Alpine's busybox chooses its
   applet by the name; with a fixed environment; and writes to a staging
   directory in `.exclave/`, which is the host's (8.1 rule 6):
   `compileall` through `PYTHONPYCACHEPREFIX`, whose tree mirrors the
   sources' directories without the `__pycache__` level, given back
   under it; the schema compiler through `--targetdir`; the MIME
   generator on a copy of `/usr/share/mime/packages`, beside which it
   writes; GIO's, the icon, the desktop and graphviz's generators,
   which write beside what they read, on a mirror of the directory
   made of links to its entries' virtual paths, which the launcher's
   walk follows into the tree, so that nothing of the tree is copied; `fc-cache`
   through a configuration that includes the tree's and names the
   staging directory after the tree's cache directories, which are
   read-only inside, so that it is the first writable one, where
   `fc-cache` writes, and the last, whose cache answers its check of
   what it wrote, which a stale cache of the tree's would fail; and
   TeX Live's steps in place, since they write at fixed paths,
   `/var/lib/texmf` and `/etc/texmf/web2c`, which the packages' links
   name (`texmf-dist/ls-R` is a link to
   `/var/lib/texmf/ls-R-TEXLIVEDIST`): for the run each directory is
   moved aside into the staging directory and its path in the tree
   made a link to a copy of it there, so that inside the exclave the
   path, and every link into it, leads to the copy, which is the
   host's and writable. The directories are put back as the run ends:
   when it succeeds, when it fails, on `SIGINT`, `SIGTERM` or `SIGHUP`,
   which end the step running, and on an internal error; a run killed
   otherwise, by `SIGKILL` or a crash of the machine, leaves them aside,
   `check` and `wrap` refuse the exclave meanwhile, and the next run
   puts them back before anything else, accepting only what a run
   leaves, the generator's own paths, and refusing anything else in its
   place by name. Two runs on one exclave never share the staging
   directory: a run holds `.exclave/` locked, and a second is refused.
   What the steps made, the
   links `updmap-sys` makes among it, then joins the tree as the other
   caches do. A step that names a file by its real path sees the
   copy's host path: `fmtutil` names each format so and adds it to no
   tree's `ls-R`, which is why `mktexlsr` runs last, and a link a
   step made to the copy's path is refused. The steps run with
   `SOURCE_DATE_EPOCH=0` and `FORCE_SOURCE_DATE=1`, so that the
   pdfTeX formats and their logs are the same on every run; LuaTeX's
   formats, the logs of the LaTeX ones and `updmap.log` are not, and a
   second run rewrites them; no file the steps make names the copy's
   host path (Ubuntu 24.04's `texlive-latex-base`,
   `texlive-latex-recommended` and `texlive-fonts-recommended`,
   measured November 2026). A
   font cache is named by its directory's virtual path, which is why
   `fc-cache` runs inside, and records the directory's modification
   time; GTK takes an icon cache older than its theme's directory for
   stale, so the directory is given the cache's time where its own is
   later, as `gtk-update-icon-cache` gives it. A copy that loses the times,
   `cp -r`, leaves the font caches stale, and fontconfig then writes
   its own under the user's home, until `exclave caches` runs on the
   copy. `compileall` runs in one process, since its workers need
   `concurrent.futures`, which a minimal Python lacks, and a
   forkserver socket, whose path under the staging directory can pass
   the 108 bytes a socket's may have. Python's bytecode is checked
   against its source's hash rather than its time, so a copy that
   loses the times, `cp -r` or a checkout, keeps it valid, and an
   edited source is compiled again; `PYTHONDONTWRITEBYTECODE` keeps
   the interpreter's own imports from writing theirs first by the
   time, which `compileall` would take as up to date. What a generator
   says is printed after its name, a schema it passed over among it.
   The tree changes only once every generator has succeeded and every
   file it was to make is there, so a
   failure leaves the exclave as it was: each file made replaces the
   tree's where they differ, through a new file renamed over it, since
   a tree's files may be hard links shared with a copy (6.1), at the
   path its directory resolves to in the tree, so that a link in the
   tree leads inside it; and the tree hash is recorded again. A second
   run changes nothing but what a generator makes differently on every
   run, and a run after the tree changed remakes the
   caches, though a file a generator no longer makes, the bytecode of
   a source since removed, stays. A tree that differs from its
   recorded hash is refused, so that the hash recorded vouches for no
   edit `exclave caches` has not seen. The generators run on the
   host's machine, so an exclave of another architecture is refused,
   its caches made on a machine of its own. On Ubuntu 24.04's `python3-minimal`, ten
   standard modules import in 110 ms without the bytecode and 23 ms
   with it; `PYTHONPYCACHEPREFIX` on a host directory at run time, the
   alternative that needs no command, gives 21 ms after its first run
   but writes outside the exclave (`test/bytecode.py`, measured
   November 2026). GLib's own application lookup, `gio mime`, reads
   the desktop files rather than `mimeinfo.cache`, which is for the
   programs that still read it. Locales from `localedef`, which the
   notes name too, are made by hand the same way: run the generator
   inside the exclave writing to a host directory, copy its output into
   the tree, and record the tree hash with `exclave unwrap` and `wrap`
   (13 item 48).
4. **Strip** the volatile directories (8.1). Their empty placeholders,
   the conventional host names' and the eleven identity files (8.4) are
   added by `wrap` where the tree lacks them.
5. **Record** every input as a `pkg` record of `.exclave/hashes` (6.4),
   which is all that `unpack` writes outside `tree/`: the launcher, the
   manifest and the `README` are `wrap`'s.

`unpack` and `wrap` run on any machine, for an exclave of either
architecture, since nothing of the tree runs: `unpack` writes the cache
the tree's `ldconfig` would write, and `wrap EXCLAVE LAUNCHER` installs
the launcher given, whose machine the static check reads the tree as:
the loader's directories from the loader file, the objects of that
machine checked and the others foreign (10.3). An arm64 exclave is made
on x86-64 in about three and a half seconds, with the tree hash of one
made inside the arm64 virtual machine (measured November 2026):
`scripts/inputs`
makes the arm64 gcc exclave on the reference machine, and the kernel
matrix only runs it (17).

The result of `unpack` is an unwrapped exclave, which is a directory.
Anything may be done to it before it is wrapped, with the tools one uses
on directories: copy a built prefix in, add a manifest, delete
documentation, add shortcuts.

**By hand**, a tree needs no package reader. A `.deb`'s payload is a
tar archive (`data.tar.zst` on Ubuntu, `data.tar.xz` on Debian):

```
mkdir -p hello.exclave/tree
ar p hello.deb data.tar.xz | tar -xJ -C hello.exclave/tree
exclave wrap hello.exclave
```

That is enough for a package that needs nothing beyond itself. A
closure needs the rest of what `unpack` does: the merged-`/usr` links
made before extraction (`ln -s usr/bin hello.exclave/tree/bin` and the
rest), the links the maintainer scripts would make, and the cache made
by the tree's own `ldconfig -r`, whose absence the static check reports
(10.3). `rpm2cpio` and `cpio` extract an `.rpm`, and an `.apk` is a
gzipped tar whose dot-files at the top are its control files. Such an exclave's hashes file has no `pkg` records (6.4);
the suite makes one this way (17).

**Wrap** wraps an exclave, in an order that leaves a refused exclave
unwrapped:

1. It installs the launcher given, or the one it carries, if none is there, adds the
   placeholders and identity files the tree lacks (8.1, 8.4), and writes `exclave 1` as the manifest
   if there is none. It refuses a manifest that is not in canonical form
   or that exceeds the launcher's tables (8.1).
2. It checks the tree as it stands, and refuses, wrapping nothing, on any
   of: a wrapper of another launcher (a copy whose launcher was replaced;
   `relink` is the cure); a wrapper without an original; an original
   without a wrapper; an executable that its user could not execute,
   since its wrapper would run with the launcher's mode; or any error of
   the static check (10.3).
3. Only then does it wrap every executable file outside data
   directories (6.1), never over an existing original, and write the
   launcher, manifest and tree hashes to the hashes file.

**Unwrap** moves every original back over its wrapper, which is how the
oracles get a plain tree (17). It refuses an original without a wrapper,
since that file is not the exclave's, and drops the launcher, manifest
and tree hashes from the hashes file, keeping the inputs.

**Relink** replaces the launcher and relinks every wrapper to it, and
updates the hashes file's launcher and tree records if the exclave is
wrapped. Wrappers are hard links to the launcher (6.1), so replacing
`.exclave/launcher` alone would leave the wrappers on the old inode and
the redirect blind to them (7.4.4). An original without a wrapper is
left alone and reported.

**Check** reports every executable outside data directories that is not
wrapped, every wrapper problem that `wrap` refuses on, and a tree that
differs from the tree hash recorded in the hashes file. An exclave with
a hashes file but no tree hash is reported as unwrapped; one with
wrappers but no hashes file is reported as a `wrap` that never
finished. Then it runs the static check and, given logs, the dynamic
check (10.3).

**Hash** prints the tree hash (6.4).

**Alpine and rpm sets** go through the same five steps. The apk reader
presents `.PKGINFO`, and the rpm reader its header, with the field names
of a `.deb`, so the dependency report, extraction and the hashes file
are the same code; the synthesis rules are Debian's, read in each
format's spelling. Alpine keeps `/bin`, `/sbin` and `/lib` as
directories of their own, so no merged-`/usr` links are made, and adds
one rule, busybox's applet links (13 item 37). rpm adds a handful, among
them cpio hard links, `rpmvercmp` ordering, Fedora 42's merge of `sbin`
into `bin` and Fedora's p11-kit CA bundle. The package comments of
`unpack/apk` and `unpack/rpm` list each format's differences.

**The step before the tool** belongs to whoever makes the exclave, and
`exclave-fetch` is exclave's own: three fetchers, one for each format,
`exclave-fetch debs`, `apks` and `rpms` (the package `fetch/`, run from
a checkout as `scripts/fetch-debs`, `fetch-apks` and `fetch-rpms`). It
is a program of its own, shipped beside the command in a release, the
one program of exclave that opens a network connection, and nothing
the tool's commands do depends on it; its arguments, as each fetcher's
`--help` lists them, its cache's layout and its checks are part of
what a release keeps (6.7). Each resolves a closure from a
repository's index, chooses providers of virtual names by priority,
verifies every download against the index's checksum, and fills a
directory. They know about mirrors and snapshot services because those
are locators; the tool does not, because a hash is not a locator.

- `fetch debs` resolves `Depends` and `Pre-Depends` from an
  archive's `Packages` index, adds the Essential set, checks the
  suite's `InRelease` signature against the keyrings it is given
  (`--keyring`, the archive's signing keys), and the index against the
  digests that signed file lists.
- `fetch apks` resolves `D:` dependencies through the index's
  `p:` provides, checks the `APKINDEX` signature against the public key
  its signature names (`--key`, a file named as apk names it in
  `/etc/apk/keys`), and checks each package's checksums as apk does: the
  index's checksum against the control section, and `.PKGINFO`'s
  `datahash` against the data section.
- `fetch rpms` reads a yum or dnf repository's `repomd.xml` and
  `primary.xml`, resolves `Requires` through `Provides` and the files
  the index lists, checks `repomd.xml`'s signature where the repository
  serves one (`repomd.xml.asc`; CentOS does, Fedora does not, and the
  fetcher says which), and checks every rpm's own signatures against
  the keyrings given (`--keyring`, an `RPM-GPG-KEY` file) as rpm does:
  the header signature over the header, whose payload digest covers the
  payload, or a signature over header and payload together.

None follows a weak dependency. `fetch debs` resolves `Depends` and
`Pre-Depends` and never `Recommends`, which apt installs by default,
or `Suggests`; `fetch rpms` resolves `Requires` and never the weak
`Recommends` and `Supplements` dnf installs by default; and `fetch
apks` resolves `D:` and never an `install_if` package apk adds when
its conditions are installed. A closure is therefore smaller than the
package manager's, and a program that needs what it only recommends
works in part: Ubuntu's `golang-go` recommends `gcc`, without which Go
builds with cgo off and refuses `-race`, and `libssl3t64` does not
bring the `openssl` package's `openssl.cnf`. The maker names such a
package among those the fetch is given.

Given a cache directory (`--cache DIR`), each fetcher keeps there every
file a signed one names by its digest as `KIND/DIGEST`, whatever
mirror, snapshot or URL served it: the packages and the indexes, an apk
by the SHA-1 of its control section. Without one it keeps nothing
outside `--out`: the run works in a directory of its own inside it,
removed when the run ends, however it ends but by `SIGKILL` (a signal
stops the downloads first, and ends the run once they have), with an
`--out` the run made and left empty, and the next run fetches
everything again. A download is streamed to a file of its own and
hashed, renamed into place only once it is the file named, and checked
again every time it is used, a damaged one fetched again, four packages
at a time, the first failure reported in the order of their names; what changes
at its URL, `InRelease`, `APKINDEX` and `repomd.xml`, is fetched on
every run but from a snapshot, which never changes. `fetch debs` reads
the gzip `Packages` index where the Release file lists one, the same
index as the xz one and quicker to decompress, which was most of a
warm fetch.

The signatures are checked in the program (`fetch/verify.go`), nothing
of the machine's: OpenPGP's packets, hashes and public-key arithmetic
are go-crypto's, but for the version 3 signatures CentOS 7 made, which
it does not read, whose hash is computed there and checked with Go's
RSA; Alpine's RSA is Go's. The rule is apt's for a file signed by
several keys, as the archives' `InRelease` files are: one good
signature by a key of the keyring, and no bad one. The keys are the
caller's, the machine's own keyrings or the key files `scripts/inputs`
pins by hash, and the fetchers never fetch one; every key in a keyring
is taken as valid, as `gpgv` takes it, neither expiry nor revocation
consulted, so the keyring is the whole statement of trust. What remains trusted is the keys' provenance, an
unsigned `repomd.xml` for which versions a repository offers, and SHA-1
in the signatures Alpine makes (13 item 32).

### 10.2 Built software

Building software is the build system's job, not the tool's. A script
that wants an exclave of something it built runs the build inside a gcc
exclave, installs into a staging directory, and makes an exclave of the
result:

```
gcc-13.exclave/tree/usr/bin/sh -c './configure --prefix=/usr/local && make && make install DESTDIR=$PWD/stage'
scripts/unpack tool.exclave runtime/*.deb          # libc6 and whatever else the result links against
cp -a stage/usr/local tool.exclave/tree/usr/
exclave wrap tool.exclave                          # the static check says whether it all links inside
```

There is no recipe format, no builder exclave and no closure copying:
recipes and their parameters are the beginning of a distribution, which
exclave is not (3). The runtime the result needs is packages the script
already has, and the static check verifies that every library resolves
inside the exclave. Optimisation flags are the build's own, and the manifest's
`cpu` record (6.2) is declared by whoever makes the exclave. This is how
to get any CPU level, or `-march=native`, from a baseline distribution,
and how exclaves bootstrap exclaves: gcc 14 built inside the gcc 13
exclave and wrapped with gcc 13's runtime packages is a gcc 14 exclave.
The hashes file of such an exclave records the runtime packages and the
tree; it cannot re-derive the prefix, and does not claim to.

### 10.3 Checks

**Static.** The static check runs on every ELF file under `tree/`
outside data directories, reading originals in place of wrappers.

- Every `PT_INTERP` resolves through the tree's symlinks, outside every
  data directory, to a path the exclave owns by 8.1 with its `host`
  records applied, and all of them resolve to one file. This is the
  one-loader rule of 7.3, read from the files rather than declared.
- Every `DT_NEEDED` resolves under `tree/` by that loader's algorithm:
  `DT_RPATH`, `DT_RUNPATH` with `$ORIGIN` and the other substitutions,
  the exclave's `ld.so.cache`, then the loader's own default
  directories. The defaults are read from the loader file in the tree:
  glibc's build writes its trusted directories into the loader as a
  table, the one `ld.so --list-diagnostics` prints as
  `path.system_dirs`, which the suite checks it against (17); musl's are
  its fixed list; a loader without the table gets Debian's and Fedora's
  defaults, with a warning. The `glibc-hwcaps` subdirectories on x86-64
  are searched first. The loader satisfies its own soname without
  a search, as `ld.so` does. Executables are checked first, so that
  `RPATH` inheritance down a chain is seen; a library that nothing
  reaches is a `dlopen` candidate and is checked on its own. A
  `DT_NEEDED` that no search finds, when the tree has a library of that
  soname elsewhere, is a warning naming where: no host library can
  stand in for it, and it loads once a program has opened it by its
  path, as the JVM opens `lib/server/libjvm.so` before the libraries
  that need `libjvm.so`. One the tree lacks altogether is an error, a
  package missing from the set, but for a `dlopen` candidate, where it
  is a warning: a library nothing reaches is loaded only by a
  `dlopen`, a plugin, an NSS or PAM module or a Python extension among
  them, and Ubuntu ships plugins whose package does not require what
  they need, iproute2's `tc` modules (`libatm1t64`) and libcaca's GL
  driver, so the closures of `nginx` and `ffmpeg` hold one; such a
  library fails to load on a host without that package as it does
  inside. A missing package that such a library needs is thus a
  warning rather than a refusal, and its failed open shows in
  `EXCLAVE_LOG`.
- A search directory the exclave does not own, on an `RPATH` or among
  the defaults, is an error, since the host's library would load from
  it. A tree that does not own `/etc` is an error, since the loader
  would read the host's `ld.so.cache` and `ld.so.preload`. A library or
  loader that resolves into a data directory is an error.
- No `ld.so.cache` entry may name a file that is not a shared library,
  the launcher behind a wrapper included.
- The libc that each resolved library depends on, transitively, is the
  loader's.
- A glibc older than 2.35 without `/usr/lib/locale/C.utf8` draws a
  warning: the locale inside an exclave is `C.UTF-8` (6.2), which older
  glibc does not build in, so programs would run in the plain C locale.
- A file the tree ships in a trust directory, `/etc/ssl/certs` or
  `/etc/pki/tls/certs` as the tree resolves them, other than the
  identity files there, draws a warning naming the `own` record that
  keeps it: the host's directory hides it wherever the host has one (8.1
  rule 5). The links a trust tool made there draw none, since the
  host's links replace them, and SSSD's directory draws none, since a
  tree that ships SSSD ships its empty state there.
- A dangling symlink is a warning; a missing `ld.so.cache` on a glibc
  tree is a warning; a file with an ELF magic that is not a well-formed
  ELF file is an error, by name.
- A file the checking user cannot read is an error, with the advice to
  `chmod u+r` it: no copy of the exclave could carry it, and the tree
  hash needs it. Being an error is what keeps `wrap` from wrapping a
  tree it cannot then hash.

Anything that would resolve on the host, and anything that would mix
libcs, is reported and the exclave is not wrapped. The check also lists
static executables, which have no interpreter to verify, and warns
about objects that are not this exclave's to run: 32-bit or big-endian
ELF files (Fedora's gcc ships 32-bit start files beside the 64-bit
ones) and files of another machine. A program's separate debug file, in
the `/usr/lib/debug` of a `-dbg` package, is skipped. It keeps the
headers but not the bytes they map, so its `PT_INTERP` is empty in the
file; the kernel refuses to execute such a file (`ENOEXEC`, as for any
interpreter path under two bytes), and nothing loads it. A library's
debug file has no `PT_INTERP` and an empty dynamic section, and passes
as a library with nothing to resolve.

**Dynamic.** `exclave check EXCLAVE LOG...` reads `EXCLAVE_LOG` files
that a workload wrote and verifies that every library it opened
resolved inside the exclave.

- A library under a working directory the launcher gave to the host is
  noted as the workload's own output, not an error, since a build that
  runs what it built is the ordinary case (10.2). The launcher gives the
  working directory to the host by 8.1 rule 4 and logs it as a `cwd
  given to the host` line; `/` is never given. A working directory under
  a volatile prefix is the host's by rule 3 with nothing to give, and is
  treated the same way when the plain `cwd` line names it (`/tmp/build`,
  say); otherwise the plain `cwd` line is a diagnostic and gives
  nothing. This test comes before the ownership test, as giving the
  working directory to the host comes before ownership at run time.
- Any other library opened at a path the host owns is an error.
- The check warns about NSS modules that the checking host's
  `nsswitch.conf` names and the exclave lacks.

The static graph cannot see `dlopen` with computed names: gcc's LTO
plugin, `libcc1`, NSS and gconv modules. The dynamic check covers what
a workload actually loaded; choosing and running the workload is the
exclave maker's job.

### 10.4 Trace pruning

`exclave prune EXCLAVE LOG...` reduces an exclave to what logged
workloads used. It reads `EXCLAVE_LOG` files and keeps:

- every path a logged syscall touched successfully, except paths the
  host owns;
- the entries of any directory a program opened, because a `getdents`
  means any of them may be used later. Only the directory's own files
  and symlinks are kept, not the contents of its subdirectories unless
  those were opened too: a listing shows names, nothing below them.
  Keeping whole subtrees would keep all of `/usr/share` for one `ls`;
- the symlink chains that reach kept files, and every symlink that
  reaches a directory;
- the loader and every library a kept ELF file needs, by the loader's
  own search (10.3);
- the identity files, and what the tree ships in the identity
  directories with what its links there lead to in the tree, which
  answer on a host that lacks them however the checking host traced
  them (8.4), and `ld.so.cache`;
- the packages' licence texts.

The licence texts are the files under every `usr/share/` of the tree,
including one inside a data directory: Debian's
`usr/share/doc/PKG/copyright` and the `usr/share/common-licenses` those
cite, and `usr/share/licenses/`, where RPM's `%license` files and the
few of Alpine's `-doc` packages that hold one put theirs; and apk's
database, `/lib/apk/db/installed`, where an Alpine tree records its
packages' licences by name (10.1). An exclave that is passed on
carries its packages' terms, and a workload never reads them, so a
trace alone would drop them.

Every other file and symlink is removed, and with it a shortcut (6.1)
to a file removed, which `prune` names, so that the pruned exclave
passes `check`. Directories are never removed, so ownership (8.1) and
what `ls` shows (8.3) do not change. A log that
names no program in the exclave, because it is empty, belongs to
another exclave, or comes from a workload that died before its first
`exec`, is refused rather than obeyed, since obeying it would empty the
exclave.

The log names canonical paths. That is why symlinks are kept by what
they reach rather than by what the log says: the `cc` that a program
ran appears in the log as the gcc it resolved to.

Afterwards the hashes file's tree hash is rewritten and the static
check runs. On the gcc 13 exclave that `scripts/inputs` makes, a
hello-world compile keeps a few hundred of its files and symlinks,
originals and licence texts included, and the pruned exclave compiles
the same program and passes the static check.

Failed opens in a later `EXCLAVE_LOG` show what pruning removed, by
name, including a missing intermediate directory. The cycle is: prune,
run the whole workload, add back from an unpruned copy.

### 10.5 The command as one file

The command is one statically linked executable for each architecture,
`build/exclave` for the machine's own and `build/exclave-aarch64` from
the cross compiler, with nothing beside it to run: no interpreter, no
library, no file of the checkout, and no network code. Beside it,
`build/exclave-fetch` and `build/exclave-fetch-aarch64` are the
fetchers (10.1), built the same way. The command carries its
architecture's launcher and the text of every exclave's `README` as data
(`tool/blob_*.go`, the launcher copied beside them by `scripts/build`),
so `wrap` and `relink` install the launcher it carries unless given
another. The launcher's machine is the exclave's:
the checks read the tree as that machine's loader would, so an exclave
of either architecture is wrapped on either (10.1).

It is Go, built by the pinned toolchain with cgo off, its paths trimmed
and no version-control stamp (`scripts/lib.sh`), unlike the launcher,
which is freestanding C because it runs inside other programs'
processes (7.1) and the command never does. Its parsers, the ELF
reader, the `ld.so.cache` reader, the log reader and the grammar, answer
a hostile file with a refusal and never a crash: the gate's unit step
runs `check` on hand-made trees whose ELF files, `ld.so.cache` and logs
lie about themselves (`test/readers_test.py`) and the grammar's
properties (`test/grammar_test.py`), and the package's own tests and
fuzz targets (`tool/*_test.go`) hold each reader to its answers (17).
Its BLAKE3 is `lukechampine.com/blake3`'s, which hashes each write of a
large file on several goroutines, 16 KB apiece, so one file is hashed on
many cores; Go runs on eight threads at most, these goroutines too, since
the machine may be in use beside the command. The tree hash (6.4) lists the
tree's directories on up to eight goroutines, takes the entries from
that listing in the walk's order, and then hashes the files' contents
on as many, the largest first, so that no large file starts last; each
goroutine writes only its own entry, so the hash is the walk's whatever
they do, and a file or directory it cannot read is named as the walk
meets it. `check`, and `wrap` before it wraps, read the tree several
times over without changing it, so they list it once and run
every pass on that listing, which answers as the disk would; the tree
hash notes which files begin with the ELF magic, so the static check
opens only those, and a directory with no `.real/` needs no look for
an original. `unpack` (10.1) is its subcommand, the package `unpack/`:
the command and `exclave-fetch` carry every step from the repository
to a wrapped exclave, and only the second opens a connection.

**A reproducible build.** `scripts/reproduce EXCLAVE DIR` builds the
launcher inside a gcc exclave, from a copy of the sources under `DIR`,
with the exclave's compiler, binutils and shell alone on `PATH`:
nothing of the machine takes part, so the file is the same bytes
wherever the exclave runs. Then it builds the command here, with the
pinned Go, from that launcher: the toolchain gives the same bytes from
the same sources anywhere, so the two files are reproducible together.
The launcher's build was already free of its checkout's path and of
time; what the machine supplied was its gcc, which the exclave now
supplies. Every x86-64 row of the kernel matrix builds the launcher
again inside its copy of the gate's gcc exclave, with no Go in the VM,
and compares it with the reference machine's (12.1).

**A release.** `scripts/release KEY DIR TOOLCHAIN EXCLAVE...` builds
the launcher inside `TOOLCHAIN`, a gcc exclave, and the command from
it, by `scripts/reproduce`, and puts under `DIR` each exclave as
`NAME.exclave.tar.zst`, zstd's level 19, the same bytes on any number
of threads (on the Alpine exclave, 6% larger than xz's and unpacked in
a tenth of its time, 0.19 s against 1.98 s, November 2026), an archive
that keeps the hard links, sorted
and without owners, made only after the exclave passes `check` and
only if it is wrapped with that launcher; the command itself as
`exclave`, and `exclave-fetch` beside it, with the licence texts of the
Go modules they link as `NOTICES`, written at the build from the pinned module cache, since
their BSD licences ask a binary distribution to carry them; `SHA256SUMS`
and `B3SUMS`, as `b3sum` writes it, over every file there; and `SHA256SUMS.sig`, the sums signed with the ssh key `KEY`
(`ssh-keygen -Y`, namespace `exclave`). A consumer needs nothing of the
checkout: the signature is verified against the releaser's public key,
obtained through a channel the consumer trusts; the sums are checked;
the archive is unpacked; and the release's own `exclave check` compares
the tree with the hashes file and runs the static check, so what runs
is what was released. The README gives the commands, and
`test/release_test.py`, a step of `scripts/extra`, runs them on a
release of the gcc exclave, with a tampered archive and a tampered
sums file refused, and `NOTICES` naming every module `go.mod` requires
(17).


## 11. Layers

exclave has no layers. An exclave is one tree, and nothing is unioned
beneath it at run time.

A record that unioned another exclave's tree beneath this one at `/`,
or attached it at a prefix, would need a second root in the translator
(7.4), a rule that the two libcs be equal, relative paths that name
another exclave's location, and an answer to whether `getdents64`
merges the two listings, which no choice gets right for every program.

Composition happens at build time instead, which the unwrapped exclave
of 10.1 makes easy: unpack two package sets as one, copy one tree into
another, or copy a sysroot into a data directory (9). The cost is disk space.

## 12. Portability envelope

| Dimension | Requirement or behaviour |
|---|---|
| Kernel | A seccomp filter with `SECCOMP_RET_TRAP` (Linux 3.5), installed with `seccomp(2)` or `prctl(PR_SET_SECCOMP)`. `SECCOMP_RET_KILL_PROCESS` (Linux 4.14) degrades to killing the thread on older kernels. `/proc` mounted. `process_vm_readv` for speed, with a pipe keeping `EFAULT` fidelity where it is refused (7.5.6). Measured from 3.10 to 7.3 (12.1) |
| Ubuntu 23.10+ desktops, Docker and CI default profiles, RHEL 7, HPC, hardened kernels | Designed to work: no privilege, user namespace or mount is needed. Docker's default seccomp profile was checked syscall by syscall, and a workload runs under it, twice: as assembled for the running kernel and as Docker installs it before Linux 4.8, where `process_vm_readv` is refused (17) |
| Read-only media, NFS, FUSE homes | Work: nothing is written |
| `noexec` media, including a `noexec` `/tmp` in CI | Not supported: neither `execve` nor `mmap(PROT_EXEC)` of a file is allowed there |
| Snap-confined terminals, gVisor-based CI, WSL1, SELinux `execmem` policies | Untested. snapd and gVisor install their own filters; WSL1 has no seccomp |
| `no_new_privs` | The filter requires it, and it also disables file capabilities and AppArmor transitions on exec: `sudo`, `su`, `pkexec`, `ping` and setcap binaries fail inside an exclave, including when run from build scripts |
| Media without symlinks or hard links (FAT) | `cp -rL` copies the launcher once per wrapper and replaces symlinks with copies; the copy works, since whether a file is a wrapper is read from the file (7.4.4) |
| Architectures | x86-64 and aarch64, from one source as two launchers (7.1). An exclave runs programs of its launcher's machine only. aarch64 is tested in the emulated matrix rows (12.1), on kernels with 4 KB and with 64 KB pages (Ubuntu's 64k kernel); kernels with 16 KB pages (Asahi's) are untested (13 item 43). Another 64-bit little-endian machine would need the same list: the syscall table, `_start`, the signal frame offsets, a restorer, the relocation type and the CPU check |
| Overhead | Within noise on a compute-bound compile; about two fifths more on thirty small compiles; about two and a half times native per `posix_spawn`; 6 to 11 times native on a tight `stat` loop (16) |

What remains host-dependent is the same set that static linking leaves:
the kernel ABI, the CPU level (7.7), and the host's identity files
and directories (8.4).

### 12.1 The kernel matrix

`test/matrix.py` runs one gcc exclave, built on the reference machine,
in a virtual machine of each distribution's own cloud image, with the
suite's named regressions and every oracle its kernel can run; 17
describes the procedure. Each x86-64 row also builds the launcher
inside its copy of the exclave (`scripts/reproduce`, 10.5) and
compares its bytes with the reference machine's build; a row whose
notes say "reproduced" built the same bytes. The oracles' results are
from the reference machine in October 2026, the 64 KB-page row's in
November 2026; GitHub's hosted runner, where the suite passes on every
x86-64 row too, fetches Fedora's newest image, release 44 with kernel
6.19:

| Distribution | Kernel | Oracles | Notes |
|---|---|---|---|
| CentOS 7 | 3.10 | none: no user namespaces | `seccomp(2)` absent, so the `prctl` form is used; `renameat`, not `renameat2` |
| Ubuntu 18.04 | 4.15 | namespace, probe and Docker profile pass; no `openat2` | bwrap 0.2 |
| Rocky Linux 8 | 4.18 | all pass | |
| Ubuntu 20.04 | 5.4 | namespace, probe and Docker profile pass; no `openat2` | |
| Debian 11 | 5.10 | all pass | the security suite lists a `bubblewrap` it does not serve; the matrix installs the release's |
| Ubuntu 22.04 | 5.15 | all pass | |
| Debian 12 | 6.1 | all pass | |
| Alpine 3.20 | 6.6 | all pass | musl host, busybox userland; the exclave's outputs run inside it only (9) |
| Fedora 42 | 6.14 | all pass | SELinux enforcing; a btrfs root, where the one-step host check is off (7.4.4) and the walk goes from the root |
| Ubuntu 26.10 | 7.3 | all pass | glibc 2.44 |
| Ubuntu 24.04 arm64 | 6.8 | all pass | aarch64: natively on GitHub's aarch64 runner, where the gate runs this kernel (17), and under TCG on the reference machine, `-cpu max`, 4 vCPUs and a translation cache of 256 MB, at about a tenth of native speed; the exclave is made on the reference machine and only run here (10.1) |
| Ubuntu 24.04 arm64, 64 KB pages | 6.8 (`generic-64k`) | all pass | aarch64 under TCG: the VM installs the 64 KB kernel and reboots into it, and runs when asked (17); reproduced |
| reference machine | 7.0 | all pass | Ubuntu 24.04, AppArmor |

Every row passes the full suite, and every oracle that its kernel can
run passes; the x86-64 rows pass the same way on GitHub's hosted
x86-64 runner (17). Three checks outside the suite run natively on
each row:

- **The release's recipe.** A release of the gcc exclave, made on the
  reference machine by `scripts/release` (10.5), is taken in the VM
  as the README gives it, with the host's own tools: the signature
  verified by `ssh-keygen -Y verify`, the sums checked by `sha256sum
  -c`, the archive unpacked by `tar --zstd` or, where the host's `tar`
  lacks that option, by `zstd -dc` into `tar -xf -`, and then the
  release's own `exclave check` and `exclave version`, and a program
  of the unpacked exclave run. The sums, the check, the version and
  the program pass on every row. A host without `ssh-keygen -Y`
  records that as its answer, as the sysroot check records the musl
  host's: measured November 2026, CentOS 7's OpenSSH 7.4, Ubuntu
  18.04's 7.6 and Rocky Linux 8's 8.0 have none, and Ubuntu 20.04's
  8.2 verifies; a host without zstd would record that too, and the
  matrix would unpack the archive with its own Python so that the
  suite still runs. The exclave the release unpacks is the one the
  row's suite then runs.

- **`noexec`.** A program built by the exclave's gcc, placed on a
  `noexec` tmpfs, is refused with status 126, permission denied, by the
  VM's own shell, by the launcher's positional entry and by an
  exclave's shell; the launcher asks the kernel for `X_OK` before it
  loads anything (7.2, 7.4.5).
- **A sysroot build.** The output of `test/sysroot.py`, a hello program
  linked inside the Ubuntu 24.04 gcc exclave against the CentOS 7
  sysroot (9), runs natively. Measured October 2026, it prints its line
  with status 0 on every glibc VM, from CentOS 7's glibc 2.17 to
  Ubuntu 26.10's 2.44. On Alpine's musl it has no loader, which the step
  records as the musl host's answer rather than a failure.

Hosts differ in ways the matrix exposes, and the rules account for
each. A host's libc may be unable to load the exclave's outputs, so
only the run inside is meaningful there (9). A setgid home directory
makes every extracted directory inherit the bit, so `install -d` on an
existing directory asks for a `chmod` that the read-only rule refuses,
exactly as a read-only mount would (8.2). `openat2` may answer `EAGAIN`
for a `..` under `RESOLVE_IN_ROOT`, which openat2(2) defines as
"retry", and the resolution oracle retries. Ubuntu 24.04's image denies
unprivileged user namespaces through AppArmor, as the reference
machine's plain terminal does, so the matrix lifts that restriction in
its own VM before the oracles.

## 13. Limitations and risks

Each item states a limitation, what happens, why, and the workaround
where there is one. The numbers are cited from the source and tests,
and stay fixed.

1. **gdb sees an exclave's libraries only through the launcher's
   script.** External debugging works once the exclave is in gdb's
   auto-load safe-path (7.6, 13.1). gdb's own `info sharedlibrary`
   stays empty, and a `dlopen` between two traps is seen at the next
   `r_brk` call. A program built inside an exclave is debugged with a
   gdb in the exclave, since the host's gdb runs in the host's world
   without the exclave's libraries. From inside, breakpoints hit
   whether gdb is given the program, `gdb PROGRAM`, or runs it through
   the positional entry by its host path, `gdb --args
   <exclave>/.exclave/launcher PROGRAM`, as 13.1 gives for the host:
   gdb reads the launcher at an exec past its start, for a program it
   was given the launcher's second (7.6), and the carried script loads,
   which passes the translated calls' `SIGSYS`; gdb prints that exec as
   the process "executing new program", the launcher. The second exec
   needs gdb's own start, a `vfork` child's `PTRACE_TRACEME`. With `set
   exec-wrapper` gdb counts one exec more, the wrapper's, which the
   second then ends, and the script loads only after the wrapper's first
   `SIGSYS`; that stop, and every one of a run without the script, the
   exclave outside the auto-load safe-path, is passed by `handle SIGSYS
   nostop noprint pass`, on the command line or in `.gdbinit` (item 54
   for strace and others that start a program by `fork`). From the
   host, a breakpoint in a musl program hits and one in the exclave's
   libc does not.

2. **Translated syscalls cost more than native ones.** Every trapped
   syscall pays for a signal, the handler and its fixed syscalls; an
   untrapped one pays only for the filter. A compile makes several
   times the host's syscalls, so path-heavy work is slower than
   native, while compute-bound work is within noise of it. The
   speculation mitigation is not forced on the program (7.4.2).
   Section 16 has the figures and the analysis.

3. **Setuid programs cannot elevate.** A seccomp filter requires
   `no_new_privs`, under which the kernel ignores the setuid and
   setgid bits and file capabilities.

4. **Foreign-ABI programs are killed, not run.** A program for another
   architecture or ABI than the launcher's dies by the filter.

5. **`io_uring` and `clone3` are refused, and a program's own seccomp
   filter is honoured only in part.** `io_uring_setup` and `clone3`
   answer `ENOSYS` (libcs fall back to `clone`), since either would let
   a program act past the translator. A program's own filter whose
   actions are `ALLOW`, `LOG`, `ERRNO`, `KILL_PROCESS` and `KILL_THREAD`
   is installed for it and judges every call as the kernel would, the
   translated ones through the judge slot (7.4.2): the sandboxes of
   `sshd`'s privilege separation, `qemu -sandbox on` and
   libseccomp-built `ERRNO` and `KILL` filters generally. Measured on
   the reference machine with Ubuntu 24.04's packages: `sshd` (OpenSSH
   9.6), run as the user on a high port, attaches its pre-authentication
   sandbox and logs a client of the tree's `ssh` in by key, as under
   `bwrap` on the unwrapped tree; and `qemu-system-x86_64` 8.2 with
   `-sandbox on` and every deny option installs its filter, which
   `/proc/<pid>/status` counts beside the launcher's, and runs and quits
   over QMP. The differences:
   - **A program's own sandbox inside an exclave confines the program's
     own calls, not an attacker who has gained code execution in it.**
     The syscall page at a fixed address holds `syscall; ret`, and the
     program's filter lets every call from it through, so code that
     jumps there escapes the filter as it escapes the translation. An
     exclave is not a security boundary (3), and anyone who runs a
     sandboxed daemon in one gives up the containment that sandbox
     exists for.
   - Refused with `ENOSYS` at install, visibly: strict mode; the `TRAP`
     action, whose `SIGSYS` is the launcher's (item 23); `TRACE` and
     `USER_NOTIF`, which need a supervisor, and the `NEW_LISTENER` and
     `WAIT_KILLABLE_RECV` flags; a return of A; an `ERRNO` of 4094,
     the judge's own answer; `LOG` on a kernel before 4.14, which kills
     on it; a read of the instruction pointer, which a judged call would
     see as the judge slot's; and a body longer than
     the room the filter built around it leaves, 4 072 instructions
     less two per distinct action other than `ALLOW`. So Chromium's and
     tor's sandboxes, container runtimes and bubblewrap still fail at
     install, or before it.
   - `LOG` writes no audit line for a translated call, whose final
     action is the launcher's trap; a judge call that the program's
     filter refuses under `SECCOMP_FILTER_FLAG_LOG` is logged as the
     original would be.
   - Each filter built around a program's takes 24 instructions and the
     stubs from the kernel's 32 768 a thread's chain may hold.
   - An install succeeds where natively it would be `EACCES`, without
     `no_new_privs` or `CAP_SYS_ADMIN`, since the launcher set
     `no_new_privs` at the border (item 3).
   - A `vfork` child's install marks its parent's memory too, which
     then makes a judge call per trap that answers that no filter
     refuses: a cost, not a difference.
   - While a program's filter may be in force, a launcher before filter
     version 10, which would re-issue every trapped call unjudged, is
     not exec'd (`EACCES`), and a launcher newer than the filter it
     finds refuses to start under one by name.
   - After an `execve` under the filter, the new launcher's bootstrap,
     `mmap` and `mprotect`, is judged by it, as a native dynamic
     program's loader would be, so a filter that kills `mmap` kills the
     new image at its start; the version probe is the prologue's to
     allow.

   Programs that depend on the rest, container runtimes, browsers'
   sandboxes, `rr`, are out of scope. `strace` inside an exclave works
   but shows a `SIGSYS` for every translated call. `valgrind`'s memcheck
   runs, its report the same as the kernel's (17).

6. **Listings differ from the host's.** A directory listing omits
   host-owned files inside exclave-owned directories (8.3); a `.real/`
   of the tree is listed nowhere inside, though it opens by name.

7. **Host tools are not found by name inside an exclave.** `PATH` is
   the exclave's, and a host program whose libraries are not in the
   exclave does not run. A symlink in the exclave's `/usr/local/bin`
   fixes the first; copying the libraries into the tree fixes the
   second.

8. **One libc per exclave.** A tree that needs two is two exclaves, or
   one exclave with the second libc's world as a data directory, which
   is never executed.

9. **GPU and other host-driver software is out of scope.** It needs
   user-space drivers that match the host kernel, which no exclave can
   ship. Steam's runtime documents the problem and solves it with
   libcapsule.

10. **Loader-path programs look different from outside.** For built
    outputs and host-path programs, `/proc/<pid>/exe` and
    `/proc/<pid>/maps` read from outside the exclave name the launcher
    and `.real/` files; read from inside, by the process itself or by
    another exclave process, `exe` is the program's (7.6), but for the
    process's tracer, which reads the launcher, and `maps` names
    `.real/` files still.

11. **`/proc/mounts` shows the host's mounts.** The exclave is not a
    mount. Its read-only answers (8.2) are the kernel's own for every
    trapped path syscall, as the syscall probe measures them (17
    item 7), except the two orders of checks in items 29 and 41.

12. **Executable but unreadable files cannot run.** The loader reads
    what the kernel would only map, and a `#!` line must be read to be
    followed; the `EACCES` is the kernel's own answer to the read.
    Executable stacks are honoured as the kernel honours them. An exec
    from a program that has lowered its hard descriptor limit to the
    number it holds answers `EMFILE`, since the handler must open the
    file to read it where the kernel's exec needs no descriptor. A
    lowered soft limit is raised to the hard one for the launcher's
    own opens (7.4.5), and a child launcher under a full soft limit of
    16 or more needs one free descriptor, as a dynamically linked
    program's loader does natively.

13. **A path too long to re-issue answers `ENAMETOOLONG`.** An exclave
    path whose real spelling, the tree's prefix followed by the virtual
    path, would not fit `PATH_MAX` answers `ENAMETOOLONG`, since the
    re-issued syscall could not name it; it is never cut to a shorter
    name, which would answer for a different file. A relative path from
    a working directory so deep that the two together pass `PATH_MAX`
    answers `ENAMETOOLONG` too, where the kernel, walking relatively,
    succeeds, because the handler resolves in virtual space and
    re-issues absolutely. So does an exec from inside of a path within
    15 bytes of `PATH_MAX`, which the child launcher reads from
    `EXCLAVE_EXECFN` and `EXCLAVE_EXEC` in its environment (7.4.5).

14. **A concurrent `chdir` can race a relative path.** If another
    thread changes directory during a relative-path syscall, the
    syscall can resolve against the older directory, and a rename of
    an ancestor of the working directory meanwhile can make it fail
    where the kernel, resolving from the directory itself, would not.
    A create relative to a working directory that another thread moves
    back and forth between a host directory and an exclave one answers
    as one or the other, success or `EROFS`, and never writes the tree
    (`test/progs/cwd_race.c`). With a thread renaming the
    working directory's parent back and forth without pause, a share of
    four threads' million relative lookups fails under the launcher,
    which varies with the machine's load, and none natively;
    `scripts/exercise` with `test/progs/cwd_rename.c` measures it in
    both worlds.
    A path relative to a descriptor has neither problem: one whose walk
    never touched the exclave is re-issued as given (7.4.3). `..` above
    a working directory that was handed to the host stays in the
    exclave.

15. **Without `process_vm_readv`, copies go through a pipe.** Where it
    is refused, `EPERM` under a seccomp profile that gates it on a
    capability as Docker's does before kernel 4.8, every copy from or
    into program memory goes through a pipe: five syscalls for the
    first page and two for each page after. `EFAULT` is still answered
    as the kernel would; the cost is the limitation.

16. **From the host, every executable in an exclave is the launcher.**
    `ldd`, `file`, `debsums`, IDE indexers, antivirus and gdb see the
    same small static binary at every executable path, and the
    originals in `.real/`. Endpoint security may flag the pattern. A
    copy of an original that a program inside makes at a host path, as
    `python3 -m venv --copies` copies `python3.12`, is the original
    itself: run from outside it is a host program, which reads the
    tree's executable files as the launcher (the venv's `pip` dies on
    the standard library's executable `platform.py` with a syntax
    error), and it runs inside through `.exclave/launcher` (7.2).

17. **Directory-service users are unknown inside without the
    module.** On a host whose users come from LDAP, SSSD or
    `systemd-homed`, `getpwuid` inside an exclave finds them only
    through the lookup module the host's `nsswitch.conf` names, which a
    glibc exclave ships from its own distribution: `libnss-sss`,
    `libnss-systemd` or `libnss-ldapd` on Debian and Ubuntu. The
    daemons' sockets are the host's (8.4), and `exclave check` names
    the package a module lacks. Debian's `libnss-systemd` and
    `libnss-ldapd` depend on the daemons themselves, 38 and 51 packages
    on Ubuntu 24.04 as `exclave-fetch debs --no-essential` resolves
    their closures, which `prune` removes again; `libnss-sss` needs
    only libc. A musl exclave loads no modules and finds the users only
    where the host runs `nscd`.

18. **Which identity files and directories are the host's is decided
    at startup.** One the host lacks then is the exclave's for the
    process's life, even once the host makes it, and one the host
    removes later is absent inside rather than the exclave's again. Its
    contents and its links are the host's at each call (8.4).

19. **Per-user state under an exclave path has no target.** The tree is
    read-only and the visibility rule has no per-user directory, so
    software that must write there needs a fixed host directory named
    by a symlink in the tree.

20. **`SIGSYS` is never blocked, whatever a mask says.** The handler
    removes `SIGSYS` from every mask a program sets, since a blocked
    `SIGSYS` would kill the process at its next trap (7.5.1), so a
    handler runs with it unblocked whatever its `sa_mask`, and a query
    of the thread's mask, `sigprocmask(SIG_BLOCK, NULL, &old)`, reports
    it unblocked. A query of an action, `sigaction(sig, NULL, &old)`,
    which passes to the kernel, reports the launcher's installation: the
    stub as the handler, the restorer installed with it (on aarch64,
    where the program gave none, the launcher's, with `SA_RESTORER`
    set), and the mask without `SIGSYS` (7.5.7). The stub, called
    directly, runs the program's handler, so Go's forwarding and a
    chain of handlers that call the one a query returned work, but a
    program that compares the handler a query returns with its own sees
    another. The old action an install replaces reports the handler and
    the mask as the program wrote them, but for the default or ignored
    installed with a mask that held `SIGSYS`, and a handler past the 256
    slots, which no slot keeps. A handler
    whose signal lands outside any trap and that blocks `SIGSYS` in its
    own frame, as a `sigfillset` on `uc_sigmask` does, returns through
    the program's restorer unseen, and the process is killed at its next
    trap; one that lands during a trap has `SIGSYS` cleared from what it
    leaves.

21. **Kernels without seccomp filter support cannot run exclaves.**
    The translator is a seccomp filter; there is no fallback.

22. **`name_to_handle_at` and parts of `openat2` differ.**
    `name_to_handle_at` answers `ENOSYS` (7.4.3). An `openat2` walk
    that never touches the exclave is the kernel's own, with every
    `resolve` flag, on the host's real mounts. One that starts in the
    exclave, enters it, or restarts at the root, which is the tree's,
    through an absolute path, a link target or `..`, sees two mounts
    under `RESOLVE_NO_XDEV`, the exclave and the host, and not the
    host's own mount boundaries (7.4.3). `RESOLVE_CACHED` is dropped
    where the kernel would look the path up. A scoped `..` under
    `RESOLVE_IN_ROOT` or `RESOLVE_BENEATH` never answers `EAGAIN`,
    which the kernel returns when a rename or a mount
    anywhere on the system raced its walk (`handle_dots` in
    `fs/namei.c`): the launcher walks in user space and sees no such
    race, so a program that retries gets the retry's answer at once.

23. **A program's own `SIGSYS` handler is never installed.** The
    install succeeds and does nothing, since the launcher's handler
    must receive every trap (7.5.2).

24. **The syscall page's address, `0x7fe00000`, must be free.** The
    launcher maps its syscall page there in every process; a program
    whose image covers it cannot run in an exclave, and the loader dies
    naming the segment it could not map. Images start low and grow
    upward, so only an image of almost 2 GB reaches it, a
    small-code-model program with nearly 2 GB of static data, or one
    linked there on purpose. A Go aarch64 program linked from `0x10000`
    runs, and the `low_image` test runs a C program laid out the same
    way on every exclave kind. A launcher built for an earlier address
    and the current one cannot run under each other (item 45, 7.4.2).

25. **A program run from a descriptor with no path cannot re-open
    itself.** `fexecve` of a `memfd` or of an unlinked file runs on the
    loader path through `/proc/self/fd` (7.6). The descriptor is closed
    once the segments are mapped and the link's text names no file, so
    the program cannot re-open its executable through `/proc/self/exe`.

26. **A `vfork` child's exec leaves its scratch chunk busy in the
    parent until the child exits** (7.5.4). A parent with 4 096 live
    spawned children has exhausted the pool and answers `ENOMEM` to
    every trapped syscall. A large argument vector built by such a
    child leaves an unused mapping of pointers in the parent, once per
    such exec.

27. **A signal handler that switches stacks between traps** may confuse
    the frame comparison that releases chunks left behind by `longjmp`
    (7.5.4). Coroutine libraries that trap from inside a signal handler
    are the only known shape, and none has been seen.

28. **`/proc/<pid>/exe` of a wrapped script names its interpreter**, as
    natively; the original's path in `.real/` never appears. Another
    process reading the link resolves a relative `#!` interpreter from
    its own working directory, where the kernel's answer is the
    interpreter as the script's exec resolved it and does not depend on
    the reader: a reader elsewhere may get a path that does not exist,
    or the script itself where the name does not resolve. A relative
    `#!` line is rare.

29. **A write-open without `O_TRUNC` of an exclave file another
    process is executing answers `EROFS`.** The kernel would answer
    `ETXTBSY` first; the handler refuses the write by its read-only rule
    (8.2) without opening the file, so it never learns that the file is
    running (17 items 1 and 7). With `O_TRUNC` the kernel answers
    `EROFS` as well. The loader-path program's own process gets
    `ETXTBSY` (7.4.3), after the permission, `EACCES` where the file's
    mode forbids the access, and ahead of any read-only answer, so an
    `O_TRUNC` open or a `truncate` of its own file on an exclave path,
    such as a `.real/` original run directly, answers `ETXTBSY` where
    the kernel would answer `EROFS`.

30. **Small alternate signal stacks overflow.** The handler runs on
    whatever stack the trap lands on, and needs the kernel's frame
    (`AT_MINSIGSTKSZ`, 3 376 bytes on the reference machine, whose
    glibc 2.39 reports 13 504 for `sysconf(_SC_MINSIGSTKSZ)`, the CPU's
    largest XSAVE area whether or not the kernel enables every part of
    it) plus its own
    3 KB budget (7.5.4). Rust's 8 KB stack is enough; a stack of exactly
    `MINSIGSTKSZ` is not. `adversarial` runs the deepest paths on
    Rust's layout, a guard page below, on every row of the matrix: on
    the reference machine they pass on 5 KB and fail on 4.4 KB. A
    handler on the alternate stack that traps adds the kernel's frame
    a second time, its own, and a program's handler whose signal lands
    during a trap adds the kernel's frame, the presented frame and its
    block, 1 152 bytes on x86-64 and 4 800 on aarch64, whose presented
    frame holds the 4 KB of floating-point records whole, and the
    trampoline's C below them, 208 and 320 bytes (7.5.7): `test/progs/sigstack.c` passes on 8 KB and
    is killed on 6 KB on the reference machine, where the kernel alone
    passes on `MINSIGSTKSZ`. An overrun that lands in mapped memory
    below the alternate stack, not a guard page, is no fault: a signal
    delivered there is placed at the stack's top again, over the frame
    in use, and the program can loop rather than die, as `sigstack.c`
    did on musl, whose `raise` traps around its `tkill`, on a stack of
    `MINSIGSTKSZ` at the top of a page. A `clone(CLONE_VM)` child's own
    stack is held to the same, since a thread has no alternate stack
    until it arms one: a child trapping on 8 KB passes and on 4 KB is
    killed, where the kernel needs no user stack for a syscall
    (`test/progs/clones.c`). Before 5.16 that death takes the whole
    program: the kernel's core dump of a process killed every process
    sharing its memory (`fs/coredump.c`, `zap_threads`), each ending
    with the child's signal, so on the matrix's 5.15 and older rows a
    `clone(CLONE_VM)` child's overflow ends the program that made it.
    musl's least thread stack, its `PTHREAD_STACK_MIN` of 2 KB, is such
    a stack: a thread made with it that traps is killed, and its program
    with it, where glibc's least, 16 KB, passes.

31. **Some paths inside structures are not translated.** A datagram
    destination in `sendto`, `sendmsg` or `sendmmsg` reaches the kernel
    as written: the filter cannot see the address family, and trapping
    every datagram send would tax every UDP program for a case no
    program has been seen to use. The visibility rule makes the
    untranslated path right for `/tmp`, `/run` and `/var/run` and wrong
    for a socket under an exclave path. `bpf` object pins, `quotactl`
    and `swapon` are likewise untranslated (`test/syscalls.py` lists
    them); `fsconfig` is refused with the rest of the mount API. `bind`
    and `connect` translate their `sockaddr_un` (7.4.3) with three
    visible differences: `getsockname` on a host socket whose real path
    passes `sun_path`'s 107 bytes answers `/proc/self/fd/N/NAME`; one
    bound by a name whose walk touched the exclave, a relative name from
    a working directory in the tree, a path through a host symlink or
    through a magic link, answers the resolved real path rather than the
    name as given, since that is what the handler bound; and a socket
    file in the tree bound by a listener outside the exclave answers
    `ECONNREFUSED`.

32. **The tool trusts its input files, and the fetchers trust their
    keys.** The tool records its inputs' hashes and checks nothing
    about their origin, which it cannot know. `fetch debs`,
    `fetch apks` and `fetch rpms` verify every download against
    its index's digest and the index against the archive's signature
    (10): the `InRelease` file's, the `APKINDEX`'s, and every rpm's own,
    with `repomd.xml`'s where the repository signs it. The keys are
    given, never fetched, so a wrong key file is trusted as a right one
    would be, and the fetchers consult neither a key's expiry nor its
    revocation, as `gpgv` does not; `scripts/inputs` pins each by its
    hash. A repository that
    does not sign `repomd.xml`, as Fedora's do not, leaves which
    versions it offers to the mirror, every package still verified.
    Alpine signs its indexes with RSA over SHA-1, so an Alpine index is
    held to a weaker digest than the others. Nothing of a package runs
    on the host: `unpack` writes the cache the tree's `ldconfig` would
    write (10.1) and the static check reads the loader's directories
    from its file (10.3), so what a package's programs do, they do
    inside an exclave.

33. **The launcher's tables are fixed in size** (8.1). A manifest or a
    tree beyond them is refused, by `exclave wrap` before it is made
    and by the launcher at startup.

34. **`EXCLAVE_LOG` writes a path's bytes from `0x80` up as they
    are**: control bytes are escaped (6.2), but a name that is not
    UTF-8 reads as the bytes it is, and a terminal in an 8-bit mode
    may take some of them as controls. A trailing
    slash, or an empty, `.` or `..` component, in an `own`, `host` or
    `data` path is refused by both the tool's and the launcher's
    manifest parser, since the visibility rule matches a path by its
    one spelling and would silently match nothing else.

35. **The locale and the shell are the exclave's, and the time zone is
    the host's whatever `TZ` says outside**: `C.UTF-8` and `/bin/sh`,
    not the user's, and the zone of the host's `/etc/localtime` (6.2,
    8.4). Messages are in English, collation is by code point, and a
    `TZ` set outside is dropped, since the zone it names needs data
    under `/usr/share/zoneinfo` that the exclave may lack; a program
    inside may set it for its children, with the data in the tree. An
    exclave that wants another locale or shell ships the data and a
    wrapper script; one that wants a fixed zone takes `/etc/localtime`
    back with `own` and ships the zone there.

36. **What still varies under a reproducible build.** The launcher does
    not touch the hostname and kernel identity from `uname` and
    `/proc`; directory listing order, which the filesystem decides; the
    build path in debug info, which `-ffile-prefix-map` handles; user
    and group ids and names, which `tar` records; the CPU's features,
    which `-march=native` embeds; or the time zone, which is the host's
    until an `own` record takes `/etc/localtime` back (6.2).

37. **A symlink in the tree with an absolute target resolves on the
    host when run from outside.** In a tree from `debootstrap` or a
    container export, `/usr/bin/awk -> /etc/alternatives/awk`, as dpkg
    writes it, resolves on the host when run from outside the exclave,
    to the host's awk or to nothing, and in the tree when run from
    inside, because only inside does the translator see the path; a
    shortcut to such a link is refused as leaving the tree (6.1). From
    outside, run the wrapper it points at, or make the link relative,
    which resolves the same inside: the links `unpack` makes, the
    alternatives, a JDK's tool links, `/usr/bin/sh` and busybox's
    applets, are relative for this reason (10.1).

38. **A static link against a Red Hat tree needs `glibc-static`**,
    which no closure of `gcc` pulls in; add it to the package list.

39. **A wrapped script run from outside the exclave gets a virtual
    path as `$0`**, whatever the spelling: through the positional entry,
    by its real path, by a relative one, or through a host symlink such
    as a shortcut (6.1). The spelling names the file in the host's world,
    where a script's `"$0.bin"` or `$(dirname "$0")/sibling` is not, and
    a wrapper exec'd from outside any filter takes no spelling from the
    environment (7.4.5). The launcher follows the spelling's chain of
    host links, each name's directory resolved on the host, to the first
    name in the tree, and gives that name's virtual path, its last
    component kept, where it leads to the script: a script a link in the
    tree names gets the link's name, which is the name's last component
    the kernel would give it and what a script that dispatches on its
    name needs (postgresql-common's
    `pg_wrapper`, behind `/usr/bin/psql` and the other client
    commands); otherwise its own canonical virtual path. A script run
    from inside, wrapped or not, gets the path as the caller spelt it,
    which is in the exclave's own world.

40. **A running program on a host path is not protected from other
    processes' writes.** The kernel executes the launcher, not the
    file, so its `ETXTBSY` covers wrappers and not originals or built
    outputs. The launcher answers `ETXTBSY` only to the process that
    loaded the program (item 29, 7.4.3); another process's write
    succeeds and may leave the running program to take `SIGBUS`.
    Natively `cp new prog` over a running `prog` fails with "Text file
    busy"; in an exclave it succeeds. Linkers unlink their output
    first, so relinking is safe either way.

41. **`fanotify_mark`'s flag bits are checked after its path** (8.2,
    17 item 7). The handler checks the mask, the command and the
    descriptor in the kernel's order before the path, but not the flag
    bits and mark types, which differ between kernels: the kernel
    refuses an unknown one after the handler's lookup, so the path's
    own error can come first.

42. **An ext4 race that the probe's own reset provokes.** On kernels
    5.10 to 6.1, natively too, ext4 refuses to clear the extent flag
    (`FS_IOC_SETFLAGS`) of a file recreated moments after its
    predecessor was deleted, so the probe (17 item 7) keeps that case
    off host files.

43. **aarch64 kernels with 16 KB pages are untested; 64 KB pages are
    tested when asked.** The loader rounds segments to the kernel's
    `AT_PAGESZ` and refuses by name a segment whose address and offset
    differ within a page, as the kernel does (7.3). Ubuntu's arm64
    packages are linked for 64 KB pages: all 379 ELF files of
    `coreutils`, `libc6` and `gcc-13` are congruent modulo 64 KB, and
    so modulo 16 KB. The launcher's own segments and the syscall page
    are 64 KB-aligned (7.4.2). The arm64 test row runs a 4 KB kernel; a
    second emulated row, `noble-arm64-64k`, installs
    `linux-image-generic-64k`, reboots into it and runs when asked
    (17). On it the suite, every oracle, the probe with no unexplained
    difference and both Docker profiles pass (12.1; November 2026,
    6.8.0-149-generic-64k). What the row has found was the tests' own
    4 KB assumptions, guard pages, faulting paths and crafted segments
    sized in 4 KB, since made the kernel's page, and one rule of the
    loader, a bss segment's offset checked where the kernel reads none
    (7.3). No 16 KB kernel has run it: Ubuntu ships none, and Asahi
    Linux's kernels for Apple silicon are the ones that use that size.

44. **Two handlers never share a scratch chunk**: a rule, not a
    limitation (7.5.4).

45. **A launcher whose syscall page is elsewhere cannot nest with this
    one.** A launcher of an earlier page generation (7.4.2), whose
    syscall page sat at another address (item 24), and this one cannot
    run under each other's filter: this launcher refuses either nesting
    by name, and relinking the older exclave with the current launcher
    fixes it.

46. **The launcher's own variables stay in `/proc/<pid>/environ`.**
    `EXCLAVE_EXECFN`, `EXCLAVE_COMM` and, on the loader path,
    `EXCLAVE_EXEC` are removed from the environment the launcher hands
    a program, so `environ`, `getenv` and every child see none of them.
    The kernel's copy, which it filled at exec and which
    `/proc/<pid>/environ` and `ps e` read, keeps them; replacing it
    takes `PR_SET_MM_ENV_START`, which needs `CAP_SYS_RESOURCE`. A
    program that reads its own `/proc/self/environ` sees the name it was
    exec'd by and its `comm`, which are the kernel's own facts about it.

47. **An Alpine exclave carries its licences by name, as Alpine
    does.** Alpine records each package's licence as an SPDX
    expression in apk's database, which `unpack` writes (10.1), and
    ships few licence texts: of the fourteen source packages of the
    gate's Alpine closure only `mpfr4-doc` holds one. Whoever passes an
    Alpine exclave on supplies the texts the named licences require,
    as for an Alpine system.

48. **Some caches only a tree's own binary can make are made by
    hand.** `unpack` and `wrap` run nothing of the tree (10.1), and
    `exclave caches`, which runs the tree's generators inside the
    exclave, makes Python bytecode, GSettings schemas, the MIME
    database, GIO's module cache, gdk-pixbuf's loader cache, icon
    caches, the desktop database, fontconfig's caches, graphviz's
    plugin configuration and TeX Live's configuration, indexes and
    formats. Without it Python compiles each module on
    import, nearly five times the import time of ten standard modules,
    a GLib program finds no schemas, gdk-pixbuf reads only its built-in
    formats, fontconfig writes its caches under the user's home,
    `dot` knows no output format and `pdflatex` finds no format. The font and icon caches are
    valid while the tree keeps its directories' modification times: a
    copy that loses them, `cp -r`, leaves fontconfig writing its own
    under the home until `exclave caches` runs on the copy. Locales
    from `localedef` are not among them; `unpack` names them from the
    packages' trigger interests, and the maker runs `localedef` inside
    the exclave the same way (10.1). TeX Live's indexes and formats are
    made in place, by a run that changes the tree while it lasts
    (item 56). `exclave caches` runs only on a machine of the exclave's
    architecture.

49. **Shadow stacks are off, by glibc's choice.** The kernel offers
    user shadow stacks on the reference machine (`user_shstk`, kernel
    7.0 on a Zen 5) and Ubuntu's and Fedora's programs and loaders are
    marked for them, but glibc 2.39 through 2.42 never mark `SHSTK`
    usable (`sysdeps/x86/cpu-features.c`, `#if CET_ENABLED && 0`), so
    the loader asks the kernel for none, with
    `GLIBC_TUNABLES=glibc.cpu.x86_shstk=on` or without, natively or in
    an exclave: measured October 2026 with `strace`, no
    `ARCH_SHSTK_ENABLE` is issued. The border drops `GLIBC_TUNABLES`
    (6.2), but a program inside sets it for the programs it runs, so
    the suite runs a CET-marked program inside with the tunable set,
    through a signal, a thread making trapped calls, a `longjmp` across
    one, a handler whose signal lands during a trapped call, so that the
    trampoline's return through the kernel's frame and the handler's
    return from the handler-call slot run (7.5.7), and a `fork` and
    `exec`, and reports whether a shadow stack was on (17); the day a glibc turns them on, the handler's paths run on
    one there. Until then the handler has not run on a shadow stack.

50. **On the loader path the kernel's image is the launcher's.** The
    fields of `/proc/<pid>/stat` the kernel fills at exec, the code's
    start and end, the stack's start and the end of the argument and
    environment areas, describe the launcher, which the kernel exec'd,
    not the program it loaded; `arg_start`, `cmdline` and `comm` are the
    program's. The program's argument and environment strings lie where
    the kernel put them for the launcher, the program's environment
    contiguous after its arguments and the launcher's variables
    after that (item 46), and `AT_EXECFN` names a string of the
    launcher's own rather than the top of the stack; at the border the
    three fixed variables of 6.2 are the launcher's strings. Moving the
    kernel's fields takes `PR_SET_MM`, which needs `CAP_SYS_RESOURCE`.
    `exec_auxv` measures every other entry of the initial stack and the
    auxiliary vector against the kernel (17 item 4).

51. **A handler that did not ask for the alternate stack runs on it
    when its signal lands during a trap.** The launcher's handler runs
    on the alternate stack where one is armed (7.5.3), and a program's
    handler whose signal lands while it runs is called below the
    launcher's frames and the presented frame (7.5.7), so one installed
    without `SA_ONSTACK` runs on the alternate stack, where natively it
    would run on the main stack, and `sigaltstack(NULL, &old)` in it
    reports `SS_ONSTACK`; one installed with it has the part of the
    stack below the launcher's frames, where natively it would have the
    whole. The presented frame and its block add 1 152 bytes on x86-64
    and 4 800 on aarch64 to the kernel's own; the aarch64 figure for
    such a handler on a small alternate stack is **[measure]** on the
    arm64 row. A 5 KB handler beside
    an 8 KB alternate stack armed for `SIGSEGV`, Rust's shape, reaches
    the guard page under the launcher and runs natively
    (`test/progs/sigstack.c`); on aarch64, whose signal frame is larger,
    the `SIGSEGV` handler has no room either and the program is killed.
    A handler that uses more than a few hundred bytes beside a small
    alternate stack is the shape to avoid; running such handlers on the
    trap site's stack was considered and refused (14.3).

52. **aarch64's protection keys are not the program's in the handler.**
    The permission overlay of Arm's FEAT_S1POE, `POR_EL0`, is to aarch64
    what PKRU is to x86-64 (7.5.6), and the handler does not load the
    program's from the frame's `poe_context`: no machine here has the
    feature to test it on. A syscall the handler issues into a buffer
    under an overlay key other than 0 would be checked against the
    kernel's own `POR_EL0`, and a copy into one would pass where the
    program denied it.
53. **A directory's size on XFS counts `.real/`'s entry.** The size
    of a directory that holds `.real/` is corrected on ZFS, btrfs and
    tmpfs, whose sizes count entries by a rule (8.3); XFS sizes a small
    directory by its entries' bytes in its own format, and ext4 and
    others by blocks, which one entry rarely moves, and those sizes are
    left as the kernel gives them. Nothing reads a directory's size for
    its contents; its link count is corrected everywhere.

54. **A traced `fork` child's exec stops its tracer with `SIGSYS`
    first.** A child that asks to be traced, `PTRACE_TRACEME`, and then
    execs stops for its tracer at its trapped `execve`'s `SIGSYS`, before
    the handler runs, where the kernel's first stop is the `SIGTRAP`
    after the exec. A tracer that passes the signal on, as strace and
    gdb's start do, then meets the `SIGTRAP` and carries on; one that
    takes any first stop for the exec is a stop early. A `vfork` child's
    request waits for its exec and its tracer sees the kernel's stops
    (7.4.5), but a `fork` child's is made at once, since it may stop for
    its tracer before it execs. Where `kcmp` is refused, a `vfork` child
    of a `fork` child that has not exec'd since the fork is told apart
    from a `fork` child by nothing the launcher can read, and is taken
    for one: its request is made at once, and its tracer, blocked in
    `vfork`, and it wait for each other for ever. A `vfork` child that
    exits without exec'ing after its request leaves the request in its
    parent's scratch until the next search for one, which a later child
    given the same pid, after the pid space has wrapped, could find first.
    A deferred request is answered 0 where the kernel would refuse it
    (Yama's `ptrace_scope` 2 or 3); the exec then runs untraced. The
    exec that makes a deferred request is followed by a second, the
    launcher's own (7.6), so its tracer meets one exec stop more than the
    kernel gives, two `SIGTRAP`s or `PTRACE_EVENT_EXEC` stops where the
    kernel gives one; a tracer that detaches at the first is not met by a
    second.

55. **The trust directory is the host's, but a link's text read inside,
    and a name past a link, are the exclave's.** `/etc/ssl/certs` and
    `/etc/pki/tls/certs` are identity directories (8.1 rule 5, 8.4), so
    a program that verifies through the directory alone, `openssl
    s_client -CApath /etc/ssl/certs -no-CAfile` or a `capath` given to
    Python's `ssl` or to curl, trusts the host's set inside as outside
    (against a public server, verify code 0 inside as natively, and 20
    with `own "/etc/ssl/certs"`, Ubuntu 24.04's `openssl` and
    `ca-certificates`, measured November 2026), an authority the host's
    administrator added under `/usr/local/share/ca-certificates` with
    it, and a JDK reads the host's keystore. What remains:
    - A program that reads a link's text there and resolves it itself
      reaches the tree's names: `realpath(3)` and `readlink -f` of
      `/etc/ssl/certs/<hash>.0` walk
      `/usr/share/ca-certificates/mozilla/<name>.crt` in virtual space,
      which the tree has only if it ships the certificates.
    - A descriptor or a working directory reached through a link there
      is named by the kernel's name for its target, `/proc/self/fd/N` of
      a certificate opened through the directory the host's file by its
      host path, which inside is the tree's, as for an identity file
      (8.4). A link to a directory there whose target is the exclave's
      by the rule is passed by its name, so a `..` after it climbs back
      into the trust directory, where the kernel would climb from the
      target, and a descriptor on it lists the host's names where a path
      relative to it walks the same names on the host.
    - After a final link in the directory the kernel follows the rest on
      the host and counts its links afresh, where the kernel on a bind
      mount would count the whole walk to 40.
    - Under `RESOLVE_NO_XDEV` a host link at an identity directory's
      name with components after it is judged at the name, where the
      kernel judges the crossing at the directory the link reaches; the
      two differ only where an `own` record names that directory.
    - The tree's own directory is hidden where the host has one: the
      links its trust tool made there and any file it ships there but
      the identity files the host lacks; `exclave check` names such a
      file, which an `own` record keeps.
    - Where the host reaches an identity directory through a link above
      it rather than at its name, `getcwd` there answers the kernel's
      name for it, which the rule may give the tree, where a bind mount
      would answer the name it was entered by; none of the hosts
      surveyed has that shape.
    - A name outside the two directories and the four trust files is the
      tree's unless its link leads into one, as Debian's
      `/usr/lib/ssl/certs` and `/usr/lib/ssl/cert.pem` do: Fedora's and
      Red Hat's `/etc/pki/tls/cert.pem` leads into the tree's
      `/etc/pki/ca-trust/extracted`.

56. **TeX Live's configuration, indexes and formats are made in place.**
    Debian's TeX scripts write `fmtutil.cnf`, `updmap.cfg`, the
    hyphenation files and the `ls-R` indexes under `/var/lib/texmf`, at
    fixed paths the packages ship links to (`texmf-dist/ls-R` names
    `/var/lib/texmf/ls-R-TEXLIVEDIST`), and build the formats from
    them; in an unpacked tree `pdflatex` finds no format and
    `mktexfmt` no entry to build one from. `exclave caches` runs them
    (10.1) with `/var/lib/texmf` and `/etc/texmf/web2c` each moved
    aside and its path in the tree a link to a copy in `.exclave/` for
    the run. While the run lasts the tree is not what its hash records,
    and a program the exclave runs meanwhile sees the copies; a run
    killed by `SIGKILL`, or by the machine's crash, leaves the
    directories aside, `check` and `wrap` refuse the exclave, and the
    next run of `exclave caches` puts them back before anything else. The steps are tex-common's,
    so only Debian's layout is made, where the tree holds tex-common's
    scripts and both directories, the smallest set of them too
    (`texlive-binaries`, `tex-common` and `texlive-plain-generic`,
    whose formats `fmtutil --strict` builds as well); a step that fails
    fails the command, the other caches with it, as any generator's
    failure does. After the run `pdflatex`,
    `bibtex` and `kpsewhich` inside give the kernel's answers on the
    same tree, and Debian's `tlmgr` refuses in user mode as it does
    outside (Ubuntu 24.04's `texlive-latex-base`,
    `texlive-latex-recommended` and `texlive-fonts-recommended`,
    measured November 2026).

57. **A link a program inside makes at a host path names a virtual
    path.** A program inside sees the tree at `/`, so a symlink it
    writes at a host path holds the virtual path as its text: `python3
    -m venv DIR` without `--copies` makes `DIR/bin/python3 ->
    /usr/bin/python3`, and the scripts `pip` installs there start
    `#!DIR/bin/python`. Inside the exclave the link leads to the
    tree's interpreter and the venv works, `pip install` into it
    included; run from outside, the kernel follows the link on the
    host, to the host's `/usr/bin/python3` or to nothing, so the venv
    runs the host's interpreter where the host has one and fails
    where it has none (Ubuntu 24.04's `python3-venv`, measured
    November 2026). A link's text is data the launcher does not
    rewrite, since which world a link is meant for is the program's
    to know. Run the venv from inside, by the exclave's shell or the
    positional entry, `EXCLAVE/.exclave/launcher DIR/bin/python3`,
    which follows the link in the exclave's world (7.2), or point
    the link at the wrapper's host path, `ln -sfn
    EXCLAVE/tree/usr/bin/python3 DIR/bin/python3`, with which it runs
    the exclave's interpreter from outside too, `sys.prefix` the
    venv's; `--copies` copies the original instead (item 16).

58. **A handler that runs during a trapped call meets the launcher at
    the edges.** A handler whose signal lands during a trapped call
    finds the trap site's frame, decides what the program does, and is
    unwound through into the program's frames (7.5.7), so a deferred
    `pthread_cancel` of a thread blocked in a trapped call ends it on
    musl and on every glibc, its cleanup handlers and destructors run,
    as natively (`test/progs/clones.c`). What is not the kernel's:
    - A signal that lands while the launcher walks the call's path,
      before the re-issue, finds the call about to be made: the counter
      at the program's syscall instruction and the number (x86-64) or
      the first argument (aarch64) in the result register, the kernel's
      frame for a signal that arrives just before a syscall instruction.
      Natively a signal that arrives while a call that does not wait is
      under way is delivered after it, with its answer; here the handler
      runs first and the call is made when it returns. On x86-64 `rcx`
      and `r11` in that frame hold what the syscall instruction left in
      them at the trap, not what they held before it, which nothing
      recovers.
    - A signal that lands after the re-issue, while the launcher
      finishes the call, finds it made, with the re-issue's answer in
      the result register, before the launcher's adjustment of a
      listing's or a link's length.
    - A signal that lands in the trampoline itself, before or after the
      handler it is running, finds the trampoline's counter and
      registers; one that lands at the program's restorer, as the
      trampoline returns through the kernel's frame, counts as outside
      and finds the launcher's registers about to be restored. One
      delivered onto a handler that has not yet run finds that handler's
      address, as natively.
    - A handler that ends with an `rt_sigreturn` of its own on the frame
      it was given is refused with `SIGSEGV` under a shadow stack, and
      on aarch64 when the frame carries an `extra_context`; elsewhere it
      resumes the program at the presented state, leaving the launcher's
      frames as a `longjmp` does (7.5.7).
    - An unwind through the presented frame under an x86-64 shadow
      stack would leave the shadow stack pointer short: libgcc
      (`config/i386/shadow-stack-unwind.h`) counts one shadow-stack entry
      per frame it unwinds, the kernel's restore token for a signal
      frame, where the presented frame has the launcher's entries and
      two tokens of the kernel's beneath it, so the first return after
      the landing would fault. It cannot be run while glibc enables no
      shadow stack (item 49).
    - LLVM's libunwind recognises the restorer's instructions on aarch64,
      as libgcc does, but on x86-64 has no such recognition
      (`_LIBUNWIND_CHECK_LINUX_SIGRETURN` is defined for aarch64,
      LoongArch, RISC-V and s390x) and steps through a signal frame only
      by the unwind information of glibc's `__restore_rt`: under the
      launcher its unwind ends at the handler-call slot, as natively it
      ends at musl's restorer, which carries none.
    - Stepping over a handler's return in gdb sets the resume breakpoint
      at the presented counter: where the call was not made, that is
      the program's syscall instruction, which the launcher's handler
      passes over without executing it, and `next` runs on to the next
      stop.
    - What the launcher held when a handler leaves by `siglongjmp` or an
      unwind stays held: the descriptor of a long path's `connect` or
      `bind` leaks, and the cache's lock, if an insert held it, stays
      taken, so the process caches nothing more (7.5.7).
    - On aarch64 a delivery that carries an `esr_context`, a fault's
      syndrome, presents it only where the trap's frame carries one too,
      whose record it fills; ASan reads it to tell a write fault, which a
      signal landing during a trapped call is not.
    - Past 256 distinct pairs of handler and mask installed in one
      process, an install is made directly, and its handler finds the
      launcher's frame.
    - The handler runs on less of the alternate stack (item 51).

### 13.1 Debugging and profiling recipe

Yama's `ptrace_scope` forbids attaching to a non-descendant on most
distributions, so gdb launches the program itself. The launcher carries
a gdb script (7.6) that adds the program's and its libraries' symbols;
gdb must be allowed to load it. Put `add-auto-load-safe-path
/path/to/exclaves` in `~/.gdbinit` once, or use `set auto-load
safe-path /` for a session:

```
gdb -iex 'set auto-load safe-path /' --args <exclave>/gcc -O2 -c file.c          # a wrapped program
gdb -iex 'set auto-load safe-path /' --args <exclave>/.exclave/launcher ./prog    # a built output, through the positional entry (7.2)
gdb -iex 'set auto-load safe-path /' ./prog                                    # with the exclave's gdb, inside: the program itself
(gdb) break main                   # pending until the script adds the program
(gdb) set follow-fork-mode child   # to stop inside cc1 rather than the driver
(gdb) run
```

`break` works in the program and in the exclave's libc, `bt` walks
through both, and `info files` lists what the script added; `info
sharedlibrary` is empty (7.6, item 1). Every translated syscall is a
`SIGSYS` stop that gdb passes through, so a run under gdb slows in
proportion to its traps. A gdb inside an exclave takes the same
commands, and the program itself as well as the launcher by its host
path, `gdb ./prog` or `gdb /usr/bin/gcc`: gdb then prints the
launcher's second exec as the process "executing new program" (7.6),
and runs the program again at the next `run` (item 1).

How the script works. The launcher exports six names: the base, entry
and real file of the program, the base and file of its loader, and
`exclave_debug_hook`, a function it calls once before jumping into the
program. `src/gdb.py`, carried in `.debug_gdb_scripts`, is auto-loaded
at launch and at every exec of a launcher. It makes gdb pass `SIGSYS`
without stopping and breaks on the hook, where it adds the program's
symbol file at its base and the loader's at its own. At the program's
entry it walks the loader's link map (`_r_debug` on glibc,
`_dl_debug_addr` on musl) and adds each library at its load address,
resolving names in the tree as the translator does and taking a
wrapper's original; a breakpoint on `r_brk` repeats the walk after
every `dlopen`. `info sharedlibrary` is empty because the launcher
carries no `DT_DEBUG`. With `set follow-fork-mode child` the same
happens in `cc1`. Where gdb was given the program, the script reads at
the launcher's second exec the name the program was exec'd by, from the
kernel's copy of its environment, and makes it gdb's file again when the
process exits, since following that exec made the launcher its file (7.6).

`perf record` needs nothing special and symbolises `cc1` down to
functions. perf cannot read the maps of a process under a different
AppArmor label, so run it under the same label as the program.


## 14. Alternatives considered

Each alternative below was weighed and rejected, most after being built
or measured; the reasons are kept so that a choice can be reopened when
the balance moves. This section is the home of every "why not"; 16.7
and 19 point here.

### 14.1 How the tree is projected

**User and mount namespaces.** A read-only bind mount of the tree at
`/` is the obvious projection, and its answers are what the launcher
imitates. It is unavailable where exclave is most needed: from an
ordinary terminal on Ubuntu 23.10 and 24.04, inside Docker's default
profile, on many HPC hosts and hardened kernels (4.3, 15.7). A second
backend where namespaces are allowed would make an exclave behave
differently by machine and double the code, for no measurable gain on
a compute-bound compile (16.8). Namespaces are the test oracle (17
item 1), not a mechanism.

**A ptrace supervisor**, as PRoot and CARE use (15.1). Every
intercepted syscall stops the tracee twice and switches to another
process, and the supervisor holds the ptrace slot, so nothing inside
can be debugged or traced. exclave services the syscall in the process
that made it.

**seccomp user notification** (`SECCOMP_RET_USER_NOTIF`). A supervisor
again, with a context switch per trap, slower than a signal. It cannot
change the target's registers, so `chdir` and `execve` would be
emulated rather than re-issued, and seccomp_unotify(2) warns that calls
such as `open` "are vulnerable to ToCToU attacks".
`SECCOMP_IOCTL_NOTIF_ADDFD` (5.9, atomic with `SECCOMP_ADDFD_FLAG_SEND`
from 5.14) installs a descriptor the supervisor opened, which covers
`open` and nothing like `chdir`.

**Syscall User Dispatch** (`PR_SET_SYSCALL_USER_DISPATCH`, 5.11), the
kernel's in-process `SIGSYS` mechanism built for Wine, dispatches every
syscall outside an exempt code range rather than a chosen set, costs
the same signal as a seccomp trap, and is reset by "any fork or exec of
the existing process", so a child would run untranslated between the
two. Its documentation calls it "not a mechanism for sandboxing system
calls"; it does show that in-process `SIGSYS` emulation is a supported
use of the kernel.

**libc interposition** through `LD_PRELOAD`, as fakechroot does
(15.1), sees only libc's exported functions: libc's internal opens,
raw syscalls, static and Go programs escape it, and the loader works
before any constructor runs. A preload is visible to the program, and
keeping `EFAULT` needs the copy the handler makes anyway. Interposing
inside the exclave's own glibc would avoid the signal for
libc-mediated calls, with the same holes.

**Rewriting syscall sites** (zpoline, lazypoline, rr, 15.1): after the
first trap at an address, patching the `syscall` instruction into a
call to the handler. The two-byte `syscall` on x86-64 has room only for
`call *%rax`, which needs a mapping at address 0, refused without
privilege (`vm.mmap_min_addr`); patching longer sequences changes the
program's text under other threads, a debugger, a JIT and any checksum.
It would remove at most the signal, half of the 1.3 µs floor of a trap
(16.2), and the trap stays for every site not rewritten. A load-time
rewriter such as SaBRe is the compatible shape, since the launcher
already loads the program; it is the lever if a syscall-bound workload
ever matters.

**FUSE or a union filesystem.** Needs the host's `fusermount`, and
cannot make the tree appear at `/usr`.

**`openat2` with `RESOLVE_IN_ROOT` as the resolver.** Cannot express
host-owned prefixes inside the root (8.1), and needs kernel 5.6. It is
the oracle for canonicalisation instead (17 item 2).

**Kernel-side loader substitution through BPF `binfmt_misc`** (15.3).
Registration needs root. Where a user may register it, it could
accelerate dispatch; it cannot be the mechanism, for the same
uniformity reason as namespaces.

### 14.2 How a program finds its loader and keeps its identity

**Relocating paths inside binaries**, as Spack and conda do with padded
prefixes (15.2). Works only for software that cooperates, since an
address can be computed arbitrarily, and must be redone on every move.

**Patching the interpreter string** (`PT_INTERP`) to an absolute path,
as udocker, uninative and Linuxbrew do (15.2), ties the tree to one
location. The location-independent string `/proc/self/fd/999`, with the
launcher held open on that descriptor, gives patched programs the
identity of a kernel exec, but it is per-process state that a program
can close or reuse; it rests on an undocumented ordering inside the
kernel's exec; a stray file on the descriptor runs the program on the
host's loader, untranslated; a patched file run alone fails
cryptically; scanners flag the string; and it does not reach programs
built inside the exclave. Wrappers, a hard link to the launcher at each
executable's path with the original in `.real/` (6.1), give shipped
programs the same identity with none of this, and the loader path (7.6)
covers the rest.

**Copies with patched headers in a cache.** A cache directory, which
6.1 forbids, for a benefit wrappers provide without one.

**Mixed libcs with a per-file interpreter table.** No case needs it, and
`dlopen` with computed names makes the library-search hazard
unverifiable. One libc per exclave, with data directories for others
(9, 13 item 8).

**A host world for programs on host paths.** Running a program the
exclave did not ship on the host's own libraries breaks `make check`
whenever the exclave's libc differs from the host's, and is a second
mode to maintain. Inside an exclave there is one world.

**gdb's JIT interface, or a `DT_DEBUG` mirror.** gdb reads a JIT
symbol file at the addresses its sections carry, so a
position-independent program's DWARF would need relocating; a mirror
would make gdb look libraries up on the host's `/` and read the
launcher for a wrapper. The script the launcher carries (7.6) adds
every file at its base, originals included.

### 14.3 Inside the launcher

| Alternative | Why not |
|---|---|
| `chmod -R a-w` for read-only | The tree resists `rm -r`, loses its modes to version control and careless copies, and its owner can restore the bits. Refusal in the handler depends on nothing; its price is 8.2's error precedence. |
| Resolving host symlinks in the host's domain | A host link into `/usr` would reach the host's `/usr`. Links resolve in the exclave's view; the identity files' host links and the links in the identity directories are followed by the kernel on the host (8.4). |
| A union of the host's trust directory and the tree's | Answers no one's directory: the tree's hash links would stand beside the host's, so an authority the host removed would still verify inside, and a listing would merge two sets in an order neither has. The host's directory at its name, with the identity files the host lacks in it the exclave's, answers as the host's own directory does (8.4). |
| Binding the host's trust directory with its links resolved in virtual space, a `host` record | Its links are absolute paths into `/usr/share/ca-certificates`, which inside are the tree's, so the directory would trust nothing the tree does not ship, and a `host` record for each target directory still misses `/usr/local/share/ca-certificates` and whatever another host's trust tool links to (8.4). |
| Honouring `clone3` by copying the signal frame onto the child's stack | The FPU save area must be copied with the frame and the frame's pointer to it moved, or every new thread starts with a corrupt `MXCSR`. That can be done, but it ties the handler to the kernel's signal-frame layout on both architectures, a layout that grows with each new register set, where `ENOSYS` costs a few traps per `posix_spawn` (7.5.5). |
| Returning a program's handler straight to the trap site, the launcher's frames abandoned | The launcher may be holding descriptors of its walk or the cache's lock where the signal lands, and the frame the handler would return through carries the launcher's shadow-stack token (x86-64's, aarch64's GCS) where the program's is needed. The handler returns through the restorer's instructions in the handler-call slot, which the filter answers with an error, into the trampoline, and the launcher ends its call as the handler decided (7.5.7). |
| Calling a program's handler with a return into the trampoline's own code | Simpler, and no filter rule, but an unwinder finds no unwind information at the return address and stops there: glibc's cancellation would jump to its innermost cleanup buffer and pass over the cleanup handlers that C built with `-fexceptions`, Fedora's default, and C++ destructors keep in the frames between, an unlock among them, and a C++ exception thrown from the handler would end in `std::terminate`. A return address at the restorer's instructions is one libgcc's fallback and gdb take for the kernel's (7.5.7). |
| Editing the kernel's frame for the delivery in place | Needs the launcher's registers kept elsewhere while the handler runs, on every trap's stack. A frame of the trampoline's own, of the kernel's layout, leaves the kernel's frame holding the launcher's state (7.5.7). |
| Running a handler that did not ask for the alternate stack on the trap site's stack | As natively, but the launcher's frames stay live on the alternate stack meanwhile, where a signal for an `SA_ONSTACK` handler, as Go installs every one, would be delivered at its top, over them. Narrowing the alternate stack for the handler's run leaves windows on either side of the switch, a narrowed stack for good after a `siglongjmp` out of the handler, the handler's own `sigaltstack` calls overwritten, and under `SS_AUTODISARM` a nested trap's frame on another stack than its parent's, where the comparison of 7.5.4 could release a live chunk (13 item 51). |
| One table of actions, an entry per signal | A `vfork` child's install would rewrite its parent's entry in the memory they share, and two threads installing at once could leave the kernel's action and the entry disagreeing. A slot per distinct handler and mask, never rewritten and named by the kernel's action through its stub, keeps each delivery's handler the one the kernel delivered for (7.5.7). |
| Deferring a signal that lands in the walk to the trap's end, blocked and queued again | The handler would then see the call made, as natively for a call that does not wait, but the signal would stay blocked through a call that waits, so a Ctrl-C landing in a FIFO open's walk would not interrupt the open, and `SA_RESETHAND` has already reset the action the queued signal would meet. The call is presented about to be made (13 item 58). |
| Copying the trap's floating-point state by a layout of the launcher's own | Ties the launcher to the save area's layout, as honouring `clone3` would. On x86-64 the presented frame's pointer names the trap's frame's save area; on aarch64 the trap's records are copied as they lie, by the length their own headers give, and copied back (7.5.7). |
| Reclaiming scratch by comparing stack pointers across threads | Meaningless across alternate stacks and coroutines; scratch is reclaimed by liveness sweeps (7.5.4). |
| Synthesising host entries into `getdents64` | Invents results: a listing would name what no directory holds, merged in an order no choice gets right for every program. Empty placeholders in the tree give `ls /` the same answer for free (8.3). |
| A canonicalisation cache shared across processes | Would save a few hundred `lstat`s per compile, but an inherited descriptor is visible to the program (descriptor counts, `close_range`, leak checks), and a file outside the exclave is state an edited tree makes wrong (14.5). |
| Caching host paths | A host directory can be replaced at any time. The one-step host check (7.4.4) gets most of the benefit without remembering anything. |
| Skipping the empty top-level directories at startup | The placeholders are how `ls /` lists the host's directories (8.3), and only reading a directory says it is empty: seven placeholders read per start in the gcc exclave, the five volatile ones not at all, since the host owns them whatever they hold (8.1 rule 3). |
| Dropping `getpid` and `gettid` per trap | About 100 ns a trap, but a process-wide value is wrong in a `vfork` child while a parent's thread is in its handler (7.5.4), and the launcher has no thread-local storage. |

### 14.4 The environment

| Alternative | Why not |
|---|---|
| An environment allowlist | Users could not pass `CC`, `CPATH`, `MAKEFLAGS` or a CA bundle, and applied at every exec it would break `ldd`, libtool and `fakeroot`. Path-valued variables resolve inside the exclave, so passing them is safe (6.2). |
| The user's locale, and `TZ` | Locale data is bound to its glibc's version, so `LANG` would work only where the exclave ships the locale and fall silently to `C` elsewhere; a zone name in `TZ` needs the exclave's `tzdata`, which few package closures pull in, and glibc without it keeps the name with no offset. Three fixed values at the border (6.2) need no data, and the zone comes from the host's `/etc/localtime`, a TZif file any libc reads (8.4). |
| UTC inside, `TZ=UTC0` at the border | Needs no data either, but every timestamp a program prints or embeds is then in a zone that is nobody's on a host elsewhere, the difference a user meets first; the host's zone is a host fact like its users, and a build that wants a fixed one takes `/etc/localtime` back with `own`. |
| Recording the maker's locale in the exclave | A manifest record for what a rule says. An exclave that wants another locale sets it in a wrapper script. |

### 14.5 The format and the tool

| Alternative | Why not |
|---|---|
| A generated index beside the manifest | Every record the launcher uses is readable from the tree in microseconds, and a tree edited without re-indexing would be silently wrong (6.3). |
| Layers at run time | A second root in the translator, a libc rule, a record naming another exclave's location and an unanswered listing question, to save disk. Composition is a copy at build time (11). |
| The tool fetching from archives | Acquisition has its own trust argument and failure surface; it is the step before the tool, `fetch` (10). |
| `from-source` with build recipes | The beginning of a distribution. A build script builds inside an exclave, and an exclave is made of the staging directory plus the runtime packages (10.2). |
| `env` and `entry` records | Both duplicate a file: a symlink in `/usr/local/bin`, a wrapper script, a symlink at the top of the exclave (6.2). |
| Several roots per CPU level, `chroot` re-rooting, maintainer scripts run in a scratch exclave | Two exclaves are two exclaves; a writable root would be a second world; a tree that needs its scripts run comes from outside (7.7, 7.8, 10.1). |
| A single-file form | A cache directory, which 6.1 forbids. `tar` makes a directory one file (6.6). |

## 15. Related work

The problem of 4.1, a program bound to its host by its interpreter,
libraries, compiled-in data paths and environment, has been attacked
from two directions: projecting a tree onto the paths the program
expects, and relocating the program to expect others. This survey,
made in September 2026, gives what each system needs from the host and
how exclave differs; 15.5 compares them in one table, and 14 says why
exclave does not take their mechanisms.

### 15.1 Systems that project a tree

**PRoot, CARE and CDE.** PRoot is a user-space `chroot`, `mount
--bind` and `binfmt_misc` on ptrace: a supervisor rewrites the path
arguments of every syscall and, for `execve`, substitutes the pack's
loader. CARE runs a program once under PRoot, records every file it
touches and ships the archive with PRoot inside; CDE (Guo, 2011), the
first automatic packager, did the same, and its paper is the reference
for the completeness problems of trace capture that `exclave prune`
inherits (10.4). All pay a ptrace round trip per intercepted syscall;
PRoot's seccomp acceleration "may exhibit problems in Linux kernels
above 4.0", in udocker's words, and udocker leaves it off. PRoot is
maintained (5.5.0, October 2026, adds `fchmodat2`), and **proot-next**
reimplements it in Rust with seccomp user notification in place of
most ptrace stops: a pool of supervisor threads performs the real
syscall, and `execve`, `chdir`, `chroot` and unix-socket `bind` and
`connect` still take a ptrace stop. It confines "paths, not
privileges", as exclave does, and stays a supervisor outside the
process (14.1).

**fakechroot, and the fakechroot engine of `guix pack -RR`.** An
`LD_PRELOAD` library interposes libc's path functions and, for
`execve`, runs the chroot's `ld.so` directly. Guix adds a wrapper that
finds the loader relative to itself and an `la_objsearch` audit hook
for `ld.so`'s own search, and reports "very little overhead, and only
on file system function calls", against PRoot's "prohibitive" cost for
MPI and multi-threaded work. A preload sees only libc's exported calls
(14.1).

**udocker** runs container images without root through PRoot,
fakechroot, runc, crun or Singularity. Its fakechroot modes rewrite
each executable's interpreter with PatchELF to an absolute path, so
such containers "cannot be moved across hosts"; exclave patches
nothing.

**`guix pack -RR`, nix-user-chroot, nix-portable, conty, junest** prefer
user namespaces and fall back to PRoot or fakechroot where they are
denied, so their behaviour varies by host, which exclave's single
mechanism avoids (4.3, 14.1).

**gVisor systrap**, gVisor's default platform from 2023: a seccomp
filter returns `SECCOMP_RET_TRAP` for every syscall, a stub `SIGSYS`
handler writes the request to shared memory, and the sentry in another
process services it. It replaced ptrace because "this alone proved to
be faster than using PTRACE_SYSEMU". exclave has the same trap shape,
but services the syscall in the process and traps only path-taking
syscalls.

**burrow and chroot-ng** have exclave's shape exactly, on aarch64
alone: a seccomp filter traps the path syscalls with `SIGSYS`, a
handler in the process emulates them, and a freestanding binary with
its own ELF loader maps the program and its interpreter, "without
root, user namespaces or ptrace". Both were written for Android
without user namespaces, to run a distribution's rootfs there, and
both say they are not a security boundary. burrow measures one trap at
about 1.1 µs on a tablet, 0.4 µs of it the kernel's signal delivery,
against 40 to 64 µs for a ptrace stop and 9.5 µs for a user
notification served on the same core, which is the ranking 14.1 gives.
Where they differ from exclave: they emulate a root user and parts of
`/proc`, chroot-ng emulates `ptrace` for a guest's `strace` and `gdb`
and runs programs from `noexec` media through its loader, and neither
has the hard-link wrapper for identity (7.6), the read-only rule in the
kernel's order (8.2), one source for two architectures, or a kernel
oracle for its answers (17). The in-process trap is not exclave's
alone; the combination around it is.

**Binary rewriting: zpoline, SaBRe, syscall_intercept, lazypoline,
rr.** zpoline's trampoline at address 0 needs a lowered
`vm.mmap_min_addr`; SaBRe rewrites at load time, syscall_intercept
patches glibc under `LD_PRELOAD`; lazypoline (2024) keeps Syscall User
Dispatch as the exhaustive slow path and rewrites each site on its
first trap, the shape any acceleration of exclave would take (14.1).
rr allows a syscall only from a page holding an untraced `syscall`;
the launcher's syscall page (7.4.2) is that idea at a fixed address, so
that filters inherited across `execve` agree.

**Reverie and hermit**, Meta's interception framework and the
deterministic sandbox on it, are the state of the art for a ptrace
supervisor with seccomp assistance.

**MBOX** (Kim and Zeldovich, 2013) layers a private filesystem over the
host on seccomp and ptrace and lets the user commit changes back, the
alternative to a tree read-only by refusal (8.2).

**Systrace, Janus, Ostia and "Traps and Pitfalls"** (Garfinkel, 2003),
the security-interposition lineage. The paper's pitfalls are exclave's
test checklist (17 item 6); its first, incorrect replication of OS
semantics, is the one no design escapes, and the reason for the kernel
oracles of 17.

### 15.2 Systems that relocate binaries

**exodus** bundles a binary and its libraries with "a small statically
linked launcher binary that invokes the relocated linker directly". It
addresses the interpreter and the libraries only, so gcc's `cc1` and
headers would not be found.

**sharun** is a modern exodus: its `userland-execve-rust` maps the
bundled interpreter, builds the stack and jumps to the entry, as the
launcher's loader does (7.3); its `--hard-links` option links the
launcher under each program's name "for correct /proc/self/exe".

**Ermine and Statifier** pack one program, its loader and libraries
(Ermine also its data files) into one executable; single-program, and
commercial or unmaintained.

**Spack and conda** relocate binary caches by rewriting `RPATH` and by
string replacement of the install prefix, made safe by padding install
paths to a fixed length. Rewriting hard-coded strings "is impossible to
do generally since addresses could be computed arbitrarily" (14.2).

**Yocto's uninative** is the largest production precedent for patching
interpreter strings: every native tool restored from Yocto's
shared-state cache has its interpreter rewritten to a bundled glibc's
loader, "a way of allowing a single set of cross/native sstate to work
over multiple distros". The path is absolute, so the cache is tied to
the build directory, as **Linuxbrew**'s bottles are tied to the prefix
`/home/linuxbrew/.linuxbrew`.

**Cosmopolitan's Actually Portable Executables** carry a loader that
maps the program's segments "the same way the kernel does, based on ELF
phdrs", with raw syscalls and no libc. The launcher's loader is the
same idea applied to someone else's binaries; APE requires building
with Cosmopolitan.

**Zig** ships its libc as headers and sources, locates everything
relative to its own executable, and builds startup objects on demand.
It owns its compiler's source, which exclave does not (4.2).

**Plash** (Seaborn, 2005) ran unmodified programs on a modified glibc
that sent file operations to a server holding the authority, accepting
early that owning the libc inside the environment is the price of
running unmodified programs: exclave's one-libc rule seen from the
other side (13 item 8).

### 15.3 The interpreter trick

**A custom `PT_INTERP` that loads the real loader.** Pointing
`PT_INTERP` at one's own interpreter, which "maps the legitimate RTLD
into memory and updates the auxiliary vector accordingly" before
handing over, is documented in tmp.0ut issue 2 in an offensive context.
It is the launcher's loader (7.3), including the `AT_BASE` rewrite, and
evidence that glibc's loader tolerates being mapped by someone else.

**nix-ld** is the closest existing implementation of the launcher's
loader. Installed at `/lib64/ld-linux-x86-64.so.2` on NixOS so that
unpatched binaries run, it is `#![no_std]`, applies its own relocations
at startup, and when started as an interpreter maps the real loader,
sets `AT_BASE` to its load bias and jumps with the original stack
pointer. Run directly, it `execve`s the real loader.

**BPF `binfmt_misc`.** A proposal to let `PT_INTERP` be relative to the
executable was called "ripe for malicious loader injection attacks" by
Christian Brauner, who proposed instead a BPF `struct_ops` for
`binfmt_misc` (LWN, 2026), now in the kernel's documentation: a
handler with a `match` and a `load` program, registered in a user
namespace and usable only there, whose `L` flag loads a binary that
asks for a loader as a native executable and whose `T` flag hands the
binary to an interpreter through `AT_EXECFD`. Its documentation says
the `L` flag "is therefore not an enforcement mechanism". That accepts
that hermetic binaries need a substituted loader, through a mechanism
that needs a user namespace of one's own, which is the constraint of
4.3 again; the launcher's wrappers and loader are the analogue that
needs none, and the objection applies to exclave as to `LD_PRELOAD`:
an exclave is not a security boundary (3).

Each piece of the launcher, a no-libc loader that maps the real
`ld.so`, interpreter substitution at scale, hard-linked launchers for
identity, exists separately in nix-ld, uninative, sharun and the
tmp.0ut technique, and burrow and chroot-ng (15.1) also install a
syscall translator before the real loader runs, on aarch64. exclave
claims no novelty: it is the combination its author wanted and could
not find, with the tests of 17.

### 15.4 Shadow wrappers

exclave puts a hard link to the launcher at every executable's path
and keeps the original in a `.real/` directory beside it (6.1). The
pattern is old. busybox and toybox are one binary under hundreds of
names, and the kernel's `/proc/<pid>/exe` names the link that was
executed, the fact the wrapper design rests on. Nix's `makeWrapper`
moves a program to `.foo-wrapped`; ccache and distcc put a link under
each compiler's name; `dpkg-divert` moves a file aside to
`foo.distrib`; libtool's uninstalled wrappers keep the real binary in
`.libs/`, so that `make check` runs programs before installation.

What exclave adds: the wrapper is the launcher itself rather than a
script, so the kernel executes it with the program's identity and no
interpreter is involved; every syscall but exec on a wrapper's path is
redirected to the original, so tools inside the exclave never see the
wrapper; and scripts are wrapped as well as ELF files, so a script
cannot escape to the host's interpreter.

### 15.5 Comparison

The four bindings are those of 4.1.

| System | Interpreter | Libraries | Data paths | Environment | Privilege | Supervisor | Moves with a copy |
|---|---|---|---|---|---|---|---|
| Static linking | n/a | yes | no | no | none | no | yes |
| exodus | `ld.so` trampoline | yes | no | no | none | no | yes |
| Ermine, Statifier | embedded loader | yes | own VFS | no | none | no | yes |
| Spack, conda padding | patched path | patched | patched strings | no | none | no | needs re-patching |
| fakechroot, Guix engine | `ld.so` run directly | interposed | libc calls only | wrapper | none | no | yes |
| udocker F modes | patched to an absolute path | yes | fakechroot | wrapper | none | no | "cannot be moved across hosts" |
| PRoot, CARE, CDE | rewritten `execve` | yes | yes | wrapper | none | ptrace | yes |
| proot-next | rewritten `execve` | yes | yes | wrapper | none | notification threads, ptrace for exec | yes |
| burrow, chroot-ng (aarch64) | own loader, exec of itself | translated | translated | wrapper | none | no | yes |
| gVisor systrap | sentry | sentry | sentry | sentry | none, but a runtime | yes | image |
| bwrap, Guix userns, conty, junest | bind mounts | yes | yes | yes | user namespaces | no | yes |
| Docker, Podman | image | yes | yes | yes | daemon or user namespaces | yes | image |
| BPF `binfmt_misc` | kernel substitution | through the loader | no | no | a user namespace to register in | no | yes |
| **exclave** | launcher at every executable's path, originals in `.real/` | translated | translated | passed through minus loader and libc variables and `TZ`; `PATH`, `LANG`, `SHELL` fixed | none | no | yes, `cp -a` |

exclave, burrow and chroot-ng are the rows that are unprivileged, have
no supervisor, cover all four bindings and move with a copy; exclave is
the one of them on x86-64, and the one whose answers are checked
against the kernel's (17). Its nearest relatives are burrow and
chroot-ng for the trap, gVisor systrap before them, CARE for pruning,
and the wrappers of 15.4 for identity.

### 15.6 Kernel and library behaviour the design relies on

Read from source:

- **`fs/binfmt_elf.c`.** `load_elf_binary` reads the `PT_INTERP`
  string and calls `bprm_open_interpreter()` before
  `begin_new_exec()`, which drops the old memory map and closes
  close-on-exec descriptors. The interpreter must be `ET_EXEC` or
  `ET_DYN`. The string must satisfy `p_filesz >= 2 && p_filesz <=
  PATH_MAX` and end in a NUL at `p_filesz - 1`; it is then used as a C
  string, so NUL padding after a shorter path is valid. The
  interpreter's own `PT_INTERP` is ignored. `AT_BASE` is the
  interpreter's load address; `AT_EXECFN` is the filename passed to
  `execve` (7.3).
- **`kernel/signal.c`.** `force_sig_info_to_task()` resets the handler
  to `SIG_DFL` and unblocks the signal when it is blocked or ignored;
  `force_sig_seccomp()` uses `HANDLER_CURRENT` for `SECCOMP_RET_TRAP`,
  keeping `HANDLER_EXIT` and `SA_IMMUTABLE` for the kill actions. So a
  blocked `SIGSYS` is fatal and an installed handler is kept (7.5.1).
- **glibc `elf/rtld.c`.** The loader computes its own address
  PC-relative (`elf_machine_load_address()`) and never trusts
  `AT_BASE` for itself. `dl_main` recognises an interpreter-mode start
  when the program's entry is in `AT_ENTRY`. The loader's name is taken
  from the executable's `PT_INTERP` string, and when the soname differs
  a second name is chained, so `DT_NEEDED ld-linux-x86-64.so.2` still
  resolves to the loaded interpreter when the string names another path
  (7.3).
- **musl `ldso/dlstart.c`.** The loader's base is `aux[AT_BASE]`, and is
  recomputed from `PT_DYNAMIC` only when that is zero. The launcher's
  `AT_BASE` rewrite is therefore required for musl (7.3).
- **`binfmt_misc`.** The `F` flag opens the interpreter when it is
  registered and spawns from the opened image; `O` passes the target's
  descriptor as `AT_EXECFD`. The kernel has held pre-opened
  interpreters since 2011.

### 15.7 Environment facts checked

**Ubuntu's user-namespace restriction.** Ubuntu 23.10 and 24.04 set
`kernel.apparmor_restrict_unprivileged_userns=1`: "applications
requiring unprivileged namespaces require explicit allowance by their
AppArmor profile". Turning it off is root's and lost on reboot. This
matches the measurement of 4.3. The bypasses published on oss-security
in 2025 are bugs, not a mechanism to build on.

**HPC container tools.** Apptainer, Charliecloud and Enroot all need
unprivileged user namespaces, or in Apptainer's older mode a setuid
helper. None covers the host that denies user namespaces.

**Docker's default seccomp profile**, `seccomp/default.json` in
`moby/profiles` at commit `3c28324` (Apache-2.0), which
`scripts/inputs` fetches pinned by hash and `test/docker_profile.py`
runs an exclave under (17 item 5). For the syscalls the launcher needs:

| Syscall | Verdict |
|---|---|
| `seccomp`, `prctl`, `rt_sigaction`, `rt_sigprocmask`, `rt_sigreturn`, `sigaltstack`, `mmap` | allowed |
| `close_range`, `openat2`, `faccessat2`, `execveat`, `statx` | allowed |
| `process_vm_readv`, `process_vm_writev`, `ptrace` | allowed on kernels 4.8 and later, whatever the capabilities |
| `clone3` | refused without `CAP_SYS_ADMIN`; glibc falls back to `clone` |
| `unshare`, `mount`, `chroot`, `pidfd_getfd`, `bpf` | need capabilities |

So the trap, the handling of `openat2` and the `process_vm_readv` copy
that keeps `EFAULT` (7.5.6) all work under the default profile, and gdb
inside a container works. The launcher's own filter refuses `clone3`
everywhere (7.4.2, 7.5.5). The profile blocks nothing the design needs
(12).

**Steam's runtime** documents the one case in which a closed
environment must import host libraries: graphics drivers "come from
the host system", since the user-space driver must match the kernel's,
and Steam loads them in an isolated namespace with libcapsule. GPU
software would need such an import, and is outside exclave's scope (13
item 9).

### 15.8 Sources

- [PRoot manual](https://github.com/proot-me/proot/blob/master/doc/proot/manual.rst); [CARE](https://proot-me.github.io/care/); [CARE paper, TRUST 2014](https://dl.acm.org/doi/10.1145/2618137.2618138)
- [CDE: Using System Call Interposition to Automatically Create Portable Software Packages, USENIX ATC 2011](https://pg.ucsd.edu/publications/CDE-create-portable-Linux-packages-short-paper_USENIX-2011.pdf); [CDE, LISA 2011](https://pg.ucsd.edu/publications/CDE-create-portable-Linux-packages_LISA-2011.pdf)
- [fakechroot(1)](https://manpages.debian.org/testing/fakechroot/fakechroot.1.en.html); [Faster relocatable packs with Fakechroot, Guix-HPC 2020](https://hpc.guix.info/blog/2020/05/faster-relocatable-packs-with-fakechroot/); [Invoking guix pack](https://guix.gnu.org/manual/1.5.0/en/html_node/Invoking-guix-pack.html)
- [udocker on PyPI](https://pypi.org/project/udocker/); [Enabling rootless Linux Containers in multi-user environments: the udocker tool](https://www.sciencedirect.com/science/article/pii/S0010465518302042)
- [Releasing Systrap, gVisor 2023](https://gvisor.dev/blog/2023/04/28/systrap-release/); [systrap README](https://github.com/google/gvisor/blob/master/pkg/sentry/platform/systrap/README.md)
- [zpoline, USENIX ATC 2023](https://www.usenix.org/conference/atc23/presentation/yasukata); [zpoline documentation](https://github.com/yasukata/zpoline/blob/master/Documentation/README.md); [SaBRe](https://github.com/srg-imperial/SaBRe); [syscall_intercept](https://github.com/pmem/syscall_intercept)
- [lazypoline: System Call Interposition Without Compromise, 2024](https://gulmezmerve.github.io/files/2024-lazypoline.pdf); [Engineering Record and Replay for Deployability (rr)](https://nimrodpar.github.io/assets/publications/rr.pdf)
- [Reverie](https://github.com/facebookexperimental/reverie/blob/main/README.md); [hermit](https://github.com/facebookexperimental/hermit)
- [seccomp_unotify(2)](https://www.man7.org/linux/man-pages/man2/seccomp_unotify.2.html); [Add seccomp notifier ioctl that enables adding fds, LWN](https://lwn.net/Articles/821351/)
- [Syscall User Dispatch](https://docs.kernel.org/admin-guide/syscall-user-dispatch.html); [Emulating Windows system calls in Linux, LWN](https://lwn.net/Articles/824380/)
- [MBOX: Practical and Effective Sandboxing for Non-root Users, USENIX ATC 2013](https://www.usenix.org/system/files/conference/atc13/atc13-kim.pdf); [Traps and Pitfalls: Practical Problems in System Call Interposition Based Security Tools, 2003](https://cs155.stanford.edu/papers/traps.pdf); [Ostia, NDSS 2004](https://www.ndss-symposium.org/ndss2004/ostia-delegating-architecture-secure-system-call-interposition/)
- [exodus](https://github.com/intoli/exodus); [sharun](https://github.com/VHSgunzo/sharun); [Ermine: Statifier, static linking and Ermine](https://www.magicermine.com/sesl.html); [ELF statifier](http://statifier.sourceforge.net/)
- [Spack build caches](https://spack.readthedocs.io/en/v0.23.1/binary_caches.html); [spack.relocate](https://spack.readthedocs.io/en/latest/_modules/spack/relocate.html); [Strategies for Binary Relocation, Lobsters discussion](https://lobste.rs/s/2lnncd/strategies_for_binary_relocation)
- [uninative: Add uninative, OpenEmbedded commit](https://git.openembedded.org/openembedded-core/commit/?id=e66c96ae9c7ba21ebd04a4807390f0031238a85a); [Linuxbrew bottles](https://github.com/Linuxbrew/brew/wiki/Bottles); [Plash](http://plash.beasts.org/environment.html)
- [Cosmopolitan APE specification](https://github.com/jart/cosmopolitan/blob/master/ape/specification.md); [APE loader](https://justine.lol/apeloader/)
- [Preloading the linker for fun and profit, tmp.0ut 2](https://tmpout.sh/2/6.html); [nix-ld](https://github.com/nix-community/nix-ld); [nix-ld: a clean solution for issues with pre-compiled executables on NixOS](https://blog.thalheim.io/2022/12/31/nix-ld-a-clean-solution-for-issues-with-pre-compiled-executables-on-nixos/)
- [Bringing BPF to binfmt_misc, LWN 2026](https://lwn.net/Articles/1086947/); [binfmt-misc.rst](https://github.com/torvalds/linux/blob/master/Documentation/admin-guide/binfmt-misc.rst)
- [burrow](https://github.com/RickyTr99/burrow); [chroot-ng](https://github.com/sylirre/fake-chroot-ng); [proot-next](https://github.com/selkies-project/proot-next); [PRoot releases](https://github.com/proot-me/proot/releases)
- [fs/binfmt_elf.c](https://github.com/torvalds/linux/blob/master/fs/binfmt_elf.c); [kernel/signal.c](https://github.com/torvalds/linux/blob/master/kernel/signal.c); [glibc elf/rtld.c](https://github.com/bminor/glibc/blob/master/elf/rtld.c); [musl ldso/dlstart.c](https://git.musl-libc.org/cgit/musl/tree/ldso/dlstart.c); [binfmt_misc admin guide](https://www.kernel.org/doc/html/latest/admin-guide/binfmt-misc.html)
- [Understanding AppArmor User Namespace Restriction, Ubuntu](https://discourse.ubuntu.com/t/understanding-apparmor-user-namespace-restriction/58007); [Ubuntu 24.04 release notes](https://documentation.ubuntu.com/release-notes/24.04/); [Three bypasses of Ubuntu's unprivileged user namespace restrictions, oss-security 2025](https://seclists.org/oss-sec/2025/q1/253)
- Docker's default seccomp profile: [`seccomp/default.json` in moby/profiles at 3c28324](https://github.com/moby/profiles/blob/3c28324314729dbade8287e868eef6338c42807a/seccomp/default.json)
- [Steam Runtime possible designs](https://github.com/ValveSoftware/steam-runtime/blob/master/doc/possible-designs.md); [Apptainer user namespaces](https://apptainer.org/docs/admin/main/user_namespace.html); [Charliecloud](https://charliecloud.io/latest/); [enroot requirements](https://github.com/NVIDIA/enroot/blob/main/doc/requirements.md)

## 16. Performance

What an exclave costs a program, where the cost goes, and what the
launcher does about it. The figures come from the reference machine
(2), with the tree on ZFS, and the gcc exclave of `scripts/inputs`,
measured October 2026 unless stated; the older kernels are the x86-64
rows of the matrix (12.1), run under KVM on the same machine. 13 item 2
states the limitation; 16.9 says how to reproduce the figures.

### 16.1 The cost model

An exclave costs a program in four places:

1. **Every trapped syscall**, the path-taking ones (7.4.3): a `SIGSYS`
   delivery and return, the handler's fixed work, its own lookups while
   canonicalising, and the re-issued syscall (16.2).
2. **Every untrapped syscall**: the seccomp filter runs on it, unless
   the kernel's action cache (5.11 and later) has proved the answer
   constant for that syscall number (16.3).
3. **Every process start**: the launcher's startup (7.2), its loader
   (7.3) and a cold canonicalisation cache; at the border also the
   filter install (16.4).
4. **Everything else**, which costs nothing, except on kernels that
   force a speculation mitigation on a process that installs a seccomp
   filter, which the launcher prevents (16.5).

In summary (16.8): a trapped `stat` costs 2.0 to 4.1 µs where the
host's costs 0.3 to 0.4; an untrapped syscall about 10 ns more than
natively; a `posix_spawn` about twice the native time; small compiles
about a third more; a compute-bound compile the same as natively.

### 16.2 What a trap costs

**The floor.** Two programs settle what a trap costs however well the
handler is written. A filter that traps `getppid`, with a handler that
only writes the result, costs 0.60 µs a round trip, against 45 ns for
the plain syscall. A handler that also makes the launcher's three fixed
calls, `getpid`, `gettid` and a `process_vm_readv` of the path, and
re-issues a `stat` on a fixed real path, costs 1.3 µs, against 0.41 µs
for that `stat` natively. The signal is half of the floor, and nothing
a handler does removes it.

**Above the floor** is the handler's own computation; the trapped rows
of 16.8 give it by kind of path. A warm seven-component exclave-path
`stat` costs 2.46 µs, about 1.2 µs above the floor, and makes four
syscalls besides the trapped one: `getpid`, `gettid`,
`process_vm_readv` and the re-issue. The visibility rule (8.1) is
compiled at startup into one table and asked once per candidate
component (16.6 item 3).

**Host paths** are not cached (7.4.4), since a host directory can
change at any time, so a walk through them makes one `lstat` per
component, except where one `openat2` can stand in for the directories
ahead (16.6 item 4).

**Relative paths** first make `getcwd` and the search check of 7.4.3,
then start the walk in the working directory as the kernel names it,
since that name has no symlink in it (16.6 item 5).

**A program's own filter** adds the judge call to every trap (7.4.2):
a warm exclave-path `stat`, 2.13 µs in a process with no filter of its
own, costs 2.27 µs under a 152-instruction filter the program installed,
0.14 µs more, the kernel running the program's filter and the launcher's
once more and a syscall that does not execute. A process that installs
no filter makes no judge call. An untrapped `getppid` costs 53 to 54 ns
with the program's filter and without, since the action cache still
proves it allowed; natively that filter takes it from 46 to 50 ns to 54
to 57, the seccomp entry any first filter costs.

**What a small compile traps.** `gcc -O0 hello.c` through an exclave
makes about 900 traps from a working directory nine deep, with
`TMPDIR` the checkout's `build/tmp` (16.8), counted by `EXCLAVE_LOG`.
335 of them are `readlink`, almost all
answered `EINVAL` on a directory: glibc's `realpath` reads every
component of a path as a link, so a path *n* deep costs *n* traps, and
each trap walks the path again. This is why `realpath` is the most
expensive row of 16.8.

**Queries of an action** do not trap, and cost what they cost natively;
a query returns the launcher's stub (7.5.7, 13 item 20). The stub's
test of its return address adds 32 instructions to a delivery outside a
trap, 66.6 against 34.6 in user space per signal over 100 000, within
the kernel's own variation in cycles.

**A signal during a trap** costs, beside its own delivery, the
trampoline's presented frame, its copies and comparison, and the
handler's return through the handler-call slot's refused
`rt_sigreturn`, 160 ns: a signal delivered inside a trapped
`rt_sigsuspend`, pending and unblocked by the call, costs 1.93 to 1.96
µs a round against 1.77 to 1.82 before the trampolines and 0.70
natively. Outside a trap, the trampoline's few instructions and the
second stage for its `rt_sigreturn`, 15 to 20 ns: a `tgkill` to itself
with a handler, 0.70 to 0.71 µs against 0.68 to 0.70 before and 0.67
natively. Every trap pays the record's four words, the re-issue slot's
check, the entry stub's write and the second stage of the filter for
the `rt_sigreturn` of its own return, which the action cache no longer
proves allowed (7.4.2): 50 ns, a warm four-component exclave-path
`stat` costing 2.42 to 2.46 µs against 2.37 to 2.40 before, 9.4 k cycles
after. The figures in microseconds here are the best of five runs of
100 000, in three rounds alternating native, the launcher before the
trampolines and this one, all at the machine's faster pace (16.9).

### 16.3 Untrapped syscalls and the filter

Every syscall runs the filter unless the kernel's action cache (5.11)
has proved the answer for its number constant, which it can only where
the answer depends on neither the instruction pointer nor an argument.
The filter's first stage is a binary decision tree on the
syscall number whose leaf for every number the rule does not single
out is `ALLOW` (7.4.2 gives the program's size and how many numbers
that is). The action cache proves those numbers allowed and skips the
filter for them; where the cache is absent an allowed syscall runs
11.9 instructions on average and 27 at most.

An untrapped `getppid` costs 53 to 55 ns against 43 to 45 natively,
and `read(-1)` 54 against 46; what is left is the kernel's seccomp
entry, which any filter costs. The install takes 75 to 100 µs, most of
it the kernel compiling and checking the program.
`test/filter_test.c`, in the gate's unit step, runs the program in an
interpreter against the rule written out separately, for every number
and the arguments each check reads, and asks of every number what the
action cache asks.

Why a tree: a filter that tests the instruction pointer first makes no
number constant for the action cache, so an untrapped `getppid` costs
78 ns against 43, and 1.5 µs against 84 ns on CentOS 7's 3.10, which
interprets the filter. A linear allow-list ahead of the page check
brings `getppid` to 56 ns but doubles the install, to about 200 µs,
because the kernel builds its action cache by emulating the filter once
per number.

### 16.4 Process start

A `posix_spawn` of `/usr/bin/true` from inside an exclave costs 2.1
times the native time (966 µs against 450, the medians of eleven
alternated runs of 300 spawns, November 2026) and makes 285 syscalls
against 37 (`strace -f -c`, the difference between 60 spawns and 20).
Each process it starts takes 110 page faults against 55. `perf stat`
puts about two thirds of a spawn's CPU time in the kernel: process
creation, `execve`, page faults and the syscalls of the launcher's
start. At the border the
filter install adds 75 to 100 µs (16.3).

Where the time goes, by stamps of the cycle counter at each step of a
scratch build, medians of 300 spawns: in the parent, about 70 µs from
the call to the trapped `execve`, `clone3` refused (7.5.5) and glibc's
fallback resetting each signal's disposition by hand, 64 `rt_sigaction`
calls, two of them trapped; the exec handler (7.4.5), 50 µs; the
kernel's exec of the launcher, about 120 µs; the launcher's start (7.2);
then the loader `ld.so` and the program's own start, where `ld.so`'s
three path calls and two `fstat`s trap. A syscall in a process that has
just started costs 2 to 3 µs on this machine rather than the fraction of
that a warm loop measures, so the start's syscalls are most of its time.
Of the launcher's start, the ownership set (8.1 rule 1) reads the tree's
top level is read and each of its directories opened and read, seven
placeholders in the gcc exclave read twice each, since only an empty
read proves a directory empty; the identity files' and directories'
`lstat`s (8.4), twenty syscalls at the 2 to 3 µs each costs here, one
per file and per directory, one more for the target of each of the two
files that are host symlinks on this machine, and one for each directory
on the way, in the tree, to the copy of Java's keystore, which this
machine lacks, so sixteen on this machine with the keystore; the search
for the manifest and its read 40 µs; and the loading of the program and
its loader, with the loader's name walked through the tree in a cache
that is empty in a new process, about 150 µs.

The start reads what it needs of the tree once: a volatile top-level
directory is not read at all, since the host owns it whatever it holds
(8.1 rule 3), and the others are opened by name in the tree's open
directory; the manifest is opened where the search finds it and read
whole when it fits a page; the program's original is opened once and
its header, program headers, notes and `PT_INTERP` taken from one read
of its first page, as are the loader's; and a classification makes its
wrapper check from its own `lstat` (7.4.4). The tables a start touches
are sized to it (16.6 item 9). Together these took a spawn from 1 060
µs to 956, 315 syscalls to 281 and 142 page faults to 110, measured
alternately on the launchers before and after them; a wrapper of
`true` run from outside makes 169 syscalls, where the native `true`
makes 29.

In the parent, the exec handler reads the head of every environment
variable to drop the launcher's own. It reads the heads with one
`process_vm_readv` for up to 256 variables rather than one call each,
about a hundred calls in a desktop session, and reads a variable on
its own when the batch cannot read it whole, at the end of a mapping.

A spawn traps little: glibc's `posix_spawn` makes two trapping
`rt_sigaction` installs and one trapping `rt_sigprocmask`, its child's
queries of the actions passing to the kernel (7.5.5, 7.5.7); 1 000
spawns take 2.645 to 2.654 G instructions with the trampolines and
without them alike (`perf stat`). 100 000 spawns
from one process leave its RSS flat, +160 to +176 kB against +248 to
+252 kB natively in two runs of `test/bench.py`, and the regression of 17 item 4 fails when 300 in a row grow the
address space by more than 256 kB, where it measures no growth at all.

### 16.5 Speculative Store Bypass

On a kernel whose default is `spec_store_bypass_disable=seccomp`, from
4.17 up to 5.15 unless the distribution changed it and on backports
before, a process that installs a seccomp filter without
`SECCOMP_FILTER_FLAG_SPEC_ALLOW` is forced into Speculative Store
Bypass Disable, with every descendant. An exclave is not a security
boundary (3) and its programs did not ask for the mitigation, so the
launcher passes the flag, and installs without it where the kernel
answers `EINVAL` (before 4.17; CentOS 7's 3.10 accepts it, a
backport).

`Speculation_Store_Bypass` in `/proc/self/status`, natively and in an
exclave whose filter is installed without the flag, by a static probe
on each x86-64 row of the matrix:

| Kernel | native | without the flag |
|---|---|---|
| CentOS 7, 3.10 | thread vulnerable | thread force mitigated |
| Ubuntu 18.04, 4.15 | thread vulnerable | thread force mitigated |
| Rocky 8, 4.18 | thread vulnerable | thread vulnerable |
| Ubuntu 20.04, 5.4 | thread vulnerable | thread force mitigated |
| Debian 11, 5.10 | thread vulnerable | thread force mitigated |
| Ubuntu 22.04, 5.15 | thread vulnerable | thread force mitigated |
| Debian 12, 6.1 | thread vulnerable | thread vulnerable |
| reference, 7.0 | thread vulnerable | thread vulnerable |

What forcing it costs: three small static compute loops, best of two,
on each of the five affected kernels.

| | `qsort` of 3 M ints | an LZ hash-chain matcher | a stack-machine loop |
|---|---|---|---|
| native | 0.28 to 0.30 s | 0.08 to 0.11 s | 0.06 s |
| in an exclave, without the flag | 0.29 to 0.31 s | 0.15 to 0.17 s | 0.34 to 0.35 s |
| in an exclave, with the flag | 0.28 to 0.30 s | 0.08 to 0.10 s | 0.06 s |

Without the flag the matcher runs 1.7 times slower and the interpreter
loop 5.8 times; sorting, whose loads rarely follow its stores, does not
care. A context-mixing compressor on a 1 MB trace takes about 40% more
on the reference machine with the mitigation forced by `prctl` (1.73 to
1.78 s against 1.22 to 1.38 s). With the flag, programs in an exclave
run at native speed on these kernels.

### 16.6 Optimisations

The mechanisms the launcher has for speed, by payoff, each with what it
buys and the check that holds it; 16.8 has the figures of the launcher
as a whole.

1. **`SECCOMP_FILTER_FLAG_SPEC_ALLOW` on the install** (16.5). Code
   whose loads follow its stores runs at native speed on the five
   kernels that would force the mitigation, rather than up to 5.8 times
   slower. Check: `speculation_unchanged`, on every matrix row.
2. **The filter as a decision tree on the syscall number** (16.3). The
   action cache skips the filter for every number allowed by number
   alone, and an untrapped syscall costs about 10 ns over native.
   Check: `test/filter_test.c`.
3. **The visibility rule compiled once.** Everything the rule matches
   a path against, the `own` and `host` records, identity files and
   directories, volatile directories, the exclave's own directory and the working
   directory given to the host, is an entry of one table built at
   startup. A path's owner is its longest matching prefix, looked up at
   its `/` boundaries in one pass; the walk asks once per candidate and
   builds a real path only for a component it has not yet remembered
   (8.1, 7.4.4). The same rule as linear scans, about forty comparisons
   asked five to eight times per component, would make a
   seven-component exclave-path `stat` 4.9 µs rather than 2.4. Check:
   the resolution oracle and the syscall probe (17 items 2 and 7).
4. **Host directories checked in one step** (specified in 7.4.4).
   Where the directories ahead of a walk are all plainly the host's,
   one `openat2` with `RESOLVE_NO_SYMLINKS` stands in for their
   `lstat`s, and anything it cannot vouch for is left to the walk;
   kernels before 5.6 keep the walk. Checks: `host_walk_one_step`,
   which fails where the launcher could use the check and does not,
   and `casefold_alias`.
5. **Relative paths start from the working directory as the kernel
   names it.** `getcwd` and `/proc/self/fd/N` return a path without
   symlinks, so the walk starts with that directory resolved, unless
   the name could mislead (7.4.3), rather than walking its ancestors
   again from the root, which the kernel never does. Check:
   `bind_mount_alias`, from a working directory inside a bind mount of
   the tree, which a launcher ignoring the mount condition writes
   through.
6. **Exec and startup trimmed** (16.4). The environment's heads are
   read in batches; the exec's wrapper check is the walk's remembered
   answer; the loader reads the program's notes through the descriptor
   it maps from, out of one read of its first page; an identity file is
   `lstat`ed once; a volatile top-level directory is never read; the
   manifest is opened once and read without a stat or a mapping.
   Checks: `exec_vectors` places a variable at the end of a mapping,
   and `start_reads_once` fails on a start that reads a volatile
   directory, opens an original twice, stats the manifest or `lstat`s a
   real path twice.
7. **Paths through the tree's real root start at the root.** A program
   that finds its files from its `argv[0]`, as gcc does, spells them
   through `<exclave>/tree/` when run by that path from outside. The
   launcher knows that name from `/proc/self/exe`, so such a path starts
   at the root after one `faccessat` of the exclave's directory, which
   keeps the walk's answer where a directory above the tree is not
   searchable or the exclave was moved while it runs (7.4.4); an
   `openat2` with `resolve` flags still walks. A small compile makes
   about 1 000 `lstat`s rather than 4 339. Check:
   `real_root_is_the_tree`, with that spelling and its relative and
   doubled-slash forms.

8. **`readlink` of an exclave path answered from the cache.** The walk
   has classified the path's last component (item 3), so a directory, a
   file or a wrapper answers `EINVAL` and a symlink its remembered text
   without the re-issue; a path the cache does not hold, an absent one
   above all, is asked of the kernel. glibc's `realpath` reads every
   component of a path with `readlink`, 746 of a small compile's 1 250
   traps (16.2), each now one trap and no syscall. Check: the probe's
   `readlink` groups, and `realpath` in 16.8.

9. **The tables a start touches are sized to it.** The rule table
   (item 3) uses the first slots of its array, at least twice what the
   start can place, a power of two: 128 slots and one page in the gcc
   exclave rather than 2 048 and twelve pages, each faulted in twice,
   as a lookup reads it and then an entry writes it. The
   canonicalisation cache (7.4.4) starts in a table of 256 slots, one
   page, where `true` puts a few dozen entries; the insert that would
   fill it past seven eighths copies its entries into the full table
   of 16 384 slots and publishes that, so a compile, about a thousand
   entries, pays for the copy once. A reader uses the table it loaded,
   and a table replaced is never written again. With the start's reads
   (16.4), a process `posix_spawn` starts takes 110 page faults rather
   than 140, against 55 natively. Checks: the copy in
   `test/cache_test.c`, every entry answering after it, and the
   page-fault row of 16.8.

Items 4 and 7 are shortcuts past the walk, and a shortcut drops every
question the walk asked, the ones nobody wrote down included. Each
therefore asks the kernel what it actually reached: item 4 reads back
the kernel's name for what it opened, about 0.7 µs per host chain, and
item 7 makes its `faccessat`. That costs a small compile about a
millisecond of CPU.

### 16.7 What is left alone

Each of these would cut a cost of 16.1 and is not done, for the reason
the pointer gives.

- Rewriting syscall sites: at most the 0.6 µs signal (14.1).
- A seccomp user-notification supervisor, or Syscall User Dispatch
  (14.1).
- libc interposition through the exclave's own glibc (14.1).
- A canonicalisation cache shared across processes (14.3).
- Caching host paths (14.3).
- Skipping the empty top-level directories at startup (14.3).
- Dropping `getpid` and `gettid` per trap (14.3).
- The one-step host check before 5.6, through an `O_PATH` open read
  back from `/proc/self/fd`: possible, and not built (16.6 item 4).
- Reading the placeholders when a path first reaches one rather than
  at startup. The seven of the gcc exclave cost a start 28 syscalls,
  about 60 µs of the ownership set's 97 (16.4), and `true` never asks
  about one; but the rule table is written once before anything traps
  (16.6 item 3), and a set filled in under the handler, from any
  thread or a `vfork` child, would be state written while it is read.
- Deciding which identity files and directories are the host's at
  each call rather than at startup (13 item 18): 20 syscalls of a start
  on the reference machine, at the 2 to 3 µs each costs in a new
  process. The directories on the way to one the host has are
  directories to the walk whether or not the tree ships them (8.4), so
  the walk would have to ask the host about the name at every such
  directory, or treat them as directories for an absent one too, which
  changes answers in a tree made by hand.
- The handler's `.real/` question after a trapped `fstat` (8.3), one
  `newfstatat` per `fstat` of a file, two per start of a dynamic
  program: telling a directory from a file first needs the program's
  buffer read back, which is as many syscalls.

A profile of thirty `gcc -O0 hello.c` through the gcc exclave,
November 2026, finds no hot spot in the launcher's own code: it is 7%
of the samples, the walk, the rule table, the cache and string copies,
no function above 1.5%. Against native, the user's cycles rise 14%
and the kernel's 85%, which is most of the overhead: the signal, the
fixed calls of each trap, the walk's `lstat`s and process start. Of a
compile's extra syscalls, 591 are the one-question check of the
directories above the tree (16.6 item 7), one for each path spelt
through the tree's real root, as gcc spells its own files.

If overhead matters again, the next steps are the spawn, whose kernel
side, the exec and the faults, wants a profile with kernel symbols,
which `kernel.kptr_restrict` withholds from an unprivileged user; then
glibc's `realpath`, which costs *n* traps for a path *n* deep.

### 16.8 Measured results

November 2026, on this launcher, the machine otherwise idle. The rows
are from two runs of `test/bench.py --launcher`, each the best of
three, the better of the two taken (the `sqlite3.c` row from the second,
with `--sqlite`), from its working directory nine components deep and
with `TMPDIR` the checkout's `build/tmp`; each per-call row runs native
and then the exclave in the same run, and the compile rows alternate
native and exclave runs, so that both columns of a row see the same
pace.

| Workload | native | exclave |
|---|---|---|
| `stat()`, three-component exclave path | 301 ns | 2.05 µs |
| `stat()`, seven-component exclave path | 354 ns | 2.66 µs |
| `stat()`, ten-component host path | 404 ns | 4.06 µs |
| `stat()`, relative name, working directory nine deep on the host | 277 ns | 3.18 µs |
| `realpath()` of that working directory | 1.65 µs | 23.7 µs |
| `getppid()`, untrapped | 44 ns | 52 ns |
| `posix_spawn` of `/usr/bin/true`, alternated runs | 435 to 460 µs | 1.02 to 1.06 ms |
| page faults of each process `posix_spawn` starts | 55 | 116 |
| 100 000 `posix_spawn`s from one process, RSS | +248 to +252 kB | +160 to +176 kB |
| thirty `gcc -O0 hello.c` | 1.14 s | 1.60 s |
| a 61-file project, `-O1 -c` each then link | 1.11 s | 1.53 s |
| `gcc -O2 -c sqlite3.c` | 12.87 s | 13.03 s, identical object |
| syscalls for one `gcc -O0 hello.c`, all processes (`strace -f -c`) | 2 651 | 13 388 |

Thirty small compiles cost 40% more than natively and the 61-file
project 38% more. The compute-bound compile runs within noise of
native, 1% more, and produces an identical object, also on the kernels
that would force the speculation mitigation (16.5). A `posix_spawn`
costs 2.4 times native: 1.02 to 1.06 ms against 435 to 460 µs in five
rounds alternating native, the launcher before the trampolines and
this one, the two launchers within noise of each other (1.03 to 1.06
ms before), as the table's row gives. The syscall count moves with `TMPDIR`'s depth, since the
compiler's temporary files are walked on the host, not with the working
directory's.
What is left of a small compile's overhead, by `strace` and
`EXCLAVE_LOG`: about 900 traps at the 1.3 µs floor from a working
directory nine deep, 335 of them glibc's `readlink`s of `realpath` (16.6
item 8); five process starts, each more the kernel's exec, page faults
and process creation than the launcher's code (16.4); and the launcher's
own walk (16.7).

**Real software.** An exclave of `gcc g++ make libc6-dev python3`
(120 packages); four projects, each built from its source by the
host's toolchain and by the exclave's through the exclave's own shell,
`make -j4`, then the project's own test or a run of the result, by
`test/realsoft.py`. Measured September 2026 with an earlier launcher,
before the optimisations of 16.6:

| Project | configure, host / exclave | make, host / exclave | result |
|---|---|---|---|
| zlib 1.3.1 | 0.3 s / 0.4 s | 0.9 s / 0.9 s | `make test` passes in both |
| Lua 5.4.7 | none | 1.1 s / 1.1 s | the interpreter runs in both |
| SQLite 3.46.1, autoconf and libtool | 2.2 s / 2.9 s | 51.8 s / 51.8 s | the shell answers in both |
| re2c 3.1, autotools, C++ | 3.6 s / 4.9 s | 8.1 s / 9.6 s | the built re2c runs in both |

Configure scripts, which spawn a process per test, cost about a third
more; the compile-heavy builds nothing to a fifth more. Everything a
build touched, `/tmp`, the source directory and the working directory,
resolved without a manifest record being added.

**The command.** On the gate's gcc exclave (159 MB, 709 ELF files), best
of five, November 2026, on this machine's 16 threads: `wrap` of the
unwrapped tree 0.18 s, `check` 0.11 s and `hash` 0.05 s, the listing
and the hashing on eight threads (10.5). On a tree of 105 204 files and
links, the gcc exclave with 100 000 small files added in 100
directories, `hash` takes 0.30 s, `check` 0.40 s, and `prune` to a log
naming half of the added files 1.8 s, the kernel's unlinks and stats
most of it; on that tree the kernel's opens, reads and stats are most
of the hash too.

### 16.9 Reproducing

- The reference machine's CPU, under the `powersave` governor, swings
  about threefold in pace between runs, so a figure is taken in cycles
  or instructions (`perf stat`), or from runs alternated so that both
  sides see the same pace, never from one run's wall clock against
  another's.
- `test/bench.py --exclave EXCLAVE [--sqlite PATH] [--launcher
  LAUNCHER]` prints the per-call and compile rows of 16.8, best of
  three, native against a copy of the exclave relinked with the given
  launcher (by default `build/launcher`). The exclave must contain
  gcc-13; the host's `gcc-13`, else its `gcc`, gives the native column.
  `--sqlite` names the `sqlite3.c` amalgamation `scripts/inputs`
  extracts. To compare two launchers, run it once with each.
- `test/realsoft.py --exclave EXCLAVE --src INPUTS/src`, where `INPUTS`
  is the directory `scripts/inputs` filled, builds the projects of
  16.8.
- `test/vm_run.py --script SH FILE...` runs a script beside the given
  files on every x86-64 kernel of the matrix; a static program that
  prints the `Speculation_Store_Bypass` line of `/proc/self/status`,
  run natively and through `EXCLAVE/.exclave/launcher`, gives the
  first table of 16.5.
- `EXCLAVE_LOG` (6.2) lists every trap of a workload with its path,
  which is how the traps of 16.2 are counted; `strace -f -c` counts the
  syscalls.
- `perf record` names the launcher's functions only when the exclave
  carries an unstripped launcher; with the stripped `build/launcher`,
  `perf` folds the launcher's code into `_start` or `sig_restorer`.
  Make the copy with
  `tree.fresh_exclave(SRC, DST, launcher="build/launcher.debug")`.

## 17. Testing

The launcher reimplements part of the kernel's path walk, so the tests
take their expected answers from the kernel wherever possible, not from
the person who wrote the test. The kernel gives the expected answer on
a read-only bind mount of the same tree, or through `openat2`
resolving with chroot semantics. Where the kernel cannot be the
oracle (signals, threads, nesting, the border), a named regression
states the expected answer and gives the reason. The seven items below
are the strategy. Source comments cite them as "17.4" and "17.7",
meaning items 4 and 7.

1. **Namespaces as the oracle.** Where user namespaces are available
   (on the reference machine and in most of the matrix VMs), a workload
   runs twice: once under `bwrap` with the unwrapped tree bound
   read-only at `/`, and once under the launcher. Exit status and
   output are compared. The read-only bind is the oracle for 8.2's error
   matrix. It runs on every kernel of the matrix that has user
   namespaces, because the order in which the kernel checks for errors
   differs between kernels.
2. **The kernel as the oracle for canonicalisation.** `openat2` with
   `RESOLVE_IN_ROOT` resolves a path with chroot semantics. Random trees
   full of symlink mazes, `..` and trailing slashes are resolved both
   ways, and the results are compared for the subset that stays inside
   the exclave.
3. **Grammar property tests** as stated in 6.2, plus mutated manifests
   for both parsers. The launcher's manifest parser is the one place
   where a malformed byte meets freestanding C on every exec.
4. **Named regressions.** Most are programs that compute, not just
   spawn; the rest exercise the tool. Each asserts the kernel's answer
   or the rule's. They fall into groups, one file each,
   `test/regress_*.py`:
   - *signals and threads*: `SA_ONSTACK` handlers that trap, a FIFO
     `open` interrupted by `SIGINT` or left by `siglongjmp`, the
     trapped signal syscalls answered in the kernel's order, a timer,
     a child process and a sibling thread raining signals on loops of
     trapped calls with every disposition and the restart rules, the
     alternate stack at each size with `SS_AUTODISARM` and a handler
     landing on it (13 items 30 and 51), `vfork` and `clone` children
     trapping on stacks down to 2 KB and a thread on the least stack
     its libc allows (13 item 30), `pthread_cancel` and `pthread_exit`
     unwinding through a blocking trap, a deferred `pthread_cancel`
     of a thread blocked in a trapped open, which musl and glibc judge
     by the counter in the frame, the frame a handler finds for a
     signal that lands in a blocking trapped open with and without
     `SA_RESTART`, outside any trap and in a rain on stats of a long
     path, a handler that redirects a blocked call, one that changes
     its mask in the frame, one that `siglongjmp`s out and one that
     unwinds, installs from a `vfork` child and from two threads at
     once, an install's old action as written and a query's the
     launcher's, a handler called by another through the stub a query
     returned, Go forwarding a fault in C code to the handler C installed
     (`test/progs/go_fwd.go`), an
     ignored signal across `execve` and `SA_RESETHAND`, an unwind from
     such a handler that runs the trap site's cleanup handlers and
     destructors, the regression built from the measurement of that
     layout (`test/progs/unwind_frame.c`), and a handler that blocks
     `SIGSYS` in its frame (7.5.7, 13 items 20 and 58); the rare places
     a signal can land, the entry stub before its record, its tail
     between the test and the write, the launcher's restorer, a stub
     before its handler, are reached only by the rain, Go's goroutines beside a collector, 64 threads trapping
     at once and threads trapping while
     another spawns, a descriptor-relative path looked up while its
     directory's parent is renamed, in both forms of the walk (16.6
     item 5; the walk from the root under a second mount of the
     tree's filesystem, which failed on the matrix's btrfs row until
     the failed walk was re-issued as given), the scratch pool under contention
     (`test/scratch_test.c`), and the cache's growth from its first
     table and its lock across `fork` (`test/cache_test.c`);
   - *spawning and exec*: 300 `posix_spawn`s in a row, which must leave
     the address space as it was (16),
     `fexecve`, `memfd`
     and unlinked files, scripts with and without `#!` and with `#!` lines
     the kernel's buffer cuts, a program, a loader or an interpreter
     under a data directory, `PATH` search,
     faulty argument vectors, unusual images, the identity a program
     exec'd from inside gets, and another process's `exe` link, one
     running a wrapped script whose relative interpreter the reader
     cannot resolve among them;
   - *the launcher and its filter*: a CET-marked program inside with the
     shadow-stack tunable set, reporting whether glibc enabled one (13
     item 49), a blocked or sent `SIGSYS`, older
     and newer launchers nested and side by side, a child that asks to be
     traced and execs, by `vfork` and by `fork` (7.4.5, 13 item 54), a tracer's reading of its
     tracee's `exe` and gdb's breakpoints inside, given the launcher or the
     program itself, run after run (7.6), a program installing
     its own filter, the speculation state, `x28` as a signal landing
     mid-trap finds it on aarch64 (7.5.3), and an adversarial program
     (`adversarial`), which runs the handler's deepest paths on Rust's
     alternate stack too, and a start that reads what it needs of the
     tree once (16.4), and the positional entry given a wrapper by every
     spelling the kernel would exec, relative, absolute and through
     host links (7.2);
   - *paths and the border*: working directories on either side, host
     symlinks, the read-only matrix of 8.2, the open flags the kernel
     judges before the walk, unix sockets, `PATH_MAX`,
     `openat2`'s `resolve` flags, `/proc` magic links, those to objects
     with no path among them, a link's text read as stored, and the
     `*xattrat` calls;
   - *programs that matter*: the loader, `dlopen`, locales and gconv,
     Rust and Go, built outputs run inside, a byte-for-byte comparison
     with a host compile, gdb, and a `noexec` mount;
   - *ownership, identity files and the log*: ownership read from the
     tree and failing closed, `host` and `own` records in the order
     8.1 decides them, the root and the exclave's own directory as the
     walk sees them, identity files, the no-follow calls on an
     identity link against the native run of the same program, an
     identity link retargeted and replaced by a file under a running
     shell, SSSD's directory the host's, through a host link to a directory and from a
     tree without `/var/lib`, and `own` giving it back, the trust
     directory against the native run, its links followed on the host,
     `..` out of it into the tree and `RESOLVE_BENEATH` from the root,
     and in a user namespace a hash link to an authority under
     `/usr/local`, a link to a directory, a create there, the bundle
     and Java's keystore the exclave's where the host lacks them, `own`
     on the directory and on a name in it, and a host link at its name,
     the
     log's names and escapes, and the log's path refused when relative
     or inside the exclave;
   - *the tool's unpack and wrap*: the three package readers, a tree
     made by hand, `wrap`'s refusals, `ld.so.cache` written as the
     tree's own `ldconfig` writes it, byte for byte on copies altered to
     exercise each rule, and the loader's table of directories against
     what it prints, a wrap with the other machine's launcher, which
     `exclave caches` refuses, as it refuses an exclave not wrapped or
     unwrapped again, the
     exclave's README and version;
   - *the tool's check and prune*: the static check's model of the
     loader, a tree naming two loaders, an unreadable file, and
     pruning with logs.

   The tests say what each asserts, in their docstrings and their
   failure messages. `test/run.py` runs them on the fixtures
   `test/suite.py` makes, through the runner of `test/harness.py`,
   which the unpack tests share.
5. **Kernel matrix.** Docker's default seccomp profile stands for the
   environment where user namespaces are blocked. VMs run kernels 3.10,
   4.15, 4.18, 5.4, 5.10, 5.15, 6.1, 6.6, 6.14 and 7.3, and an emulated
   aarch64 row runs 6.8, with a second emulated row for the 64 KB-page
   build of 6.8 (13 item 43); the results are in 12.1. The kernel source a
   rule follows is cited beside the handler code that follows it, so a
   breakage can be diagnosed. The path-syscall list is checked against
   the kernel's own syscall table.
6. **The "Traps and Pitfalls" checklist.** These are the classic
   failure modes of syscall interposition, each covered by a named
   test above:

   | Pitfall | Where it is tested |
   |---|---|
   | incorrect replication of OS semantics | items 1, 2 and 7 |
   | indirect resource paths | unix sockets, `/proc` magic links, identity files |
   | races | threads trapping while another spawns; the scratch pool's sweep |
   | symbolic links | item 2's mazes; the probe's link forms |
   | relative paths and the working directory | the working-directory launches; `PATH_MAX` past the working directory |
   | signals | the `SA_ONSTACK`, FIFO, `SIGINT` and `siglongjmp` cases; the frame a handler finds during a trap (`sigframe`) |
   | threads | 64 threads; Go's goroutines |
   | descriptor manipulation | `fexecve`, `memfd`, `openat2` from descriptors |
   | argument copying | unbounded and faulty vectors; bad pointers |

7. **The kernel as the oracle for every trapped path syscall.** A
   probe issues every trapped path syscall and every descriptor syscall,
   plus the `chattr` ioctls, with every path form and with the invalid
   arguments the kernel checks before the lookup, under `bwrap` and
   under the launcher. It compares the answers case by case. A
   difference is either fixed in the handler, following the kernel's
   order of checks, or listed with the rule that makes it right. It is
   never accepted silently, and the rule names the syscalls and the
   answers it covers, so that it cannot absorb a new difference: a
   syscall the kernel lacks is accepted only for the syscalls added
   after the matrix's oldest kernel, each with its release. The tree's
   files the probe names are copies of their own in the kernel's world,
   not hard links to the given exclave's, which another gate step may
   be running. The probe's maze is fixed, so that no run can lose a
   form; the resolution oracle's mazes are random, from the commit's
   seed in the gate and one of the moment under `--full` and in
   `scripts/extra`, printed with any difference. A limitation is
   measured the same way before it is fixed, by an exerciser run in
   both worlds.

**What implements each item.**

| Item | Implementation |
|---|---|
| 1 | `test/oracle_ns.py`: shell workloads under `bwrap` and under the launcher, compared, those meant to succeed first checked to show under `bwrap` what they are meant to, so that one failing alike in both worlds on a tool or a file the tree lacks is no pass; plus programs of the suite under `bwrap` against the suite's own expectations: the read-only matrix (`test/progs/ro_matrix.c`), `openat2`, `creat_slash`, `slash_links`, `open_flags`, `unix_socket`, `magic_links`, `rename_dots`, `program_perm`, `exe_link` and the exec exercisers `exec_script`, `exec_elf`, `exec_auxv` and `exec_state`, and the signal exercisers `sigcalls`, `sigrain`, `sigstack` and `clones`, `memfd_exec`, and `seccomp_filter`, a program's own filter (`test/kernel_answers.py`) |
| 2 | `test/oracle_resolve.py`: 30 000 paths over ten random mazes, resolved by `openat2(RESOLVE_IN_ROOT)` on the tree and by the launcher from inside |
| 3 | `test/manifest_test.c` and `test/grammar_test.py`: two properties on random byte strings asked of the command's `format` (a value in canonical form is canonical, and one with every byte escaped is rewritten to it), and both spellings decoded by the launcher's parser to the bytes they were made from; the command's parser and the launcher's compared on manifests, their mutations and the line an error names. `test/filter_test.c` runs the filter against the rule of 7.4.2, and a program's filter as the handler builds it from the program's, the page's and the judge slot's addresses; `tool/*_test.go` the command's grammar, readers and tree hash against their statements here |
| 4 | `test/run.py` with `test/regress_*.py` and `test/progs/`: the named tests |
| 5 | `test/syscalls.py`, `test/docker_profile.py`, `test/matrix.py` |
| 6 | the tests of item 4 |
| 7 | `test/progs/probe.c` and `test/oracle_syscalls.py`; `test/exercise.py` for new cases |

`test/syscalls.py` classifies every syscall in the kernel's table for
this machine (x86-64's `unistd_64.h`, or the generic table aarch64
uses) up to the filter's ceiling. It fails on one it does not know. It
names any syscall above the ceiling as a note, since the filter traps it
and the handler answers `ENOSYS` until it is classified (7.4.2). It
requires the trap list in `src/filter.c` to equal its own, the
syscall numbers in `src/sys.h` to be the kernel's, the trap set and the
syscall page to be those the filter's version shipped with (7.4.2), and
every path and descriptor syscall the filter traps to have a case in the
probe of item 7.

`test/docker_profile.py` assembles Docker's default profile into BPF
and installs it with `bwrap` around a workload in the exclave, the way
a CI container would. The launcher stacks its own filter on top. The
profile runs twice: as assembled for the running kernel, and as Docker
installs it before kernel 4.8, where `process_vm_readv` is refused and
the launcher copies program memory through a pipe (7.5.6). The workload
includes a bad pointer that must be `EFAULT` either way.

`test/stackcheck.py` is not one of the seven items, but the gate runs
it. It walks gcc's call graph from `on_sigsys` in both launchers' builds
and enforces the handler's stack budget of 7.5.4.

**Requirements.** The build needs gcc, and `scripts/install-go` and
`scripts/install-uv` need curl or wget. The command is built by the
pinned Go in `.go/`, its modules pinned by `go.sum`;
every driver runs on the pinned Python uv installs into the checkout,
and the code checks' ruff, ty, shellcheck, shfmt and taplo come from
`uv.lock` the same way; none is taken from the machine. The namespace oracle, the syscall probe, the
Docker profile run and the exerciser need `bwrap` (bubblewrap) and
unprivileged user namespaces; the resolution oracle needs `openat2`
(Linux 5.6). The suite uses `strace`, `gdb`, Go and `rustc`; a test
whose tool is missing skips and names it. The plain-label run of
`scripts/extra` needs AppArmor's `aa-exec` and is left out without it. Optionally,
`aarch64-linux-gnu-gcc` builds the aarch64 launcher and command, and the matrix
needs QEMU with KVM and `cloud-image-utils` (`qemu-system-arm` and the
AAVMF firmware for the emulated row). Where `bwrap` cannot create a user namespace (Ubuntu
23.10 and later from a plain terminal, most containers), an oracle or
the probe says it cannot run and exits 0, and the gate prints that step
as SKIP rather than ok.

**Running it.** From a clean checkout, these commands reach a passing
gate:

```sh
scripts/install-go
scripts/install-uv
scripts/build
scripts/inputs build/inputs
D=build/inputs
EXCLAVE_TEST_INPUTS=$D scripts/gate $D/gcc13.exclave
```

`scripts/inputs DIR` makes the test inputs: the four exclaves, Ubuntu
24.04's gcc-13 closure, which is the gate's, Alpine 3.21's gcc, Fedora
42's gcc and Ubuntu 24.04's clang-18 closure, which `scripts/extra`
takes beside it; the arm64 gcc-13 exclave; `sss.exclave`, Ubuntu
24.04's Essential set with `libnss-sss`, for `test/nss_test.py`, and
`caches.exclave`, with `python3-minimal`, GLib's tools,
`shared-mime-info` and GNOME's schemas, for `test/caches_test.py`,
and `gdb.exclave`, the gcc-13 closure with `gdb`, for the suite's gdb
tests, which the gate's gcc exclave cannot run,
each made for the machine's own architecture since its programs run
there, and on x86-64 `alpine-caches.exclave`, Alpine 3.21's
`python3`, `glib`, `shared-mime-info` and GNOME's schemas, for the
same test; and
Docker's default seccomp profile, from the distributions' package archives and
GitHub alone, which is all a continuous-integration run fetches.
`scripts/inputs DIR examples` makes what the example runs take as
well: the packages `test/realsoft.py` builds with, CentOS 7's glibc for
the sysroot of 9, the workloads' exclaves, and the source tarballs of
`test/realsoft.py`, `test/bench.py` and `test/workloads.py`, some from
their authors' own sites. Packages come through the
fetchers of `fetch/`, which verify each download against the repository
index's checksum and keep it in `DIR/packages`, their cache: nothing is
kept outside `DIR`. Every other third-party
file is pinned by its BLAKE3-256 in the script, checked by `exclave hash`. An item `DIR` already
has is skipped, and whatever is missing is fetched again. The items
run three at a time once the signing keys are fetched, each a fetch,
an unpack and a wrap of a few hundred megabytes on mostly one core; on
the reference machine, with the fetchers' caches warm, the gate's
inputs are made in 10 s, 25 s one item after another (November 2026),
when the mirrors answer at once. Every run fetches each suite's signed
index again, a 256 KB `InRelease` for each of a deb fetch's three
suites, which archive.ubuntu.com served in 2.5 to 3 s each on a slower
afternoon, when the same run took 17 to 30 s.
The repository holds no third-party input.

**The gate** (`scripts/gate [--full] [--since REV] [--jobs N] EXCLAVE`)
is the one check run before a commit, and it is fast: every step is a
test, which fails on a case with the answer expected, in seconds.
What is broader or slower, a budget or an integrated run rather than
a test, is `scripts/extra`'s and the matrix's, run when the maintainer
asks; a bug one of them finds gets a fast reproduction as a test in
the gate, and the run that found it stays where it is, since a long
integrated run fails slowly and names a stage, not a cause. The gate
runs the steps below that the change can affect, the
uncommitted paths or, in a clean tree, the last commit's, and with
`--since REV` the commits after `REV` as well, so that a series is gated
once before it is pushed.
`test/affected.py` derives them from what each step runs: its drivers
and the sources it builds, each Python driver followed through the
sibling modules it imports and the repository paths it names
(`build/exclave` is the command, so `tool/`, `unpack/` and `fetch/`;
`build/launcher` the launcher, so `src/`; `test/progs/probe.c` the
probe's program). So the command reaches every step whose driver runs
it, unpack's and the fetchers' tests among them, and its packages reach
the Go step;
a program reaches the suite, or the one oracle that compiles
it; a helper reaches whatever imports it. A launcher source,
`scripts/build`, `scripts/lib.sh`, `scripts/install-go`, `go.mod`,
`go.sum`, `LICENSE`, `.python-version`, the gate and the derivation
itself run every step, and all but the last two say the matrix is due,
as do the command's packages and the matrix's own code, since the VMs
run them; documents, scripts and settings run the code checks alone;
and a path nothing names runs everything. `--full` runs every step
whatever changed.
The steps run two at a time, or `--jobs N`, so that the machine stays
usable, each with its own log under `build/gate/`, one line each with
its time, ok, SKIP or FAIL:

- the code checks, `scripts/check`: ruff, ty, shellcheck, shfmt and
  taplo over the Python, the shell scripts and the TOML; gofmt, go fix,
  go vet, staticcheck and deadcode over the Go; over the C,
  clang-format (`.clang-format`), gcc's strict warnings as errors (the
  flags `scripts/lib.sh` gives every C build: the launcher for each
  architecture and as `build/launcher-old`, and the unit tests), gcc's
  analyser (`-fanalyzer`) on
  the same sources compiled at -O0, where it follows the paths of the
  code as written (null and uninitialised uses, memory freed twice or
  never, writes past a bound; the syscalls are opaque calls to it,
  since it cannot see what the kernel writes), and clang-tidy with its
  static analyser on the launcher for each architecture and on the unit
  tests (`.clang-tidy`); and the
  figures the documents quote that the tree itself can produce,
  compared with the documents by `test/figures.py`, which
  `scripts/figures` prints;
- the unit step: the manifest parser, the grammar comparison, the
  filter test, `test/syscalls.py`, the scratch-pool test, the cache's
  growth and its lock across `fork` (`test/cache_test.c`), the `#!` line
  test and the CPU level test, each built from the current sources for
  the host under AddressSanitizer and UndefinedBehaviorSanitizer, where
  a finding exits 99, which no test answers; the command's ELF,
  `ld.so.cache` and log readers on hostile files, and its grammar,
  through `build/exclave` (`test/readers_test.py`,
  `test/grammar_test.py`); and `test/tables_test.py`, which
  reads the tables more than one part carries, the identity files
  (8.4), the volatile directories (8.1), the identity directories
  (8.1 rule 5) and the names the launcher
  logs for the syscalls the filter traps, from each source and fails
  when they differ;
- the stack budget of both launchers (the aarch64 one when it is
  built);
- the Go step (`go test`, then `go mod verify`): the command's unit
  tests, the grammar's positions and canonical form, the ELF, cache and
  log readers on files that lie, the tree hash against its statement,
  the tree's resolution, the version orders, the dependency parsers and the header
  fields, the root walk's escapes and loops, the ld.so.cache writer on
  a shared object made in the test, the signature checks on keys made
  in the test, and the seeds of their fuzz targets, each reader on a
  package made in the test and on cut and corrupt ones, the OpenPGP
  packet reader, and the laws of each order; and the modules in the
  cache as `go.sum` records them;
- unpack's tests (`test/unpack_test.py`), which need no exclave: each
  reader's own, and hostile package files in each format, built by
  `test/packages.py` (`..` and `.real` refused; symlinks that climb
  out or are absolute, and synthesis and the volatile step through
  links to the host, kept inside the tree; hard links to what the tree
  does not hold; modes and special files; conflicts and `Replaces`;
  payloads cut short, flipped, empty or not compressed, and declared
  sizes the disk cannot hold; tar's long names and base-256 numbers,
  and data after an archive's end). A refusal must be one line with nothing left behind,
  and no case may change a directory beside the output that the
  packages aim at;
- the fetchers' tests (`test/fetch_test.py`), which need gpg and
  openssl, to make the keys and signatures, and say so without them:
  each fetcher run through a `file://`
  URL on a repository of one package made and signed there, with keys
  made there; the signed repository yields its package, and one signed
  by another key, altered after signing, with its package altered, or
  unsigned is refused in one line with nothing fetched, as is one whose
  signature holds but whose index or package does not match a digest or
  a size the chain from the signature records;
- on the exclave given: the suite, the resolution oracle, the
  namespace oracle and the syscall probe;
- when `EXCLAVE_TEST_INPUTS` names the directory `scripts/inputs`
  filled, the Docker profile run on it, and `test/nss_test.py` on its
  `sss.exclave`, Ubuntu's Essential set with `libnss-sss`: in a user
  namespace, a stand-in for SSSD answers one user on a tmpfs at
  `/var/lib`, `getent` inside finds the user by name and by uid
  through the tree's module, and `exclave check` warns of the modules
  the exclave lacks and not of the one it ships, and on the Alpine
  exclave that musl finds the users only through `nscd`; and
  `test/caches_test.py` on its `caches.exclave`, Ubuntu's
  `python3-minimal`, GLib's tools, `shared-mime-info`, GNOME's schemas
  and the generators of the other caches with something for each to
  index, and on x86-64 its `alpine-caches.exclave`, Alpine's, whose
  shell is busybox: before `exclave caches` and after it, a module
  imports from its source and then from bytecode checked by the
  source's hash, `gsettings` finds no schemas and then a key's
  default, and GIO takes an HTML file for plain text and then for
  HTML; and the suite's gdb tests (`-k gdb`) on its `gdb.exclave`,
  since the gate's gcc exclave carries no gdb; and, each where the tree holds its generator and skipped with
  the reason where it does not, GIO opens its modules and then only
  `giomodule.cache`, `gdk-pixbuf-pixdata` cannot read a BMP image and
  then reads it, each icon theme's cache is missing and then
  validates, names every icon and is no older than its directory, a
  cursor theme whose index names no directory gets none, the
  desktop database maps each MIME type to the desktop files that name
  it, and `fc-list` writes font caches under the home and then lists
  the same fonts and writes none; `exclave check` passes on the tree hash recorded, a second run
  changes no file and records the same hash, a tree changed since is
  refused, and the given exclave, whose files the copy shares by hard
  links, is left as it was; a generator that fails, on a MIME package
  that is a directory, leaves the tree, its hash and `.exclave/` as
  they were; and on a copy of the first exclave without the other
  generators, stand-ins for TeX Live's at their names, which write in
  place (10.1): what they write, through a link into a directory among
  it, is in the tree and the directories are the tree's again; a
  second run changes nothing; a run at once is refused; a run killed
  before a directory moved, after it moved and after its link was made
  is undone by the next while `check` and `wrap` refuse the exclave; a
  `keep/` with a directory both aside and in the tree, an unknown
  entry, a path that is not the generator's or a file for a directory
  is refused with nothing moved; and a generator that fails, one that
  writes into the read-only tree, one that makes a link to the copy and
  a run ended by `SIGTERM` leave the tree, its hash and `.exclave/` as
  they were;
- when `EXCLAVE_TEST_INPUTS` names that directory, the compatibility
  test (`test/compat_test.py`) against the baseline it holds in
  `baseline/`, the first release's command and an exclave it ships
  (6.7): this command checks, hashes and reads the logs of the
  exclave as the release made it, and unwraps and wraps it again with
  every earlier path unchanged and only its identity placeholders
  added; the release's command checks and hashes a copy this build
  relinked; and the two launchers nest either way. Before the first
  release, and on a machine the release is not for, there is no
  baseline and the step is SKIP.

Every driver runs `build/launcher` on a copy of its own, so the exclave
given to the gate is never run as it is nor written. The suite wraps a
copy from the given exclave's tree. The other drivers take
`tree.fresh_exclave`, a copy relinked with `build/launcher`, because an
exclave carries the launcher it was wrapped with. The three oracles
keep theirs between runs (`tree.kept_worlds`, under `build/kept/`),
with the unwrapped tree `bwrap` binds, keyed by the input's hashes file
and relinked whenever the build has changed, and make anew only what
they add; copying the tree on every run was a third of their time, and
together they take 3.5 s rather than 4.5 s. Each test has a
budget of 30 s, against a slowest test of about 5 s on the fixture, so a
test that crawls fails instead of stalling the gate: every program a
test runs is started in a session of its own, its timeout is cut to what
is left of the budget, and when that runs out its whole process group is
killed, a launcher's children with it, and the test fails by name. The exit status is the
number of failed steps.

**Beyond the gate** (`scripts/extra [--jobs N] EXCLAVE...`) runs, with
the gate's step runner (`scripts/steps.sh`) and when the maintainer
asks, what is broader than the gate or slower, or a budget or an
integration run rather than a test: on every exclave given, the suite,
the suite once more on `build/launcher-debug`, the launcher with gcc's
undefined-behaviour checks, each a trap instruction, since the launcher
links no runtime to report one, the resolution oracle, the namespace
oracle, the syscall probe and the Docker profile run; and on the first
exclave, the suite under the plain terminal's AppArmor label (`aa-exec
-p unconfined`), where user namespaces are denied (12), and two more
steps:

- the fuzz step (`test/fuzz.py`): the launcher's parsers, the manifest
  parser and the `#!` line, under mutation of the exclave's own files,
  the harness `test/fuzz.c` with `test/launcher_fuzz.c` built under the
  sanitisers of the unit step and run for ten seconds. The seeds are
  the manifest, the hashes file and a log and `#!` lines the step
  writes. Each seed is run as it is and then
  mutated, bits and bytes, runs inserted, deleted and copied, integers
  set to boundaries, cuts and splices, the input in a block of exactly
  its size, so that a read past it is the sanitiser's to report. A
  parser answers every input: a refusal is an answer, and a
  sanitiser's finding, a signal or an exit is not, and then the input
  is kept with the number that remakes it; and the command's parsers
  under Go's own fuzzer, ten seconds a target from the seeds their tests
  hold (`tool/*_test.go`, `unpack/*/fuzz_test.go`, `fetch/fuzz_test.go`),
  the grammar, the ELF reader, the ld.so.cache reader and the log reader
  among them, an input that panics kept under the package's
  `testdata/fuzz`, which the gate's Go step then runs as a case;
- the release test (`test/release_test.py`): a release of the exclave
  made by `scripts/release`, the launcher built inside it and the
  command from that by `scripts/reproduce`, signed with a key made there, and taken
  as a consumer takes it, the README's recipe step by step, with a
  tampered archive and a tampered sums file refused and `NOTICES`
  naming the modules the command links (10.5).

**The suite** (`scripts/test --exclave EXCLAVE`, or `--tree DIR` for an
unwrapped tree) makes an exclave under its work directory, compiles
`test/progs/` with the tree's own C compiler, four programs at a time
(on the reference machine the gcc fixture's exclave is made and its
programs compiled in 0.7 s), and runs the named tests.
`-k NAME` runs one test, or every test whose name contains a substring.
`--budget` sets the per-test limit. `--keep` keeps the work
directory. `--launcher` tests another build in place of
`build/launcher`, `build/launcher-debug` in `scripts/extra`. The exit status is the number of failures.
A test prints one line, PASS, FAIL or SKIP: SKIP, with its reason, for
a test that cannot run here at all, for a missing tool or a tree or
kernel that cannot answer, while one that ran part of what it states
passes with a note naming the rest. The summary line counts the skips
apart (`N tests, F failures, S skipped`), so a matrix row that lost a
tool shows it. Given an exclave, the suite first hashes its tree and refuses to run
unless the hash is the hashes file's `tree` record: the suite's copies
hard-link the input's files, so a write that escaped one would change
the input itself, and every later run would test a tree no exclave has.

The Go regression is built static with cgo off, by the host's `go`, or
on the reference machine for a matrix VM's machine. It runs as a host
program, its goroutines trapping beside one that collects garbage, so
that Go's preemption signal lands in the handler mid-trap (7.5.3); the
image from `0x10000` that Go's aarch64 linker lays out is `low_image`'s
(13 item 24). It skips where no build exists.

**The fixture.** The suite runs on the exclave pruned to what the suite
itself touches. The first run on an exclave logs every invocation it
makes inside it (`EXCLAVE_LOG`). If that run has no failure, it prunes a
copy to those logs with `exclave prune` and keeps it under
`build/fixtures/` if the copy passes the static check, so a partial log
never makes a partial fixture. There is one fixture per exclave, named
by its hashes file and stamped with a hash of the sources that decide
what the tests touch: the suite's own files, `test/tree.py`,
`test/packages.py`, `test/progs/`, the command's and the launcher's. A run with no fixture uses the full
exclave and makes one, removing that exclave's older ones and any a run
left half made when it was interrupted. The stamp also names the tests
that skipped when the fixture was made. A fixture
with another stamp is still used, since a change to the sources rarely
changes what the tests touch: when every test passes the stamp is
renewed. The whole exclave decides for a test the fixture may have
misled, which runs again there, printed `RECHECK` with the reason: one
that fails on a fixture made with other sources, and one that skips on
any fixture though it did not when the fixture was made, since a test can
skip for a file the prune left out. A recheck that passes says so in a
line of its own, since the fixture lacked what the test needs or the
test is flaky, and the summary line counts the rechecks; the fixture
then goes for the next run to remake. The suite runs faster on the
fixture than on the whole exclave.

**The probe** (`test/progs/probe.c`, `test/oracle_syscalls.py`) puts the
whole trapped-syscall surface in front of the kernel. It crosses every
trapped path syscall and descriptor-addressed one with every flag that
changes resolution, the path forms over a fixed maze and the `*at`
descriptors. The forms include the identity files, with a trailing
slash, as a directory on the way and one the host lacks, the trust
directory, a subject-hash link and its `.pem` link in it, a `..` out of
it, a name the host lacks there and a descriptor on it, the hash and
`.pem` names chosen from the host's directory and left out where it
has none, and 40 links
in one walk and 41, in the tree, across the border at every link and
through links walked as directories, since the kernel counts links
over the whole walk. One
program issues each case through `syscall(2)` under `bwrap`, with
8.1's visibility rule spelt in `bwrap`'s terms, and under the
launcher, and the answers are compared line by line. In `bwrap`'s
terms an identity directory is the host's directory bound writable at
its name, or, where the host's name is a link, the link laid in the
kernel's root as an identity file's is and the directory it reaches
bound at its own name; the directories its links lead into are bound
at their names too, which no form names (`tree.identity_dir_binds`). An answer says
which object a path reached, not only that it reached one: a
successful open answers the path its descriptor names, every file of
the maze and the host area has a size and a `user.probe` value of its
own, and the process keeps one inotify descriptor, so two paths to one
inode answer one watch descriptor. What the calls leave behind is
compared too: after each group, the host area, the probe's `/tmp`
directory and the launcher's maze, entry by entry with its type,
permissions, size, link count, link text, `user.probe` and mtime, must
be the same in both worlds, the maze as the kernel's read-only root
keeps it, so a call that answers 0 and does nothing, a symlink that
stores the translated text or a write that escaped the read-only
refusal fails even when its answer is right. Where the host is the
truth, on a host entry bound into `bwrap`'s read-only root, on a
rename or a link from the trust directory to another host path, which
the binds make a crossing of mounts (`EXDEV`) where the host's one
mount answers the permission, and for a `chown` to root, a third run, the probe on the host itself through the
tree's own loader, answers the cases that name such a path, and the
launcher must answer as it does. Each group's run must also exit 0
with nothing on stderr in every world, as must the resolution oracle's
run and the read-only matrix under `bwrap`, so a diagnostic or a crash
after the last answer fails too; a run of the oracles that passes
60 s, a few hundred times the slowest's 0.2 s, is killed with its
process group and fails by its group's name. A difference fails unless
the list `EXPECTED` names its reason: the oracle's own
construction, a stated limitation (13 items 29 and 41), or what an
older kernel lacks or decided differently, such as `truncate` checking
the mount before the permission on 6.1 and earlier (6.14 checks the
permission first). The handler answers as the newest kernel does. A
difference that is a launcher defect, found and not yet fixed, is
listed apart by its two exact answers, printed by every run, and fails
once the answers agree until its entry goes, on a host whose files can
show it (an entry says which hosts can, such as one whose
`/etc/resolv.conf` is a symlink). On the reference machine no case of
the four exclaves `scripts/extra` runs differs unexplained, and no
defect is open.
`test/oracle_syscalls.py`'s module docstring holds the argument kinds,
the path forms, `openat2`'s `EAGAIN` retry and the accepted differences.

The probe does not cover signals, threads, `vfork`, nesting, the
border, or the host's own mount
boundaries, which `bwrap` rebuilds. Those stay with the named
regressions.

**The exerciser** (`scripts/exercise --exclave EXCLAVE PROG.c ARGS`)
measures a limitation before it is fixed. A small C program prints one
line per case as `<case>: <answer>`. The driver compiles it with the
exclave's compiler and runs it under `bwrap` with the unwrapped tree
read-only at `/`, and under the launcher. It prints the two outputs side
by side and marks the lines that differ. The kernel's column is the
expectation, and the marked lines are the work. `HOSTDIR` in the
arguments becomes a fresh writable host directory. The work lives under
`build/exercise/`, and the copy there is relinked whenever the build has
changed. The program then becomes a named test asserting the kernel's
answers, and a trapped syscall's cases join the probe. For the host's
own mounts, which `bwrap` rebuilds, a test replays its host-only cases
natively from the harness, as `openat2_xdev` does.

**The kernel matrix** (`scripts/matrix --exclave EXCLAVE
[--docker-profile FILE]`) runs one gcc exclave, built on the reference
machine, in virtual machines, one at a time with 1 GB each (`--jobs N`
for more). It is due when
the gate says a change reaches the VMs: a launcher source, the command,
the pinned Python, or the matrix's own code; other changes leave the
kernels' answers as they were. Being the costliest check, it runs when
the maintainer approves it, usually once before a series of commits is
pushed, rather than before each commit. Each VM
boots its distribution's cloud image under QEMU with KVM behind a
copy-on-write overlay; cloud-init installs strace, zstd and, where the
distribution has it, bubblewrap, and on CentOS 7 zstd from Fedora's
archive of EPEL 7. The exclave, the test tree, the
checkout's launcher, command and `unpack`, built for the VM's machine
by `scripts/build` first, which takes no time when they are up to
date, and the pinned Python are copied in, and the exclave is relinked there
by the command, which runs as it is on every kernel of
the matrix, CentOS 7's 3.10 included. For the rows of the reference
machine's architecture the exclave goes in as a release of it,
made on the reference machine by `scripts/release` with a key made
there, and the row takes the release as a consumer does before
anything else runs (12.1); the exclave the release unpacks is the
row's, so the payload carries it once. The
Python is built for the VM's machine and libc and
installed by the repository's uv: the glibc builds need only glibc 2.17,
so CentOS 7 runs the same Python as Fedora 42, and Alpine takes the musl
build. A VM's own `python3`, if it has one, is never used.
Each row runs the suite on the full exclave with a budget scaled to the
VM. Where `bwrap` works it then runs the two oracles, the probe and,
given the profile, the Docker profile run, first lifting the AppArmor
sysctl that denies unprivileged user namespaces on Ubuntu 24.04's
image. Three checks run outside the suite: the release's recipe, the
README's commands for taking a release run in the VM with the host's
own `ssh-keygen`, `sha256sum`, `tar` and `zstd`; a program built by the
exclave's gcc on a `noexec` tmpfs the VM mounts as root, run by the
VM's shell, the positional entry and the exclave's shell; and the
output of `test/sysroot.py` run natively. The results go to
`build/matrix-results.md` and are tabulated in 12.1.

**The emulated arm64 rows** (`scripts/matrix --exclave EXCLAVE
--exclave ARM64_EXCLAVE --only noble-arm64 [--docker-profile FILE]`;
`--only noble-arm64-64k` for the 64 KB-page row, whose VM installs
`linux-image-generic-64k` and reboots into it before the suite) boot Ubuntu
24.04's arm64 cloud image under `qemu-system-aarch64 -M virt -cpu max`
with TCG and the AAVMF firmware, since user-mode emulation has no
seccomp and the reference machine has no KVM for another architecture.
The matrix takes one gcc exclave per machine its rows need, each told
by the launcher it carries; the arm64 one is `scripts/inputs`'s
`gcc13-arm64.exclave`, made here from the arm64 packages with the
aarch64 launcher `scripts/build` builds when `aarch64-linux-gnu-gcc`
is installed (10.1), and the VM only relinks and runs it with the
aarch64 launchers and command. A fresh VM has no fixture, so the suite runs on the full
exclave with logging, which makes the row long (12.1); it runs when
asked, not in the gate, and making it shorter is in 18.

**On GitHub's hosted runners** (`.github/workflows/ci.yml`), the gate
and the matrix run when a maintainer dispatches the workflow, from the
Actions tab or as `gh workflow run ci.yml -f matrix=true` (`false`
for the gate alone) on the pushed `main`, never at a push; `gh run
list --workflow ci.yml` names the run, `gh run watch ID
--exit-status` waits for it and `gh run view ID --log-failed` shows
what failed. It calls `scripts/install-uv`, with `.uv/` restored
from the last run with the same pins so that uv, its Python and its
packages are downloaded once, `scripts/inputs` for the gate's inputs
alone, from the package archives and GitHub (cached between runs,
keyed on the inputs script and the fetchers), `scripts/gate --full`
and `scripts/matrix`, adding only what a runner lacks and the
reference machine has: packages, the KVM device opened to the runner,
and the AppArmor sysctl. Every download, uv's and Go's, a package
file's, a source's or an image's, tries a failed or stalled connection
again over about a minute (`fetch/net.go`; curl's own retries in the
scripts), since a runner has been refused
by GitHub for two minutes at a time; a server's own answer, a 404, is
final. The gate runs on an x86-64 runner on the gcc exclave
and, natively, on an aarch64 runner on the arm64 gcc exclave
made there, whose kernel is Ubuntu 24.04's 6.8, the one the emulated
`noble-arm64` row boots: so that row has no job there, and the
aarch64 build gets the unit tests and the stack budget,
which the emulated row never ran (its code checks go without
shellcheck and taplo, which have no aarch64 wheel; the shell and the
TOML are text, checked on x86-64). The x86-64 rows run under KVM, two
VMs at a time. The 64 KB-page row has no job: no hosted runner boots
such a kernel or offers KVM on aarch64, and it would be emulated there
too, so it runs from the reference machine when asked, like the other emulated
row. The results are the jobs' logs and the matrix job's results
table, kept as the run's artifacts; the figures the documents quote stay
those measured on the reference machine.

`test/vm_run.py --script SH FILE...` boots the same x86-64 rows and
runs a script beside the files it is given, for exclaves made to ship,
where the suite does not apply. The two VM drivers are the one
exception to the rule that only `scripts/inputs` downloads: they fetch
each cloud image once into `build/images`, and the VMs
install their packages through cloud-init.

**The example runs** (`scripts/examples EXCLAVE`) need inputs and time
the gate cannot afford. Each runs when its input variable is set:

- `EXCLAVE_TEST_SRC`: `test/realsoft.py` builds zlib, Lua, SQLite and
  re2c inside the exclave and on the host, and compares the results and
  the times.
- `EXCLAVE_TEST_SQLITE`: `test/bench.py` produces the performance table
  of 16.
- `EXCLAVE_TEST_RPMS`: `test/sysroot.py` builds against a CentOS 7
  glibc held as a data directory (9), with every compiler the exclave
  has, gcc and clang.
- python3 in the exclave: `test/bytecode.py` makes Python's bytecode
  with `exclave caches` (10.1) and times the imports before and after.
- `EXCLAVE_TEST_INPUTS`: `test/workloads.py` runs real workloads
  in exclaves of their own, each in the same work directory under
  `bwrap` with the tree read-only at `/` and under the launcher,
  and compares the outputs byte for byte, the hashes of what the builds
  make included: valgrind's memcheck over a faulty program, `pdftotext`,
  `pdffonts` and `pdftoppm` of a PDF with embedded fonts and a
  substituted one, a cargo build, zlib built by CMake and ninja with four
  jobs, a Java program run as source and compiled by `javac` and the
  trusted entries of its keystore counted, a
  Python process with threads, subprocesses and sqlite, an article
  with a citation through `pdflatex` and `bibtex` in TeX Live's
  exclave once `exclave caches` made its formats, and a Hutter
  Prize entry's unmodified `build.sh` (cmix-neif 1.0: clang-18 and
  lld-18 under `env -i`, `make -j` unbounded, a profile-guided second
  build) in an exclave of the packages its `install.sh` names at the
  Ubuntu snapshot it pins, the judging image a contest rebuilds it in.
  All agree; all but the entry take under two seconds in either world,
  and the entry builds in about two minutes, to the byte its author published
  (its `comp9`'s SHA-256 is the one in the entry's `SHA256SUMS`).
- `EXCLAVE_TEST_ARM64`: the emulated aarch64 row on the arm64 gcc
  exclave named, with `EXCLAVE_TEST_DOCKER` adding the Docker profile
  run.

They exist because real builds and other hosts expose behaviour no
synthetic test anticipates (12.1). `scripts/example DIR` at the repository's
root is the README's first run as a script, from a clean checkout to a
program that runs on any glibc since 2.17.

**The rules that hold the suite together.** 19 indexes these; they are
stated here.

- *A test asserts what the tree says, never what one distribution
  says.* `test/tree.py` and the suite's `tree_facts` answer for the
  tests: the compiler, the shell, where a tool lives, the multiarch
  directory, the libc, the machine, the loader the originals name and
  the syscall numbers a trace shows; the C, Rust and Go programs read
  them from the environment. So one suite passes on Debian, Alpine and
  Fedora exclaves. An exclave kind that cannot answer a test skips it
  with the reason, as musl does for 10.3's hand-made glibc layouts.
- *Tests are independent and pass in any order.* Setup makes the
  exclave, the compiled programs and the environment; every test makes
  what it needs beyond those. After every test the harness compares the
  shared exclave's manifest, hashes file and launcher (its inode, size
  and mtime), the environment, and every tree entry's path, size, mode
  and mtime, directories' included, with what setup made, and fails a
  test that changed them: a file made and removed again moves its
  directory's mtime, and the tree's files are hard links to the fixture
  or the given exclave, so a write that escaped the read-only refusal
  would outlast the run. A test that puts files in a tree does so in a
  copy of its own (`copy_exclave`); one that relinks an exclave or
  rewrites its manifest copies a small exclave setup makes too, the
  shared one pruned to what a shell, `cat`, `grep` and a test program
  touch. `-k NAME` passes like the whole
  run. Suites run side by side in the gate, so a name
  in a shared namespace (an abstract socket, a file in `/tmp`) carries
  the pid.
- *Nothing downloads during a test.* A test, an oracle and the gate
  take their inputs as paths; the VM drivers are the exception above.
- *The checkout's path has no limit of its own.* The gate passes from a
  checkout 250 characters deep. Sockets the tests bind are named
  relatively or under a short directory in `/tmp`, and `adversarial`
  keeps its interpreter chains there, since a `#!` line holds 255
  bytes.

## 18. Roadmap

The format, the launcher and the tool are complete for what section 3
asks of them. What comes next is use, releases and a few open
questions.

1. **Exclaves of real packaged software.** Beyond the compilers, the
   example runs make exclaves of valgrind, poppler, Rust, CMake, a Java
   JDK, Python, TeX Live and a contest's judging image, which rebuilds
   an entry to the byte, and run them against the kernel (17); the JDK
   closed three gaps, its alternatives (`java-jinfo`), its keystore
   (`java-cacerts`) and the static check's refusal of a soname only a
   prior `dlopen` by path provides (10.3), and TeX Live one, its
   indexes and formats, which `exclave caches` makes in place (10.1).
   Further real software decides which of the tool's synthesis gaps
   close next (10.1): `unpack` does not generate
   locales or the caches `exclave caches` does not
   make (10.1 lists those it makes), and a gap closes when a real exclave needs it, as a rule in the synthesis
   table rather than an option. `unpack`'s notes name the caches a tree
   lacks from the packages' trigger interests, and failed opens in an
   `EXCLAVE_LOG` show where an exclave misses one (10.1).
2. **Releases.** There is no public release yet. A release has its
   shape, `scripts/release` (10.5), its binaries built reproducibly
   inside a gcc exclave, and every build is named by the project's
   version and its commit (7, 10). The first release is x86-64; an
   aarch64 release comes later, made on an aarch64 machine, as its
   exclaves are (10.1). The commit gate (17)
   and the kernel matrix (12.1) run on the reference machine, and on
   GitHub's hosted runners when a maintainer dispatches the workflow;
   nothing runs at a push. Before it nothing promises compatibility
   between commits (2); from it on, the versions of 6.7 do, and the
   first release is the baseline every later commit is held to: its
   URL and hashes go into `scripts/inputs`, which fetches it, and the
   gate's compatibility step runs against it (17).
3. **aarch64 kernels with 16 KB or 64 KB pages.** The loader rounds to
   the kernel's page size and the launcher's own segments are 64 KB
   aligned (13 item 43). The matrix's `noble-arm64-64k` row, on
   Ubuntu's `linux-image-generic-64k`, passes the suite and every
   oracle, and rebuilds the launcher and the command to the same
   bytes (12.1); no 16 KB kernel has run it (13 item 43).
4. **The emulated arm64 rows' speed.** The arm64 rows run under QEMU's
   TCG emulation at about a tenth of native speed (12.1), so they run
   when asked rather than at every commit; the exclave they run is made
   on the reference machine (10.1). On GitHub's aarch64 runner the gate
   runs natively on the 4 KB-page kernel that row boots (17); the
   64 KB-page row would be emulated there too, since no hosted runner
   boots such a kernel, so it has no job, and a lighter fixture is
   what would shorten it.
5. **Hosts the matrix has not covered.** Snap-confined terminals,
   gVisor-based CI, WSL1 and SELinux `execmem` policies are listed as
   untested in the portability envelope (12); each is a matrix row to
   add, or a limitation to state.
6. **The command's hashing.** The tree is listed once and hashed with
   BLAKE3, the largest file first and each large file on many cores
   (10.5), so what is left of the tree hash on a tree of many small
   files is the kernel's opens, reads and stats (16.8).
   `lukechampine.com/blake3` has assembly for x86-64 alone, so an
   aarch64 machine hashes in Go, on as many cores, and slower per
   core; how much slower is unmeasured.

## 19. Design decisions

These decisions are settled: each was weighed against alternatives,
most of them tried or measured (14), and its reason still holds.
Reopening one wants a measurement or a case the reason does not cover.
Each line gives the decision, the reason in brief and where it is
specified.

### 19.1 Format

- **An exclave is a directory at every stage**: `cp`, `ln` and an
  editor between `unpack` and `wrap` need not be features of the tool
  (6, 10).
- **The launcher reads the manifest and the tree, nothing generated**:
  an index beside the tree goes silently wrong when the tree is edited
  (6.3).
- **Ownership is the tree's non-empty top-level entries**: the tree is
  the rule's only source, with nothing to refresh (8.1).
- **The exclave's own directory and the path to it are the host's**: a
  program locating itself by its real path must find its files
  (8.1 rule 6).
- **Each program's loader is its own `PT_INTERP`, the exclave's own
  file**: nothing names the loader twice (7.3, 10.3).
- **One libc per exclave; a second enters only as a data directory**:
  `dlopen` with computed names would make a mixed tree unverifiable
  (9, 13 item 8).
- **Shortcuts are symlinks; there are no `entry` or `env` records**: a
  symlink or a wrapper script does both jobs (6.1).
- **A strict manifest grammar with one canonical spelling**, the output
  of `exclave format`: both parsers refuse anything else (6.2).
- **What one build reads that another wrote is versioned, each part by
  its own number; a reader refuses a version it does not know, a later
  build reads every earlier one of the same version, and anything an
  earlier reader would refuse or misread moves the version**: an
  exclave outlives the build that made it (6.7).
- **Hashes are BLAKE3-256, and the hashes file records and never
  locates**: BLAKE3 hashes one file on many cores, and `b3sum` checks
  a hash without the tool; locating belongs to the step before the tool
  (6.4).
- **No layers, no single-file form, no several roots per CPU level**:
  composition is a copy at build time, `tar` makes one file, and an
  exclave per CPU level is two exclaves (11, 6.6).
- **Every exclave carries a `README`**, for whoever finds it; nothing
  reads it (6.1).
- **MIT licence, its text in the launcher's `.exclave.license`
  section**: every exclave holds a copy of the launcher, and the licence
  goes with every copy (7).

### 19.2 Launcher

- **One mechanism, a seccomp filter and a `SIGSYS` handler in the
  process**: no namespaces, no ptrace supervisor, no second backend
  (4.3, 14).
- **Freestanding, `ET_DYN`, one source for every architecture**: the
  handler runs inside programs whose libc is not its own (7.1).
- **A wrapper for every executable file, and the loader path for
  programs without one**: process identity is the kernel's, and
  originals stay byte-identical (7.4.5, 7.6).
- **A program inside sees upstream's tree: no listing of the tree shows
  `.real/`**, at the cost of a trap per listing call, which measures as
  nothing beside a listing's `stat`s (8.3).
- **One world inside an exclave**: a host world for programs on host
  paths would break `make check` whenever the two libcs differ (7.4.5).
- **Read-only by refusal, in the kernel's order of checks, not by
  `chmod`**: careless copies lose modes; refusal depends on nothing
  (8.2).
- **Symlinks resolve in virtual space; identity files' host links, and
  the links in identity directories, are followed by the kernel on the
  host, at each call**: a host link into `/usr` must never reach the
  host's `/usr` through the exclave's, and the names that describe the
  host, the trust directory's certificates among them, reach what the
  host's links say (8.4).
- **An identity directory is the host's directory at its name, its
  links followed on the host at each call, as an identity file's chain
  is, with `..` at its root climbing in the exclave; the identity files
  the host lacks in it are the exclave's**: the trust set is the host's
  through the bundle and the directory alike, and a union of the host's
  entries and the tree's would answer no one's directory (8.1 rule 5,
  8.4).
- **The environment passes through, minus the loader and libc
  variables that name host files and `TZ`, with three constants set at
  the border**: locale data is bound to its libc, a zone name needs
  data the exclave may lack while the host's `/etc/localtime` is data
  any libc reads, and an allowlist would stop a user passing `CC` (6.2,
  8.4).
- **One run-time knob, `EXCLAVE_LOG`, an absolute host path outside the
  exclave**; `EXCLAVE_EXEC`,
  `EXCLAVE_EXECFN` and `EXCLAVE_COMM` are the launcher's own protocol,
  honoured by a wrapper only under an inherited filter (6.2, 7.4.5).
- **What the launcher derives from the tree fails closed and loud**: a
  tree it cannot read correctly is refused by name (6.3).
- **A fixed syscall page at `0x7fe00000` identifies the launcher's own
  syscalls**: the same in every process, above every linker's program
  images; a bare syscall instruction appears in the launcher's text only
  in the bootstrap and the version probe, and the restorer lies in the
  page (7.4.2).
- **The filter's trap set is versioned; an equal or newer inherited
  filter is reused, an older one stacked under**: no syscall a launcher
  needs translated goes untrapped, and a trap it does not know is
  `ENOSYS`, never re-issued (7.4.2).
- **The filter answers by number first and is installed with
  `SECCOMP_FILTER_FLAG_SPEC_ALLOW`**: the kernel's action cache allows
  most syscalls without running it, and an exclave is not a security
  boundary (7.4.2).
- **`clone3` is refused with `ENOSYS`**: honouring it means copying the
  signal frame and its FPU save area for the child, a dependence on the
  kernel's frame layout on both architectures, to save some sixty traps per
  spawn (7.5.5). A flag only `clone3` offers, which a library came to
  need and so dropped its fallback to `clone`, would reopen it.
- **A program's own seccomp filter is honoured by the kernel, through a
  judge slot in the syscall page, for the actions `ALLOW`, `LOG`,
  `ERRNO` and `KILL`, and refused with `ENOSYS` otherwise**: the handler
  installs the program's filter with a prologue and an epilogue that
  exempt the page but for that slot, and re-issues each trapped call
  from the slot, which the launcher's filter answers with a mark that
  any refusal of the program's outranks, so the kernel applies the
  program's filters per thread, across `fork`, `exec` and `TSYNC`, as
  natively, and no handler interprets them. A sandbox is never silently
  weaker than natively for the program's own calls, and what cannot be
  honoured fails visibly at install; it does not contain code that
  jumps through the page (7.4.2, 13 item 5).
- **A program's handlers are installed behind the launcher's
  trampolines, and only installs trap**: a handler whose signal lands
  during a trapped call finds the trap site's frame, and what it decides
  there, a redirect, a mask, is what the program does; a query passes to
  the kernel and returns the stub, which called directly runs the
  program's handler, so that a query costs nothing and a spawn's child,
  which queries every signal, traps no more than before (13 item 20). It is the handler doing one more of
  the kernel's jobs, building the frame a handler sees, not a second
  mechanism. The handler is called from the syscall page with its
  return address at the restorer's own instructions and a frame of the
  kernel's layout above it, so that unwinders and gdb walk from it into
  the program's frames, and the filter answers that one `rt_sigreturn`
  with an error so that the return comes back to the trampoline, which
  ends the launcher's call as the kernel and the handler decided and
  returns through the kernel's frame as the shadow stack expects. The
  floating-point state is the program's, by pointer on x86-64 and by
  the records' own lengths on aarch64, so nothing ties the launcher to
  a save area's layout (7.5.7, 14.3, 13 item 58).
- **Handler memory comes from scratch chunks reclaimed by liveness,
  with no lock and a stack budget**: the handler runs on whatever
  alternate stack a program set up (7.5.4).
- **A path the re-issue could not name is refused, never cut; a
  `rename` or `link` across the border is `EXDEV` first** (8.2).
- **gdb is served by exported facts and a carried script**, not the JIT
  interface, which cannot relocate a position-independent program's
  debug information (7.6).
- **Overhead is reduced inside the mechanism, not by adding one**:
  syscall-site rewriting, a supervisor, libc interposition and shared
  caches were considered and left alone (16).

### 19.3 Tool

- **The commands that make, check and ship an exclave never fetch**:
  `wrap`, `check`, `prune`, `hash`, `format`, `relink` and `unwrap`
  read the directory they are given and open no network connection, so
  what they say of an exclave rests on its files alone, and `unpack`
  reads only the package files it is given. Getting those files is the
  step before them, with a trust argument of its own, the archive's keys
  and sums; `exclave-fetch` is that step, a program of its own beside
  the command, so that the command holds no network code at all, and a
  defined part of a release, its arguments and checks kept as 6.7 keeps
  the formats (10, 10.1).
- **The tool's input is a directory holding `tree/`, and `unpack` is
  the step before it**: what made the tree, package files, `tar` or a
  build, is not the tool's concern, so `unpack` is a subcommand apart
  from `wrap`, sharing with it only the layout and the hashes file (10,
  10.1).
- **The command is Go, one static file per architecture carrying its
  launcher, with `unpack` as its subcommand, and `exclave-fetch` a
  second such file**: each runs with nothing beside it, and they are the
  programs that read what comes from outside, package files, indexes
  and the trees they make, so their parsers are a memory-safe
  language's, and the delicate ones, tar, gzip, bzip2, XML, HTTP, TLS
  and RSA, are Go's own standard library's, with xz, zstd and OpenPGP
  from the pure-Go modules `go.mod` pins and no C compiled in; a static
  file is what portability asks of every step from the repository to a
  wrapped exclave; `wrap` takes the other architecture's launcher,
  since the checks read the tree as the launcher's machine (10, 10.1,
  10.5).
- **Building software is the build system's job**: an exclave of built
  software is a staging directory plus runtime packages, with no
  recipes (10.2).
- **Maintainer scripts are never run; their effects are synthesised
  from one table every reader shares**: a tree whose scripts must run
  comes from outside and is wrapped (10.1).
- **Package readers share one interface and are chosen by the file**
  (10.1).
- **One pinned Python, never the machine's**, for the tests: uv, pinned
  with a checksum per architecture in `scripts/install-uv`, installs the
  version `.python-version` names into the checkout, and every script
  and the matrix VMs run that one (10, 17).
- **One pinned Go, never the machine's**, for the command:
  `scripts/install-go` installs the toolchain `go.mod` names
  into the checkout, checked the same way, with the modules `go.sum`
  pins, the one time anything fetches them; every build is static, its
  paths trimmed and its version-control stamp off, so the same sources
  give the same bytes in a checkout or a copy (10, 17).
- **The Python is ruff- and ty-clean**: `scripts/check` runs ruff, ty,
  shellcheck, shfmt and taplo from `uv.lock`, and an ignored rule or a
  suppression carries its reason (17).
- **The Go is gofmt-, go vet-, staticcheck- and deadcode-clean**, with
  `go fix`'s modernisations applied and no line over 120 columns, as
  `scripts/check` checks through the pinned toolchain, the two tools
  the versions `go.mod`'s tool directives pin; `go test` is a gate step
  with `go mod verify`, and every parser of its own has a fuzz target
  `scripts/extra` runs (17).
- **The C is clang-formatted and clean under gcc's strict warnings and
  clang-tidy**, the launcher for both architectures;
  clang-format and clang-tidy come from `uv.lock`, gcc is the one that
  builds them, and the build itself does not stop on a warning, since a
  newer gcc may find something new. A check `.clang-tidy` turns off
  carries its reason (17).
- **`wrap` checks before it touches the tree**: a refused exclave is
  left unwrapped (10.1, 10.3).
- **Nothing of the tree runs during `unpack` or `wrap`**: the cache is
  written as the tree's `ldconfig` would write it and the loader's
  directories are read from the loader file, so an exclave of either
  architecture is made on either, and a package's programs run only
  inside an exclave (10.1, 10.3, 13 item 32).
- **The caches only a tree's own programs can make are made by
  `exclave caches`, after `wrap`, inside the exclave**: Python's
  bytecode, GSettings schemas, the MIME database, the GIO,
  gdk-pixbuf, icon, desktop and font caches and graphviz's plugin
  configuration have no writer but their generators, and running them under the exclave's launcher keeps
  a package's programs inside an exclave, while a command of its own
  keeps `unpack` and `wrap` the same on every machine (10.1, 13 item
  48).
- **The tool applies `host` records as the launcher does**, by longest
  prefix (10.3).
- **A foreign ELF object is a warning, and a tree stays readable by its
  owner**: a tree no one can read can be neither hashed nor copied
  (10.1, 10.3).
- **The dynamic check and pruning read `EXCLAVE_LOG` files**: what a
  traced run touched is the evidence (10.3, 10.4).
- **`prune` keeps the packages' licence texts**: a pruned exclave passed
  on carries the packages' terms (10.4, 13 item 47).
- **Few options, as a preference for the least complexity rather than
  a law**: the commands that make an exclave take paths, and `format
  --check` is their one flag today; the fetchers take the arguments a
  download needs. A flag, a mode or a manifest key is weighed against
  the rule that would make it unnecessary and against a stated
  limitation, and added where it is the simpler answer (10).

### 19.4 Tests

- **The kernel is the oracle**: the handler answers what the newest
  kernel answers on a read-only bind mount, and a difference is
  accepted only under a named reason (17 items 1, 2 and 7).
- **A test asserts what the tree says, not what one distribution
  says**: the suite runs on every exclave kind, and a kind that cannot
  answer skips with its reason (17 item 4).
- **The suite runs on its fixture, the exclave pruned to what it
  touches** (17).
- **The commit gate is one script, and `scripts/build` only builds**; a step
  that could not run is reported as SKIP (17).
- **Every driver runs the build's launcher on a relinked copy of its
  own**: an exclave carries the launcher it was wrapped with (17).
- **Tests take their inputs as paths**: only `scripts/inputs` fetches,
  each third-party input pinned by its hash, and the VM drivers, which
  download cloud images; the repository holds no third-party file (17).
- **Tests are independent**: any order, any single test, several suites
  at once (17).
- **The emulated arm64 rows run when asked**, not at every commit (18);
  the hosted workflow is dispatched by hand, never by a push (17).

### 19.5 Scope

- **Not a security sandbox**: the translation is bypassable by a
  program that wants to bypass it (3).
- **Namespaces are not part of the design**; they are the test oracle
  where available (4.3).
- **Little-endian 64-bit Linux only**, x86-64 and aarch64; no
  cross-architecture emulation and no 32-bit programs (3, 12).
- **No host drivers**: GPU and other host-driver software are out of
  scope (13).
- **`noexec` media are not supported**: the kernel allows neither
  `execve` nor an executable mapping of a file there (12).

