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

## 1. Summary

exclave turns Linux software that depends on its environment,
compilers included, into a directory that behaves like a single static
executable. The directory can be copied anywhere and any program in it
run by path. The software inside never touches a host library, header
or loader, and reads no host configuration but eight identity files:
who the users are, how names resolve, which certificate authorities
are trusted (8.4). There is no daemon, no image store, no package
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
rest), and the identity files such as `/etc/passwd` and
`/etc/resolv.conf` (8.1). Paths the exclave owns are read-only: the
handler refuses every write to them with the error the kernel gives on
a read-only bind mount (8.2). The manifest can move a path to either
side; anything the tree can say about itself the launcher reads from
the tree, so the manifest holds little else (6.2, 6.3).

The **`exclave` command** (10) is one static executable per
architecture that carries its launcher (10.5), takes a directory and
never fetches anything. Its input is an unwrapped exclave, a plain
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
below, but it has not been released: there is no release, no version
number and no continuous integration, and nothing yet promises
compatibility between one commit and the next.

What is built and tested:

- **The launcher** for x86-64 and aarch64, from one freestanding C
  source (7).
- **The `exclave` command**, reading Debian and Ubuntu `.deb`, Alpine
  `.apk` and `.rpm` packages through one reader interface (10.1); the
  fetchers in `fetch/` are examples of the step before it.
- **Four exclave kinds**, made from distribution packages: a gcc
  exclave from Ubuntu 24.04, which builds zlib, Lua, SQLite and re2c
  from source with their own configure scripts; an Alpine exclave on
  musl; a Fedora exclave; and a clang exclave that compiles C and C++
  (9, 17).
- **A glibc sysroot as a data directory**: CentOS 7's glibc inside the
  gcc exclave, never executed, links outputs against glibc 2.17, which
  run natively on any later glibc (9).
- **aarch64**: the launcher runs there, tested in an emulated row of the
  kernel matrix on a kernel with 4 KB pages (12.1, 13 item 43).
- **gdb** debugs a program in an exclave through a script the launcher
  carries, once the exclave is in gdb's auto-load safe-path (7.6, 13.1).
- **The command as one file**: `build/exclave`, 973 KB, statically
  linked, carrying its launcher, wraps, checks and prunes an exclave
  with nothing beside it (10.5).
- **Trace pruning**: in `scripts/example`, a hello-world compile against the
  CentOS 7 sysroot keeps 226 of the gcc exclave's 9 564 files and
  symlinks, counted as `exclave prune` reports them, the
  originals in `.real/` included; the pruned copy compiles the program
  again. 10.4 gives the figure for the test suite's gcc exclave.

`scripts/example` walks from a clean checkout to a program built inside an
exclave that runs on any glibc since 2.17, showing every command.

How it is tested (17):

- **The regression suite**: 79 named tests, most of them programs that
  compute, run on the gcc, Alpine, Fedora and clang exclaves
  (17 item 4).
- **Kernel oracles**, where user namespaces are available: the same
  workloads under `bwrap` with the tree bound read-only, and path
  resolution against `openat2` with `RESOLVE_IN_ROOT` (17 items 1
  and 2).
- **The syscall probe**: every trapped path and descriptor syscall,
  with every flag and path form, run under `bwrap` and under the
  launcher; 21 732 cases per exclave, each difference from the kernel
  either fixed or accepted under a named reason (17 item 7).
- **Docker's default seccomp profile**: a workload in each exclave runs
  under it, standing for a CI container where user namespaces are
  blocked (17 item 5).
- **The commit gate**, `scripts/gate`, which runs the unit tests, the
  suite, the oracles and the probe on the four exclaves in under a
  minute; an oracle that cannot run on the machine, for want of `bwrap`
  or user namespaces, is reported as SKIP, not as passing (17).
- **The kernel matrix**: the gcc exclave passes the suite in QEMU
  virtual machines of nine distributions, from CentOS 7 at kernel 3.10
  to Fedora 42 at 6.14, Alpine 3.20's musl userland and Fedora's
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
   and so is host configuration, except the eight identity files that
   describe the host (8.1 rule 5).
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
   `EXCLAVE_LOG`, which only logs; the tool's commands take paths, and
   `format --check` is its one flag.
8. **Verifiability.** Isolation and libc homogeneity are checkable by
   the tool, statically and by trace.

Non-goals:

- **Security sandboxing.** The translation can be bypassed by a program
  that wants to; untrusted code needs a real sandbox.
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
| **version probe** | The `uname` with a magic argument that a launcher issues at startup: an inherited filter answers with its version, and `EFAULT` means none (7.2, 7.4.2). |
| **positional entry** | `name.exclave/.exclave/launcher PROGRAM ARGS...`, which runs a program that has no wrapper, a host tool or a built output, inside the exclave (7.2). |
| **loader path** | How a program without a wrapper runs inside an exclave: the handler, or the positional entry, re-execs the launcher with the target in `EXCLAVE_EXEC`, and that launcher loads it with the exclave's loader (7.4.5, 7.6). |
| **one-step host check** | One `openat2` with `RESOLVE_NO_SYMLINKS` standing in for the `lstat` of each of three or more plainly host-owned directories in a path walk, where the tree's mount allows it (7.4.4). |
| **exclave path** | A path the tree answers for, read-only (8.1, 8.2). |
| **host path** | A path the host answers for, as it would without the exclave (8.1). `host` and `own` records in the manifest move a path to either side. |
| **placeholder** | An empty top-level directory of the tree, which the exclave does not own; the tool ships placeholders for `/home`, `/tmp`, `/proc` and the other conventional host names (8.1). |
| **identity file** | One of eight files, such as `/etc/passwd` and `/etc/resolv.conf`, that describe the host and are the host's by default (8.1 rule 5, 8.4). |
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
- `.real/` is a hidden sibling by convention only: `find`, `du`, `tar`
  and directory scanners see it. Hard links cost nothing; a copy that
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
  - how `b2sum -l 256` checks the hashes file's hashes without the
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
32 `data` records, which are the sizes of the launcher's tables (8.1).
A path has one spelling because the visibility rule matches a path by
it and would silently match nothing else (13 item 34). Any error names
the line and column; nothing is guessed.

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

own "/etc/hosts"                               a path the exclave owns (removes a default host file)
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
`COMPILER_PATH` and `LIBRARY_PATH`.

And it replaces four variables that name what the exclave decides for
itself, the same in every exclave on every host:

| Variable | Value | Why |
|---|---|---|
| `PATH` | `/usr/local/bin:/usr/bin:/bin` | a host tool in the user's home directory is never found by name |
| `LANG` | `C.UTF-8`, with `LANGUAGE` and every `LC_*` dropped | one UTF-8 locale with code-point collation and English messages, whatever the user's; locale data is in a format tied to the glibc that wrote it, so it must be the exclave's, and a variable that selects data the exclave may lack is a promise it cannot keep |
| `TZ` | `UTC0` | glibc and musl honour it with no file, so the time inside an exclave is UTC and `/etc/localtime` is not consulted |
| `SHELL` | `/bin/sh` | programs that spawn the user's shell find one |

These are the values reproducible builds fix by hand. An exclave that
wants another locale, zone or shell ships the data and a wrapper script
that sets the variable before it execs the program, since inside the
border nothing is touched (13 item 35). `C.UTF-8` needs no locale
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
`launcher 0`, and every translated syscall as `<syscall> <result>
<virtual path>`: one line, in one write unless the path needs more
than two escapes. A syscall whose path could not be resolved is logged
with the path as the program gave it. An exec is logged as `exec 0`
when the handler hands it to the kernel, since one that succeeds never
returns; one that fails adds a second line with its error. A newline
in a path is written as `\n` and a backslash as `\\`, the only two
escapes, which the tool undoes when it reads a log (10.3, 10.4; 13
item 34). The launcher at the border also logs the working directory
it started in. The log changes nothing else.

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
- **The host table** (8.4) is the eight identity files, compiled into
  the launcher, minus any that the manifest's `own` records name, plus
  the manifest's `host` records.

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

tool "0.1.0"

launcher "b2:<blake2b-256 of .exclave/launcher>"

pkg "gcc-13" "13.3.0-6ubuntu2~24.04.1" "amd64" "b2:<blake2b-256 hex of the .deb>"
pkg "libc6" "2.39-0ubuntu8.8" "amd64" "b2:..."

manifest "b2:<blake2b-256 of the manifest bytes>"

tree "b2:<blake2b-256 of the serialised listing>"
```

The hashes file uses the grammar of 6.2; its keys, in canonical order,
are `hashes`, `tool`, `launcher`, `pkg`, `manifest` and `tree`, each
once but for `pkg`, whose four strings are a package's name, version,
architecture and hash. It is a record of an exclave's inputs and its
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

All hashes are BLAKE2b-256, written as `b2:` followed by lowercase hex,
so `b2sum -l 256` checks any of them without the tool. The `tree` hash
is the BLAKE2b-256 of a byte string built from every entry under
`tree/` except `.real/` directories, with originals in place of
wrappers and a `.real/` file with no wrapper beside it under its own
path (6.1), sorted by the bytes of the relative path. For each entry
the string holds:

```
relative path, NUL, one of f x d l, NUL,
    f, x: the lowercase hex BLAKE2b-256 of the content
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
as it stands.

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

## 7. The launcher

The launcher is one static, freestanding, `ET_DYN` binary of 88 744
bytes stripped on x86-64 and 90 744 on aarch64 (measured October
2026), with no libc and no `PT_INTERP`; it relocates itself. Every
executable in an exclave's tree is a hard link to it, a *wrapper*, and
the program a wrapper stands for, its *original*, sits beside it in
`.real/` (6.1). Besides its code it carries:

- **Two ELF notes** in a `.note.exclave` section, `exclave` and
  `cont`, each holding one word, the *page generation* (7.4.2), by
  which one launcher recognises another (7.4.5); `cont` is the name
  launchers from before the project's rename look for.
- **The MIT licence text**, in a `.exclave.license` section that is not
  loaded, since the licence's text goes with every copy.
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
   (7.5.1); borrows two descriptors under a soft limit below 16
   (7.4.5); opens `EXCLAVE_LOG` if set (6.2).
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
   the identity files (8.4) and the working directory (8.1 rule 4), and
   compiles the visibility rule into one table.
9. Installs the `SIGSYS` handler, then the filter, unless one of this
   version or newer is inherited, which is reused (7.4.2).
10. Loads the original and its loader (7.3) and jumps. A wrapper whose
    original is a script parses its `#!` line as 7.4.5 does and loads
    the interpreter's original.

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
kernel's `X_OK` answer is final. The exit status is a shell's, 126 for
a file that exists and cannot run, 127 for one that does not. A target
that is a wrapper is exec'd as itself, by the name the caller spelt,
so that the kernel gives the program its identity, when the kernel
would reach that wrapper by that name. An absolute link of the tree on
the way would lead the kernel to the host's file instead, so then the
wrapper is exec'd by its resolved path, and `comm` is the name the
link leads to. Only a program without a wrapper reaches the loader.
Without an argument the launcher says what it is; it takes no other
argument and no flag.

### 7.3 The loader

The loader replicates the kernel's `load_elf_binary` for the original
and its loader. It maps each `PT_LOAD`, an `ET_EXEC` at its address with
`MAP_FIXED_NOREPLACE`, checked since an older kernel takes it as a hint,
an `ET_DYN` at a base chosen by reserving its span. Segments are rounded
to the kernel's page size from `AT_PAGESZ`, as the kernel rounds them,
16 or 64 KB on some aarch64 kernels (13 item 43), and a segment whose
address and offset differ within a page is refused by name, as the
kernel's own `mmap` refuses it. The loader zeroes the tail of the last
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
at `0x7fe00000` is allowed. Before anything else runs, every launcher
maps that page with `MAP_FIXED_NOREPLACE`, writes `syscall; ret` into
it (`svc #0; ret` on aarch64, then flushes the instruction cache) and
makes it read-only and executable; every later syscall of the launcher
is a `call` into the page, a `blr` on aarch64. Only that bootstrap, the
version probe below and the signal restorer use a bare syscall
instruction.

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
A program can trivially exempt itself by jumping through the page; an
exclave is not a security boundary (3).

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
- `seccomp(2)` and `prctl(PR_SET_SECCOMP)` return `ENOSYS`, which more
  programs read as "no sandbox available, continue" than `EPERM`;
  `seccomp(SECCOMP_GET_ACTION_AVAIL)` is allowed as a harmless query. A
  program that insists on its own sandbox fails visibly at install
  time.
- The rest are in the table of 7.4.3.

**Argument checks.** `rt_sigaction` traps only when a new action is
installed. `rt_sigprocmask` and `rt_sigsuspend` always trap; `ppoll`,
`pselect6`, `epoll_pwait`, `epoll_pwait2` and `io_pgetevents` trap when
they carry a mask. `ioctl` traps for `FS_IOC_SETFLAGS` and
`FS_IOC_FSSETXATTR`, the `chattr` requests, and nothing else.

**Two stages.** The first is a binary tree on the syscall number alone,
whose leaf for every number the rule does not single out is `ALLOW`, so
the kernel's action cache (5.11) proves those syscalls allowed and
skips the filter, and a kernel without the cache runs about a dozen
instructions. The other numbers go to the second stage, the rule in
order: the argument checks that can only allow (an `ioctl` other than
`chattr`'s, a query of a signal action, a wait without a mask, a
`prctl` other than seccomp's, the availability query) and the version
probe; the syscall page; the refusals; then the trap. On x86-64 the
program is 284 instructions and 376 of the 471 numbers are allowed by
number alone; on aarch64, 240 and 396. 16.3 gives why a tree and what
an untrapped syscall costs. `test/filter_test.c` runs the program in an
interpreter against the rule written out on its own, for every number
and the arguments each check reads, and `test/syscalls.py` matches the
lists in `src/filter.c` against the running kernel's table, so a new
path-taking syscall is noticed rather than discovered (17).

**The ceiling.** A syscall numbered above the filter's table, whose
last entry is 470 (`listns`), traps and is answered `ENOSYS`, like any
trap the handler does not know, so a path-taking syscall a future
kernel adds cannot reach the host untranslated. The table test asks the
running kernel above the table rather than trusting a userspace header,
which lags the kernel by years.

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
moves, and is 6. Filters before 6 allow a page at another address, so
neither launcher can run under the other's filter: a launcher under a
filter older than 6 refuses by name at startup, and a handler sends a
launcher whose note carries a page generation older than the present
2, or no word, to its own child, which refuses it by name (7.4.5, 13
item 45). `scripts/build` also builds `build/launcher-old`, the same sources at
version 3, without `bind` and `connect`, which version 4 added, the
last version to add syscalls; the regression of 17 item 4 nests it
inside the current launcher.

#### 7.4.3 Intercepted syscalls

| Group | Syscalls | Treatment |
|---|---|---|
| Path, follow final symlink | `openat`, `openat2` (below), `newfstatat`, `statx`, `faccessat`, `faccessat2`, `truncate`, `chdir`, `statfs`, `utimensat`, `fchmodat`, `fchmodat2`, `fchownat`, `*xattr` and the `*xattrat` family, `file_getattr`, `file_setattr`, `inotify_add_watch`, `fanotify_mark`, `execve`, `execveat`, and their legacy forms | translate, apply the read-only rules, re-issue |
| Path, no follow | `readlinkat`, `unlinkat`, `mkdirat`, `mknodat`, `symlinkat` (the link's path; its target is stored verbatim), `renameat2`, `linkat` unless `AT_SYMLINK_FOLLOW`, `l*xattr`, `lchown`, `lstat`, `open` with `O_NOFOLLOW`, `open` with `O_CREAT\|O_EXCL` | translate all but the final component |
| Descriptor-addressed | any of the above with an empty path and `AT_EMPTY_PATH`; a NULL path where the kernel accepts one (`fstatat` and `statx` since 6.11, the `*xattrat` family, `file_getattr` and `file_setattr` under `AT_EMPTY_PATH`, `utimensat(fd, NULL, ...)` behind `futimens`) and `EFAULT` elsewhere (the empty-path forms are behind Rust's `File::metadata` and `fexecve`); and `fchmod`, `fchown`, `fsetxattr`, `fremovexattr`, `fstatfs` and the `chattr` ioctls (`ftruncate` needs a writable descriptor, which an exclave file never has) | resolve the descriptor through `/proc/self/fd`, no component walk, no trailing-slash rule; `AT_FDCWD` is the working directory; apply the read-only rules; an `O_PATH` descriptor is `EBADF` for the five attribute calls, as natively; for `execveat` a descriptor on a symlink itself is `ELOOP`, and one on anything but a regular file, a pipe or a socket included, is `EACCES`; an original's descriptor given to `execveat` is mapped back to its wrapper |
| A path inside a structure | `bind` and `connect` with an `AF_UNIX` address whose path is not abstract | below |
| Reverse-translate results | `getcwd`; `readlinkat` of `/proc/self/{exe,cwd,fd/*}` and of the process's own pid; `readlinkat` of an identity file; `statfs` and `fstatfs` on exclave paths | strip the tree's prefix, and the `.real/` of an original, which then names its wrapper; answer the program's virtual path for `exe` on the loader path (7.6); answer the host's link text for an identity file (8.4); report `ST_RDONLY`. Any other link's text is returned as stored, as the kernel returns it |
| Self-defence | `rt_sigaction` with a new action; the mask-carrying calls above | scrub `SIGSYS` from the mask (7.5.1), with no canonicalisation |
| Denied | `clone3`, `io_uring_setup`, `seccomp` except the availability query, `prctl(PR_SET_SECCOMP)`, `uselib`, the mount API (`open_tree`, `open_tree_attr`, `move_mount`, `fsopen`, `fsconfig`, `fsmount`, `fspick`, `mount_setattr`) | `ENOSYS` |
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

A program on the loader path answers `ETXTBSY` when the process that
loaded it write-opens or truncates its file, before any read-only
answer, as the kernel answers for the programs it executes. A write by
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
Otherwise the walk of 7.4.4 honours the `resolve` flags, which are
dropped from the re-issue:

- `RESOLVE_IN_ROOT` and `RESOLVE_BENEATH` scope the walk to the
  descriptor's directory, where `..` stays or is `EXDEV`, and an
  absolute path or link target starts again at the scope or is `EXDEV`.
- `RESOLVE_NO_XDEV` is `EXDEV` where the walk crosses between the
  host's domain and the exclave's, at a component or at a `..` that
  climbs out of one into the other (`follow_dotdot`), which is where
  the kernel under a bind mount changes mounts; an identity symlink
  that is not followed is excepted, and the host's own mount boundaries
  are not seen (13 item 22).
- `RESOLVE_NO_SYMLINKS` is `ELOOP` at any link the walk would follow,
  the tree's own links and an identity file's host link included; the
  scoped flags and `RESOLVE_NO_MAGICLINKS` are `ELOOP` at a link below
  `/proc/<pid>/`.
- `RESOLVE_CACHED` is dropped, since a resolved path is opened without
  it and openat2(2) permits a caller to see success where the kernel
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
`getsockname` answers the program's own name. Any other host path,
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
        "." -> continue; ".." -> cur = parent(cur); continue
        cand = cur + "/" + p
        if no parts left and not follow_last: cur = cand; break
        if lstat(to_real(cand)) is a symlink:
            t = readlink(to_real(cand))
            if cand under /proc: t = from_real(t)    # procfs reports real paths
            parts = split(t) + parts; cur = t absolute ? "/" : cur
            if ++hops > 40: ELOOP
        else cur = cand
    return cur, with the original trailing slash if any

to_real(v):   v host-owned (8.1) ? v : tree + v
              then wrapper -> original, except for execve and execveat
from_real(r): r under tree ? r without the prefix and a final .real/ : r
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
it concerns, in the order the kernel checks it.

A symlink's target is a virtual path whoever created the link. A host
link `/tmp/x -> /usr/bin/gcc` reaches the exclave's gcc, as it would
under bwrap; an exclave link `/var/run -> /run` reaches the host's
`/run` by 8.1 rule 3. The identity files of 8.4 are the one place a host
symlink keeps its host meaning, and they are resolved at startup, not
here.

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
cannot deadlock on it. Host-owned paths are never cached. The assumption
is stated: nothing outside the exclave modifies the tree while an
exclave process runs.

**The one-step host check.** Host directories are not cached, so a walk
through them `lstat`s each, to follow a host symlink in virtual space
and to see the tree's root under another name. Where at least three
directories lie ahead of the final component and every one is plainly
the host's by the rule (not an identity file, not on the way to one,
not the tree's root by name, not under `/proc`, no `.` or `..`), one
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
never a shorter path. Then:

- **A target in a data directory** is `EACCES`, never executed (6.2).
- **A wrapper** is `execve`d: the kernel runs the launcher under the
  program's name, and identity is the kernel's.
- **A file carrying a launcher's note**, under either name, is another
  launcher and is `execve`d as it is; one whose note names an older
  page generation goes to this launcher's child, which refuses it by
  name (7.4.2).
- **Anything else** re-execs the launcher with the original `argv`
  unchanged and the virtual target path in `EXCLAVE_EXEC`; the child
  launcher resolves the target as an exec would and loads it with
  whatever loader its own header names, resolved in the exclave (7.3).
  Before that exec the handler answers what `execve` itself would:
  `ENOEXEC` for a header the loader cannot load, a 32-bit class,
  another machine or more program headers than it holds, and `ENOENT`
  for a loader that is not there, as the kernel's `open_exec` of the
  interpreter fails, so that a shell's `execvp` fallback and a
  `posix_spawn` caller see the refusal rather than a child that dies. A
  loader that exists but is not the exclave's own file, a host path or a
  data directory, is left to the child launcher, which refuses it by
  name (7.3).

**The launcher's own protocol.** `EXCLAVE_EXEC`, `EXCLAVE_EXECFN` and
`EXCLAVE_COMM` are how one launcher tells the next what to run and under
what name, not an interface. `EXCLAVE_EXEC`, set by a handler or the
positional entry, is absolute and read only by a launcher run as a
program, never by a wrapper (7.2). The kernel spells the name a program
is exec'd by as given, or `/dev/fd/N` for a descriptor and
`/dev/fd/N/name` for a path relative to one (`alloc_bprm` in
`fs/exec.c`), and from it sets `AT_EXECFN`, `comm` as its last
component (from 6.12, the file's own name for a bare descriptor) and a
script's `$0`. The handler spells the name the same way and carries it,
with the `comm` it computed, in `EXCLAVE_EXECFN` and `EXCLAVE_COMM` on
every exec it makes, of a wrapper or of the launcher, dropping any
inherited copy of the three. The launcher it execs takes them for the
program's identity (7.6), a wrapper only when a filter is inherited, so
that from the host they are as inert as `EXCLAVE_EXEC`.
Every launcher removes all three from the environment a program is
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
limit may still exec: the handler borrows one descriptor under the hard
limit for the read and gives it back, and a child launcher started
under a soft limit below 16 borrows two for its own opens, the
manifest, the tree's top level, the program and its loader, and gives
them back before the program runs. From a soft limit of 16 up the child
needs a free descriptor, as a dynamically linked program's loader does
natively. At the hard limit the exec is `EMFILE` (13 item 12).

### 7.5 Signals, threads and memory

Each rule below comes from real software failing without it, not from
reasoning.

#### 7.5.1 `SIGSYS` must never be blocked

Seccomp delivers `SIGSYS` with `force_sig`: if the signal is blocked or
ignored at that moment, the kernel resets the handler to the default
and kills the process. The handler therefore scrubs `SIGSYS` from every
mask a program tries to set: `rt_sigprocmask`, the `sa_mask` of every
`rt_sigaction` that installs an action, and the mask of every wait
that carries one (7.4.2). `rt_sigtimedwait` and `signalfd` name signals to
receive, not to block, and are left alone. The case is common: a
program installs a handler with `sigfillset` on `sa_mask`, a textbook
idiom, and touches a path inside it. A consequence is that
`sigaction(sig, NULL, &old)` reports an `sa_mask` with `SIGSYS`
cleared, not the mask the program wrote (13 item 20).

The handler checks `si_code == SYS_SECCOMP`. A `SIGSYS` sent by `kill`
or `raise` restores the default disposition and re-raises, so the
process dies as it would natively.

#### 7.5.2 Masks are edited in the signal frame

`rt_sigprocmask` cannot be honoured by re-issuing it alone: the kernel
restores the mask from the frame at `sigreturn`. The handler re-issues
it with `SIGSYS` scrubbed from the set, which makes the kernel apply
block, unblock or set semantics and fill `oldset` with the pre-trap
mask, then copies the resulting mask into the frame's `uc_sigmask` so
that it survives the return. The mask-carrying waits are re-issued
through the page with a scrubbed copy of their mask, six arguments and
all.
`rt_sigaction` on `SIGSYS` itself is accepted and ignored (13 item 23);
its `oldact` and every query report the truth, the launcher's handler,
since only installs trap. The frame is read at the offsets of the
architecture, `uc_sigmask` at 296 and the registers at 40 on x86-64,
at 40 and 184 on aarch64, where `x0` is both the first argument and the
result and the handler copies the arguments before it writes. A
restorer of the launcher's own returns through `rt_sigreturn` on both.

#### 7.5.3 The handler is interruptible, and nesting is legal

The handler is installed with `SA_SIGINFO`, `SA_ONSTACK`, `SA_NODEFER`
and an empty `sa_mask`. The program's own mask is in force during the
re-issued syscall, so a blocking `open` on a FIFO inside an exclave is
interrupted by Ctrl-C exactly as outside, and a program's own signal
handler may run inside the launcher's. It then finds the registers as
the launcher left them. A Go program without cgo keeps its goroutine in
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
guard pages safe; where none exists it is a no-op.

#### 7.5.4 Scratch memory and the stack budget

The handler uses at most 3 KB of the program's stack beyond the
kernel's signal frame: 2 568 bytes on x86-64
and 2 480 on aarch64 (measured October 2026) for a five-deep chain of
host `#!` scripts, whose six nested exec frames keep their buffers in
scratch, and under 1.7 KB on every other path. The kernel's frame is
`AT_MINSIGSTKSZ` bytes, about 3 KB on AVX-512 hardware and up to 11 KB
with AMX; a trap costs the two together, multiplied under nesting (13
item 30), and glibc's `posix_spawn` child runs on a 36 KB stack with
no guard page. `test/stackcheck.py` asserts the budget on the call
graph gcc writes with `-fcallgraph-info=su`: the deepest chain from
`on_sigsys`, `exec_target`'s recursion counted six deep and any other
recursion a failure. The launcher makes no call through a pointer,
which would have no edge.

Path buffers, argument vectors and per-thread state live in scratch
chunks mapped on demand, since a fixed pool failed 40% of `stat` calls
under 64 threads when tried. A chunk records its owner's `(pid, tid)`
and the frame that claimed it, and is released when the handler
returns. Every copy from or into program memory names the pid recorded
in the trap's own chunk, never a process-wide value, which a `vfork`
child's handler, sharing the parent's memory, could overwrite.

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
internal signals, which traps for the mask scrub. That is the cost of
refusing `clone3`: a handful of traps per `posix_spawn`, two
`rt_sigaction`s and one `rt_sigprocmask` for a parent with no handlers.
What a spawn costs in all is the child launcher's start and the kernel's
work behind it (16.4). Honouring `clone3` by copying the signal frame
onto the new stack would leave the FPU save-area pointer at the
parent's stack and start every new thread with a corrupt `MXCSR`
(14.3).

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

### 7.6 Identity

For a wrapped program the kernel runs the launcher under the program's
own path, so `/proc/<pid>/exe`, `comm`, `cmdline`, audit records and
core-dump names are the program's for every observer. For a program on
the loader path, built outputs and host-path programs, the kernel's
`exe` and `maps` name the launcher and `.real/` files, which is 13 item
10 for outside observers; `cmdline` is the original `argv`, and `comm`
and `AT_EXECFN` are what the kernel would have set, carried by the
handler that exec'd it (7.4.5). From inside, `readlink` of
`/proc/self/exe` and of the process's own pid answers the program's
virtual path while `open` and `stat` of it reach the real file, so
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
interpreter could not open it (13 item 25).

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
   directory listing per entry, so the tree is its only source. The
   tool ships empty placeholders for `/home`, `/root`, `/boot`, `/mnt`,
   `/media`, `/opt`, `/srv`, `/tmp`, `/proc`, `/dev`, `/sys` and `/run`,
   and for `/var/tmp`, so that `ls /` lists them and `cd /home` works;
   a file dropped into a placeholder makes the directory the exclave's
   with nothing to refresh. The root directory itself is the tree's
   (8.3). The tables behind the rule are fixed: 256 top-level entries,
   256 `own` records, 32 `host` records and 32 `data` records. The
   launcher refuses to start beyond them and `exclave wrap` refuses to
   wrap, with the same numbers (13 item 33).
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
5. **Eight host identity files are the host's by default:**
   `/etc/passwd`, `/etc/group`, `/etc/nsswitch.conf`, `/etc/host.conf`,
   `/etc/resolv.conf`, `/etc/hosts`,
   `/etc/ssl/certs/ca-certificates.crt` and
   `/etc/pki/tls/certs/ca-bundle.crt`. They describe who the user is,
   how names are looked up, DNS, and which authorities the machine
   trusts, all of which belong to the host, and they are data in a
   format any libc reads, not code. Six of them are on PRoot's default
   binding list; the seventh of that list, `/etc/localtime`, is not
   here, because the time zone inside an exclave is UTC (6.2) and the
   file is never consulted. `own` on one of them removes it. An identity
   file absent on the host falls through to the exclave's copy. The
   tool ships each of the eight as an empty placeholder when the tree
   lacks it, and the path walk treats the directories on the way to an
   identity file as directories whether or not the exclave ships them
   (8.4).
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
resolved on the host at startup like an identity file (8.4) and stands
for that one name; one whose host path does not exist is dropped, and
the exclave answers.

When several parts apply, the launcher decides in this order:

1. `/` itself is the tree's.
2. An identity file, or a `host` record naming a file, is the host's.
3. The working directory given to the host (rule 4) and the exclave's
   own directory (rule 6), each with the directories on the way to it,
   are the host's.
4. A volatile directory (rule 3) is the host's.
5. Otherwise the longest matching prefix among the `host` records and
   the owned paths, rule 1's entries and the `own` records, wins; at
   equal length the `host` record wins.
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
    `EILSEQ`, is reported as it is; a trailing slash is `EISDIR` for
    `open` and `ENOENT` for a non-directory create; and only then comes
    `EROFS`. `O_CREAT` without `O_EXCL` on an existing file opened
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
    `EEXIST` for the new name under `RENAME_NOREPLACE`.
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
`ETXTBSY` for a write-open or `truncate` of that program's file,
before any read-only answer, as the kernel answers for the programs it
executes (7.4.3). Another process's write-open without `O_TRUNC` of an
exclave file that is running answers `EROFS` where the kernel answers
`ETXTBSY` (13 item 29); on a host path it succeeds (13 item 40).

Two orders the handler does not follow are stated in 13: that one,
and `fanotify_mark`'s flag check (13 item 41). The oracles measure the
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
listing, and `.real/` appears in every listing of a directory that
holds an executable (13 item 6).

### 8.4 Host identity files

At startup the launcher resolves each identity file's symlink chain on
the host, `readlink` by `readlink`, from `/etc/resolv.conf` to
`/run/systemd/resolve/stub-resolv.conf` for instance, and records the
final host path in the host table under the identity file's name.
Inside the exclave the identity file then behaves as the host's link
does: `readlink` answers the host's first link text, `lstat` and an
`O_PATH | O_NOFOLLOW` open see the host's symlink itself, and an
`O_NOFOLLOW` open fails with `ELOOP`. The directories on the way to an
identity file are traversable in the path walk whether the exclave
ships them or not (8.1 rule 5). The table is fixed for the process's
life: a host retargeting `/etc/resolv.conf` under a running exclave is
not seen (13 item 18).

The translator never follows an identity file's host link in virtual
space, where `/usr` is the exclave's; it uses the host path it recorded
at startup. Nor do host symlinks in general keep their host meaning:
such a rule would let a host link into `/usr` reach the host's `/usr`.
Every other symlink, on a host path or an exclave path, is resolved in
virtual space (7.4.4).

The host's `nsswitch.conf` may name NSS modules the exclave does not
ship, `systemd`, `sss`, `mdns4_minimal`. glibc skips them, which is
right for `hosts` and wrong for `passwd` on a host whose users come
from LDAP or `systemd-homed`, where `getpwuid` then fails inside the
exclave (13 item 17). `exclave check` given a log warns of each module
the checking host's `nsswitch.conf` names that the exclave lacks
(10.3), so an exclave's maker who checks on such a host learns of it
before a user does.

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
  makes the exclave and the output, and the kernel matrix runs the
  output natively on each glibc row, CentOS 7 at glibc 2.17 included
  (12.1); Alpine's musl has no loader for a glibc program. A static
  link made the same way needs `glibc-static` in the sysroot.
- **A clang exclave**: Ubuntu 24.04's `clang-18` closure with
  `libc6-dev`, `libgcc-13-dev`, `libstdc++-13-dev` and `binutils`,
  wrapped with no error. A maker who wants `cc` adds `cc -> ../../bin/clang-18` and
  `c++ -> ../../bin/clang++-18` in the exclave's own `/usr/local/bin`,
  which is what puts a name on the exclave's `PATH` (6.2). The test
  inputs' clang exclave has none, and the test suite finds its compiler
  as `clang-18`. C and C++ compile and run inside; the sanitizer
  runtimes are in a package that set does not include. It is one of
  the gate's four exclaves (17).
- **An Alpine exclave**: `gcc musl-dev binutils make linux-headers`
  and the base, 20 packages from Alpine 3.21 fetched with
  `fetch/apks.py`, unpacked and wrapped: 87 ELF files, no error
  from the static check, and a tree hash that reproduces from the same
  files. Its gcc 14.2 compiles and runs C inside, dynamically linked
  on musl 1.2.5 and statically linked. The static output runs on a
  glibc host; the dynamic one does not, since such a host has no musl
  loader. A compile touches no host path, and it is one of the gate's
  four exclaves (17).
- **A Fedora exclave**: `gcc glibc-devel binutils make` and the base,
  87 packages from Fedora 42 fetched with `fetch/rpms.py`, with
  `glibc-minimal-langpack` chosen for the langpack, unpacked and
  wrapped: 351 ELF files, no error from the static check, and a tree
  hash that reproduces from the same files. Its gcc 15 compiles and
  runs C inside on glibc 2.41; a static link needs `glibc-static`,
  which the set does not include. A compile touches no host path, and
  it is one of the gate's four exclaves (17).
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
prunes and relinks it. It is C, in `tool/`, built by `scripts/build` as
one static file per architecture that carries its launcher (10.5), and
run from a checkout as `build/exclave` or `scripts/exclave`. The tests
judge it only through its commands. `unpack` (10.1), the step before
it, is the Python package `unpack`, run like every Python program here
by the pinned Python: the uv that `scripts/install-uv` puts in `.uv/`
installs the version `.python-version` names (3.15) into the checkout,
and every script runs through it (`scripts/lib.sh`), so nothing the
machine has installed decides which Python runs.

The tool's input is an unwrapped exclave, a directory holding `tree/`.
What made the tree is the step before the tool: `unpack` from package
files (10.1), a build's staging directory (10.2), `debootstrap`, a
container export or `tar`. Neither the tool nor `unpack` opens a
network connection: the files they are given are their inputs, whoever
fetched them, and any record of where they came from is the fetcher's
to keep. Every command takes paths, and `format --check` is the only
flag:

```
exclave wrap EXCLAVE                wrap an exclave (idempotent; a bare directory holding tree/ becomes an exclave)
exclave unwrap EXCLAVE              unwrap an exclave again
exclave check EXCLAVE [LOG...]      wrappers, the tree against the hashes file, the static check, and with EXCLAVE_LOG files the dynamic check
exclave prune EXCLAVE LOG...        drop what no logged workload touched
exclave format [--check] FILE...    canonical form of a manifest or hashes file; --check only reports
exclave hash EXCLAVE                the tree hash of 6.4
exclave relink EXCLAVE [LAUNCHER]   replace the launcher and relink every wrapper
exclave unpack OUT APK...           an unwrapped exclave from Alpine package files, as scripts/unpack makes it (18 item 7)
```

`wrap` and `relink` also write the exclave's `README` (6.1) where it
has none. Every command except `format` and `unpack`, which makes the
directory it is given, refuses,
before reading or writing anything, a directory without `tree/`, and
every command except `wrap` refuses one without `.exclave/`.

### 10.1 From packages

```
scripts/fetch-debs --out debs gcc-13 libc6-dev       # or apt, a mirror, a hand-made directory
scripts/unpack gcc-13.exclave debs/*.deb
exclave wrap gcc-13.exclave
ln -s tree/usr/bin/gcc-13 gcc-13.exclave/gcc
```

**Unpack** is the step before the tool, as fetching is the step before
it: the Python package `unpack` beside the tool, run as `scripts/unpack
OUT PKG...`, which shares with the tool only the layout of 6.1 and the
hashes file of 6.4. It reads `.deb`, `.apk`
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
   declares, is the fetcher's concern; `fetch/debs.py` adds it
   unless given `--no-essential`.
2. **Extract** each `data.tar.*` into `tree/`, after creating the
   distribution's merged-`/usr` symlinks (`bin`, `sbin`, `lib`, `lib32`,
   `lib64`, `libx32` to their `usr/` counterparts). Directories and
   identical symlinks shipped by several packages are normal. A regular
   file shipped by two packages is an error unless one declares
   `Replaces` on the other; the merged-`/usr` spellings of a path count
   as one path. A maintainer script that adds a renaming diversion is
   refused with a message, since the tree would have to hold the file
   under dpkg's renamed name. Diversions with `--no-rename`, and the
   merged-`/usr` and `zutils` transitions that every Ubuntu 24.04
   closure carries, leave a fresh tree unchanged and are ignored. A
   member whose path resolves outside the tree through a symlink is
   refused, as is a hard link whose target does, and so is a member
   under the reserved name `.real` (6.1). A package file that cannot
   be read is refused in one line, and a failed unpack leaves no
   output behind.
   `ar` and `tar` are read in Python, xz, gzip and bzip2 through the
   standard library, and zstd through its `compression.zstd`. Modes
   and modification times come from the archive, with setuid and setgid
   bits dropped (they mean nothing under `no_new_privs`, 12) and every
   file made readable by its owner; special files are skipped with a
   note.
3. **Synthesise** the effects of maintainer scripts; the scripts are
   never run. The rules, keyed by package, approximate dpkg's configure
   step for the case without privilege; a tree whose scripts must really
   run comes from `debootstrap`, a container export or a chroot, and
   `wrap` makes an exclave of it. The rules:
   every `update-alternatives --install` line in a `postinst`, with
   its slaves, the highest priority winning, which yields `awk`,
   `which`, `pager`, `cc` and the rest without a per-package list;
   dash's `/bin/sh`; `/etc/passwd` and `/etc/group` from base-passwd's
   masters; `ca-certificates.crt`, concatenated from the certificates
   `ca-certificates.conf` enables; OpenSSL's compiled-in trust paths
   when a libssl is present, so that the host's bundle at the identity
   path (8.4) is consulted; and `ld.so.cache`, by `ldconfig -r` with the
   exclave's own static `ldconfig`, before wrapping so that the cache
   never indexes the launcher, its `aux-cache` removed since it records
   inodes and modification times.

   Not synthesised: `locale-gen`, GLib schemas, MIME and font caches,
   and Python bytecode, which Python makes for itself where it can write
   and does without where it cannot. Failed opens in an `EXCLAVE_LOG`
   show what an exclave tried and could not find.
4. **Strip** the volatile directories (8.1). Their empty placeholders,
   the conventional host names' and the eight identity files (8.4) are
   added by `wrap` where the tree lacks them.
5. **Record** every input as a `pkg` record of `.exclave/hashes` (6.4),
   which is all that `unpack` writes outside `tree/`: the launcher, the
   manifest and the `README` are `wrap`'s.

`unpack` runs on any machine. A tree of another architecture gets no
`ld.so.cache`, since its `ldconfig` cannot run here, and `unpack` says
so. `wrap` must run on a machine of the exclave's architecture: the
static check asks the tree's loader for its directories and checks the
objects of the launcher's machine, and on any other machine it refuses
with the reason. The kernel matrix makes its arm64 exclave inside the
arm64 virtual machine for this reason (17).

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

1. It installs this machine's launcher if none is there, adds the
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
into `bin` and Fedora's p11-kit CA bundle. The module docstrings of
`exclave/apk.py` and `exclave/rpm.py` list each format's differences.

**The step before the tool** belongs to whoever makes the exclave.
Three fetchers in `fetch/`, one for each format, are worked examples;
they are not part of the tool's exclave. Each resolves a closure from a
repository's index, chooses providers of virtual names by priority,
verifies every download against the index's checksum, and fills a
directory. They know about mirrors and snapshot services because those
are locators; the tool does not, because a hash is not a locator.

- `fetch/debs.py` resolves `Depends` and `Pre-Depends` from an
  archive's `Packages` index, adds the Essential set, and checks the
  index against the suite's `Release` digests.
- `fetch/apks.py` resolves `D:` dependencies through the index's
  `p:` provides and checks each package's checksums as apk does: the
  index's checksum against the control section, and `.PKGINFO`'s
  `datahash` against the data section.
- `fetch/rpms.py` reads a yum or dnf repository's `repomd.xml` and
  `primary.xml` and resolves `Requires` through `Provides` and the files
  the index lists.

None verifies a signature, the `Release` file's, the apk index's or the
rpm metadata's, so the mirror is trusted (13 item 32). `fetch/debs.py`'s
default mirrors are plain `http://`, so with them the network path is
trusted too; an `https` mirror or `--snapshot` leaves only the mirror.

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
  directories. The defaults are asked of the loader in the tree (`ld.so
  --list-diagnostics` on glibc 2.33 and later; musl's fixed list;
  Debian's list for older loaders), including the `glibc-hwcaps`
  subdirectories on x86-64. The loader satisfies its own soname without
  a search, as `ld.so` does. Executables are checked first, so that
  `RPATH` inheritance down a chain is seen; a library that nothing
  reaches is a `dlopen` candidate and is checked on its own.
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
- the identity files (8.4) and `ld.so.cache`;
- the packages' licence texts.

The licence texts are the files under every `usr/share/` of the tree,
including one inside a data directory: Debian's
`usr/share/doc/PKG/copyright` and the `usr/share/common-licenses` those
cite, and `usr/share/licenses/`, where RPM's `%license` files and
Alpine's `-doc` packages put theirs. An exclave that is passed on
carries its packages' terms, and a workload never reads them, so a
trace alone would drop them. An Alpine exclave has its licence texts
only if the packages' `-doc` packages went in.

Every other file and symlink is removed. Directories are never removed,
so ownership (8.1) and what `ls` shows (8.3) do not change. A log that
names no program in the exclave, because it is empty, belongs to
another exclave, or comes from a workload that died before its first
`exec`, is refused rather than obeyed, since obeying it would empty the
exclave.

The log names canonical paths. That is why symlinks are kept by what
they reach rather than by what the log says: the `cc` that a program
ran appears in the log as the gcc it resolved to.

Afterwards the hashes file's tree hash is rewritten and the static
check runs. On the gcc 13 exclave that `scripts/inputs` makes, a
hello-world compile keeps 220 of 5 204 files and symlinks, counted as
`prune` prints them, originals included; 87 of them are licence texts.
The count moves by a file or two with where the work directory lies.
The pruned exclave compiles the same program and passes the static
check. (The README's example, an exclave with a CentOS 7 sysroot copied
in, keeps 226 of 9 564 by the same count.)

Failed opens in a later `EXCLAVE_LOG` show what pruning removed, by
name, including a missing intermediate directory. The cycle is: prune,
run the whole workload, add back from an unpruned copy.

### 10.5 The command as one file

The command is one statically linked executable for each architecture,
`build/exclave` for the machine's own and `build/exclave-aarch64` from
the cross compiler, 973 KB and 795 KB, with nothing beside it to run: no
interpreter, no library, no file of the checkout. It carries its
architecture's launcher and the text of every exclave's `README` as data
(`tool/blobs.S`), so `wrap` installs the launcher it carries and
`relink` uses it unless given another. An exclave is wrapped on a
machine of its own architecture (10.1), so each file carries that
architecture's launcher and no other.

It is ordinary C on the C library, glibc linked statically, unlike the
launcher, which is freestanding because it runs inside other programs'
processes (7.1) and the command never does. The scripts build it with
the same strict warnings as the launcher, and the gate runs a build
under ASan and UBSan, `build/exclave-asan`. Its BLAKE2b is written from
RFC 7693 and tested against the RFC's vector and Python's `hashlib`
(17).

The step before it, `unpack` (10.1), is a Python package run by the
pinned Python, like the fetchers and the tests. The command's own
`unpack` makes the same tree from `.apk` files alone, with gzip and
DEFLATE written from RFC 1951 and RFC 1952 and a tar reader that reads
what Python's `tarfile` reads (18 item 7).

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
| Kernel | A seccomp filter with `SECCOMP_RET_TRAP` (Linux 3.5), installed with `seccomp(2)` or `prctl(PR_SET_SECCOMP)`. `SECCOMP_RET_KILL_PROCESS` (Linux 4.14) degrades to killing the thread on older kernels. `/proc` mounted. `process_vm_readv` for speed, with a pipe keeping `EFAULT` fidelity where it is refused (7.5.6). Measured from 3.10 to 7.0 (12.1) |
| Ubuntu 23.10+ desktops, Docker and CI default profiles, RHEL 7, HPC, hardened kernels | Designed to work: no privilege, user namespace or mount is needed. Docker's default seccomp profile was checked syscall by syscall, and a workload runs under it, twice: as assembled for the running kernel and as Docker installs it before Linux 4.8, where `process_vm_readv` is refused (17) |
| Read-only media, NFS, FUSE homes | Work: nothing is written |
| `noexec` media, including a `noexec` `/tmp` in CI | Not supported: neither `execve` nor `mmap(PROT_EXEC)` of a file is allowed there |
| Snap-confined terminals, gVisor-based CI, WSL1, SELinux `execmem` policies | Untested. snapd and gVisor install their own filters; WSL1 has no seccomp |
| `no_new_privs` | The filter requires it, and it also disables file capabilities and AppArmor transitions on exec: `sudo`, `su`, `pkexec`, `ping` and setcap binaries fail inside an exclave, including when run from build scripts |
| Media without symlinks or hard links (FAT) | `cp -rL` copies the launcher once per wrapper and replaces symlinks with copies; the copy works, since whether a file is a wrapper is read from the file (7.4.4) |
| Architectures | x86-64 and aarch64, from one source as two launchers (7.1). An exclave runs programs of its launcher's machine only. aarch64 is tested in the emulated matrix row (12.1), on a kernel with 4 KB pages; kernels with 16 KB or 64 KB pages (Asahi, RHEL's and Ubuntu's 64k kernels) are untested (13 item 43). Another 64-bit little-endian machine would need the same list: the syscall table, `_start`, the signal frame offsets, a restorer, the relocation type and the CPU check |
| Overhead | Within noise on a compute-bound compile; about a third more on thirty small compiles; about twice native per `posix_spawn`; 6 to 10 times native on a tight `stat` loop (16) |

What remains host-dependent is the same set that static linking leaves:
the kernel ABI, the CPU level (7.7), and the eight host identity files
(8.4).

### 12.1 The kernel matrix

`test/matrix.py` runs one gcc exclave, built on the reference machine,
in a virtual machine of each distribution's own cloud image, with the
suite's 79 named regressions and every oracle its kernel can run; 17
describes the procedure. Measured October 2026:

| Distribution | Kernel | Suite | Oracles | Notes |
|---|---|---|---|---|
| CentOS 7 | 3.10 | 74 of 74 | none: no user namespaces | `seccomp(2)` absent, so the `prctl` form is used; `renameat`, not `renameat2` |
| Ubuntu 18.04 | 4.15 | 74 of 74 | namespace, probe and Docker profile pass; no `openat2` | bwrap 0.2 |
| Rocky Linux 8 | 4.18 | 74 of 74 | all pass | |
| Ubuntu 20.04 | 5.4 | 74 of 74 | namespace, probe and Docker profile pass; no `openat2` | |
| Debian 11 | 5.10 | 74 of 74 | all pass | the security suite lists a `bubblewrap` it does not serve; the matrix installs the release's |
| Ubuntu 22.04 | 5.15 | 74 of 74 | all pass | |
| Debian 12 | 6.1 | 74 of 74 | all pass | |
| Alpine 3.20 | 6.6 | 74 of 74 | all pass | musl host, busybox userland; the exclave's outputs run inside it only (9) |
| Fedora 42 | 6.14 | 74 of 74 | all pass | SELinux enforcing |
| Ubuntu 24.04 arm64 | 6.8 | 74 of 74 | all pass | aarch64 under TCG, `-cpu max`, 4 vCPUs, at about a tenth of native speed: the suite takes 55 minutes, the row 81; the exclave is made inside the VM (10.1) |
| reference machine | 7.0 | 74 of 74 | all pass | Ubuntu 24.04, AppArmor |

Every row passes the full suite, and every oracle that its kernel can
run passes. Two checks outside the suite run natively on each row:

- **`noexec`.** A program built by the exclave's gcc, placed on a
  `noexec` tmpfs, is refused with status 126, permission denied, by the
  VM's own shell, by the launcher's positional entry and by an
  exclave's shell; the launcher asks the kernel for `X_OK` before it
  loads anything (7.2, 7.4.5).
- **A sysroot build.** The output of `test/sysroot.py`, a hello program
  linked inside the Ubuntu 24.04 gcc exclave against the CentOS 7
  sysroot (9), runs natively. Measured October 2026, it prints its line
  with status 0 on the eight glibc VMs, from CentOS 7's glibc 2.17 to
  Fedora 42's 2.41. On Alpine's musl it has no loader, which the step
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
   without the exclave's libraries. On musl a breakpoint in the
   program hits and one in the exclave's libc does not.

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

5. **`io_uring`, `clone3` and a program's own seccomp filter are
   refused.** `io_uring_setup` and `clone3` answer `ENOSYS` (libcs fall
   back to `clone`), and installing a filter is refused (7.4.2), since
   either would let a program act past the translator. Programs that
   depend on them, container runtimes, browsers' sandboxes, `rr`,
   `qemu -sandbox`, are out of scope. `strace` inside an exclave works
   but shows a `SIGSYS` for every translated call. `valgrind` is
   untested.

6. **Listings differ from the host's.** A directory listing omits
   host-owned files inside exclave-owned directories, and shows
   `.real/` (8.3).

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
    `/proc/<pid>/maps` read from outside the process name the launcher
    and `.real/` files; read from inside they are right (7.6).

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
    lowered soft limit is borrowed against (7.4.5), and a child
    launcher under a full soft limit of 16 or more needs one free
    descriptor, as a dynamically linked program's loader does natively.

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
    syscall can resolve against the older directory. `..` above a
    working directory that was handed to the host stays in the exclave.

15. **Without `process_vm_readv`, copies go through a pipe.** Where it
    is refused, `EPERM` under a seccomp profile that gates it on a
    capability as Docker's does before kernel 4.8, every copy from or
    into program memory goes through a pipe: five syscalls for the
    first page and two for each page after. `EFAULT` is still answered
    as the kernel would; the cost is the limitation.

16. **From the host, every executable in an exclave is the launcher.**
    `ldd`, `file`, `debsums`, IDE indexers, antivirus and gdb see the
    same small static binary at every executable path, and the
    originals in `.real/`. Endpoint security may flag the pattern.

17. **Directory-service users are unknown inside.** On hosts whose
    users come from LDAP, SSSD or `systemd-homed`, `getpwuid` fails
    inside an exclave, which sees only the host's identity files (8.4).

18. **Identity files are resolved once, at startup.** A host change to
    `/etc/resolv.conf` under a running exclave is not seen.

19. **Per-user state under an exclave path has no target.** The tree is
    read-only and the visibility rule has no per-user directory, so
    software that must write there needs a fixed host directory named
    by a symlink in the tree.

20. **`sigaction` queries report scrubbed masks.** The handler removes
    `SIGSYS` from every mask a program sets, since a blocked `SIGSYS`
    would kill the process at its next trap, so `sigaction(sig, NULL,
    &old)` reports an `sa_mask` without it (7.5.1).

21. **Kernels without seccomp filter support cannot run exclaves.**
    The translator is a seccomp filter; there is no fallback.

22. **`name_to_handle_at` and parts of `openat2` differ.**
    `name_to_handle_at` answers `ENOSYS` (7.4.3). An `openat2` walk
    that never touches the exclave is the kernel's own, with every
    `resolve` flag, on the host's real mounts. One that starts in the
    exclave, enters it, or restarts at the root, which is the tree's,
    through an absolute path, a link target or `..`, sees two mounts
    under `RESOLVE_NO_XDEV`, the exclave and the host, and not the
    host's own mount boundaries (7.4.3). `RESOLVE_CACHED` is dropped. A
    scoped `..` under `RESOLVE_IN_ROOT` or `RESOLVE_BENEATH` never
    answers `EAGAIN`, which the kernel returns when a rename or a mount
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
    natively; the original's path in `.real/` never appears.

29. **A write-open without `O_TRUNC` of an exclave file another
    process is executing answers `EROFS`.** The kernel would answer
    `ETXTBSY` first; the handler refuses the write by its read-only rule
    (8.2) without opening the file, so it never learns that the file is
    running (17 items 1 and 7). With `O_TRUNC` the kernel answers
    `EROFS` as well. The loader-path program's own process gets
    `ETXTBSY` (7.4.3), ahead of any read-only answer, so an `O_TRUNC`
    open or a `truncate` of its own file on an exclave path, such as a
    `.real/` original run directly, answers `ETXTBSY` where the kernel
    would answer `EROFS`.

30. **Small alternate signal stacks overflow.** The handler runs on
    whatever stack the trap lands on, and needs the kernel's frame
    (`AT_MINSIGSTKSZ`, 3.4 KB on the reference machine) plus its own
    3 KB budget (7.5.4). Rust's 8 KB stack is enough; a stack of exactly
    `MINSIGSTKSZ` is not.

31. **Some paths inside structures are not translated.** A datagram
    destination in `sendto`, `sendmsg` or `sendmmsg` reaches the kernel
    as written: the filter cannot see the address family, and trapping
    every datagram send would tax every UDP program for a case no
    program has been seen to use. The visibility rule makes the
    untranslated path right for `/tmp`, `/run` and `/var/run` and wrong
    for a socket under an exclave path. `bpf` object pins, `quotactl`
    and `swapon` are likewise untranslated (`test/syscalls.py` lists
    them); `fsconfig` is refused with the rest of the mount API. `bind`
    and `connect` translate their `sockaddr_un` (7.4.3) with two visible
    differences: `getsockname` on a host socket whose real path passes
    `sun_path`'s 107 bytes answers `/proc/self/fd/N/NAME`, and a socket
    file in the tree bound by a listener outside the exclave answers
    `ECONNREFUSED`.

32. **The tool trusts its input files, and the fetchers trust the
    mirror.** The tool records its inputs' hashes and checks nothing
    about their origin, which it cannot know. `fetch/debs.py`,
    `fetch/apks.py` and `fetch/rpms.py` verify every
    download against its index's digest, but none verifies a signature:
    not a Debian or Ubuntu `Release` file's, not the apk index's, not an
    rpm repository's metadata's. The mirror is therefore trusted, and
    with `fetch/debs.py`'s default mirrors, which are plain `http://`,
    so is the network path; an `https` mirror or `--snapshot` leaves
    only the mirror. Unpack and the tool also run two of the packages'
    binaries on the host, outside any exclave: the tree's static
    `ldconfig` during `unpack`, to make the cache (10.1), and the
    tree's loader with `--list-diagnostics` during the static check, to
    learn its search directories (10.3). A package one would not run is a package
    one should not unpack.

33. **The launcher's tables are fixed in size** (8.1). A manifest or a
    tree beyond them is refused, by `exclave wrap` before it is made
    and by the launcher at startup.

34. **`EXCLAVE_LOG` escapes only the newline and the backslash**; a
    path with any other byte appears in the log as it is. A trailing
    slash, or an empty, `.` or `..` component, in an `own`, `host` or
    `data` path is refused by both the tool's and the launcher's
    manifest parser, since the visibility rule matches a path by its
    one spelling and would silently match nothing else.

35. **The locale, the time zone and the shell are the exclave's**:
    `C.UTF-8`, UTC and `/bin/sh`, not the user's (6.2). `date` prints
    UTC, messages are in English, and collation is by code point. An
    exclave that wants otherwise ships the data and a wrapper script.

36. **What still varies under a reproducible build.** The launcher does
    not touch the hostname and kernel identity from `uname` and
    `/proc`; directory listing order, which the filesystem decides; the
    build path in debug info, which `-ffile-prefix-map` handles; user
    and group ids and names, which `tar` records; or the CPU's features,
    which `-march=native` embeds.

37. **A symlink in the tree with an absolute target resolves on the
    host when run from outside.** `/usr/bin/awk ->
    /etc/alternatives/awk` resolves on the host when run from outside
    the exclave, and in the tree when run from inside, because only
    inside does the translator see the path. From outside, run the
    wrapper it points at, or use a relative link; this is why the
    busybox applet links are made relative (10.1).

38. **A static link against a Red Hat tree needs `glibc-static`**,
    which no closure of `gcc` pulls in; add it to the package list.

39. **A wrapped script run through the positional entry gets its
    canonical virtual path as `$0`.** The entry execs the wrapper by
    its real path from outside any filter, where a wrapper takes no
    spelling from the environment (7.4.5). Every other way of running a
    script, from inside or outside, gets the path as the caller spelt
    it.

40. **A running program on a host path is not protected from other
    processes' writes.** The kernel executes the launcher, not the
    file, so its `ETXTBSY` covers wrappers and not originals or built
    outputs. The launcher answers `ETXTBSY` only to the process that
    loaded the program (item 29, 7.4.3); another process's write
    succeeds and may leave the running program to take `SIGBUS`.
    Natively `cp new prog` over a running `prog` fails with "Text file
    busy"; in an exclave it succeeds. Linkers unlink their output
    first, so relinking is safe either way.

41. **`fanotify_mark` checks in a different order from the kernel**
    (8.2, 17 item 7). Its path is resolved before its flags and
    descriptor are checked, where the kernel checks those first. The
    difference is unreachable in practice: fanotify needs
    `CAP_SYS_ADMIN`, which no exclave process has.

42. **An ext4 race that the probe's own reset provokes.** On kernels
    5.10 to 6.1, natively too, ext4 refuses to clear the extent flag
    (`FS_IOC_SETFLAGS`) of a file recreated moments after its
    predecessor was deleted, so the probe (17 item 7) keeps that case
    off host files.

43. **aarch64 kernels with 16 KB or 64 KB pages are untested.** The
    loader rounds segments to the kernel's `AT_PAGESZ` and refuses by
    name a segment whose address and offset differ within a page, as
    the kernel does (7.3). Ubuntu's arm64 packages are linked for 64 KB
    pages: all 379 ELF files of `coreutils`, `libc6` and `gcc-13` are
    congruent modulo 64 KB. The launcher's own segments and the syscall
    page are 64 KB-aligned (7.4.2). The arm64 test row runs a 4 KB
    kernel; a row with `linux-image-generic-64k` would make support a
    measured fact.

44. **Two handlers never share a scratch chunk**: a rule, not a
    limitation (7.5.4).

45. **A bundle made before the project's rename, a "can", is converted
    by hand.** A can is an exclave in the format's earlier names:
    `.can/` for `.exclave/`, `root/` for `tree/`, `opener` and `lock`
    for `launcher` and `hashes`. A can still runs as it is, from
    anywhere, and runs an exclave's programs as an exclave runs its
    own. The `exclave` command refuses one by name rather than reading
    it. A can's launcher whose syscall page is at the earlier address
    (item 24) and the current launcher cannot run under each other: the
    current one refuses either nesting and points here (7.4.2); the
    conversion, which relinks, fixes it. Converting a can is renames,
    two edits and three commands:

    ```
    cd OLD.can && mv .can .exclave && mv root tree && mv .exclave/opener .exclave/launcher && mv .exclave/lock .exclave/hashes
    sed -i -e 's/^can 1$/exclave 1/' -e 's/^isa /cpu /' .exclave/manifest
    sed -i -e 's/^lock 1$/hashes 1/' -e 's/^cannery /tool /' -e 's/^opener /launcher /' .exclave/hashes
    cd .. && mv OLD.can OLD.exclave                               # the suffix is a convention; any name works
    scripts/exclave relink OLD.exclave build/launcher          # the current launcher behind every wrapper
    scripts/exclave unwrap OLD.exclave && scripts/exclave wrap OLD.exclave   # the manifest's hash, recorded again
    ```

    The converted exclave's hashes file equals the one a fresh `unpack`
    and `wrap` of the same packages writes, apart from the launcher's
    hash.

46. **The launcher's own variables stay in `/proc/<pid>/environ`.**
    `EXCLAVE_EXECFN`, `EXCLAVE_COMM` and, on the loader path,
    `EXCLAVE_EXEC` are removed from the environment the launcher hands
    a program, so `environ`, `getenv` and every child see none of them.
    The kernel's copy, which it filled at exec and which
    `/proc/<pid>/environ` and `ps e` read, keeps them; replacing it
    takes `PR_SET_MM_ENV_START`, which needs `CAP_SYS_RESOURCE`. A
    program that reads its own `/proc/self/environ` sees the name it was
    exec'd by and its `comm`, which are the kernel's own facts about it.

47. **An Alpine exclave has no licence texts unless the `-doc` packages
    are added.** Alpine ships a package's licence text in its `-doc`
    package, which a closure of `gcc` does not pull in, and records the
    licence by name in the package's metadata, which the hashes file
    does not copy. Whoever passes an Alpine exclave on adds the `-doc`
    packages, whose texts land in `usr/share/licenses/` and survive
    pruning (10.4).

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
(gdb) break main                   # pending until the script adds the program
(gdb) set follow-fork-mode child   # to stop inside cc1 rather than the driver
(gdb) run
```

`break` works in the program and in the exclave's libc, `bt` walks
through both, and `info files` lists what the script added; `info
sharedlibrary` is empty (7.6, item 1). Every translated syscall is a
`SIGSYS` stop that gdb passes through, so a run under gdb slows in
proportion to its traps.

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
happens in `cc1`.

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
| Resolving host symlinks in the host's domain | A host link into `/usr` would reach the host's `/usr`. Links resolve in the exclave's view; the identity files are handled at startup (8.4). |
| Honouring `clone3` by copying the signal frame onto the child's stack | The copy leaves the FPU save-area pointer at the parent's stack, and every new thread starts with a corrupt `MXCSR`. `ENOSYS` costs a few traps per `posix_spawn` (7.5.5). |
| Reclaiming scratch by comparing stack pointers across threads | Meaningless across alternate stacks and coroutines; scratch is reclaimed by liveness sweeps (7.5.4). |
| Synthesising host entries into `getdents64` | Invents results and traps every directory read. Empty placeholders in the tree give `ls /` the same answer for free (8.3). |
| A canonicalisation cache shared across processes | Would save a few hundred `lstat`s per compile, but an inherited descriptor is visible to the program (descriptor counts, `close_range`, leak checks), and a file outside the exclave is state an edited tree makes wrong (14.5). |
| Caching host paths | A host directory can be replaced at any time. The one-step host check (7.4.4) gets most of the benefit without remembering anything. |
| Skipping the empty top-level directories at startup | The placeholders are how `ls /` lists the host's directories (8.3), and only reading a directory says it is empty: twelve reads per start in the gcc exclave. |
| Dropping `getpid` and `gettid` per trap | About 100 ns a trap, but a process-wide value is wrong in a `vfork` child while a parent's thread is in its handler (7.5.4), and the launcher has no thread-local storage. |
| A smaller first cache table | The cache's 256 KB table and 1 MB string area fault in as entries land, part of about 70 extra page faults per process; a smaller table trades them for rehashing. |

### 14.4 The environment

| Alternative | Why not |
|---|---|
| An environment allowlist | Users could not pass `CC`, `CPATH`, `MAKEFLAGS` or a CA bundle, and applied at every exec it would break `ldd`, libtool and `fakeroot`. Path-valued variables resolve inside the exclave, so passing them is safe (6.2). |
| The user's locale and time zone | Locale data is bound to its glibc's version, so `LANG` would work only where the exclave ships the locale and fall silently to `C` elsewhere; the zone would need two host-resolution rules. Four fixed values at the border (6.2) need none, and are what reproducible builds set. |
| Recording the maker's locale in the exclave | A manifest record for what a rule says. An exclave that wants another locale sets it in a wrapper script. |

### 14.5 The format and the tool

| Alternative | Why not |
|---|---|
| A generated index beside the manifest | Every record the launcher uses is readable from the tree in microseconds, and a tree edited without re-indexing would be silently wrong (6.3). |
| Layers at run time | A second root in the translator, a libc rule, a record naming another exclave's location and an unanswered listing question, to save disk. Composition is a copy at build time (11). |
| The tool fetching from archives | Acquisition has its own trust argument and failure surface; it is the step before the tool, `fetch/debs.py` and its siblings (10). |
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
above 4.0", in udocker's words, and udocker leaves it off.

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
`binfmt_misc` (LWN, 2026) that can override `PT_INTERP` with a
BPF-selected interpreter, registered by root. That accepts that
hermetic binaries need a substituted loader, through a privileged
mechanism; the launcher's wrappers and loader are the unprivileged
analogue, and the objection applies to exclave as to `LD_PRELOAD`: an
exclave is not a security boundary (3).

Each piece of the launcher, a no-libc loader that maps the real
`ld.so`, interpreter substitution at scale, hard-linked launchers for
identity, exists separately in nix-ld, uninative, sharun and the
tmp.0ut technique. This survey found no system that also installs a
syscall translator before the real loader runs.

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
| gVisor systrap | sentry | sentry | sentry | sentry | none, but a runtime | yes | image |
| bwrap, Guix userns, conty, junest | bind mounts | yes | yes | yes | user namespaces | no | yes |
| Docker, Podman | image | yes | yes | yes | daemon or user namespaces | yes | image |
| BPF `binfmt_misc` | kernel substitution | through the loader | no | no | root to register | no | yes |
| **exclave** | launcher at every executable's path, originals in `.real/` | translated | translated | passed through minus loader and libc variables; `PATH`, `LANG`, `TZ`, `SHELL` fixed | none | no | yes, `cp -a` |

exclave is the only row that is unprivileged, has no supervisor, covers
all four bindings and moves with a copy. Its nearest relatives are
gVisor systrap for the trap, CARE for pruning, and the wrappers of
15.4 for identity.

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
- [Bringing BPF to binfmt_misc, LWN 2026](https://lwn.net/Articles/1086947/)
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

In summary (16.8): a trapped `stat` costs 1.9 to 3.6 µs where the
host's costs 0.3; an untrapped syscall about 10 ns more than natively;
a `posix_spawn` about twice the native time; small compiles about a
third more; a compute-bound compile the same as natively.

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

**What a small compile traps.** `gcc -O0 hello.c` through an exclave
makes about 1 250 traps. 746 of them are `readlink`, almost all
answered `EINVAL` on a directory: glibc's `realpath` reads every
component of a path as a link, so a path *n* deep costs *n* traps, and
each trap walks the path again. This is why `realpath` is the most
expensive row of 16.8.

### 16.3 Untrapped syscalls and the filter

Every syscall runs the filter unless the kernel's action cache (5.11)
has proved the answer for its number constant, which it can only where
the answer depends on neither the instruction pointer nor an argument.
The filter's first stage is a binary decision tree on the
syscall number whose leaf for every number the rule does not single
out is `ALLOW` (7.4.2 gives the program's size and how many numbers
that is). The action cache proves those numbers allowed and skips the
filter for them; where the cache is absent an allowed syscall runs
11.7 instructions on average and 27 at most.

An untrapped `getppid` costs 53 to 55 ns against 43 to 45 natively,
and `read(-1)` 54 against 46; what is left is the kernel's seccomp
entry, which any filter costs. The install takes 75 to 100 µs, most of
it the kernel compiling and checking the program.
`test/filter_test.c`, in the gate's unit step, runs the program in an
interpreter against the rule written out separately, in 569 590 cases,
and asks of every number what the action cache asks.

Why a tree: a filter that tests the instruction pointer first makes no
number constant for the action cache, so an untrapped `getppid` costs
78 ns against 43, and 1.5 µs against 84 ns on CentOS 7's 3.10, which
interprets the filter. A linear allow-list ahead of the page check
brings `getppid` to 56 ns but doubles the install, to about 200 µs,
because the kernel builds its action cache by emulating the filter once
per number.

### 16.4 Process start

A `posix_spawn` of `/usr/bin/true` from inside an exclave costs about
twice the native time (2.0 times, alternated runs) and makes 550
syscalls. `perf` puts 78% of a spawn in the kernel: process creation,
`execve` and page faults (124 per spawn against 55 natively). At the
border the filter install adds 75 to 100 µs (16.3).

The launcher's part of a start is its startup (7.2), which reads each
empty top-level directory of the tree once to know it is a placeholder
(8.1 rule 1), twelve in the gcc exclave, and `lstat`s each identity
file once (8.4); the loader (7.3), which reads the program's notes
through the descriptor it maps from; and, in the parent, the exec
handler (7.4.5), which reads the head of every environment variable to
drop the launcher's own. It reads the heads with one `process_vm_readv`
for up to 256 variables rather than one call each, about a hundred
calls in a desktop session, and reads a variable on its own when the
batch cannot read it whole, at the end of a mapping.

A spawn traps little: glibc 2.39's `posix_spawn` makes two trapping
`rt_sigaction` calls and one trapping `rt_sigprocmask`, since queries
of a signal action do not trap (7.5.5). 100 000 spawns from one process
leave its RSS flat, +152 kB against +200 kB natively (17 item 4).

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
   a path against, the `own` and `host` records, identity files,
   volatile directories, the exclave's own directory and the working
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
   it maps from; an identity file is `lstat`ed once. A `posix_spawn` of
   `true` makes 550 syscalls rather than 679, within the run-to-run
   spread in time. Check: `exec_vectors` places a variable at the end
   of a mapping.
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
- A smaller first cache table (14.3).
- The one-step host check before 5.6, through an `O_PATH` open read
  back from `/proc/self/fd`: possible, and not built (16.6 item 4).

If overhead matters again, the next steps are the spawn, where `perf`
puts 78% in the kernel, so a profile with kernel symbols comes first;
then glibc's `realpath`, which costs *n* traps for a path *n* deep.

### 16.8 Measured results

Best of three, October 2026, on a machine running other work, whose
pace moved between whole runs (the native `posix_spawn` took 170 to
410 µs). The per-call rows are from `test/bench.py --launcher`; the
compile rows alternated native and exclave runs, so both saw the same
pace.

| Workload | native | exclave |
|---|---|---|
| `stat()`, three-component exclave path | 304 ns | 1.90 µs |
| `stat()`, seven-component exclave path | 346 ns | 2.46 µs |
| `stat()`, seven-component host path | 360 ns | 3.57 µs |
| `stat()`, relative name, working directory six deep on the host | 277 ns | 2.74 µs |
| `realpath()` of that working directory | 0.98 µs | 13.3 µs |
| `getppid()`, untrapped | 45 ns | 55 ns |
| `posix_spawn` of `/usr/bin/true`, against native | 1 | 2.0 times |
| 100 000 `posix_spawn`s from one process, RSS | +200 kB | +152 kB |
| thirty `gcc -O0 hello.c` | 0.56 s | 0.74 s |
| a 61-file project, `-O1 -c` each then link | 0.55 s | 0.74 s |
| CPU time of one `gcc -O0 hello.c`, `perf stat` | 19.0 ms | 24.2 ms |
| `gcc -O2 -c sqlite3.c` | 14.00 s | 13.75 s, identical object |
| syscalls for one `gcc -O0 hello.c`, all processes (`strace -f -c`) | 2 650 | 11 889 |

Thirty small compiles cost 32% more than natively, the 61-file project
35% more, and a small compile's CPU time 27% more. The compute-bound
compile runs within noise of native and produces an identical object,
also on the kernels that would force the speculation mitigation (16.5).
What is left of a small compile's overhead, by `perf` and `strace`:
about 1 250 traps at the 1.3 µs floor; five process starts, each more
the kernel's exec, page faults and process creation than the launcher's
code; and the launcher's own walk, 8% of the compile's CPU time, half
of it in canonicalisation.

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
of three, October 2026: `wrap` of the unwrapped tree 0.85 s, `check`
0.77 s and `hash` 0.63 s, most of each the tree hash. The same listing
hashed through Python's `hashlib`, whose BLAKE2b is vectorised, took
0.53 s (18 item 6).

### 16.9 Reproducing

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
   or the rule's. They fall into six groups:
   - *signals and threads*: `SA_ONSTACK` handlers that trap, a FIFO
     `open` interrupted by `SIGINT` or left by `siglongjmp`, Go's
     goroutines, 64 threads trapping at once and threads trapping while
     another spawns, and the scratch pool under contention
     (`test/scratch_test.c`);
   - *spawning and exec*: 100 000 `posix_spawn`s with RSS measured (16),
     `fexecve`, `memfd`
     and unlinked files, scripts with and without `#!` and with `#!` lines
     the kernel's buffer cuts, `PATH` search,
     faulty argument vectors, unusual images, and the identity a program
     exec'd from inside gets;
   - *the launcher and its filter*: a blocked or sent `SIGSYS`, older
     and newer launchers nested and side by side, a program installing
     its own filter, the speculation state, and an adversarial program
     (`adversarial`);
   - *paths and the border*: working directories on either side, host
     symlinks, the read-only matrix of 8.2, unix sockets, `PATH_MAX`,
     `openat2`'s `resolve` flags, `/proc` magic links, those to objects
     with no path among them, and the `*xattrat`
     calls;
   - *programs that matter*: the loader, `dlopen`, locales and gconv,
     Rust and Go, built outputs run inside, a byte-for-byte comparison
     with a host compile, gdb, and a `noexec` mount;
   - *ownership, the log and the tool*: ownership failing closed, the
     log's names and escapes, the log's path refused when relative or
     inside the exclave, a link's text read as stored, the three package readers, `wrap`'s
     refusals, pruning, `check`, and a directory in the pre-rename
     `.can/` layout refused by name by every command.

   The tests in `test/run.py` say what each asserts, in their
   docstrings and their failure messages.
5. **Kernel matrix.** Docker's default seccomp profile stands for the
   environment where user namespaces are blocked. VMs run kernels 3.10,
   4.15, 4.18, 5.4, 5.10, 5.15, 6.1, 6.6 and 6.14, and an emulated
   aarch64 row runs 6.8; the results are in 12.1. The kernel source a
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
   | signals | the `SA_ONSTACK`, FIFO, `SIGINT` and `siglongjmp` cases |
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
   never accepted silently. A limitation is measured the same way
   before it is fixed, by an exerciser run in both worlds.

**What implements each item.**

| Item | Implementation |
|---|---|
| 1 | `test/oracle_ns.py`: 20 shell workloads under `bwrap` and under the launcher, compared, plus the read-only matrix program (`test/progs/ro_matrix.c`) under `bwrap` against its own expectations |
| 2 | `test/oracle_resolve.py`: 3 000 paths over a random maze, resolved by `openat2(RESOLVE_IN_ROOT)` on the tree and by the launcher from inside |
| 3 | `test/manifest_test.c` and `test/grammar_test.py`: two properties on random byte strings asked of the command's `format` (a value in canonical form is canonical, and one with every byte escaped is rewritten to it); the command's parser and the launcher's compared on manifests, their mutations and the line an error names. `test/filter_test.c` runs the filter against the rule of 7.4.2; `test/tool_test.c` the command's BLAKE2b against RFC 7693 and `hashlib` |
| 4 | `test/run.py` with `test/progs/`: 79 named tests |
| 5 | `test/syscalls.py`, `test/docker_profile.py`, `test/matrix.py` |
| 6 | the tests of item 4 |
| 7 | `test/progs/probe.c` and `test/oracle_syscalls.py`; `test/exercise.py` for new cases |

`test/syscalls.py` classifies every syscall in the kernel's table for
this machine (x86-64's `unistd_64.h`, or the generic table aarch64
uses) up to the filter's ceiling. It fails on one it does not know. It
names any syscall above the ceiling as a note, since the filter traps it
and the handler answers `ENOSYS` until it is classified (7.4.2). It
requires the trap list in `src/filter.c` to equal its own, and the
syscall numbers in `src/sys.h` to be the kernel's.

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

**Requirements.** The build needs gcc, and the static C library for the
command (Ubuntu's `libc6-dev`), and `scripts/install-uv` needs curl or
wget. Every Python program, `unpack`, the fetchers and every driver,
runs on the pinned Python uv installs into the checkout, and the code
checks' ruff, ty, shellcheck, shfmt and taplo come from `uv.lock` the
same way; none is taken from the machine. The namespace oracle, the syscall probe, the
Docker profile run and the exerciser need `bwrap` (bubblewrap) and
unprivileged user namespaces; the resolution oracle needs `openat2`
(Linux 5.6). The suite uses `strace`, `gdb`, Go and `rustc`; a test
whose tool is missing skips and names it. The gate's plain-label run
needs AppArmor's `aa-exec` and is left out without it. Optionally,
`aarch64-linux-gnu-gcc` builds the aarch64 launcher and command, and the matrix
needs QEMU with KVM and `cloud-image-utils` (`qemu-system-arm` and the
AAVMF firmware for the emulated row). Where `bwrap` cannot create a user namespace (Ubuntu
23.10 and later from a plain terminal, most containers), an oracle or
the probe says it cannot run and exits 0, and the gate prints that step
as SKIP rather than ok.

**Running it.** From a clean checkout, four commands reach a passing
gate:

```sh
scripts/install-uv
scripts/build
scripts/inputs ~/.cache/exclave-inputs
D=~/.cache/exclave-inputs
EXCLAVE_TEST_INPUTS=$D scripts/gate $D/gcc13.exclave $D/alpine.exclave $D/f42.exclave $D/clang.exclave
```

`scripts/inputs DIR` makes the gate's four exclaves: Ubuntu 24.04's
gcc-13 closure, Alpine 3.21's gcc, Fedora 42's gcc, and Ubuntu 24.04's
clang-18 closure. It also makes what the example runs take: the
packages `test/realsoft.py` builds with, CentOS 7's glibc for the sysroot of 9, the arm64 gcc-13 closure,
Docker's default seccomp profile, and the source tarballs of
`test/realsoft.py` and `test/bench.py`. Packages come through the
fetchers of `fetch/`, which verify each download against the repository
index's checksum and cache it under `~/.cache`. Every other third-party
file is pinned by its BLAKE2b-256 in the script. An item `DIR` already
has is skipped, and whatever is missing is fetched again. The
repository holds no third-party input.

**The gate** (`scripts/gate [--full] [--jobs N] EXCLAVE...`) is the check run
before a commit. It runs the steps below that the change can affect, the
uncommitted paths or, in a clean tree, the last commit's: a launcher
source, `scripts/build`, `scripts/lib.sh`, `LICENSE` or `.python-version` runs every step and
says the matrix is due, and so does the matrix's own code; the gate
itself runs every step; the command, `tool/`, runs the unit step, the
suite in both orders, the oracles, the probe, the unpack oracle and the
Docker profile run, and says the matrix is due, since the VMs run it;
`unpack/` runs the suite in both orders and the unpack oracle; the suite or its programs add the random
order; a test or a helper runs the steps that use it; documents,
scripts and settings run the code checks alone; and a path the rules do
not know runs everything. `--full` runs every step whatever changed.
The steps run four at a time, or `--jobs N`, so that the machine stays
usable, each with its own log under `build/gate/`, one line each with
its time, ok, SKIP or FAIL:

- the code checks, `scripts/check`: ruff, ty, shellcheck, shfmt and
  taplo over the Python, the shell scripts and the TOML; over the C,
  clang-format (`.clang-format`), gcc's strict warnings as errors (the
  flags `scripts/lib.sh` gives every C build: the launcher for each
  architecture and as `build/launcher-old`, the command for each
  architecture, and the unit tests) and clang-tidy with its static
  analyser on the launcher for each architecture, on the command and on
  the unit tests (`.clang-tidy`, `tool/.clang-tidy`);
- the unit step: the manifest parser, the grammar comparison, the
  filter test, `test/syscalls.py`, the scratch-pool test, the `#!` line
  test, the CPU level test and the command's BLAKE2b test, each built from the current sources for the host under
  AddressSanitizer and UndefinedBehaviorSanitizer, where a finding
  exits 99, which no test answers;
- the stack budget of both launchers (the aarch64 one when it is
  built);
- for every exclave given: the suite in the given order and in a
  random order, the resolution oracle, the namespace oracle and the
  syscall probe;
- for the first exclave, the suite once more under the plain
  terminal's AppArmor label (`aa-exec -p unconfined`), where user
  namespaces are denied (12), and once on `build/launcher-debug`,
  the launcher with gcc's undefined-behaviour checks,
  each a trap instruction, since the launcher links no runtime to
  report one;
- the unpack oracle, `test/unpack_oracle.py`: `build/exclave-asan
  unpack` and `scripts/unpack` given the same `.apk` files, each into
  an output of its own, and compared by exit status, standard output
  and the directory each leaves: every entry's kind, mode, link text,
  contents, hard-link group and, from the archive, modification time.
  The sets are generated (the gzip and DEFLATE forms zlib accepts and
  refuses, some built by hand; the tar forms; conflicts and `Replaces`;
  the synthesis an Alpine set reaches; the refusals), and with
  `EXCLAVE_TEST_INPUTS` Alpine's own packages too; a set the command
  does not read or synthesise yet must be refused by it alone;
- when `EXCLAVE_TEST_INPUTS` names the directory `scripts/inputs`
  filled, the Docker profile run on every exclave.

Every driver runs `build/launcher` on a copy of its own, so an exclave
given to the gate is never run as it is nor written. The suite wraps a
copy from the given exclave's tree. The other drivers take
`tree.fresh_exclave`, a copy relinked with `build/launcher`, because an
exclave carries the launcher it was wrapped with. Each test has a
budget of 30 s, against a slowest test of about 2 s natively, so a test
that crawls fails instead of stalling the gate. The exit status is the
number of failed steps. On the reference machine the whole gate, on the
four exclaves with their fixtures and with the Docker profile, four
steps at a time, takes 76 s (measured October 2026).

**The suite** (`scripts/test --exclave EXCLAVE`, or `--tree DIR` for an
unwrapped tree) makes an exclave under its work directory, compiles
`test/progs/` with the tree's own C compiler, and runs the named tests.
`-k NAME` runs one test, or every test whose name contains a substring.
`--order reverse` and `--order random` (with `--seed`) change the
order. `--budget` sets the per-test limit. `--keep` keeps the work
directory. `--launcher` tests another build in place of
`build/launcher`, `build/launcher-debug` in the gate. The exit status is the number of failures.

The Go regression is built static with cgo off, by the host's `go`, or
on the reference machine for a matrix VM's machine. It runs as a host
program, twice: once as `go` links it, and once linked from `0x10000`,
as Go's aarch64 linker lays an image out (13 item 24). It skips where
neither build exists.

**The fixture.** The suite runs on the exclave pruned to what the suite
itself touches. The first run on an exclave logs every invocation it
makes inside it (`EXCLAVE_LOG`). If that run has no failure, it prunes a
copy to those logs with `exclave prune` and keeps it under
`build/fixtures/` if the copy passes the static check, so a partial log
never makes a partial fixture. There is one fixture per exclave, named
by its hashes file and stamped with a hash of the sources that decide
what the tests touch: `test/run.py`, `test/tree.py`, `test/progs/`,
`exclave/` and the launcher's. A run with no fixture uses the full
exclave and makes one, removing that exclave's older ones. A fixture
with another stamp is still used, since a change to the sources rarely
changes what the tests touch: when every test passes the stamp is
renewed, and a test that fails runs again on the whole exclave, whose
answer decides, and the stale fixture goes for the next run to remake. On
the reference machine the fixtures of the gcc, clang, Fedora and Alpine
exclaves hold 1 070, 1 062, 1 269 and 548 files, a sixth to a quarter of
each exclave's, counting every entry of `tree/` that is not a directory
or a symlink to one, originals included. On the fixture one suite takes
17 s on the reference machine, on the whole exclave 30 s.

**The probe** (`test/progs/probe.c`, `test/oracle_syscalls.py`) puts the
whole trapped-syscall surface in front of the kernel. It crosses the 61
trapped path syscalls and six descriptor-addressed ones with every flag
that changes resolution, 66 path forms over a random maze and the `*at`
descriptors. One program issues each case through `syscall(2)` under
`bwrap`, with 8.1's visibility rule spelt in `bwrap`'s terms, and under
the launcher, and the answers are compared line by line. A difference
fails unless the list `EXPECTED` names its reason: the oracle's own
construction, a stated limitation (13 items 29 and 41), or what an
older kernel lacks or decided differently, such as `truncate` checking
the mount before the permission on 6.1 and earlier (6.14 checks the
permission first). The handler answers as the newest kernel does. On
the reference machine 21 732 cases run on each of the gate's four
exclaves and none differ; no matrix row has a difference either.
`test/oracle_syscalls.py`'s module docstring holds the argument kinds,
the path forms, `openat2`'s `EAGAIN` retry and the accepted differences.

The probe does not cover signals, threads, `vfork`, nesting, the
border, `getdents` (which is not trapped), or the host's own mount
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
for more), all nine x86-64 rows in about eleven minutes. It runs when the
gate says a change reaches the VMs: a launcher source, the command, the
pinned Python, or the matrix's own code; other changes leave the
kernels' answers as they were. Each VM
boots its distribution's cloud image under QEMU with KVM behind a
copy-on-write overlay; cloud-init installs strace and, where the
distribution has it, bubblewrap. The exclave, the test tree, the
checkout's launcher and command and the pinned Python are copied in,
`unpack` installed into that Python in editable form as `uv sync`
installs it here (a `.pth` naming the checkout), and the exclave is
relinked there by the command, which runs as it is on every kernel of
the matrix, CentOS 7's 3.10 included. The
Python is built for the VM's machine and libc and
installed by the repository's uv: the glibc builds need only glibc 2.17,
so CentOS 7 runs the same Python as Fedora 42, and Alpine takes the musl
build. A VM's own `python3`, if it has one, is never used.
Each row runs the suite on the full exclave with a budget scaled to the
VM. Where `bwrap` works it then runs the two oracles, the probe and,
given the profile, the Docker profile run, first lifting the AppArmor
sysctl that denies unprivileged user namespaces on Ubuntu 24.04's
image. Two checks run outside the suite: a program built by the
exclave's gcc on a `noexec` tmpfs the VM mounts as root, run by the
VM's shell, the positional entry and the exclave's shell; and the
output of `test/sysroot.py` run natively. The results go to
`build/matrix-results.md` and are tabulated in 12.1. The x86-64 rows
take about ten minutes and are run before a launcher change is
committed.

**The emulated arm64 row** (`scripts/matrix --exclave EXCLAVE --only
noble-arm64 --debs-arm64 DIR [--docker-profile FILE]`) boots Ubuntu
24.04's arm64 cloud image under `qemu-system-aarch64 -M virt -cpu max`
with TCG and the AAVMF firmware, since user-mode emulation has no
seccomp and the reference machine has no KVM for another architecture.
It carries the aarch64 launchers, which `scripts/build` builds when
`aarch64-linux-gnu-gcc` is installed, and the arm64 packages, and makes
the gcc exclave inside the VM, since an exclave is wrapped on its own
architecture. A fresh VM has no fixture, so the suite runs on the full
exclave with logging, which makes the row long (12.1); it runs when
asked, not in the gate, and making it shorter is in 18.

`test/vm_run.py --script SH FILE...` boots the same x86-64 rows and
runs a script beside the files it is given, for exclaves made to ship,
where the suite does not apply. The two VM drivers are the one
exception to the rule that only `scripts/inputs` downloads: they fetch
each cloud image once into `~/.cache/exclave-images`, and the VMs
install their packages through cloud-init.

**The example runs** (`scripts/examples EXCLAVE`) need inputs and time
the gate cannot afford. Each runs when its input variable is set:

- `EXCLAVE_TEST_SRC`: `test/realsoft.py` builds zlib, Lua, SQLite and
  re2c inside the exclave and on the host, and compares the results and
  the times.
- `EXCLAVE_TEST_SQLITE`: `test/bench.py` produces the performance table
  of 16.
- `EXCLAVE_TEST_RPMS`: `test/sysroot.py` builds against a CentOS 7
  glibc held as a data directory (9).
- `EXCLAVE_TEST_DEBS_ARM64`: the emulated aarch64 row, with
  `EXCLAVE_TEST_DOCKER` adding the Docker profile run.

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
  shared exclave's manifest, hashes file, and every tree entry's path,
  size, mode and mtime with what setup made, and fails a test that
  changed them. `--order random`, `--order reverse` and `-k NAME` pass
  like the given order. Suites run side by side in the gate, so a name
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

1. **Exclaves of real packaged software.** The exclaves built so far
   are compilers and the tool itself. The next exclaves are of real
   packaged software that people run, and they decide which of the
   tool's synthesis gaps close (10.1): `unpack` does not generate
   locales, GLib schemas, MIME or font caches, or Python bytecode, and a
   gap closes when a real exclave needs it, as a rule in the synthesis
   table rather than an option. Failed opens in an `EXCLAVE_LOG` show
   where an exclave lacks one.
2. **Releases.** There is no release, version number or continuous
   integration yet. Until there is, the commit gate (17) and the kernel
   matrix (12.1) run on the reference machine, and nothing promises
   compatibility between commits (2).
3. **aarch64 kernels with 16 KB or 64 KB pages.** The loader rounds to
   the kernel's page size and the launcher's own segments are 64 KB
   aligned, but no such kernel has run an exclave (13 item 43). A
   matrix row on a 64 KB-page kernel, Ubuntu's
   `linux-image-generic-64k` for one, would turn this into a measured
   fact.
4. **The emulated arm64 row's speed.** The arm64 row runs under QEMU's
   TCG emulation at about a tenth of native speed (12.1), so it runs
   when asked rather than at every commit. A faster row, on native
   aarch64 hardware or a lighter fixture, would let it run as often as
   the x86-64 rows.
5. **Hosts the matrix has not covered.** Snap-confined terminals,
   gVisor-based CI, WSL1 and SELinux `execmem` policies are listed as
   untested in the portability envelope (12); each is a matrix row to
   add, or a limitation to state.
6. **The command's hashing.** `wrap`, `check` and `hash` spend most of
   their time on the tree hash, and the command's BLAKE2b, written
   plainly from RFC 7693, is slower than a vectorised one such as
   Python's `hashlib` (16.8). A faster implementation keeps every
   recorded hash; another hash function would be a change of the format
   (6.4, 19.1).
7. **`unpack` in the command.** `exclave unpack OUT APK...` makes from
   Alpine package files the tree `scripts/unpack` makes, as the unpack
   oracle (17) compares on generated sets and on Alpine's own: the
   extraction rules of 10.1, busybox's applet links, and the synthesis
   rules a set of `.apk` files can reach. It does not report
   dependencies yet, nor read `.deb` and `.rpm` files, whose zstd, xz,
   `ar` and cpio it lacks; a set that needs the CA bundles or an
   `ld.so.cache` synthesised, a GNU long name or a global PAX header is
   refused rather than unpacked differently. Whether the command takes
   unpacking over, leaving Python to the fetchers and the tests, is
   open; zstd and xz would come from libraries or from their
   specifications, RFC 8878 and the xz format.

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
- **Hashes are BLAKE2b-256, and the hashes file records and never
  locates**: locating belongs to the step before the tool (6.4).
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
- **One world inside an exclave**: a host world for programs on host
  paths would break `make check` whenever the two libcs differ (7.4.5).
- **Read-only by refusal, in the kernel's order of checks, not by
  `chmod`**: careless copies lose modes; refusal depends on nothing
  (8.2).
- **Symlinks resolve in virtual space; identity files' host links are
  resolved once at startup**: a host link into `/usr` must never reach
  the host's `/usr` (8.4).
- **The environment passes through, minus the loader and libc
  variables that name host files, with four constants set at the
  border**: locale data is bound to its libc, the time zone is not a
  host fact, and an allowlist would stop a user passing `CC` (6.2).
- **One run-time knob, `EXCLAVE_LOG`, an absolute host path outside the
  exclave**; `EXCLAVE_EXEC`,
  `EXCLAVE_EXECFN` and `EXCLAVE_COMM` are the launcher's own protocol,
  honoured by a wrapper only under an inherited filter (6.2, 7.4.5).
- **What the launcher derives from the tree fails closed and loud**: a
  tree it cannot read correctly is refused by name (6.3).
- **A fixed syscall page at `0x7fe00000` identifies the launcher's own
  syscalls**: the same in every process, above every linker's program
  images; a bare syscall instruction appears only in the bootstrap, the
  version probe and the restorer (7.4.2).
- **The filter's trap set is versioned; an equal or newer inherited
  filter is reused, an older one stacked under**: no syscall a launcher
  needs translated goes untrapped, and a trap it does not know is
  `ENOSYS`, never re-issued (7.4.2).
- **The filter answers by number first and is installed with
  `SECCOMP_FILTER_FLAG_SPEC_ALLOW`**: the kernel's action cache allows
  most syscalls without running it, and an exclave is not a security
  boundary (7.4.2).
- **`clone3` is refused with `ENOSYS`**: honouring it with a prepared
  child frame corrupted the FPU state of new threads (7.5.5).
- **A program's `rt_sigaction` install traps; its queries do not**
  (7.5.2).
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

- **The tool takes files and never fetches**: acquisition has its own
  trust argument; `fetch/` holds examples of that step (10).
- **The tool's input is a directory holding `tree/`, and `unpack` is
  the step before it**: what made the tree, package files, `tar` or a
  build, is not the tool's concern, so `unpack` is a Python package of
  its own, apart from the C tool (10, 10.1).
- **Building software is the build system's job**: an exclave of built
  software is a staging directory plus runtime packages, with no
  recipes (10.2).
- **Maintainer scripts are never run; their effects are synthesised
  from one table every reader shares**: a tree whose scripts must run
  comes from outside and is wrapped (10.1).
- **Package readers share one interface and are chosen by the file**
  (10.1).
- **The tool is static C, one file per architecture carrying its
  launcher**: it runs with nothing beside it, and ordinary C on the C
  library is enough, since unlike the launcher it never runs inside
  another program (10.5).
- **One pinned Python, never the machine's**, for `unpack`, the
  fetchers and the tests: uv, pinned with a checksum per architecture
  in `scripts/install-uv`, installs the version `.python-version` names
  into the checkout, and every script and the matrix VMs run that one
  (10, 17).
- **The Python is ruff- and ty-clean**: `scripts/check` runs ruff, ty,
  shellcheck, shfmt and taplo from `uv.lock`, and an ignored rule or a
  suppression carries its reason (17).
- **The C is clang-formatted and clean under gcc's strict warnings and
  clang-tidy**, the launcher and the command for both architectures;
  clang-format and clang-tidy come from `uv.lock`, gcc is the one that
  builds them, and the build itself does not stop on a warning, since a
  newer gcc may find something new. A check `.clang-tidy` or
  `tool/.clang-tidy` turns off carries its reason (17).
- **`wrap` checks before it touches the tree**: a refused exclave is
  left unwrapped (10.1, 10.3).
- **An exclave is wrapped on a machine of its architecture**: the static
  check asks the tree's own loader for its directories (10.3).
- **The tool applies `host` records as the launcher does**, by longest
  prefix (10.3).
- **A foreign ELF object is a warning, and a tree stays readable by its
  owner**: a tree no one can read can be neither hashed nor copied
  (10.1, 10.3).
- **The dynamic check and pruning read `EXCLAVE_LOG` files**: what a
  traced run touched is the evidence (10.3, 10.4).
- **`prune` keeps the packages' licence texts**: a pruned exclave passed
  on carries the packages' terms (10.4, 13 item 47).
- **No options**: the commands take paths and `format --check` is the
  one flag; a rule or a stated limitation is preferred to a flag, a
  mode or a manifest key (10).

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
- **The emulated arm64 row runs when asked**, not at every commit (18).

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

