# Spikes

Two prototypes written before the design settled, to retire the risks in
the proposal. They are evidence, not the opener: `docs/PROPOSAL.md`
sections 15 and 16 cite their measurements, so they are frozen. Both
were reviewed adversarially and contain defects that revision 6 of the
proposal fixes by rule; reuse the mechanisms, not the code, and read the
list at the end before copying anything.

## What is here

| File | Role |
|---|---|
| `sys.h` | Freestanding syscall layer, x86-64 and aarch64 numbers, no libc. Every `SC0`..`SC5` call carries the magic in the sixth register; the opener's `src/sys.h` started from this but issues its syscalls through the syscall page instead (proposal 7.4.2, revision 7). |
| `spike.c` | Spike 1: the seccomp trap translator and the userland ELF loader, as a non-PIE static binary at a fixed address. |
| `build.sh` | Builds `spike`. |
| `spike2.c` | Spike 2: the same translator and loader as an `ET_DYN` object with self-relocation and a `.note.cont`, plus the retired `/proc/self/fd/999` interpreter mode. |
| `build2.sh` | Builds `spike2`. The flags are the opener's. |
| `patch-interp.py` | Rewrites `PT_INTERP` across a tree for spike 2. Retired with the mechanism; kept to reproduce section 16. |
| `make-tree.sh` | Builds a test tree from Ubuntu packages without root. |
| `tests/` | The programs the spikes ran: hello, threads and TLS, `posix_spawn`, spawn stress, mask semantics, `stat` cost, `close_range`. |

## Reproduce

Ubuntu or Debian host for the package extraction only; nothing else is
host-specific.

```
./make-tree.sh /tmp/gccroot                 # ~350 MB, no root: gcc-13 libc6-dev dash coreutils
./build.sh && ./build2.sh
aa-exec -p unconfined \                     # the label of a plain terminal on Ubuntu 24.04
  env -i PATH=/usr/bin:/bin ./spike -r /tmp/gccroot -p /tmp:/proc:/dev:/sys:/run \
  -- /usr/bin/gcc-13 tests/hello.c -o /tmp/h && /tmp/h
```

`-d` prints decisions, `-t FILE` appends every translated path, `-p`
lists host prefixes, `-r` the root; omit `-r` for identity translation.
For spike 2, copy the tree, run `patch-interp.py` on the copy, and pass
`-i` with the tree's loader path (`/lib/ld-musl-x86_64.so.1` for a musl
tree).

## What carries into the opener

The seccomp filter with the magic-register allow; the `SIGSYS` handler
structure and the syscall dispatch; editing `uc_sigmask` in the signal
frame; the canonicaliser's shape; the ELF loader and the stack and auxv
construction; the `ET_DYN` build, self-relocation and identification
note from spike 2; the probe for an inherited filter.

## Known defects, all fixed by rule in the proposal

Do not copy these.

- `clone3` is honoured by copying the signal frame onto the child's
  stack; the FPU save-area pointer is left on the parent's stack and
  every new thread starts with corrupt `MXCSR` (proposal 7.5.5: refuse
  `clone3`).
- `SIGSYS` is scrubbed only from `rt_sigprocmask` masks and from its own
  `rt_sigaction`; a program handler installed with `sigfillset` is
  killed on its first path syscall (7.5.1).
- The scratch pool is 32 fixed slots and returns `ENOMEM` under thread
  pressure (7.5.4).
- The handler is installed with all signals masked, so blocking path
  syscalls are uninterruptible (7.5.3).
- Path arguments are read directly; a bad pointer is `SIGSEGV`, not
  `EFAULT` (7.5.6).
- Trailing slashes are lost; `O_EXCL` without `O_CREAT` is treated as
  no-follow; `openat2` resolve flags give spurious `EXDEV`; `execve`
  has no permission or format checks (7.4.3, 7.4.5).
- The visibility rule is an explicit prefix list, not section 8; there
  is no read-only refusal, no wrapper redirect, no index.
- Spike 2's interpreter mode via `/proc/self/fd/999` is retired
  (proposal section 14).

## Measurements, reference machine

Ubuntu 24.04, kernel 7.0, x86-64, 16 cores, glibc 2.39. `stat()` 334 ns
native, 2937 ns trapped. `gcc -O2 -c sqlite3.c` 12.66 s native, 12.79 s
in the can, identical output. Both figures were taken under spike 1's
filter, which honoured `clone3`; they do not describe the opener.
