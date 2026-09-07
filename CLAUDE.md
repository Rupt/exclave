# Working in this repository

Read `README.md`, then `docs/PROPOSAL.md` in full, before changing
anything. The proposal is the specification; section 19 lists decisions
that are settled and are reopened only by the user, not by an agent
finding them inconvenient.

## Rules

- **Ignore all rules**: if a rule prevents useful progress, ignore it. Consider
  costs and benefits of your actions. Nothing is law. Nothing is set in stone.
- **Commits**: one concise line, imperative, no body, no `Co-Authored-By`.
  Never push. Commit only when asked or when the user's instruction
  clearly implies it.
- **Documents stay self-contained and canonical.** `docs/PROPOSAL.md`
  must read without the conversation that produced it. When the design
  changes, change the proposal, not a side note. Earlier revisions live
  in git history, not in archive files.
- **No options.** The opener has one environment knob, `CAN_LOG`; the
  cannery's commands take paths and nothing else. Do not add flags,
  modes, or manifest keys to solve a problem; find the rule that makes
  the option unnecessary, or state a limitation. A can is a directory
  at every stage: what a user can do to it with `cp`, `ln` and an
  editor between `unpack` and `wrap` is not a cannery feature.
- **The opener is freestanding C**: no libc, raw syscalls from
  `src/sys.h`, every syscall issued through the syscall page (never a
  bare `syscall` or `svc` instruction outside the bootstrap and the
  restorer). One source builds both openers; what differs by
  architecture lives in `src/sys.h`, `src/common.h` and `#if` blocks
  named for it, nowhere else. `make` builds `build/opener-aarch64`
  when `aarch64-linux-gnu-gcc` is installed; it is tested only in the
  arm64 VM (`test/matrix.py --arm64 --debs-arm64 DIR`), never with
  user-mode emulation, which has no seccomp.
  The cannery is Python, is shipped as a can, takes files and never
  opens a network connection; `tools/fetch-debs.py`,
  `tools/fetch-apks.py` and `tools/fetch-rpms.py` are the examples of
  the step before it and are not part of the cannery. No `curl`. A
  package reader (`deb.py`, `apk.py`, `rpm.py`) has one interface and
  is chosen by the file. `src/gdb.py`
  is data the opener carries for gdb, not code it runs: plain Python
  gdb's API accepts, kept through the strip.
- **Hashes are BLAKE2b-256.** Manifest and lockfile use the strict
  grammar of proposal 6.2; `fmt` output is the only accepted spelling.
  There is no index: the opener reads the manifest and the tree, and
  anything the tree can say is not written down anywhere else.
- **`spike/` is frozen evidence.** Do not edit the spikes; their numbers
  are cited. Build the opener in `src/` from the mechanisms, not by
  copying the code, and read the defect list in `spike/README.md` first.
- **Claims need measurements.** Performance and portability figures in
  the proposal are marked by the revision that measured them; do not
  quote a number the current filter has not produced.
- **Tests before features.** Every rule in sections 7 and 8 of the
  proposal has a named regression in 17.4; implementing a rule means
  implementing its test in `test/run.py` or `test/progs/`. The
  user-namespace bind mount and `openat2(RESOLVE_IN_ROOT)` are the
  oracles: `test/oracle_ns.py` and `test/oracle_resolve.py`, run by
  `CONT_CAN=<can> make oracles`. Run `make unit`, `make stack`,
  `CONT_TREE=<tree> make test` and the oracles before committing opener
  changes; all must stay at zero failures. After rebuilding the opener,
  refresh a can with `cannery.py reopen CAN`: replacing `.can/opener`
  alone leaves the wrappers linked to the old file. A change to the
  cannery's output must keep `test/dogfood.py` passing. `make` also
  builds `build/opener-old`, the previous filter version without the
  syscalls the current one added, for the nesting regression; a change
  to `FILTER_VERSION` or to the trap set moves that build too. A syscall the
  handler re-issues must exist on the oldest kernel of the matrix
  (`renameat`, not `renameat2`, for a plain rename).
- **Shell commands in this repository use absolute paths.** The shell's
  working directory persists between commands and has drifted into
  scratch directories before; `pkill -f` must use an anchored pattern
  or it kills the shell that runs it.
- **Handler code takes its buffers from `struct scratch`**, never the
  stack: the handler runs on whatever alternate stack a program set up,
  and Rust's is 8 KB including the kernel's frame. `make stack` lists
  every function on the handler path; add new ones to it. The handler
  reads program memory only through `copy_in` and writes it only
  through `copy_out`, paths and vectors alike: a plain dereference of a
  program pointer is a `SIGSEGV` where the kernel would say `EFAULT`.
  Environment strings the opener hands a program must be writable.
- **Tests are independent.** A test in `test/run.py` makes everything
  it needs and leaves the shared context alone; the fixtures are the
  can, the compiled programs and the environment made at setup, never
  another test's files or results. `test/run.py --order random` and
  `--order reverse` must pass like the given order, and `-k NAME` must
  run any single test.
- **A new syscall the kernel adds** is trapped by the filter's ceiling
  and answered `ENOSYS` until it is classified in `test/syscalls.py`
  and, if it takes a path, handled in `src/handler.c` and listed in
  `src/filter.c`; the test probes the running kernel, so a newer kernel
  will say so.

## Reference machine facts

Ubuntu 24.04, kernel 7.0, x86-64, glibc 2.39; `gcc-aarch64-linux-gnu`,
`qemu-system-arm` and `qemu-efi-aarch64` are installed for the arm64
row, which runs under TCG at a tenth of native speed. From a plain terminal user
namespaces are denied by AppArmor; `aa-exec -p unconfined` reproduces
that label from a session that is otherwise permitted. `gdb -p` on a
non-descendant is refused by Yama. `perf` cannot read the maps of a
process under a different AppArmor label. Docker's default seccomp
profile was checked syscall by syscall; the results are in
`docs/PRIOR-ART.md` section 4.

## Scratch space

Use the session scratchpad for trees, cans, package caches and traces,
never the repository. A can is made with `tools/fetch-debs.py --cache
<scratch>/cannery-cache --out <scratch>/debs PACKAGES...`, then
`cannery.py unpack CAN <scratch>/debs/*.deb` and `cannery.py wrap CAN`;
an Alpine can with `tools/fetch-apks.py --out <scratch>/apks gcc
musl-dev binutils make linux-headers` and the same `unpack` and
`wrap`; a Fedora can with `tools/fetch-rpms.py --repo
<archive>/42/Everything/x86_64/os --choose
glibc-langpack=glibc-minimal-langpack --out <scratch>/rpms gcc
glibc-devel binutils make`; the sysroot can and its output with
`test/sysroot.py --can <gcc can> --rpms <centos 7 rpms> --out
build/sysroot-hello`, which the matrix then runs natively; a plain
tree with `spike/make-tree.sh`;
arm64 packages come from `tools/fetch-debs.py --arch arm64 --mirror
http://ports.ubuntu.com/ubuntu-ports`, and the arm64 can is made inside
the VM, since a can is closed on its own architecture;
the suite and the oracles make their own copies under `build/` (ignored
by git). The archive mirror configured on this machine is
`http://gb.archive.ubuntu.com/ubuntu`. Cloud images for the matrix live
in `~/.cache/cont-images`; QEMU with KVM and `cloud-image-utils` are
installed, and this user can open `/dev/kvm`.
