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
  oracles: `test/oracle_ns.py` and `test/oracle_resolve.py`. The commit
  gate is `test/gate.sh CAN...` with the gcc, Alpine, Fedora and clang
  cans (`CONT_CACHE=<cache>` adds dogfood): the unit tests, the stack
  budget, the suite on every can in two orders, the oracles, the
  syscall probe and the Docker profile, every step in parallel on
  copies, under a minute; it must
  stay at zero failures, and `test/matrix.py --can <can>` (eight
  minutes) before committing opener changes. A test asserts what the
  tree says, never what Debian says: the compiler, the shell and the
  file behind it, where a tool lives and the libc come from
  `test/tree.py` and `tree_facts`, and a can kind that cannot answer is
  a skip that prints its reason. The suite runs on the can pruned to
  what the suite touches, made by the first run on a can and kept under
  `build/fixtures/` by the can's lock and the test sources; a new test
  that touches a file the fixture lacks fails once, and the next run
  remakes the fixture. After rebuilding the opener,
  refresh a can with `cannery.py reopen CAN`: replacing `.can/opener`
  alone leaves the wrappers linked to the old file. A change to the
  cannery's output must keep `test/dogfood.py` passing. `make` also
  builds `build/opener-old`, the previous filter version without the
  syscalls the current one added, for the nesting regression; a change
  to `FILTER_VERSION` or to the trap set moves that build too. A syscall the
  handler re-issues must exist on the oldest kernel of the matrix
  (`renameat`, not `renameat2`, for a plain rename).
- **The kernel is the oracle for the handler's answers.**
  `test/oracle_syscalls.py` runs every trapped syscall with every path
  form under `bwrap` and under the opener and compares them case by
  case. A difference is fixed in the handler, in the kernel's order of
  checks (`fs/namei.c` is the reference), or listed in `EXPECTED` with
  the rule that makes it right; it is never accepted silently, and the
  read-only rule of 8.2 is stated in that order.
- **Shell commands in this repository use absolute paths.** The shell's
  working directory persists between commands and has drifted into
  scratch directories before; `pkill -f` must use an anchored pattern
  or it kills the shell that runs it.
- **Handler code takes its buffers from `struct scratch`**, never the
  stack: the handler runs on whatever alternate stack a program set up,
  and Rust's is 8 KB including the kernel's frame. `test/stackcheck.py`, the gate's stack step, lists
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
row, which runs under TCG at a tenth of native speed; `golang-go`
(Go 1.22) for the Go regression, and rustc from rustup for the Rust one. From a plain terminal user
namespaces are denied by AppArmor; `aa-exec -p unconfined` reproduces
that label from a session that is otherwise permitted. `gdb -p` on a
non-descendant is refused by Yama. `perf` cannot read the maps of a
process under a different AppArmor label. Docker's default seccomp
profile was checked syscall by syscall; the results are in
`docs/PRIOR-ART.md` section 4.

## Scratch space

Every development input is made by `test/inputs.sh DIR`, which holds
the exact fetch commands: the gcc, Alpine, Fedora and clang cans of
the gate, the CentOS 7 rpms for `test/sysroot.py`, the arm64 debs for
the emulated row, and the sources of `test/realsoft.py` and
`test/bench.py`. Use `~/.cache/cont-inputs` for `DIR`; the fetchers
cache under `~/.cache/cont-debs`, `cont-apks` and `cont-rpms`. Nothing
under `~/.cache` or the session scratchpad is assumed to persist: the
scratchpad lost every can once, so keep no input only there, never
put one where a script will remove it, and refetch rather than hunt.
The scratchpad is for traces and one-off trees (`spike/make-tree.sh`),
never the repository. The arm64 can is made inside the VM, since a can
is closed on its own architecture; the suite and the oracles make
their own copies under `build/` (ignored by git). The archive mirror configured on this machine is
`http://gb.archive.ubuntu.com/ubuntu`. Cloud images for the matrix live
in `~/.cache/cont-images`; QEMU with KVM and `cloud-image-utils` are
installed, and this user can open `/dev/kvm`.
