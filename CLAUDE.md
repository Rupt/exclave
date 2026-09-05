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
- **No options.** The opener has one environment knob, `CAN_LOG`. Do not
  add flags, modes, or manifest keys to solve a problem; find the rule
  that makes the option unnecessary, or state a limitation.
- **The opener is freestanding C**: no libc, raw syscalls from
  `src/sys.h`, every syscall issued through the syscall page (never a
  bare `syscall` instruction outside the bootstrap and the restorer).
  The cannery is Python and is shipped as a can. No `curl`.
- **Hashes are BLAKE2b-256.** Manifest, index and lockfile use the strict
  grammar of proposal 6.2; `fmt` output is the only accepted spelling.
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
  cannery's output must keep `test/dogfood.py` passing. A syscall the
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
- **A new syscall the kernel adds** is trapped by the filter's ceiling
  and answered `ENOSYS` until it is classified in `test/syscalls.py`
  and, if it takes a path, handled in `src/handler.c` and listed in
  `src/filter.c`; the test probes the running kernel, so a newer kernel
  will say so.

## Reference machine facts

Ubuntu 24.04, kernel 7.0, x86-64, glibc 2.39. From a plain terminal user
namespaces are denied by AppArmor; `aa-exec -p unconfined` reproduces
that label from a session that is otherwise permitted. `gdb -p` on a
non-descendant is refused by Yama. `perf` cannot read the maps of a
process under a different AppArmor label. Docker's default seccomp
profile was checked syscall by syscall; the results are in
`docs/PRIOR-ART.md` section 4.

## Scratch space

Use the session scratchpad for trees, cans, package caches and traces,
never the repository. A can is made with `cannery.py from-packages
--cache <scratch>/cannery-cache`; a plain tree with `spike/make-tree.sh`;
the suite and the oracles make their own copies under `build/` (ignored
by git). The archive mirror configured on this machine is
`http://gb.archive.ubuntu.com/ubuntu`. Cloud images for the matrix live
in `~/.cache/cont-images`; QEMU with KVM and `cloud-image-utils` are
installed, and this user can open `/dev/kvm`.
