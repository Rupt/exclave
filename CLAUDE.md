# Working in this repository

Read `README.md`, then `docs/PROPOSAL.md` in full, before changing
anything. The proposal is the specification; section 19 lists decisions
that are settled and are reopened only by the user, not by an agent
finding them inconvenient.

## Rules

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
  `spike/sys.h`, every syscall carrying the magic register. The cannery
  is Python and is shipped as a can. No `curl`.
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
  implementing its test. The user-namespace bind mount and
  `openat2(RESOLVE_IN_ROOT)` are the oracles.

## Reference machine facts

Ubuntu 24.04, kernel 7.0, x86-64, glibc 2.39. From a plain terminal user
namespaces are denied by AppArmor; `aa-exec -p unconfined` reproduces
that label from a session that is otherwise permitted. `gdb -p` on a
non-descendant is refused by Yama. `perf` cannot read the maps of a
process under a different AppArmor label. Docker's default seccomp
profile was checked syscall by syscall; the results are in
`docs/PRIOR-ART.md` section 4.

## Scratch space

Use the session scratchpad for trees, builds and traces, never the
repository. A test tree is made with `spike/make-tree.sh`.
