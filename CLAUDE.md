# Working in this repository

If a rule prevents you from improving or maintaining exclave, ignore it.
Everything below is a preference with its reason beside it; weigh the
cost and the benefit and use your judgement.

Start with `README.md`, then `docs/PROPOSAL.md` in full. The proposal is
the specification; section 19 lists decisions that are settled, which
the user reopens and an agent usually leaves alone.
`docs/REVIEW-RESPONSE.md` has every review finding and where it landed.

## How a change is usually made

The loop that has served well, in the order it pays:

1. **Measure first.** A limitation or a suspected wrong answer gets an
   exerciser: a small C program in `test/progs/` that prints one line
   per case. `test/exercise.py --exclave EXCLAVE PROG.c ARGS` runs it
   under `bwrap` with the unwrapped tree read-only at `/`, where the
   kernel answers, and under the launcher, and marks the lines that
   differ. The kernel's column is the expectation. For a trapped
   syscall, its cases go into `test/oracle_syscalls.py` too, and a probe
   run before the fix puts the differences on record.
2. **Fix in the kernel's order.** The handler tends to answer what the
   kernel answers on a read-only bind mount, check by check
   (`fs/namei.c` is the reference); a difference that is the oracle's
   own construction or a stated limitation goes into the probe's
   `EXPECTED` list with the rule that makes it right, since a
   difference accepted without a reason hides the next defect.
3. **Regression.** The exerciser becomes a named test in `test/run.py`
   asserting the kernel's answers. A test that asserts what the tree
   says rather than what Debian says (`test/tree.py`, `tree_facts`)
   passes on every exclave kind, and an exclave kind that cannot answer
   can skip with its reason.
4. **Documents.** The proposal's rule (7 or 8), its limitation (13),
   the regression list (17.4), the change list (2) and section 19 are
   where a change is recorded; figures there are measured rather than
   guessed, because the documents are what a reader trusts.
5. **Gate, matrix, commit.** `test/gate.sh EXCLAVE...` on the gcc,
   Alpine, Fedora and clang exclaves at zero failures, `test/matrix.py
   --exclave EXCLAVE` before a launcher change is committed, one commit
   per item.

## Preferences

- **Commits**: one short status line, imperative, the length of a
  subject line and not a paragraph folded onto one line, no body, no
  `Co-Authored-By`. Name what changed and let the diff, the proposal
  and the tests carry the detail; much of the history here is
  overlong, so match the intent rather than that habit. Pushing is the
  user's to do. Committing when asked, or when the instruction clearly
  implies it, keeps the history the user's.
- **Documents stay self-contained and canonical.** `docs/PROPOSAL.md`
  should read without the conversation that produced it, so a design
  change goes into the proposal rather than a side note, and earlier
  revisions live in git history rather than archive files.
- **No options.** The launcher has one environment knob, `EXCLAVE_LOG`,
  and the tool's commands take paths, `format --check` the one flag. A
  flag, a mode or a manifest key is rarely the answer; the rule that
  makes the option unnecessary, or a stated limitation, usually is. An
  exclave is a directory at every stage, so what a user can do to it
  with `cp`, `ln` and an editor between `unpack` and `wrap` need not be
  a feature of the tool. Test scripts may take arguments.
- **The launcher is freestanding C**: no libc, raw syscalls from
  `src/sys.h`, every syscall issued through the syscall page (a bare
  `syscall` or `svc` instruction belongs only in the bootstrap, the
  filter-version probe and the restorer, since the filter recognises the
  page and the probe must not be allowed by it). One source builds both
  launchers, and what differs by architecture sits best in `src/sys.h`,
  `src/common.h` and `#if` blocks named for it; the aarch64 build leaves
  `x28` alone (`-ffixed-x28`), where a Go program keeps its goroutine
  while the handler runs (7.5.3). `make` builds `build/launcher-aarch64`
  when `aarch64-linux-gnu-gcc` is installed; it is tested in the arm64
  VM (`test/matrix.py --exclave EXCLAVE --only noble-arm64 --debs-arm64
  DIR --docker-profile FILE`), since user-mode emulation has no seccomp. A syscall the handler
  re-issues is best one the oldest kernel of the matrix has (`renameat`,
  not `renameat2`, for a plain rename).
- **Handler buffers come from `struct scratch`** rather than the stack,
  because the handler runs on whatever alternate stack a program set
  up, and Rust's is 8 KB including the kernel's frame.
  `test/stackcheck.py`, the gate's stack step, walks gcc's call graph
  from `on_sigsys` and fails over 3 KB or on a recursion other than
  `exec_target`'s, so a new function is counted without a list; a call
  through a pointer would have no edge, and the launcher makes none.
  Program memory is read through `copy_in` and written through
  `copy_out`, paths and vectors alike. Environment strings the launcher
  hands a program should be writable.
- **The filter's trap set is versioned.** `make` also builds
  `build/launcher-old`, an older filter version without syscalls a later
  one added (version 3, without version 4's `bind` and `connect`), for
  the nesting regression; the version moves whenever the trap set
  grows or the syscall page moves (6: to `0x7fe00000`, above program
  images), and a version that adds syscalls moves that build and the
  regression's trap with it. A new syscall the
  kernel adds is trapped by the filter's ceiling and answered `ENOSYS`
  until it is classified in `test/syscalls.py` and, if it takes a path,
  handled in `src/handler.c` and listed in `src/filter.c`.
- **The tool is Python**, shipped as an exclave, takes files and does not
  open a network connection; `tools/fetch-debs.py`,
  `tools/fetch-apks.py` and `tools/fetch-rpms.py` are the step before
  it. `curl` has not been needed. A package reader (`deb.py`, `apk.py`,
  `rpm.py`) has one interface and is chosen by the file. A change to
  the tool's output is checked by `test/dogfood.py`. `src/gdb.py` is
  data the launcher carries for gdb, not code it runs.
- **Hashes are BLAKE2b-256.** Manifest and hashes file use the strict
  grammar of proposal 6.2, and `format` output is the accepted spelling.
  There is no index: the launcher reads the manifest and the tree, and
  anything the tree can say is best not written down anywhere else.
- **`spike/` is frozen evidence.** Its numbers are cited, so the spikes
  are better left unedited; the launcher in `src/` is built from the
  mechanisms rather than by copying the code.
- **Claims and measurements.** Figures in the proposal are marked by
  the revision that measured them; a number the current filter has not
  produced is better left out than quoted.
- **The gate.** `test/gate.sh EXCLAVE...` (`EXCLAVE_TEST_INPUTS=DIR`,
  the directory `test/inputs.sh` filled, adds the Docker profile and
  dogfood) runs the unit tests, the stack budget, the suite on every
  exclave in two orders and, for the first exclave, under the plain
  terminal's AppArmor label, the oracles and the syscall probe, every step in parallel on copies, in about a
  minute with a 30 s budget per test. Every driver runs `build/launcher`
  on a copy of its own, the suite an exclave it wraps from the given
  exclave's tree and the others `tree.fresh_exclave`, a copy relinked
  with `build/launcher`, since the launcher an exclave carries is the
  one it was wrapped with; a copy kept between runs (`test/exercise.py`)
  is relinked again when the build has changed. A hand-made copy has
  neither: relink it. The suite runs on the exclave pruned to what it
  touches, made by the first run on an exclave and kept under
  `build/fixtures/`, keyed by the exclave's hashes and the sources of
  the suite, its programs and the tool; a change to those makes the next
  run use the whole exclave and remake it. A launcher or `test/tree.py`
  change that makes a test touch a file the fixture lacks fails that
  test until the fixture is removed. After rebuilding the launcher,
  `exclave/exclave.py relink EXCLAVE` refreshes an exclave; replacing
  `.exclave/launcher` alone leaves the wrappers linked to the old file.
- **Tests are independent.** A test in `test/run.py` makes what it
  needs and leaves the shared context alone; the fixtures are the exclave,
  the compiled programs and the environment made at setup. `--order
  random` and `--order reverse` are expected to pass like the given
  order, and `-k NAME` to run any single test. Several suites run at
  once in the gate, so a name in a shared namespace, an abstract socket
  or a file in `/tmp`, carries the pid.
- **Shell commands with absolute paths.** The shell's working directory
  persists between commands and has drifted into scratch directories
  before; `pkill -f` with an anchored pattern avoids killing the shell
  that runs it.

## Reference machine facts

Ubuntu 24.04, kernel 7.0, x86-64, glibc 2.39; `gcc-aarch64-linux-gnu`,
`qemu-system-arm` and `qemu-efi-aarch64` are installed for the arm64
row, which runs under TCG at a tenth of native speed; `golang-go`
(Go 1.22) for the Go regression, and rustc from rustup for the Rust
one. From a plain terminal user namespaces are denied by AppArmor;
`aa-exec -p unconfined` reproduces that label from a session that is
otherwise permitted. `gdb -p` on a non-descendant is refused by Yama.
`perf` cannot read the maps of a process under a different AppArmor
label. Docker's default seccomp profile was checked syscall by
syscall; the results are in `docs/PRIOR-ART.md` section 4. The archive
mirror configured on this machine is `http://gb.archive.ubuntu.com/ubuntu`;
`archive.ubuntu.com` has served this machine at 13 kB/s.

## Scratch space

Every development input is made by `test/inputs.sh DIR`, which holds the
exact fetch commands: the gcc, Alpine, Fedora and clang exclaves of the
gate, Docker's seccomp profile and dogfood's packages, the CentOS 7 rpms
for `test/sysroot.py`, the arm64 debs for the emulated row, and the
sources of `test/realsoft.py` and `test/bench.py`. It is the one script
that downloads: a test takes its inputs as paths and touches no
network, and the repository holds no file of someone else's, so a
third-party input is fetched there, pinned by its hash.
`~/.cache/exclave-inputs` is a good `DIR`; the fetchers cache under
`~/.cache/exclave-debs`, `exclave-apks` and `exclave-rpms`. Nothing
under `~/.cache` or the session scratchpad is assumed to persist: the
scratchpad lost every exclave once, so an input is best not kept only
there, nor put where a script will remove it, and refetching beats
hunting. The scratchpad suits traces and one-off trees
(`spike/make-tree.sh`); a driver worth running twice belongs in `test/`.
The arm64 exclave is made inside the VM, since an exclave is wrapped on
its own architecture; the suite, the oracles and `test/exercise.py` make
their own copies under `build/` (ignored by git). Cloud images for the
matrix live in `~/.cache/exclave-images`; QEMU with KVM and
`cloud-image-utils` are installed, and this user can open `/dev/kvm`.
