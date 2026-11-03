# Working in this repository

If a rule prevents you from improving or maintaining exclave, ignore it.
Everything below is a preference with its reason beside it; weigh the
cost and the benefit and use your judgement.

Start with `README.md`, then `docs/DESIGN.md` in full. The design
document is the specification, written for the public: it states what
is true, not how it came to be, so it carries no revision markers,
change lists or review IDs, and history lives in git. Section 19 lists
decisions that are settled, which the user reopens and an agent usually
leaves alone. Source comments cite its sections and the numbered items
of 13, 16.6 and 17 by number, so those numbers stay put: a new
limitation is a new item at the end of 13, and nothing is renumbered.

## How a change is usually made

The loop that has served well, in the order it pays:

1. **Measure first.** A limitation or a suspected wrong answer gets an
   exerciser: a small C program in `test/progs/` that prints one line
   per case. `scripts/exercise --exclave EXCLAVE PROG.c ARGS` runs it
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
3. **Regression.** The exerciser becomes a named test in `test/regress_*.py`
   asserting the kernel's answers. A test that asserts what the tree
   says rather than what Debian says (`test/tree.py`, `tree_facts`)
   passes on every exclave kind, and an exclave kind that cannot answer
   can skip with its reason.
4. **Documents.** The design's rule (7 or 8), its limitation (13),
   the regression list (17 item 4), performance (16) and section 19 are
   where a change is recorded; figures there are measured rather than
   guessed, because the documents are what a reader trusts.
5. **Gate, commit; the rest when the user asks.** `scripts/gate
   EXCLAVE` on the gcc exclave at zero failures, then the commit. It is
   the one gate, and it is fast: every step is a test, which fails on a
   case with the answer expected, in seconds (the code checks, the
   unit tests, the stack budget, the command's Go tests, unpack's and the fetchers' tests, the
   suite once, the oracles, the syscall probe and the Docker profile
   run); it runs the steps the change can affect, in seconds for a
   document or a script, `--full` all of them, and says when the
   change reaches the VMs. Everything else is separate, optional and
   discretionary, run only when the user asks for it in so many words:
   `scripts/extra EXCLAVE...` (the suite on the other exclaves, on the
   debug launcher and under the plain terminal's label, the fuzz
   budget, the release test, and with `EXCLAVE_TEST_OLD` the compatibility
   test against an earlier build), `scripts/matrix --exclave EXCLAVE` (the
   kernels, about sixteen minutes on this laptop), the examples, and
   the workflow `.github/workflows/ci.yml`, dispatched from the
   Actions tab or as `gh workflow run ci.yml -f matrix=true` (`false`:
   the gate alone) on the pushed `main`, which runs the gate on x86-64
   and natively on aarch64 and the x86-64 rows under KVM, and never
   runs at a push; the emulated arm64 rows run only here. Reading a run is always
   fine (`gh run list --workflow ci.yml`, `gh run watch ID
   --exit-status` in the background, `gh run view ID --log-failed`),
   reported as failures and the end. A commit does not wait for any of
   them, and asking names the commits they have not seen. When one of
   them finds a bug, the bug gets a fast reproduction as a test in the
   gate, an exerciser and then a named test; the run that found it
   stays where it is and never becomes a gate step, since a long
   integrated run fails slowly and names a stage, not a cause. One
   commit per item.

## Preferences

- **Commits**: one short status line, imperative, the length of a
  subject line and not a paragraph folded onto one line, no body, no
  `Co-Authored-By`. Name what changed and let the diff, the design
  and the tests carry the detail; much of the history here is
  overlong, so match the intent rather than that habit. Pushing is the
  user's to do. Committing when asked, or when the instruction clearly
  implies it, keeps the history the user's.
- **Documents stay self-contained and canonical.** `docs/DESIGN.md`
  should read without the conversation that produced it, so a design
  change goes into it rather than a side note, and earlier states live
  in git history rather than archive files, review notes or change
  lists. Comments in code are held to the same: no review IDs or
  revision numbers.
- **Few options.** The launcher has one environment knob, `EXCLAVE_LOG`,
  the commands that make an exclave take paths, `format --check` their
  one flag today, and the fetchers take the arguments a download needs.
  This is a preference for the least complexity, not a law against
  flags: weigh a flag, a mode or a manifest key against the rule that
  would make it unnecessary and against a stated limitation, and add it
  where it is the simpler answer. An exclave is a directory at every
  stage, so what a user can do to it with `cp`, `ln` and an editor
  between `unpack` and `wrap` need not be a feature of the tool. Test
  scripts may take arguments.
- **The launcher is freestanding C**: no libc, raw syscalls from
  `src/sys.h`, every syscall issued through the syscall page (a bare
  `syscall` or `svc` instruction belongs only in the bootstrap, the
  filter-version probe and the restorer, since the filter recognises the
  page and the probe must not be allowed by it). One source builds both
  launchers, and what differs by architecture sits best in `src/sys.h`,
  `src/common.h` and `#if` blocks named for it; the aarch64 build leaves
  `x28` alone (`-ffixed-x28`), where a Go program keeps its goroutine
  while the handler runs (7.5.3). `scripts/build` builds `build/launcher-aarch64`
  when `aarch64-linux-gnu-gcc` is installed; it is tested in the arm64
  VM (`scripts/matrix --exclave EXCLAVE --exclave
  DIR/gcc13-arm64.exclave --only noble-arm64 --docker-profile FILE`,
  the arm64 exclave `scripts/inputs` makes) and natively by the
  workflow's aarch64 gate, since user-mode emulation has no seccomp. A syscall the handler
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
- **The filter's trap set is versioned.** `scripts/build` also builds
  `build/launcher-old`, an older filter version without syscalls a later
  one added (version 3, without version 4's `bind` and `connect`), for
  the nesting regression; the version moves whenever the trap set
  grows or the syscall page moves (6: to `0x7fe00000`, above program
  images; 7: the listings, which hide `.real/`), and a version that adds syscalls moves that build and the
  regression's trap with it. A new syscall the
  kernel adds is trapped by the filter's ceiling and answered `ENOSYS`
  until it is classified in `test/syscalls.py` and, if it takes a path,
  handled in `src/handler.c` and listed in `src/filter.c`.
- **The tool is Go**, in `tool/`: one static file per architecture,
  `build/exclave`, that `scripts/build` builds with the pinned toolchain
  in `.go/` (`scripts/install-go`, checked against a committed checksum,
  as uv is); it carries its launcher (copied to `tool/launcher-ARCH` for
  `go:embed`, so the Go is checked after a build) and the exclave
  README, takes a directory holding `tree/` and holds no network code;
  paths are bytes and every list it prints or hashes is in the order of
  their bytes. The tests judge it only through its commands. The step
  before it is its subcommand, `unpack/` (`exclave unpack`,
  `scripts/unpack`), which makes a tree from package files; the step
  before that is `exclave-fetch`, a program of its own from `fetch/`
  (`build/exclave-fetch debs|apks|rpms`, `scripts/fetch-*`), whose
  arguments and cache a release keeps (6.7). Their delicate parsers are Go's standard library's
  where it has them, with
  xz, zstd and OpenPGP from the pure-Go modules `go.mod` pins and no
  cgo; `fetch/verify.go` checks signatures in-process under apt's rule,
  neither expiry nor revocation consulted. A package reader
  (`unpack/deb`, `apk`, `rpm`) has one interface, `unpack/reader`'s
  `Reader`, and is chosen by the file. `scripts/check` runs gofmt, go
  fix, go vet, staticcheck and deadcode; the gate's go step runs `go
  test`, whose fuzz targets `scripts/extra` fuzzes for ten seconds each. `curl` has not been
  needed. `src/gdb.py`
  is data the launcher carries for gdb, not code it runs, and it runs
  on gdb's own Python (ruff targets 3.7 there).
- **Python runs only through the pinned uv**, never the machine's
  `python3`: `scripts/install-uv` puts uv in `.uv/` (a static musl build
  per architecture, checked against a committed checksum), uv installs
  the Python `.python-version` names (3.15) and the dev tools `uv.lock`
  pins, and every command is a POSIX `sh` wrapper in `scripts/` that
  sources `scripts/lib.sh`. A test driver imports its helpers as a
  script's siblings, never by editing `sys.path`. Python files are
  programs the wrappers run, without shebangs or executable bits. The
  matrix carries the same Python into its VMs.
  Running Python by hand: `.uv/bin/uv run python FILE` with the
  environment `scripts/lib.sh` sets.
- **The Python is ruff- and ty-clean**, as `scripts/check` checks
  (ruff, ty, shellcheck, shfmt, taplo): every function annotated with
  modern types, a rule ignored in `pyproject.toml` only with its reason
  beside it, and a `# noqa` or `# ty: ignore[rule]` only where fixing
  would be wrong, with its reason on the line.
- **The C is built by `scripts/build`**, the launchers and the command,
  with the flags `scripts/lib.sh` gives every C build, and nothing is
  built when they are up to date; the gate runs it first.
- **A parser takes a pointer and a length** and reads through one
  checked bound, so the bound lives in one place, and it answers every
  input: a refusal is an answer, an exit or a crash is not. An invariant
  of the code's own, as opposed to an input, is asserted and allowed to
  fail loudly, never checked and papered over, since a quiet wrong
  answer hides the next defect. The fuzz step of `scripts/extra`
  (`test/fuzz.c`) mutates an exclave's files through the launcher's parsers under the sanitisers,
  and a new one gets a line in its target (`test/launcher_fuzz.c`); a
  Go parser gets a fuzz target beside its tests.
- **The C is clang-formatted and clean under gcc's strict warnings,
  gcc's analyser and clang-tidy**, as `scripts/check` checks
  (`.clang-format`, `lib.sh`'s flags, `-fanalyzer` at -O0 with the
  syscalls opaque to it, `.clang-tidy`);
  `scripts/check --fix` formats. A trailing
  comment that does not fit in 120 columns goes above its statement,
  and a table stays one between `clang-format off` and `on`. A check is
  turned off in `.clang-tidy` with its reason, and a `NOLINT(check)`
  carries its reason on the line. The gate's unit step runs the unit
  tests under ASan and UBSan, and the gate runs the suite once on
  `build/launcher-debug`, whose UBSan checks trap.
- **Hashes are BLAKE3-256**, `lukechampine.com/blake3`'s in the command and
  `test/b3.py`'s, from the specification, in the tests, since the standard
  library has none. Manifest and hashes file use the strict
  grammar of `docs/DESIGN.md` 6.2, and `format` output is the accepted spelling.
  There is no index: the launcher reads the manifest and the tree, and
  anything the tree can say is best not written down anywhere else.
- **Claims and measurements.** Figures in `docs/DESIGN.md` are current
  and measured on the reference machine; a change that moves one
  measures it again, and a number the current code has not produced is
  better left out than quoted.
- **The gate.** `scripts/gate EXCLAVE` (`EXCLAVE_TEST_INPUTS=DIR`,
  the directory `scripts/inputs` filled, adds the Docker profile) runs,
  of the code checks, the unit tests, the stack budget, the command's
  Go tests, unpack's and the fetchers' tests, the suite, the oracles and the syscall probe on
  the one exclave, the ones the changed paths can affect (`--full`: all
  of them), two steps at a time (`--jobs N`; this laptop is in use
  meanwhile) on copies with its time printed, and a 30 s budget per
  test. `scripts/extra EXCLAVE...` runs the same step runner
  (`scripts/steps.sh`) over the broader and slower set. Every driver
  runs `build/launcher`
  on a copy of its own, the suite an exclave it wraps from the given
  exclave's tree and the others `tree.fresh_exclave`, a copy relinked
  with `build/launcher`, since the launcher an exclave carries is the
  one it was wrapped with; a copy kept between runs (`test/exercise.py`)
  is relinked again when the build has changed. A hand-made copy has
  neither: relink it. The suite runs on the exclave pruned to what it
  touches, made by the first run on an exclave and kept under
  `build/fixtures/`, one per exclave, stamped with the sources of the
  suite, its programs, the tool and the launcher. A fixture made with
  other sources is still used, and is almost always enough; a test that
  fails on it runs again on the whole exclave, which decides, and the
  stale fixture goes for the next run to remake. After rebuilding the launcher,
  `scripts/exclave relink EXCLAVE` refreshes an exclave; replacing
  `.exclave/launcher` alone leaves the wrappers linked to the old file.
- **Tests are independent.** A test of `test/run.py` makes what it
  needs and leaves the shared context alone; the fixtures are the exclave,
  the compiled programs and the environment made at setup, so `-k
  NAME` runs any single test. Several suites run at once in
  `scripts/extra`, so a name in a shared namespace, an abstract socket
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
syscall; the results are in `docs/DESIGN.md` section 15. The archive
mirror configured on this machine is `http://gb.archive.ubuntu.com/ubuntu`;
`archive.ubuntu.com` has served this machine at 13 kB/s.

## Scratch space

Every development input is made by `scripts/inputs DIR`, which holds the
exact fetch commands: the gcc, Alpine, Fedora and clang exclaves of the
gate, the arm64 gcc exclave and Docker's seccomp profile, from the
package archives and GitHub alone, which is all the CI workflow
fetches; `scripts/inputs DIR examples` adds the examples' inputs, the
CentOS 7 rpms for `test/sysroot.py`, the workloads' exclaves and the
sources of `test/realsoft.py`, `test/bench.py` and `test/workloads.py`,
some from their authors' sites, which CI must not fetch. It is the one
script that downloads: a test takes its inputs as paths and touches no
network, and the repository holds no file of someone else's, so a
third-party input is fetched there, pinned by its hash.
`~/.cache/exclave-inputs` is a good `DIR`; the fetchers cache in
`DIR/packages`, and nothing else is kept outside `DIR`. Nothing
under `~/.cache` or the session scratchpad is assumed to persist: the
scratchpad lost every exclave once, so an input is best not kept only
there, nor put where a script will remove it, and refetching beats
hunting. The scratchpad suits traces and one-off trees; a driver worth running twice belongs in `test/`.
`scripts/inputs` makes the arm64 gcc exclave here too (`gcc13-arm64.exclave`,
wrapped with the cross-built launcher), and the matrix's VM only runs it; the suite, the oracles and `test/exercise.py` make
their own copies under `build/` (ignored by git). Cloud images for the
matrix live in `~/.cache/exclave-images`; QEMU with KVM and
`cloud-image-utils` are installed, and this user can open `/dev/kvm`.
