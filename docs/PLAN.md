# Pre-release plan

This is the working plan for exclave's first public release: the items
to finish before it, in the order they are taken, and the decisions
behind them. `docs/DESIGN.md` is the specification and states what is
true; this document states what is to be done and is edited as items
land. The release point is not decided here: it is decided once every
item below is done and the investigations at the end have run.

## Decisions

Taken in November 2026 with the user, each with its reason:

- **The audience** is as general as reasonable: compilers and build
  tools first, and Python, a Java JDK and TeX Live as the applications
  the release should serve. Sandboxes that use seccomp's `TRAP` action
  (browsers, Electron, tor; DESIGN 13 items 5 and 23) are not part of
  the first release.
- **Versions are `0.0.n`**, n incrementing from 1 (`VERSION`). The
  version names a build, with its commit; the formats carry versions of
  their own (DESIGN 6.7).
- **The first release is x86-64.** The aarch64 launcher stays built and
  tested, and an aarch64 release follows later, made on an aarch64
  machine as its exclaves are. The emulated arm64 rows are costly and
  run when asked.
- **The first release is the compatibility baseline.** From it on,
  every commit is held to the release's files by the compatibility test,
  which CI runs against the release's assets fetched from GitHub and
  pinned by hash.
- **The archive is zstd only** (`NAME.exclave.tar.zst`), for the reason
  DESIGN 10.5 gives. The consumer's recipe gives the portable form for
  hosts whose `tar` lacks `--zstd`.
- **The trust directory is generalised**: identity extends from files to
  directories, so that `/etc/ssl/certs` and its kind are the host's with
  their links followed on the host, as the identity files' are (DESIGN
  13 item 55). Design first, reviewed against kernel facts; then the
  implementation, reviewed again.
- **Other hosts stay untested**: snap-confined terminals, gVisor and
  WSL1 are stated as untested in DESIGN 12 and get no matrix row now.
- **Locales wait.** `exclave caches` does not make locales until a real
  exclave needs one; the border's `C.UTF-8` serves the three
  applications of the audience unless the sweep finds otherwise, and an
  exclave that wants another locale ships the data and a wrapper script
  (DESIGN 13 item 35).
- **Figures in the documents.** A figure that development moves is
  removed rather than kept current: counts of tests, probe cases,
  packages and files, per-row matrix counts, the version numbers the
  code owns. What stays is a measurement that supports a claim, with
  the conditions it was measured under, re-measured when a change moves
  it; a constant that is the design's own; and a figure inside a quoted
  transcript.

## Items

Each item follows the method of `CLAUDE.md`: measure, fix, regression,
documents, gate, one commit per item. Status is in brackets.

1. **The documents brought in line with the code** [done]. The
   versions table of 6.7, the portability table of 12, the matrix table
   of 12.1, the README's page-size and release-contents statements; then
   the figures rule applied throughout `docs/DESIGN.md`, `README.md` and
   the exclave README.
2. **Versioning `0.0.n`** [done]: `VERSION` is `0.0.1`.
3. **The compatibility baseline** [done]: a record of the baseline
   release's assets that `scripts/inputs` fetches, the compatibility
   test a step of the gate, and so of CI, reporting SKIP until a release
   exists; a later `wrap` may add only its identity placeholders to an
   earlier exclave (DESIGN 6.7).
4. **The consumer's recipe on every kernel of the matrix** [done, the
   matrix run on it due]: a release of the gcc exclave verified, unpacked and
   checked in each matrix VM with the release's own command, each
   host's answer recorded (old hosts lack `ssh-keygen -Y` and
   `tar --zstd`); the README's consumer section says what the recipe
   needs.
5. **The trust directory** [done]: three identity directories and eleven
   identity files, Java's keystores among them, the host's with their
   links followed on the host; designed, reviewed against kernel facts,
   implemented and reviewed three times more; item 55 states what
   remains (DESIGN 8.4).
6. **The sweep over Python, a JDK and TeX Live** [done]: real
   exclaves of the three run against the kernel's answers; each gap a
   rule in `unpack` or a generator of `exclave caches` with a test, or a
   new limitation. TeX's in-place configuration and formats (item 56)
   and Java's certificate keystore were the gaps going in; both are
   closed, TeX's through `exclave caches` writing in place and the
   keystore as an `unpack` rule, and the CA bundle rule now fires on
   Ubuntu 24.04 (10.1, 13 items 48, 56 and 57).
7. **Investigations, after the items above** [done]: the spawn's
   kernel side is profiled with kernel symbols in a matrix VM
   (`scripts/profile-spawn`, DESIGN 16.4 and 16.7), which names the
   candidate cuts and decides none; and the defect hunt in memory
   placement, descriptors and processes found the launcher's image
   charged against a small data limit, now mapped as it fills, and
   stated what remains (DESIGN 13 items 59 to 63).
8. **The release point** [not decided]: the gate, the hosted workflow
   with the matrix, the emulated arm64 row and the release test all
   passing on one commit; `docs/DESIGN.md` and `README.md` consistent
   with it; then `scripts/release` on that commit, and the baseline
   record of item 3 filled from its assets.
9. **The suite on the Alpine exclave** [done]: the suite had not run on
   musl since an exerciser took glibc's stack-end symbol; that and four
   tests asserting glibc's wording, stack minimum and `raise` are fixed,
   and the suite passes on every kind. The fifth failure was a launcher
   limitation, now 13 item 58.
11. **A program handler's view of a trapped call** [done, the arm64 row on
    it due]: a program's handlers are installed behind trampolines that
    present the trap site's frame, a frame of the kernel's layout from the
    page's handler-call slot so that unwinders walk into the program's
    frames, and carry what the handler decides back into the trapped call;
    an `rt_sigaction` install traps and a query passes to the kernel,
    returning the stub, which, called directly as Go's forwarding and a
    chain of handlers call it, runs the program's handler (13 item 20
    states what a query reports); filter version 11, the page generation
    unchanged (7.5.7). A deferred
    `pthread_cancel` of a thread blocked in a trapped open now acts on musl
    and glibc 2.41.
10. **The positional entry's spellings** [done]: `.exclave/launcher
    ./PATH`, `../PATH` and a host symlink to a wrapper die with
    "cannot exec the wrapper" where the absolute spelling ran: the walk of the spelling overwrote the
    wrapper's real path, so the entry exec'd a directory; fixed, with a
    regression over every spelling, and item 57 names the entry as a way
    to run a venv from outside.
12. **The start's memory** [done]: the first of the profile's candidate
    cuts (item 7). The start keeps its buffers in the scratch chunk the
    first trapped call takes and the exclave's paths in the arena, so a
    process started inside touches two dozen pages fewer, and the
    image's `.bss` is half what it was, which lowers the data limit a
    wrapper runs under (DESIGN 7.2, 16.4, 16.6 item 10, 13 item 60).
13. **Top-level directories read on reach** [done]: the second of the
    profile's candidate cuts (item 7). A start lists the tree's top
    level and reads a directory when a path first reaches it, so a
    process that names no placeholder reads none: thirty syscalls
    fewer in a start. The rule's table stays one its readers never
    lock, a directory's entry changing once by a compare-and-swap, and
    the late read needs a descriptor, which is a limitation of its own
    (DESIGN 8.1 rule 1, 16.4, 16.6 item 11, 13 item 64).
14. **A program where the kernel's exec would put it** [done, the
    kernel rows on it due]: of the limitations the defect hunt stated
    (item 7), the break. The kernel's record of the image it exec'd
    takes the program's through `PR_SET_MM_MAP`, which needs no
    capability, so the loader places a position-independent program
    two thirds up the address space with its break above it, as the
    kernel does, and at the kernel's own addresses without
    randomization; the record's code, data and stack are the
    program's too (DESIGN 7.3, 13 items 24, 50 and 59). The auxiliary
    vector could go with the record and stays the launcher's: gdb
    attached to a program reads it beside the launcher's file, and
    refuses to continue when it describes the program (13 item 62,
    `gdb_attach`).
15. **One working directory for a run** [done]: of the same
    limitations, the view. The directory a run starts in, given to the
    host by rule 4, is told from each launcher to the ones it execs,
    in `EXCLAVE_CWD` under the exclave's mark, so a program started
    after a `chdir` elsewhere sees it as its parent does, where each
    process had a view of its own start (DESIGN 8.1 rule 4, 7.4.5, 13
    item 63).
16. **One mapping at the start** [done]: another of the profile's
    candidate cuts (item 7). The cache's lock page, the first scratch
    chunk and the reserve are one span, mapped in one call and opened
    in a second, two calls and one mapping fewer in every start
    (DESIGN 16.6 item 12).

## After the first release

- An aarch64 release, built on an aarch64 machine.
- Sandboxes that use the `TRAP` action (13 items 5 and 23), a design
  project of its own.
- Locales in `exclave caches`, when an exclave needs them.
- Further sweeps as real exclaves show the next gaps (DESIGN 18 item 1).
