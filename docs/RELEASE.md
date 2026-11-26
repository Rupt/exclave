# Making a release

A release is the `exclave` command and `exclave-fetch` for x86-64 in one
archive with their licences, `exclave-N-x86_64.tar.gz`, and its sums,
`SHA256SUMS`, attached to a GitHub release of the tag `vN`
(`docs/DESIGN.md` 6.7 and 10.5). aarch64 is experimental and is not
released (`docs/DESIGN.md` 13 item 66). `N` is the next ordinal, 1 for
the first release; `VERSION` holds the last release's, 0 before the
first.

Two scripts make it, run in turn on the reference machine from `main`,
with the inputs `scripts/inputs build/inputs` makes
(`EXCLAVE_TEST_INPUTS` names another directory):

```bash
scripts/release-prepare N
```

```bash
scripts/release-publish N
```

## `scripts/release-prepare N`: on this machine

1. Refuses unless the tree is `main` with no uncommitted change to a
   tracked file, `HEAD` holds origin's `main`, origin has no tag `vN`,
   and the machine is x86-64.
2. Commits `VERSION` set to `N`, "Set the version to N", and does not
   push it; where `VERSION` is `N` already, from a run before, it is
   kept.
3. Runs every step of the gate on the gcc exclave, which must end with
   nothing failed and nothing skipped. `scripts/extra` is not run: a
   release waits on nothing the gate would not, and what `scripts/extra`
   finds becomes a test in the gate.
4. Makes the files with `scripts/release build/release-vN
   build/inputs/gcc13.exclave`, the launcher and commands built inside
   the gcc exclave, and checks them: the archive and the sums, every
   sum, and the command it holds naming itself `exclave N+COMMIT`,
   `COMMIT` the commit at `HEAD`.

Logs go under `build/release-prepare/`. A failure is met by a fix in a
commit of its own, and the script run again, which keeps `VERSION`.

## `scripts/release-publish N`: on GitHub

1. Refuses unless `VERSION` is `N` and `build/release-vN` holds the
   files of `HEAD`, checked as above.
2. Pushes `main`.
3. Takes the newest workflow run on `HEAD`, or dispatches
   one with the kernel matrix (`gh workflow run ci.yml -f
   matrix=true`), waits for it, and stops unless every job passed, the
   matrix's among them, which runs the rows or finds them not due since
   a commit they passed on (`scripts/matrix-due`).
4. Makes the annotated tag `vN` on `HEAD` and pushes it.
5. Creates the GitHub release of `vN`, titled "exclave N", with the
   files and no text: the README says what the commands do.

Run again, it passes over what is done. A run that failed is
dispatched again, which is how one that failed by chance is retried; a
defect is fixed in a commit of its own, which takes the release back to
`scripts/release-prepare N`, whose files are then of the new `HEAD`.

## Taking a release

With the release's files in a directory, the archive unpacks to
`exclave-N-x86_64/`, its commands executable as they unpack, since an
archive keeps the mode a download would lose:

```bash
sha256sum -c SHA256SUMS
tar -xzf exclave-N-x86_64.tar.gz
exclave-N-x86_64/exclave version
```

`test/release_test.py` and the kernel matrix take a release so, the
matrix with each host's own `sha256sum` and `tar`. The sums tell a
damaged or altered file from the one they name; a release carries no
signature, so that the sums are the releaser's is the release page's
to say.

## An exclave in a release

`scripts/release` also takes exclaves after the toolchain, each wrapped
with the launcher built inside the toolchain, which the command built
there carries, and puts each in the release as `NAME.exclave.tar.zst`.
The two scripts make a release of the commands alone; one with an
exclave is made by hand with the same steps:

```bash
scripts/reproduce build/inputs/gcc13.exclave build/reproduce && build/reproduce/build/exclave relink APP.exclave
```

```bash
scripts/release build/release-vN build/inputs/gcc13.exclave APP.exclave
```

An exclave is taken as `test/release_test.py` takes one:

```bash
sha256sum -c SHA256SUMS
tar --zstd -xf APP.exclave.tar.zst     # or, where tar has no --zstd: zstd -dc APP.exclave.tar.zst | tar -xf -
exclave-N-x86_64/exclave check APP.exclave
```
