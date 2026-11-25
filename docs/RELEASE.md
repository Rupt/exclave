# Making a release

A release is the `exclave` command and `exclave-fetch` for x86-64, with
their licences and sums, attached to a GitHub release of the tag `vN`
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
   push it; a commit that already does so at `HEAD` is kept.
3. Runs every step of the gate on the gcc exclave, then `scripts/extra`
   on the gcc, Alpine, Fedora and clang exclaves. Each must end with
   nothing failed and nothing skipped.
4. Makes the files with `scripts/release build/release-vN
   build/inputs/gcc13.exclave`, the launcher and commands built inside
   the gcc exclave, and checks them: the five files, every sum, and the
   command naming itself `exclave N+COMMIT`, `COMMIT` the version
   commit.

Logs go under `build/release-prepare/`. Nothing has left the machine, so
a failure is undone here: take the version commit off (`git reset
--hard HEAD^`), fix the cause in a commit of its own, and run the script
again.

## `scripts/release-publish N`: on GitHub

1. Refuses unless `HEAD` is the commit that sets `VERSION` to `N` and
   `build/release-vN` holds its files, checked as above.
2. Pushes `main`.
3. Takes the newest workflow run on the version commit, or dispatches
   one with the kernel matrix (`gh workflow run ci.yml -f
   matrix=true`), waits for it, and stops unless every job passed, the
   matrix's among them.
4. Makes the annotated tag `vN` and pushes it.
5. Creates the GitHub release of `vN`, titled "exclave N", with the
   files and `docs/release-notes.md` as its text.

Run again, it passes over what is done. A run that failed is
dispatched again, which is how one that failed by chance is retried; a
defect is fixed in a commit of its own, which takes the release back to
`scripts/release-prepare N`, since `main` then moves past the version
commit.

The notes, `docs/release-notes.md`, are the release page's text: how
the files are checked and taken. They name no version and no figure,
so that they serve every release unchanged.

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

Its notes then add how an exclave is taken, as `test/release_test.py`
and the kernel matrix take one:

```bash
sha256sum -c SHA256SUMS
tar --zstd -xf APP.exclave.tar.zst     # or, where tar has no --zstd: zstd -dc APP.exclave.tar.zst | tar -xf -
./exclave check APP.exclave            # the tree against its hashes file, the wrappers, the static check
```
