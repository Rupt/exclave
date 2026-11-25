# Making a release

A release is the `exclave` command and `exclave-fetch` for x86-64, with
their licences and sums, attached to a GitHub release of the tag `vN`
(`docs/DESIGN.md` 6.7 and 10.5). aarch64 is experimental and is not
released (`docs/DESIGN.md` 13 item 66). The steps run on the reference
machine from a clean checkout of `main`, with `R` its path and `N` the
next ordinal, 1 for the first release.

## 1. The version

`VERSION` holds the number of the last release, 0 before the first. The
release's commit sets it to `N`, and nothing else:

```bash
cd "$R" && git switch main && git pull --ff-only && git status --short   # nothing listed
```

```bash
echo N > "$R/VERSION" && git -C "$R" commit -q -m "Set the version to N" VERSION && git -C "$R" push
```

## 2. The checks, on that commit

Each must pass on the commit of step 1; a failure is fixed in a commit
of its own, and the release starts again at step 1 on the new `main`.

```bash
cd "$R" && EXCLAVE_TEST_INPUTS=build/inputs scripts/gate --full build/inputs/gcc13.exclave
```

```bash
cd "$R" && gh workflow run ci.yml -f matrix=true   # the gate on x86-64 and aarch64 and the x86-64 kernel matrix
```

```bash
cd "$R" && D=build/inputs; EXCLAVE_TEST_INPUTS=$D scripts/extra $D/gcc13.exclave $D/alpine.exclave $D/f42.exclave $D/clang.exclave
```

The workflow's run is read with `gh run list --workflow ci.yml` and
`gh run view ID`; every job must succeed. `scripts/extra` ends with
`0 failed`.

## 3. The files

`scripts/release` builds the launcher inside the gcc exclave and the
commands from it (`scripts/reproduce`), and refuses a directory that is
not empty and a tree its commit does not hold:

```bash
cd "$R" && scripts/release build/release-vN build/inputs/gcc13.exclave
```

```bash
cd "$R/build/release-vN" && ls && sha256sum -c SHA256SUMS && ./exclave-x86_64 version
```

The directory holds `exclave-x86_64`, `exclave-fetch-x86_64`, `LICENSE`,
`NOTICES` and `SHA256SUMS`, every sum is `OK`, and the version is
`exclave N+COMMIT`, `COMMIT` the commit of step 1
(`git -C "$R" describe --always --exclude='*'`).

## 4. The tag and the release

```bash
git -C "$R" tag -a vN -m "exclave N" && git -C "$R" push origin vN
```

```bash
cd "$R" && gh release create vN --verify-tag --title "exclave N" --notes-file docs/release-notes.md build/release-vN/*
```

The notes, `docs/release-notes.md`, are the release page's text: how
the files are checked and taken. They name no version and no figure,
so that they serve every release unchanged.

## An exclave in a release

`scripts/release` also takes exclaves after the toolchain, each wrapped
with the launcher built inside it, which the command built there
carries, and puts each in the release as `NAME.exclave.tar.zst`:

```bash
cd "$R" && scripts/reproduce build/inputs/gcc13.exclave build/reproduce && build/reproduce/build/exclave relink APP.exclave
```

```bash
cd "$R" && scripts/release build/release-vN build/inputs/gcc13.exclave APP.exclave
```

Its notes then add how an exclave is taken, as `test/release_test.py`
and the kernel matrix take one:

```bash
sha256sum -c SHA256SUMS
tar --zstd -xf APP.exclave.tar.zst     # or, where tar has no --zstd: zstd -dc APP.exclave.tar.zst | tar -xf -
./exclave check APP.exclave            # the tree against its hashes file, the wrappers, the static check
```
