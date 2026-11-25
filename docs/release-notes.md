The `exclave` command and `exclave-fetch` for x86-64 Linux: static
programs that need nothing beside them. aarch64 is experimental and is
not released.

Taking them, with the release's files in a directory:

```bash
sha256sum -c SHA256SUMS
mv exclave-x86_64 exclave && mv exclave-fetch-x86_64 exclave-fetch && chmod +x exclave exclave-fetch
./exclave version
```

The sums tell a damaged or altered file from the one they name; the
release carries no signature, so that the sums are the releaser's is
this page's to say. `LICENSE` is exclave's licence and `NOTICES` the
licences of Go and the modules the programs link.

The README's [With the two commands
alone](https://github.com/Rupt/exclave#with-the-two-commands-alone)
makes a first exclave with them, and `./exclave help` lists the
commands.
