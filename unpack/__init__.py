"""unpack: makes the tree of an exclave from package files (docs/DESIGN.md 10.1).

The step before the exclave command, as fetching is the step before it: it reads .deb, .apk and
.rpm files and writes a directory that `exclave wrap` makes an exclave of. The command line is
`unpack.cli`, run as `python -m unpack`. The package readers are `unpack.deb`, `unpack.apk` and
`unpack.rpm`, behind the interface of `unpack.reader`; `unpack.steps` extracts, synthesises and
records. Nothing here imports the exclave package, whose input is the directory this one writes.
"""
