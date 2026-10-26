"""exclave: builds exclaves from package files (docs/DESIGN.md sections 6 and 10).

The command line is `exclave.cli`, run as `python -m exclave` or the `exclave` console script. The
package readers are `exclave.deb`, `exclave.apk` and `exclave.rpm`, behind the interface of
`exclave.reader`; `exclave.build` extracts, synthesises and prunes; `exclave.elfcheck` holds the
checks; `exclave.grammar` reads and writes the manifest and the hashes file; and `exclave.layout`
knows an exclave's files on disk.
"""

# The tool's version, which every hashes file records; pyproject.toml's, as scripts/check checks.
__version__ = "0.1.0"
