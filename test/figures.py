"""The figures the documents quote that the tree itself can produce, and whether they agree.

    test/figures.py            print each figure
    test/figures.py --check    compare them with the documents; exit non-zero when one differs

A figure in a document is measured, never guessed (CLAUDE.md), and the ones here come from the tree
without running anything: the suite's count of named tests, the resolution oracle's default number
of paths and the matrix's rows; sizes, which move with every change, are not quoted. The probe's
case count needs an exclave and a run: the gate's syscalls step prints it on its last line, and the
documents round it, so that a case added does not make them wrong. scripts/check runs --check.
"""

import argparse
import os
import re
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DOCS = ("README.md", "docs/DESIGN.md")


def read(path: str) -> str:
    with open(os.path.join(REPO, path), encoding="utf-8") as f:
        return f.read()


def resolve_paths() -> int:
    """The resolution oracle's default number of paths, read from its option."""
    m = re.search(r'"--paths", type=int, default=(\d+)', read("test/oracle_resolve.py"))
    if m is None:
        msg = "test/oracle_resolve.py has no --paths default"
        raise ValueError(msg)
    return int(m.group(1))


def figures() -> dict[str, int | None]:
    return {
        "named tests": sum(
            len(re.findall(r"^@test", read(os.path.join("test", f)), re.MULTILINE))
            for f in sorted(os.listdir(os.path.join(REPO, "test")))
            if f.startswith("regress_") and f.endswith(".py")
        ),
        "resolve paths": resolve_paths(),
        "matrix rows": len(re.findall(r"^    VmRow\(", read("test/matrix.py"), re.MULTILINE)),
    }


# Where each figure is quoted: (figure, regex with one group holding the number, thousands spaced)
QUOTED = (
    ("named tests", r"(\d[\d ]*) named (?:tests|regressions)"),
    ("resolve paths", r"(\d[\d ]*) paths over (?:a random maze|\w+ random mazes)"),
)


def check(found: dict[str, int | None]) -> int:
    wrong = 0
    for doc in DOCS:
        text = read(doc)
        for name, pattern in QUOTED:
            want = found[name]
            if want is None:
                continue  # not built; nothing to compare
            for m in re.finditer(pattern, text):
                quoted = int(m.group(1).replace(" ", ""))
                if quoted != want:
                    line = text.count("\n", 0, m.start()) + 1
                    print(f"{doc}:{line}: quotes {quoted} for {name}; the tree gives {want}")
                    wrong += 1
    return wrong


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--check", action="store_true", help="compare with the documents")
    args = ap.parse_args()
    found = figures()
    if args.check:
        return check(found)
    for name, value in found.items():
        print(f"{name}: {'not built' if value is None else value}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
