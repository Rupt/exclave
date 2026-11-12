"""The figures the documents quote that the tree itself can produce, and whether they agree.

    test/figures.py            print each figure
    test/figures.py --check    compare them with the documents; exit non-zero when one differs

A figure in a document is measured, never guessed (CLAUDE.md), and the ones here come from the tree
without running anything: the sizes of the launcher's tables, which are the design's own constants,
and the resolution oracle's default number of paths. Counts and sizes that move as the tree grows
are not quoted at all. A spelling that no document uses any more fails too, since a pattern that
matches nothing checks nothing. scripts/check runs --check.
"""

import argparse
import os
import re
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DOCS = ("README.md", "docs/DESIGN.md", "tool/README.txt")
WORDS: tuple[str, ...] = (
    "zero",
    "one",
    "two",
    "three",
    "four",
    "five",
    "six",
    "seven",
    "eight",
    "nine",
    "ten",
    "eleven",
    "twelve",
    "thirteen",
    "fourteen",
    "fifteen",
    "sixteen",
)
WORD = "(" + "|".join(WORDS) + ")"


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


def constant(name: str) -> int:
    """A table size of the launcher's, read from its definition in src/common.h."""
    m = re.search(rf"^#define {name} (\d+)$", read("src/common.h"), re.MULTILINE)
    if m is None:
        msg = f"src/common.h does not define {name} as a number"
        raise ValueError(msg)
    return int(m.group(1))


def figures() -> dict[str, int]:
    return {
        "resolve paths": resolve_paths(),
        "identity files": constant("N_IDENTITY"),
        "identity directories": constant("N_IDENTITY_DIRS"),
        "own records": constant("MAX_OWN_RECORDS"),
        "host records": constant("MAX_HOST_RECORDS"),
        "data records": constant("MAX_DATA_RECORDS"),
        "top-level entries": constant("MAX_TOP_LEVEL"),
    }


# Where each figure is quoted: (figure, regex with one group holding the number, in digits with the
# thousands spaced or as a word). Each is matched without regard to case, and a space in one stands
# for any white space, so a figure split over two lines is found.
QUOTED = (
    ("resolve paths", r"(\d+(?: \d{3})*) paths over (?:a random maze|\w+ random mazes)"),
    ("identity files", WORD + r" (?:host identity|identity|host) files"),
    ("identity files", WORD + r" files (?:such as|above)"),
    ("identity directories", WORD + r" identity directories"),
    ("identity directories", r"files and (?:the )?" + WORD + r" (?:identity )?directories"),
    ("own records", r"(\d+) `own` records"),
    ("host records", r"(\d+) `host` records"),
    ("data records", r"(\d+) `data` records"),
    ("top-level entries", r"(\d+) top-level entries"),
)


def number(text: str) -> int:
    word = text.lower()
    return WORDS.index(word) if word in WORDS else int(text.replace(" ", ""))


def check(found: dict[str, int]) -> int:
    wrong = 0
    texts = {doc: read(doc) for doc in DOCS}
    for name, pattern in QUOTED:
        want = found[name]
        spaced = re.compile(pattern.replace(" ", r"\s+"), re.IGNORECASE)
        seen = 0
        for doc, text in texts.items():
            for m in spaced.finditer(text):
                seen += 1
                quoted = number(m.group(1))
                if quoted != want:
                    line = text.count("\n", 0, m.start()) + 1
                    print(f"{doc}:{line}: quotes {quoted} for {name}; the tree gives {want}")
                    wrong += 1
        if not seen:
            print(f"no document quotes {name} as {pattern!r}: the check is blind")
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
        print(f"{name}: {value}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
