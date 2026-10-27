"""Name every definition in the shared C headers that no source uses (scripts/check).

The compiler reports an unused static function or macro of a .c file, but not one of a header: a
header's definitions are there to be used by someone. This lists each macro, enum constant and
function that src/sys.h, src/common.h and tool/tool.h define or declare, and fails on one that
appears in no other place in src/, tool/ or the unit tests, counting a use in the headers
themselves. A function's
definition in a .c file, a line that starts with its type, is not a use.
"""

import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
HEADERS = ("src/sys.h", "src/common.h", "tool/tool.h")
# Defined for a reader of the kernel's ABI beside the names that are used; none at present.
KEEP: set[str] = set()

DEFINE = re.compile(r"^\s*#\s*define\s+([A-Za-z_]\w*)")
FUNCTION = re.compile(r"^[A-Za-z_][\w \*]*?\b([a-z_]\w*)\s*\([^;{]*\)\s*(?:\{|;|$)")
ENUM_CONSTANT = re.compile(r"\b(NR_\w+|REG_\w+)\s*=")


def defined(path: str) -> dict[str, int]:
    """Return each name the header defines with the number of times it defines it."""
    names: dict[str, int] = {}
    with open(os.path.join(REPO, path)) as f:
        for line in f:
            for pattern in (DEFINE, FUNCTION):
                m = pattern.match(line)
                if m:
                    names[m.group(1)] = names.get(m.group(1), 0) + 1
            for m in ENUM_CONSTANT.finditer(line):
                names[m.group(1)] = names.get(m.group(1), 0) + 1
    return names


def main() -> int:
    sources = [
        os.path.join(d, f)
        for d in (os.path.join(REPO, "src"), os.path.join(REPO, "tool"), HERE)
        for f in sorted(os.listdir(d))
        if f.endswith((".c", ".h")) and (d != HERE or f.endswith("_test.c"))
    ]
    text = c_text = ""
    for p in sources:
        with open(p) as f:
            body = f.read() + "\n"
        text += body
        if p.endswith(".c"):
            c_text += body
    unused = []
    for header in HEADERS:
        for name, defs in sorted(defined(header).items()):
            if name in KEEP:
                continue
            uses = len(re.findall(rf"\b{name}\b", text))
            uses -= len(
                re.findall(rf"^[A-Za-z_][^\n(]*\b{name}\s*\([^;\n]*$", c_text, re.MULTILINE)
            )
            if uses <= defs:
                unused.append(f"{header}: {name}")
    for line in unused:
        print(line)
    if unused:
        print(f"c_unused: {len(unused)} definitions nothing uses", file=sys.stderr)
    return 1 if unused else 0


if __name__ == "__main__":
    sys.exit(main())
