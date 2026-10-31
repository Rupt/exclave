"""Run the property tests of the manifest grammar (DESIGN.md 6.2, 17 item 3).

    test/grammar_test.py [--cases N] [--seed S] [--c-parser PATH]

Two statements hold for every byte sequence b, asked of the exclave command's format: a value
spelt in canonical form is canonical (format is idempotent), and a value spelt with every byte
escaped is rewritten to that canonical form (decode, then encode, is the identity). The canonical
form is quote below, the rule of 6.2 written out here. And the two implementations of the grammar,
the command's and the launcher's C parser (built by scripts/gate's unit step, run with the files as
arguments), accept and reject the same inputs: manifests and their malformed variants (MUTATIONS);
and both name the line of an error on a known line (POSITIONS). The launcher's parser decodes each
value of the properties to the bytes it was made from, in canonical form and with every byte
escaped. Each parser reads every file of a batch in one run.
"""

import argparse
import os
import random
import subprocess
import sys
import tempfile
lazy from collections.abc import Callable

import tree

HERE = os.path.dirname(os.path.abspath(__file__))


def quote(b: bytes) -> str:
    r"""Return the canonical string literal for b (6.2).

    Printable UTF-8 as itself; backslash, double quote, newline and tab by their one-letter escapes;
    any other control character, C1 controls byte by byte, and any malformed byte as \xHH.
    """
    out, i = ['"'], 0
    while i < len(b):
        n = next((k for k in (1, 2, 3, 4) if _well_formed(b[i : i + k])), 0)
        c = b[i]
        if c in b'\\"\n\t':
            out.append({0x5C: "\\\\", 0x22: '\\"', 0x0A: "\\n", 0x09: "\\t"}[c])
        elif not n or (o := ord(b[i : i + n].decode())) < 0x20 or 0x7F <= o <= 0x9F:
            out.extend(f"\\x{x:02x}" for x in b[i : i + (n or 1)])
        else:
            out.append(b[i : i + n].decode())
        i += n or 1
    return "".join(out) + '"'


def _well_formed(b: bytes) -> bool:
    """Return whether b is exactly one well-formed UTF-8 character."""
    try:
        return len(b.decode("utf-8")) == 1
    except UnicodeDecodeError:
        return False


def write_files(d: str, texts: list[bytes]) -> list[str]:
    """Write the texts as files under d, named by their index; returns their paths."""
    paths = [os.path.join(d, f"f{i:06d}") for i in range(len(texts))]
    for p, t in zip(paths, texts, strict=True):
        with open(p, "wb") as f:
            f.write(t)
    return paths


def c_parse(c_parser: str, texts: list[bytes]) -> list[str]:
    """Run the launcher's parser once over the texts as files.

    Returns its line for each: `ok` and each own value in hex, or the error.
    """
    with tempfile.TemporaryDirectory(prefix="grammar-") as d:
        p = subprocess.run([c_parser, *write_files(d, texts)], capture_output=True, check=False)
    lines = p.stdout.decode(errors="replace").splitlines()
    if p.returncode != 0 or len(lines) != len(texts):
        # 99 is a sanitiser's finding (test/sanitize.c), on the file after the last line printed
        on = repr(texts[len(lines)][:200]) if len(lines) < len(texts) else "its output"
        sys.exit(
            f"FAIL the C parser exited {p.returncode} after {len(lines)} of {len(texts)} files, on "
            f"{on}: {p.stderr.decode(errors='replace')}"
        )
    return lines


def format_files(texts: list[bytes], *, check: bool) -> tuple[dict[int, str], list[bytes]]:
    """Run the command's format once over the texts as files.

    Returns the line it printed for each file that has one, by index, and the files' bytes after.
    """
    with tempfile.TemporaryDirectory(prefix="grammar-") as d:
        paths = write_files(d, texts)
        p_ = subprocess.run(
            [*tree.TOOL, "format", *(["--check"] if check else []), *paths],
            capture_output=True,
            check=False,
        )
        if p_.returncode not in (0, 1):
            sys.exit(f"FAIL format exited {p_.returncode}: {p_.stderr.decode(errors='replace')}")
        said = {}
        for line in p_.stdout.decode("utf-8", "surrogateescape").splitlines():
            name, _, what = line.partition(": ")
            said[int(os.path.basename(name)[1:])] = what
        after = []
        for p in paths:
            with open(p, "rb") as f:
                after.append(f.read())
    return said, after


def rand_bytes(rng: random.Random, *, path: bool = False) -> bytes:
    """A random byte string; with path, one a Linux path could hold (any byte but NUL)."""
    n = rng.randint(0, 24)
    pick = [
        lambda: rng.randint(0, 255),
        lambda: rng.choice(b'"\\\n\t /'),
        lambda: rng.randint(0x20, 0x7E),
        lambda: rng.choice(
            [0xC3, 0xA9, 0xE2, 0x82, 0xAC, 0xF0, 0x9F, 0x98, 0x80, 0xC0, 0xED, 0xA0, 0xF5, 0xFF]
        ),
    ]
    b = bytes(rng.choice(pick)() for _ in range(n))
    return b.replace(b"\0", b"\1") if path else b


def properties(rng: random.Random, cases: int, c_parser: str | None) -> int:
    bad = 0
    values, canonical, escaped = [], [], []
    for _ in range(cases):
        # the encoding's properties; a path's own spelling rules are the mutations' (6.2)
        b = rand_bytes(rng, path=True).replace(b"/", b"_")
        if b in (b".", b".."):
            b = b"_" + b
        values.append(b)
        canonical.append(f"exclave 1\n\nown {quote(b'/' + b)}\n".encode())
        every = "".join(f"\\x{x:02x}" for x in b"/" + b)
        escaped.append(f'exclave 1\n\nown "{every}"\n'.encode())
    said, _ = format_files(canonical, check=True)
    for i, what in said.items():
        bad += 1
        print(f"FAIL the canonical spelling of {values[i]!r}: {what}")
    said, after = format_files(escaped, check=False)
    for i, b in enumerate(values):
        if after[i] != canonical[i]:  # decode(encode(b)) == b
            bad += 1
            print(f"FAIL every byte of {b!r} escaped: {said.get(i)} -> {after[i]!r}")
    # the launcher's decoding, which a wrong hex digit or code point would leave accepting all
    if c_parser:
        for spelt, texts in (("canonical", canonical), ("every byte escaped", escaped)):
            for b, line in zip(values, c_parse(c_parser, texts), strict=True):
                if line != f"ok {(b'/' + b).hex()}":
                    bad += 1
                    print(f"FAIL the C parser decodes {b!r} {spelt} as {line!r}")
    return bad


MUTATIONS: list[Callable[[bytes, random.Random], bytes]] = [
    lambda t, _: t.replace(b"\n", b"\r\n", 1),
    lambda t, _: t[:-1],
    lambda t, _: b"\xef\xbb\xbf" + t,
    lambda t, _: t.replace(b" ", b"  ", 1),
    lambda t, _: t.replace(b" ", b"\t", 1),
    lambda t, _: t.replace(b'"', b"", 1),
    lambda t, _: t.replace(b"own", b"Own", 1),
    lambda t, _: t + b"# trailing\n",
    lambda t, _: t.replace(b"exclave 1", b"exclave 2", 1),
    lambda t, _: t.replace(b'own "/', b'own "//', 1),
    lambda t, _: t.replace(b'own "/', b'own "/./', 1),
    lambda t, _: t.replace(b'own "/', b'own "/../', 1),
    lambda t, _: t.replace(b'"/', b'"', 1),
    lambda t, _: t.replace(b"\\x", b"\\X", 1),
    lambda t, _: t.replace(b"own", b"env", 1),
    lambda t, rng: (
        t[: rng.randint(0, len(t))] + bytes([rng.randint(0, 31)]) + t[rng.randint(0, len(t)) :]
    ),
    lambda t, _: t.replace(b'"\n', b'" \n', 1),
    lambda t, _: t.replace(b"own", b'own "/x" own', 1),
]


def near_manifest(rng: random.Random) -> bytes:
    recs = ["exclave 1"]
    for _ in range(rng.randint(0, 4)):
        key = rng.choice(["own", "host", "data", "cpu", "cpu", "bogus"])
        val = rand_bytes(rng)
        recs.append(
            "{} {}".format(key, quote((b"/" if key in ("own", "host", "data") else b"") + val))
        )
    if rng.random() < 0.3:
        recs.insert(rng.randint(0, len(recs)), "# " + rand_bytes(rng).decode("utf-8", "replace"))
    text = ("\n".join(recs) + "\n").encode()
    if rng.random() < 0.6:
        text = rng.choice(MUTATIONS)(text, rng)
    return text


def compare(rng: random.Random, cases: int, c_parser: str) -> int:
    diverge = 0
    texts = [near_manifest(rng) for _ in range(cases)]
    said, _ = format_files(texts, check=True)
    for i, (text, line) in enumerate(zip(texts, c_parse(c_parser, texts), strict=True)):
        tool = not said.get(i, "").startswith("line ")
        c = line.startswith("ok")
        if tool != c:
            diverge += 1
            print(f"DIVERGE command={tool} launcher={c} on {text!r}")
    return diverge


POSITIONS = [  # an error on a known line, which both parsers must name (6.2)
    (b'exclave 1\n\ncpu "x86-64"\n\nown "/x"\nbogus 1\n', 6),
    (b'exclave 1\n\nown "/x"\nown "x"\n', 4),
    (b'exclave 1\n\nown "/x"\r\n', 3),
    (b'exclave 1\n\nown "/\xff"\n', 3),
    (b'exclave 1\n\nown "/x" \n', 3),
    (b'exclave 1\n\nown "/x"\n# after\n', 5),
    (b"exclave 1\n\n" + b"".join(b'own "/c%03d"\n' % i for i in range(257)), 259),
]


def positions(c_parser: str) -> int:
    bad = 0
    texts = [text for text, _ in POSITIONS]
    said, _ = format_files(texts, check=True)
    for i, ((text, want), c) in enumerate(zip(POSITIONS, c_parse(c_parser, texts), strict=True)):
        for who, msg in (("command", said.get(i, "accepted")), ("launcher", c)):
            if not msg.startswith(f"line {want:d} col "):
                bad += 1
                print(
                    f"FAIL the {who}'s parser says {msg!r} of an error on line {want:d} "
                    f"of {text[:50]!r}"
                )
    return bad


def main() -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument("--cases", type=int, default=3000)
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument(
        "--c-parser", default=os.path.join(os.path.dirname(HERE), "build", "gate", "manifest_test")
    )
    args = ap.parse_args()
    rng = random.Random(args.seed)
    c_parser = args.c_parser if os.path.exists(args.c_parser) else None
    bad = properties(rng, args.cases, c_parser)
    print(
        f"{args.cases:d} byte strings: format idempotent, decode(encode(b)) == b: {bad:d} problems"
    )
    if not c_parser:
        print(f"no C parser at {args.c_parser}: the two-parser comparison did not run")
        return 1 if bad else 0
    div = compare(rng, args.cases // 3, c_parser)
    print(f"{args.cases // 3:d} near-manifests through both C parsers: {div:d} divergences")
    bad += positions(c_parser)
    print(f"{len(POSITIONS):d} errors on known lines: both parsers name the line")
    return 1 if bad or div else 0


if __name__ == "__main__":
    sys.exit(main())
