#!/usr/bin/env python3
"""grammar_test.py — the property tests of PROPOSAL.md 6.2 and 17 item 3 (review O4-14).

    test/grammar_test.py [--cases N] [--seed S] [--c-parser PATH]

Three statements hold for every byte sequence b: encode is injective, decode(encode(b)) == b, and fmt is
idempotent. And the two implementations of the grammar, the cannery's Python parser and the opener's C parser
(built by test/gate.sh's unit step, run with a file argument), accept and reject the same inputs: manifests
and their malformed variants (MUTATIONS); and both name the line of an error on a known line (POSITIONS).
"""
import argparse
import os
import random
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(HERE), "cannery"))
import cannery  # noqa: E402


def rand_bytes(rng, path=False):
    """A random byte string; with path, one a Linux path could hold (any byte but NUL)."""
    n = rng.randint(0, 24)
    pick = [lambda: rng.randint(0, 255), lambda: rng.choice(b'"\\\n\t /'), lambda: rng.randint(0x20, 0x7e),
            lambda: rng.choice([0xC3, 0xA9, 0xE2, 0x82, 0xAC, 0xF0, 0x9F, 0x98, 0x80, 0xC0, 0xED, 0xA0, 0xF5, 0xFF])]
    b = bytes(rng.choice(pick)() for _ in range(n))
    return b.replace(b"\0", b"\1") if path else b


def properties(rng, cases):
    bad = 0
    seen = {}
    for _ in range(cases):
        b = rand_bytes(rng, path=True).replace(b"/", b"_")     # the encoding's properties; a path's own spelling rules are the mutations' (6.2)
        if b in (b".", b".."):
            b = b"_" + b
        q = cannery.quote(b)
        if seen.setdefault(q, b) != b:
            bad += 1                                              # encode is injective
        text = ("can 1\n\nown %s\n" % cannery.quote(b"/" + b)).encode()
        try:
            recs = cannery.parse(text, "can")
        except cannery.GrammarError as e:
            bad += 1
            print("FAIL parse of encoded %r: %s" % (b, e))
            continue
        if recs[1].fields[0][1] != b"/" + b:                        # decode(encode(b)) == b
            bad += 1
            print("FAIL round trip %r" % b)
        canon = cannery.dump(recs, "can")
        if canon != text or cannery.dump(cannery.parse(canon, "can"), "can") != canon:   # fmt is idempotent
            bad += 1
            print("FAIL canonical form %r" % b)
    return bad


MUTATIONS = [
    lambda t, rng: t.replace(b"\n", b"\r\n", 1), lambda t, rng: t[:-1], lambda t, rng: b"\xef\xbb\xbf" + t,
    lambda t, rng: t.replace(b" ", b"  ", 1), lambda t, rng: t.replace(b" ", b"\t", 1), lambda t, rng: t.replace(b'"', b"", 1),
    lambda t, rng: t.replace(b"own", b"Own", 1), lambda t, rng: t + b"# trailing\n", lambda t, rng: t.replace(b"can 1", b"can 2", 1),
    lambda t, rng: t.replace(b'own "/', b'own "//', 1), lambda t, rng: t.replace(b'own "/', b'own "/./', 1), lambda t, rng: t.replace(b'own "/', b'own "/../', 1),
    lambda t, rng: t.replace(b'"/', b'"', 1), lambda t, rng: t.replace(b"\\x", b"\\X", 1), lambda t, rng: t.replace(b"own", b"env", 1),
    lambda t, rng: t[:rng.randint(0, len(t))] + bytes([rng.randint(0, 31)]) + t[rng.randint(0, len(t)):],
    lambda t, rng: t.replace(b'"\n', b'" \n', 1), lambda t, rng: t.replace(b"own", b"own \"/x\" own", 1),
]


def near_manifest(rng):
    recs = ["can 1"]
    for _ in range(rng.randint(0, 4)):
        key = rng.choice(["own", "host", "data", "isa", "isa", "bogus"])
        val = rand_bytes(rng)
        recs.append("%s %s" % (key, cannery.quote((b"/" if key in ("own", "host", "data") else b"") + val)))
    if rng.random() < 0.3:
        recs.insert(rng.randint(0, len(recs)), "# " + rand_bytes(rng).decode("utf-8", "replace"))
    text = ("\n".join(recs) + "\n").encode()
    if rng.random() < 0.6:
        text = rng.choice(MUTATIONS)(text, rng)
    return text


def compare(rng, cases, c_parser):
    diverge = 0
    with tempfile.TemporaryDirectory(prefix="grammar-") as d:
        path = os.path.join(d, "manifest")
        for i in range(cases):
            text = near_manifest(rng)
            with open(path, "wb") as f:
                f.write(text)
            try:
                cannery.parse(text, "can")
                py = True
            except cannery.GrammarError:
                py = False
            c = subprocess.run([c_parser, path], stdout=subprocess.PIPE, stderr=subprocess.PIPE).returncode == 0
            if py != c:
                diverge += 1
                print("DIVERGE python=%s c=%s on %r" % (py, c, text))
    return diverge


POSITIONS = [                                     # an error on a known line, which both parsers must name (6.2)
    (b'can 1\n\nisa "x86-64"\n\nown "/x"\nbogus 1\n', 6), (b'can 1\n\nown "/x"\nown "x"\n', 4),
    (b'can 1\n\nown "/x"\r\n', 3), (b'can 1\n\nown "/\xff"\n', 3), (b'can 1\n\nown "/x" \n', 3),
    (b'can 1\n\nown "/x"\n# after\n', 5), (b"can 1\n\n" + b"".join(b'own "/c%03d"\n' % i for i in range(257)), 259),
]


def positions(c_parser):
    bad = 0
    with tempfile.TemporaryDirectory(prefix="grammar-") as d:
        path = os.path.join(d, "manifest")
        for text, want in POSITIONS:
            with open(path, "wb") as f:
                f.write(text)
            try:
                cannery.parse(text, "can")
                py = "accepted"
            except cannery.GrammarError as e:
                py = str(e)
            c = subprocess.run([c_parser, path], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True).stderr.strip()
            for who, msg in (("python", py), ("c", c)):
                if not msg.startswith("line %d col " % want):
                    bad += 1
                    print("FAIL the %s parser says %r of an error on line %d of %r" % (who, msg, want, text[:50]))
    return bad


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--cases", type=int, default=3000)
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--c-parser", default=os.path.join(os.path.dirname(HERE), "build", "gate", "manifest_test"))
    a = ap.parse_args()
    rng = random.Random(a.seed)
    bad = properties(rng, a.cases)
    print("%d byte strings: encode injective, decode(encode(b)) == b, fmt idempotent: %d problems" % (a.cases, bad))
    div = compare(rng, a.cases // 3, a.c_parser) if os.path.exists(a.c_parser) else -1
    if div < 0:
        print("no C parser at %s: the two-parser comparison did not run" % a.c_parser)
    else:
        print("%d near-manifests through both parsers: %d divergences" % (a.cases // 3, div))
        bad += positions(a.c_parser)
        print("%d errors on known lines: both parsers name the line" % len(POSITIONS))
    return 1 if bad or div > 0 else 0


if __name__ == "__main__":
    sys.exit(main())
