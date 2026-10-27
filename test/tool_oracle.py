"""Compare the exclave command's C answers with its Python ones while it is ported (DESIGN.md 18).

    test/tool_oracle.py [--exclave EXCLAVE]... [--work DIR] [--tool PATH] [--cases N] [--seed S]

For every command build/exclave answers (exclave_cmd.PORTED), the same input goes to both
implementations, each on a copy of its own: the exclaves given (copied for a command that writes),
generated trees (made twice from one seed, since a copy cannot carry a pipe or an unreadable
directory), and the directories every command must refuse. Exit status, standard output and
standard error must be the same, and so must the directory each leaves behind: every entry's kind,
mode, link text and contents, and the bytes of .exclave/. A usage error must exit 2 in both; its
text is each
argument parser's own. A difference that is right goes into EXPECTED with the rule that makes it
so. Prints one line per difference and a summary; exit status 1 when one is unexplained.

Format takes files instead: batches of manifests and hashes files, valid, reordered and malformed
(test/grammar_test.py's), and the given exclaves' own, with and without --check.

Prune is given a log of each tree's own paths, sampled over a sorted walk so that both copies get
the same one, alone, with the odd lines below, and empty. Check is given an EXCLAVE_LOG with each
generated tree: library opens, working directories, and
lines a careless reader would misread. A third of the generated trees hold an ELF world, this
host's true, its loader and its libc where its PT_INTERP and the loader's directories put them,
and every generated tree may hold an ELF file that is malformed in one of the ways the static
check names.

Generated trees hold names with spaces, newlines, non-UTF-8 bytes and the reserved .real; wrappers
with their originals, originals without a wrapper, links that dangle, loop, climb out of the tree
or name a directory; empty directories, executables, a pipe, and at most one entry no one can
read, since which of two the commands meet first is the order of a directory's listing. A
filesystem that refuses a name that is not UTF-8 (ZFS's utf8only) gets none, and says so.
"""

import argparse
import hashlib
import os
import random
import shutil
import stat
import subprocess
import sys
lazy from collections.abc import Callable

import grammar_test
import tree
from exclave_cmd import PORTED

HERE = os.path.dirname(os.path.abspath(__file__))
# the commands that write to the exclave they are given
WRITES: tuple[str, ...] = ("wrap", "unwrap", "relink", "prune")
REPO = os.path.dirname(HERE)
PYTHON = (sys.executable, "-m", "exclave")

# (command, why the two answers may differ, whether this pair of results is that case)
EXPECTED: list[tuple[str, str, Callable[[tuple, tuple], bool]]] = []

NAMES = [
    b"a",
    b"b c",
    b"line\nbreak",
    b"\xff\xfe",
    b"\xc3\xa9t\xc3\xa9",
    b".hidden",
    b"x.real",
    b"-dash",
]


def snapshot(ex: str) -> list[tuple[bytes, str, int, bytes]]:
    """Return every entry under ex as (path, kind, mode, link text or content hash), sorted."""
    out = []
    top = os.fsencode(ex)
    for dirpath, dirnames, filenames in os.walk(top):
        for name in dirnames + filenames:
            p = os.path.join(dirpath, name)
            st = os.lstat(p)
            rel = os.path.relpath(p, top)
            if stat.S_ISLNK(st.st_mode):
                out.append((rel, "l", 0, os.readlink(p)))
            elif stat.S_ISREG(st.st_mode):
                try:
                    with open(p, "rb") as f:
                        h = hashlib.blake2b(f.read(), digest_size=16).digest()
                except PermissionError:
                    h = b"unreadable"
                out.append((rel, "f", st.st_mode & 0o7777, h))
            else:
                kind = "d" if stat.S_ISDIR(st.st_mode) else "o"
                out.append((rel, kind, st.st_mode & 0o7777, b""))
    return sorted(out)


def elf_bytes(rng: random.Random) -> bytes:
    """Return an ELF file malformed in one of the ways the static check names, or a sound one."""
    with open(os.path.realpath(shutil.which("true") or "/bin/true"), "rb") as f:
        good = f.read()
    return rng.choice(
        [
            good,
            good[:12],  # not even a header
            good[:40],  # a header cut short
            good[:4] + b"\x01" + good[5:200],  # ELF32
            good[:32]
            + (len(good) + 64).to_bytes(8, "little")
            + good[40:64],  # headers past the end
            good[:18]
            + (183 if good[18] == 62 else 62).to_bytes(2, "little")
            + good[20:],  # foreign
        ]
    )


def elf_world(root: bytes, rng: random.Random) -> None:
    """Put this host's true, its loader and its libc in the tree where they are named.

    The tree owns /etc, which holds this host's ld.so.cache whole, cut short or not at all.
    """
    os.makedirs(os.path.join(root, b"etc"), exist_ok=True)
    with open(os.path.join(root, b"etc", b"hostname"), "w") as f:
        f.write("x\n")
    if os.path.exists("/etc/ld.so.cache") and rng.random() < 0.7:
        with open("/etc/ld.so.cache", "rb") as f:
            cache = f.read()
        with open(os.path.join(root, b"etc", b"ld.so.cache"), "wb") as f:
            f.write(cache if rng.random() < 0.6 else cache[: rng.randrange(len(cache))])
    true = os.path.realpath(shutil.which("true") or "/bin/true")
    interp = tree.interp(true)
    if not interp:
        return
    for v, src in (
        ("/usr/bin/true", true),
        (interp, os.path.realpath(interp)),
        ("/lib/x86_64-linux-gnu/libc.so.6", os.path.realpath("/lib/x86_64-linux-gnu/libc.so.6")),
        ("/lib/aarch64-linux-gnu/libc.so.6", os.path.realpath("/lib/aarch64-linux-gnu/libc.so.6")),
    ):
        if os.path.exists(src):
            dst = os.path.join(root, os.fsencode(v.lstrip("/")))
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            if not os.path.lexists(dst):
                shutil.copy2(src, os.fsdecode(dst))


LOG_LINES = [
    "open 3 /usr/lib/libx.so.1",
    "open 4 /lib/x86_64-linux-gnu/libc.so.6",
    "open -2 /usr/lib/libmissing.so",
    "open 3 /home/u/build/libown.so.1.2",
    "open 3 /home/u/plain.so.1a",
    "open 3 /opt/odd\\nname.so",
    "open 3 /opt/ends-in-newline.so\\n",
    "open +5 /usr/lib/libplus.so",
    "open 1_0 /usr/lib/libunderscore.so",
    "open 3 /usr/lib/libcr.so\r",
    "load 3 /lib/ld.so",
    "exec 0 /usr/bin/true",
    "launcher 0 cwd given to the host /home/u",
    "launcher 0 cwd given to the host /",
    "launcher 0 cwd /tmp/w",
    "launcher 0 cwd /srv/x",
    "garbage",
    "",
    "open  /double/space.so",
]


def make_tree(ex: str, rng: random.Random) -> None:
    """Fill ex with a random exclave-shaped directory: .exclave/ and a tree of odd entries."""
    os.makedirs(os.path.join(ex, ".exclave"))
    with open(os.path.join(ex, ".exclave", "launcher"), "wb") as f:
        f.write(b"\x7fELF launcher stand-in\n")
    root = os.fsencode(os.path.join(ex, "tree"))
    os.makedirs(root)
    dirs = [root]
    for _ in range(rng.randrange(3, 9)):
        d = os.path.join(rng.choice(dirs), rng.choice(NAMES) + str(rng.randrange(9)).encode())
        os.makedirs(d, exist_ok=True)
        dirs.append(d)
    for _ in range(rng.randrange(5, 25)):
        d = rng.choice(dirs)
        name = rng.choice(NAMES) + str(rng.randrange(99)).encode()
        p = os.path.join(d, name)
        if os.path.lexists(p):
            continue
        kind = rng.choice(["file", "exe", "wrapper", "stray", "link", "link", "empty", "pipe"])
        if kind in ("file", "exe"):
            with open(p, "wb") as f:
                f.write(rng.randbytes(rng.randrange(0, 300)))
            os.chmod(p, 0o755 if kind == "exe" else rng.choice([0o644, 0o600, 0o444]))
        elif kind in ("wrapper", "stray"):
            os.makedirs(os.path.join(d, b".real"), exist_ok=True)
            with open(os.path.join(d, b".real", name), "wb") as f:
                f.write(rng.randbytes(rng.randrange(0, 300)))
            os.chmod(os.path.join(d, b".real", name), 0o755)
            if kind == "wrapper":
                tree.link_or_copy(os.path.join(ex, ".exclave", "launcher"), os.fsdecode(p))
        elif kind == "link":
            target = rng.choice(
                [
                    b"../" * rng.randrange(0, 4) + rng.choice(NAMES),
                    b"/usr/bin",
                    b"/" + os.path.relpath(rng.choice(dirs), root),
                    name,  # itself: a loop
                    b"no-such-target",
                ]
            )
            os.symlink(target, p)
        elif kind == "empty":
            os.makedirs(p)
        else:
            os.mkfifo(p)
    if rng.random() < 0.35:
        elf_world(root, rng)
    for _ in range(rng.randrange(0, 3)):
        p = os.path.join(rng.choice(dirs), b"elf" + str(rng.randrange(99)).encode())
        if not os.path.lexists(p):
            with open(p, "wb") as f:
                f.write(elf_bytes(rng))
            os.chmod(p, 0o755)
    with open(os.path.join(ex, "log"), "w", newline="") as f:
        f.write("\n".join(rng.sample(LOG_LINES, rng.randrange(1, len(LOG_LINES)))))
        f.write(rng.choice(["\n", ""]))
    if rng.random() < 0.25:  # one entry no one can read
        victim = rng.choice([p for p in dirs if p != root] or dirs)
        os.chmod(victim, 0)


def restore_modes(path: str) -> None:
    """Make every directory under path listable again, so that it can be removed."""
    for dirpath, dirnames, _ in os.walk(path):
        for d in dirnames:
            p = os.path.join(dirpath, d)
            if not os.path.islink(p):
                os.chmod(p, 0o755)


def answer(cmd: list[str], args: list[str], make: Callable[[str], None] | None, at: str) -> tuple:
    """Run one implementation on its own copy of the input; return what it answered and left.

    make puts the input at the path given, which args name as EX, or EX/NAME for a file in it; None
    runs args as they are.
    """
    if make is not None:
        make(at)
    target = [at + a[2:] if a == "EX" or a.startswith("EX/") else a for a in args]
    # the command holds what it allocated when it exits, refusing or not: a leak is no finding
    env = dict(os.environ, ASAN_OPTIONS="detect_leaks=0")
    p = subprocess.run([*cmd, *target], capture_output=True, check=False, timeout=600, env=env)
    out, err = (x.replace(os.fsencode(at), b"EX") for x in (p.stdout, p.stderr))
    left = snapshot(at) if make is not None and os.path.isdir(at) else []
    return p.returncode, out, err if p.returncode != 2 else b"", left


def grammar_file(rng: random.Random) -> bytes:
    """Return a manifest or a hashes file: valid, reordered or malformed."""
    if rng.random() < 0.3:
        recs = [
            b"hashes 1",
            b'tool "0.1.0"',
            b"pkg "
            + grammar_test.quote(grammar_test.rand_bytes(rng)).encode()
            + b' "1" "a" "b2:0"',
            b'pkg "a" "2" "all" "b2:1"',
            b'tree "b2:2"',
        ]
        rest = recs[1:]
        rng.shuffle(rest)
        sep = b"\n\n" if rng.random() < 0.7 else b"\n"
        text = sep.join([recs[0], *rest]) + b"\n"
        return rng.choice(grammar_test.MUTATIONS)(text, rng) if rng.random() < 0.3 else text
    text = grammar_test.near_manifest(rng)
    if rng.random() < 0.3:  # the same records in another order
        lines = text.split(b"\n")
        middle = lines[1:-1]
        rng.shuffle(middle)
        text = b"\n".join([lines[0], *middle, lines[-1]])
    return text


def make_files(at: str, texts: list[bytes]) -> None:
    os.makedirs(at)
    for i, t in enumerate(texts):
        with open(os.path.join(at, f"f{i}"), "wb") as f:
            f.write(t)


def format_cases(
    rng: random.Random, batches: int, given: list[str]
) -> list[tuple[str, list[str], Callable[[str], None] | str | None]]:
    """Return format's cases: generated files in batches, the given exclaves' own, and usage."""
    cases: list[tuple[str, list[str], Callable[[str], None] | str | None]] = [
        ("usage", [], None),
        ("usage", ["--check"], None),
        ("usage", ["--bogus", "x"], None),
    ]
    for i in range(batches):
        texts = [grammar_file(rng) for _ in range(20)]
        names = [f"EX/f{j}" for j in range(len(texts))]
        cases += [
            (f"batch {i}", [*check, *names], lambda at, t=texts: make_files(at, t))
            for check in ([], ["--check"])
        ]
    for e in given:
        texts = []
        for f in ("manifest", "hashes"):
            with open(os.path.join(e, ".exclave", f), "rb") as fh:
                texts.append(fh.read())
        cases.append(
            (
                f"given {os.path.basename(e)}",
                ["--ch", "EX/f0", "EX/f1"],
                lambda at, t=texts: make_files(at, t),
            )
        )
    # a file that is not there, and a directory, after one that is
    cases.append(("absent", ["EX/f0", "EX/absent"], lambda at: make_files(at, [b"exclave 1\n"])))
    cases.append(("directory", ["--", "EX"], lambda at: make_files(at, [])))
    return cases


def copy_of(src: str) -> Callable[[str], None]:
    """Return what makes a copy of the exclave src at a path.

    Its tree is hard-linked, since no command here writes into a file of the tree.
    """

    def make(at: str) -> None:
        tree.copy_exclave(src, at)

    return make


def unwrapped_copy_of(src: str) -> Callable[[str], None]:
    """Return what makes a copy of the exclave src at a path with its originals moved back."""

    def make(at: str) -> None:
        tree.copy_exclave(src, at)
        tree.unwrap_tree(at)

    return make


def program_log(ex: str, seed: int) -> None:
    """Write EX/plog: a workload's log of the tree's own paths, sampled with the seed.

    Executables run, other files and some directories opened, a link or two followed, a failed
    call and a host path; the tree is walked in the order of its names' bytes, so that two copies
    get the same log.
    """
    rng = random.Random(seed)
    root = os.path.join(ex, "tree")
    files, dirs = [], []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames.sort(key=os.fsencode)
        rel = "/" + os.path.relpath(dirpath, root) if dirpath != root else ""
        dirs.append(rel or "/")
        if "/.real" not in rel:
            files += [
                (rel + "/" + n, os.lstat(os.path.join(dirpath, n)).st_mode)
                for n in sorted(filenames, key=os.fsencode)
            ]
    lines = []
    for v, mode in rng.sample(files, min(len(files), 40)):
        call = "exec" if mode & 0o111 else rng.choice(["open", "open", "load"])
        lines.append(
            f"{call} {rng.choice([0, 3, -2])} {v}".replace("\\", "\\\\").replace("\n", "\\n")
        )
    lines += [f"open 3 {d}" for d in rng.sample(dirs, min(len(dirs), 3))]
    lines += [
        "open 3 /proc/self/maps",
        "launcher 0 cwd given to the host /home/u",
        "exec -2 /nowhere",
    ]
    rng.shuffle(lines)
    with open(os.path.join(ex, "plog"), "w", encoding="utf-8", errors="surrogateescape") as f:
        f.write("\n".join(lines) + "\n")
    open(os.path.join(ex, "empty"), "w").close()


def with_log(make: Callable[[str], None], seed: int) -> Callable[[str], None]:
    """Return make, then the program log written beside the tree it made."""

    def made(at: str) -> None:
        make(at)
        program_log(at, seed)

    return made


def main() -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument("--exclave", action="append", default=[])
    ap.add_argument("--work", default=os.path.join(REPO, "build", "tool-oracle"))
    ap.add_argument("--tool", default=os.path.join(REPO, "build", "exclave-asan"))
    ap.add_argument("--cases", type=int, default=60)
    ap.add_argument("--seed", type=int, default=1)
    args = ap.parse_args()
    work = os.path.abspath(args.work)
    if os.path.exists(work):
        restore_modes(work)
        shutil.rmtree(work)
    os.makedirs(work)
    rng = random.Random(args.seed)
    try:
        open(os.path.join(os.fsencode(work), b"\xff"), "wb").close()
    except OSError:
        NAMES.remove(b"\xff\xfe")
        print("tool oracle: this filesystem refuses names that are not UTF-8; none generated")
    # (label, the input made at a path, or a path as it is)
    inputs: list[tuple[str, Callable[[str], None] | str]] = []
    inputs += [(f"given {os.path.basename(e)}", os.path.abspath(e)) for e in args.exclave]
    for i in range(args.cases):
        seed = rng.randrange(1 << 30)
        inputs.append((f"generated {i}", lambda at, seed=seed: make_tree(at, random.Random(seed))))
    # the directories every command refuses
    refusals = os.path.join(work, "refusals")
    for name, made in (
        ("no-tree", [".exclave"]),
        ("no-dot-exclave", ["tree"]),
        ("can", [".can", "root"]),
        ("file", []),
    ):
        p = os.path.join(refusals, name)
        os.makedirs(p)
        for d in made:
            os.makedirs(os.path.join(p, d))
        inputs.append(("refusal " + name, p))
    inputs.append(("refusal absent", os.path.join(refusals, "absent")))
    runs = differ = 0
    for cmd in PORTED:
        cases: list[tuple[str, list[str], Callable[[str], None] | str | None]] = [
            ("usage", [], None),
            ("usage", ["a", "b"], None),
        ]
        cases += [(label, ["EX"], made) for label, made in inputs]
        if cmd == "format":
            cases = format_cases(rng, args.cases, [os.path.abspath(e) for e in args.exclave])
        if cmd == "wrap":  # each exclave given, unwrapped, to wrap from the start
            cases += [
                (label + ", unwrapped", ["EX"], unwrapped_copy_of(m))
                for label, m in inputs
                if label.startswith("given") and isinstance(m, str)
            ]
        if cmd == "prune":  # with a log of the tree's own paths, alone, with odd lines, and empty
            cases = [("usage", [], None), ("usage", ["EX"], inputs[-1][1])]
            for i, (label, m) in enumerate(inputs):
                if label.startswith("refusal"):
                    cases.append((label, ["EX", "/dev/null"], m))
                    continue
                make = copy_of(m) if isinstance(m, str) else m
                cases.append((label, ["EX", "EX/plog"], with_log(make, i)))
                if callable(m):
                    cases.append(
                        (label + ", odd lines", ["EX", "EX/plog", "EX/log"], with_log(make, i))
                    )
                cases.append((label + ", empty log", ["EX", "EX/empty"], with_log(make, i)))
        if cmd == "check":  # with the log written beside the tree
            cases += [(label + ", log", ["EX", "EX/log"], m) for label, m in inputs if callable(m)]
        if cmd == "relink":  # with a launcher named, and with one that is not there
            other = os.path.join(REPO, "build", "launcher-old")
            cases += [(label + ", launcher named", ["EX", other], m) for label, m in inputs[:8]]
            cases.append(("absent launcher", ["EX", other + "-absent"], inputs[-6][1]))
        for i, (label, argv, given) in enumerate(cases):
            made = given
            if isinstance(given, str) and cmd in WRITES and label.startswith("given"):
                made = copy_of(given)
            results = []
            for impl, tool_cmd in (("py", [*PYTHON, cmd]), ("c", [args.tool, cmd])):
                at = os.path.join(work, f"{impl}-{cmd}-{i}")
                if isinstance(made, str):
                    results.append(
                        answer(tool_cmd, [made if a == "EX" else a for a in argv], None, made)
                    )
                else:
                    results.append(answer(tool_cmd, argv, made, at))
            py, c = results
            runs += 1
            same = py[0] == c[0] and (py[0] == 2 or py[1:] == c[1:])
            why = next((w for k, w, f in EXPECTED if k == cmd and f(py, c)), None)
            if not same and why is None:
                differ += 1
                print(f"DIFF {cmd} {label} {argv}:")
                for what, a, b in zip(("status", "stdout", "stderr", "left"), py, c, strict=True):
                    if a != b:
                        print(f"  {what}: python {str(a)[:300]}\n  {what}: c      {str(b)[:300]}")
    restore_modes(work)
    shutil.rmtree(work, ignore_errors=True)
    print(f"tool oracle: {', '.join(PORTED)}: {runs} cases, {differ} differ")
    return 1 if differ else 0


if __name__ == "__main__":
    sys.exit(main())
