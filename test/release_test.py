"""A release of an exclave, made and then taken as a consumer takes it (DESIGN.md 10.5).

    test/release_test.py --exclave EXCLAVE [--work DIR]

The exclave is a gcc exclave, and the release's toolchain too: scripts/reproduce builds the
launcher inside it and the command from that, and scripts/release makes a release of a copy of the
exclave under WORK, wrapped again by that command, since a release is of what the command makes.
A copy wrapped with another launcher is refused, as are a directory
that is not empty and, without the allowance this test makes itself, a tree with changes its
commit does not hold; a release of no exclave holds the two commands, named for the machine,
the licences and the sums.
Then, in a directory that holds nothing but the release's files, the README's recipe runs: the
sums are checked, the archive is unpacked, the release's
own `exclave` checks the exclave and its `exclave-fetch` runs, its tree hash is the one the hashes
file records, a program in it runs, and NOTICES names Go and every module go.mod requires with
its licence. A tampered archive fails the sums. Prints one line per step;
the exit status is the number of failures.
"""

import argparse
import os
import platform
import re
import shutil
import subprocess
import sys

import tree
from harness import FAILED, step

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)


MACHINE = platform.machine()
RELEASE = os.path.join(REPO, "scripts", "release")
# scripts/release refuses a tree with uncommitted changes; the recipe is tested on the tree as it
# stands
ANY_TREE = dict(os.environ, EXCLAVE_RELEASE_UNCOMMITTED="1")


def run(
    cmd: list[str], cwd: str, inp: bytes | None = None, env: dict[str, str] | None = None
) -> tuple[int, str]:
    p = subprocess.run(
        cmd, cwd=cwd, input=inp, capture_output=True, check=False, timeout=600, env=env
    )
    return p.returncode, (p.stdout + p.stderr).decode("utf-8", "replace")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--exclave", required=True)
    ap.add_argument("--work", default=os.path.join(REPO, "build", "release-work"))
    args = ap.parse_args()
    work = os.path.abspath(args.work)
    shutil.rmtree(work, ignore_errors=True)
    os.makedirs(work)
    toolchain = os.path.abspath(args.exclave)
    ex = tree.fresh_exclave(toolchain, os.path.join(work, "src", "one.exclave"))
    name = os.path.basename(ex)
    # the command a release ships: its launcher built inside the gcc exclave and the command from
    # it (scripts/reproduce), and wrapping
    # the copy with the launcher it carries
    built = os.path.join(work, "reproduce")
    rc, out = run([os.path.join(REPO, "scripts", "reproduce"), toolchain, built], work)
    if rc:
        sys.exit(f"scripts/reproduce: {out[-400:]}")
    command = os.path.join(built, "build", "exclave")
    for cmd in ("unwrap", "wrap"):
        rc, out = run([command, cmd, ex], work)
        if rc:
            sys.exit(f"{cmd} {ex}: {out[-400:]}")
        if cmd == "unwrap":  # wrap installs the launcher it carries where there is none
            os.remove(os.path.join(ex, ".exclave", "launcher"))
    release = os.path.join(work, "release")
    # an exclave wrapped with another launcher is refused, the files the release would ship being
    # another build's
    other = tree.fresh_exclave(
        toolchain,
        os.path.join(work, "src", "two.exclave"),
        os.path.join(REPO, "build", "launcher-old"),
    )
    rc, out = run([RELEASE, release + "-other", toolchain, other], work, env=ANY_TREE)
    step("an exclave wrapped with another launcher is refused", rc and "relink" in out, out[-300:])
    rc, out = run([RELEASE, release, toolchain, ex], work, env=ANY_TREE)
    step("scripts/release", rc == 0, out[-500:])
    if rc:
        return len(FAILED)
    rc, out = run([RELEASE, release, toolchain, ex], work, env=ANY_TREE)
    step("a directory that is not empty is refused", rc == 2 and "is not empty" in out, out[-300:])
    # a release of no exclave: the two commands, the licences and the sums
    alone = release + "-commands"
    rc, out = run([RELEASE, alone, toolchain], work, env=ANY_TREE)
    files = sorted(os.listdir(alone)) if rc == 0 else []
    wanted = sorted(
        [
            f"exclave-{MACHINE}",
            f"exclave-fetch-{MACHINE}",
            "LICENSE",
            "NOTICES",
            "SHA256SUMS",
            "B3SUMS",
        ]
    )
    step("a release of the commands alone", rc == 0 and files == wanted, f"{files} {out[-300:]}")
    rc, out = run(["sha256sum", "-c", "SHA256SUMS"], alone)
    step("its sums check", rc == 0, out)
    # without the allowance a release is of a commit: refused where the tree holds more
    rc, described = run(["git", "describe", "--always", "--dirty", "--exclude=*"], REPO)
    if rc == 0 and described.strip().endswith("-dirty"):
        rc, out = run([RELEASE, release + "-commit", toolchain], work)
        step(
            "a tree with uncommitted changes is refused",
            rc == 1 and "a release is of a commit" in out,
            out[-300:],
        )

    # the consumer's directory: the release's files and nothing of the checkout
    consumer = os.path.join(work, "consumer")
    shutil.copytree(release, consumer)
    rc, out = run(["sha256sum", "-c", "SHA256SUMS"], consumer)
    step("the sha256 sums check", rc == 0, out)
    # b3sum where the machine has it, else the release's own command, file by file
    tool = os.path.join(consumer, f"exclave-{MACHINE}")
    os.chmod(tool, 0o755)
    if shutil.which("b3sum"):
        rc, out = run(["b3sum", "-c", "B3SUMS"], consumer)
    else:
        with open(os.path.join(consumer, "B3SUMS"), encoding="utf-8") as f:
            listed = [line.split("  ", 1) for line in f.read().splitlines()]
        bad = [n for h, n in listed if run([tool, "hash", n], consumer)[1].strip() != "b3:" + h]
        rc, out = (1 if bad or not listed else 0), f"differ: {bad}"
    step("the BLAKE3 sums check", rc == 0, out)
    rc, out = run(["tar", "--zstd", "-xf", name + ".tar.zst"], consumer)
    step("the archive unpacks", rc == 0, out)
    rc, out = run([tool, "check", name], consumer)
    step("the release's exclave checks the exclave", rc == 0, out[-500:])
    fetcher = os.path.join(consumer, f"exclave-fetch-{MACHINE}")
    os.chmod(fetcher, 0o755)
    rc, out = run([fetcher, "version"], consumer)
    step("the release's exclave-fetch runs", rc == 0 and out.startswith("exclave-fetch "), out)
    rc, out = run([tool, "hash", name], consumer)
    with open(os.path.join(consumer, name, ".exclave", "hashes"), encoding="utf-8") as f:
        m = re.search(r'^tree "(b3:[0-9a-f]+)"$', f.read(), re.MULTILINE)
    step(
        "the tree hash is the one the hashes file records",
        rc == 0 and m and out.strip() == m.group(1),
        out,
    )
    root = os.path.join(consumer, name, "tree")
    shell = os.path.join(root, tree.vbin(root, "sh").lstrip("/"))
    rc, out = run([shell, "-c", "echo from inside"], consumer)
    step("a program in the unpacked exclave runs", rc == 0 and "from inside" in out, out)
    # the modules go.mod requires directly, each named in NOTICES with a licence's conditions
    with open(os.path.join(REPO, "go.mod"), encoding="utf-8") as f:
        required = re.findall(r"^\t(\S+) (v\S+)$", f.read(), re.MULTILINE)
    with open(os.path.join(consumer, "NOTICES"), encoding="utf-8") as f:
        notices = f.read()
    missing = [m for m, v in required if f"\n== {m} {v}, " not in notices]
    step(
        "NOTICES names Go and every module go.mod requires, with its licence",
        required
        and not missing
        and "\n== Go " in notices
        and notices.count("Redistribution") > len(required),
        f"missing {missing}" if missing else notices[:300],
    )
    with open(os.path.join(consumer, "LICENSE"), encoding="utf-8") as f:
        licence = f.read()
    step("LICENSE is exclave's own", "MIT License" in licence, licence[:100])

    # tampering: a byte of the archive
    with open(os.path.join(consumer, name + ".tar.zst"), "r+b") as f:
        f.seek(64)
        b = f.read(1)
        f.seek(64)
        f.write(bytes([b[0] ^ 1]))
    rc, out = run(["sha256sum", "-c", "SHA256SUMS"], consumer)
    step("a changed archive fails the sums", rc != 0 and "FAILED" in out, out)
    print(f"release: {'every step passed' if not FAILED else f'{len(FAILED)} steps failed'}")
    return len(FAILED)


if __name__ == "__main__":
    sys.exit(main())
