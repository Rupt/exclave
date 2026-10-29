"""A release of an exclave, made and then taken as a consumer takes it (DESIGN.md 10.5).

    test/release_test.py --exclave EXCLAVE [--work DIR]

The exclave is a gcc exclave, and the release's toolchain too: scripts/reproduce builds the command
and the launcher inside it, and scripts/release makes a release of a copy of the exclave under
WORK, wrapped again by that command, since a release is of what the command makes, signed with a
key made here. A copy wrapped with another launcher is refused.
Then, in a directory that holds nothing but the release's files, the README's recipe runs: the
signature is verified against the key, the sums are checked, the archive is unpacked, the release's
own `exclave` checks the exclave, its tree hash is the one the hashes file records, and a program in
it runs. A tampered archive and a tampered sums file are refused. Prints one line per step; the
exit status is the number of failures.
"""

import argparse
import os
import re
import shutil
import subprocess
import sys

import tree

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)

fails: list[str] = []


def step(name: str, ok: object, detail: str = "") -> None:
    if not ok:
        fails.append(name)
    print(f"{'ok  ' if ok else 'FAIL'} {name}{': ' + detail if detail and not ok else ''}")


def run(cmd: list[str], cwd: str, inp: bytes | None = None) -> tuple[int, str]:
    p = subprocess.run(cmd, cwd=cwd, input=inp, capture_output=True, check=False, timeout=600)
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
    # the command a release ships: built inside the gcc exclave (scripts/reproduce), and wrapping
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
    key = os.path.join(work, "key")
    subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", key], check=True)
    release = os.path.join(work, "release")
    # an exclave wrapped with another launcher is refused, the files the release would ship being
    # another build's
    other = tree.fresh_exclave(
        toolchain,
        os.path.join(work, "src", "two.exclave"),
        os.path.join(REPO, "build", "launcher-old"),
    )
    rc, out = run(
        [os.path.join(REPO, "scripts", "release"), key, release + "-other", toolchain, other], work
    )
    step("an exclave wrapped with another launcher is refused", rc and "relink" in out, out[-300:])
    rc, out = run([os.path.join(REPO, "scripts", "release"), key, release, toolchain, ex], work)
    step("scripts/release", rc == 0, out[-500:])
    if rc:
        return len(fails)

    # the consumer's directory: the release's files and nothing of the checkout
    consumer = os.path.join(work, "consumer")
    shutil.copytree(release, consumer)
    with open(key + ".pub", encoding="utf-8") as f:
        pub = f.read().split()
    with open(os.path.join(consumer, "allowed_signers"), "w", encoding="utf-8") as f:
        f.write(f"exclave-release {pub[0]} {pub[1]}\n")
    verify = [
        "ssh-keygen",
        "-Y",
        "verify",
        "-f",
        "allowed_signers",
        "-I",
        "exclave-release",
        "-n",
        "exclave",
        "-s",
        "SHA256SUMS.sig",
    ]
    with open(os.path.join(consumer, "SHA256SUMS"), "rb") as f:
        sums = f.read()
    rc, out = run(verify, consumer, sums)
    step("the signature verifies against the key", rc == 0, out)
    rc, out = run(["sha256sum", "-c", "SHA256SUMS"], consumer)
    step("the sha256 sums check", rc == 0, out)
    rc, out = run(["b2sum", "-c", "B2SUMS"], consumer)
    step("the blake2 sums check", rc == 0, out)
    rc, out = run(["tar", "-xJf", name + ".tar.xz"], consumer)
    step("the archive unpacks", rc == 0, out)
    tool = os.path.join(consumer, "exclave")
    os.chmod(tool, 0o755)
    rc, out = run([tool, "check", name], consumer)
    step("the release's exclave checks the exclave", rc == 0, out[-500:])
    rc, out = run([tool, "hash", name], consumer)
    with open(os.path.join(consumer, name, ".exclave", "hashes"), encoding="utf-8") as f:
        m = re.search(r'^tree "(b2:[0-9a-f]+)"$', f.read(), re.MULTILINE)
    step(
        "the tree hash is the one the hashes file records",
        rc == 0 and m and out.strip() == m.group(1),
        out,
    )
    root = os.path.join(consumer, name, "tree")
    shell = os.path.join(root, tree.vbin(root, "sh").lstrip("/"))
    rc, out = run([shell, "-c", "echo from inside"], consumer)
    step("a program in the unpacked exclave runs", rc == 0 and "from inside" in out, out)

    # tampering: a byte of the archive, and a sum in the sums file
    with open(os.path.join(consumer, name + ".tar.xz"), "r+b") as f:
        f.seek(64)
        b = f.read(1)
        f.seek(64)
        f.write(bytes([b[0] ^ 1]))
    rc, out = run(["sha256sum", "-c", "SHA256SUMS"], consumer)
    step("a changed archive fails the sums", rc != 0 and "FAILED" in out, out)
    with open(os.path.join(consumer, "SHA256SUMS"), "r+b") as f:
        f.seek(0)
        b = f.read(1)
        f.seek(0)
        f.write(b"0" if b != b"0" else b"1")
    with open(os.path.join(consumer, "SHA256SUMS"), "rb") as f:
        sums = f.read()
    rc, out = run(verify, consumer, sums)
    step("a changed sums file fails the signature", rc != 0, out)
    print(f"release: {'every step passed' if not fails else f'{len(fails)} steps failed'}")
    return len(fails)


if __name__ == "__main__":
    sys.exit(main())
