"""This build against an earlier one, as docs/DESIGN.md 6.7 promises between builds of one version.

    test/compat_test.py --old DIR [--work DIR]

DIR holds an earlier build's files for this machine: `exclave`, its command, and one exclave it
wrapped, `NAME.exclave`, which carries its launcher. The baseline, the first release's command and
an exclave it ships, is what scripts/inputs puts in its DIR/baseline (docs/DESIGN.md 6.7). A copy
of that exclave stays as the earlier build wrote it, another is relinked by this command to this
launcher, and each build reads the other's: this command checks, hashes, unwraps and wraps the
earlier exclave and reads its launcher's log in check and prune; the earlier command checks and
hashes this one's; and each launcher runs the other's programs, a listing among them, nested either
way. A DIR that does not exist is the state before the first release, or on a machine the release
is not for: the test says it cannot run and exits 0, which the step runner reports as SKIP.
Prints one line per step; the exit status is the number of failures.
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


def run(cmd: list[str], env: dict[str, str] | None = None) -> tuple[int, str]:
    p = subprocess.run(cmd, capture_output=True, check=False, timeout=600, env=env)
    return p.returncode, (p.stdout + p.stderr).decode("utf-8", "replace")


def recorded_tree(ex: str) -> str:
    with open(os.path.join(ex, ".exclave", "hashes"), encoding="utf-8") as f:
        m = re.search(r'^tree "(b3:[0-9a-f]+)"$', f.read(), re.MULTILINE)
    return m.group(1) if m else ""


def shell(ex: str) -> str:
    root = os.path.join(ex, "tree")
    return os.path.join(root, tree.vbin(root, "sh").lstrip("/"))


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--old", required=True)
    ap.add_argument("--work", default=os.path.join(REPO, "build", "compat-work"))
    args = ap.parse_args()
    old = os.path.abspath(args.old)
    if not os.path.isdir(old):
        print(f"compat: no baseline release yet at {old}; cannot run")
        return 0
    old_cmd = os.path.join(old, "exclave")
    if not os.access(old_cmd, os.X_OK):
        sys.exit(f"compat: no earlier build's command at {old_cmd}")
    wrapped = sorted(n for n in os.listdir(old) if n.endswith(".exclave"))
    if len(wrapped) != 1:
        sys.exit(f"compat: {old} holds {len(wrapped)} exclaves, not the earlier build's one")
    src = os.path.join(old, wrapped[0])
    old_launcher = os.path.join(src, ".exclave", "launcher")
    new_cmd = tree.TOOL[0]
    work = os.path.abspath(args.work)
    shutil.rmtree(work, ignore_errors=True)
    os.makedirs(work)
    _, version = run([old_cmd, "version"])
    print(f"against {version.strip()}")

    # the earlier build's exclave, as it wrote it, read by this one
    earlier = tree.copy_exclave(src, os.path.join(work, "earlier.exclave"))
    rc, out = run([new_cmd, "check", earlier])
    step("this command checks the earlier build's exclave", rc == 0, out[-400:])
    rc, out = run([new_cmd, "hash", earlier])
    step(
        "its tree hash is the one the earlier command recorded",
        out.strip() == recorded_tree(earlier),
        out,
    )
    log = os.path.join(work, "earlier.log")
    env = {**os.environ, "EXCLAVE_LOG": log}
    rc, out = run([shell(earlier), "-c", "ls / >/dev/null && echo ran"], env)
    step("the earlier launcher runs its program", rc == 0 and "ran" in out, out[-300:])
    rc, out = run([new_cmd, "check", earlier, log])
    step("this command reads the earlier launcher's log in check", rc == 0, out[-400:])
    pruned = tree.copy_exclave(earlier, os.path.join(work, "earlier-pruned.exclave"))
    rc, out = run([new_cmd, "prune", pruned, log])
    step("and in prune", rc == 0, out[-400:])
    before = recorded_tree(earlier)
    rc1, out1 = run([new_cmd, "unwrap", earlier])
    rc2, out2 = run([new_cmd, "wrap", earlier, old_launcher])
    step(
        "this command unwraps and wraps it again, to the same tree hash",
        rc1 == 0 and rc2 == 0 and recorded_tree(earlier) == before,
        (out1 + out2)[-400:],
    )

    # this build's exclave, read by the earlier one
    later = tree.fresh_exclave(src, os.path.join(work, "later.exclave"))
    rc, out = run([old_cmd, "check", later])
    step("the earlier command checks this build's exclave", rc == 0, out[-400:])
    rc, out = run([old_cmd, "hash", later])
    step("and hashes it as this command recorded", out.strip() == recorded_tree(later), out)

    # the two launchers, each running the other's programs, a listing among them: the call a later
    # filter version traps that an earlier handler may not answer (6.7)
    for outer, inner, name in (
        (earlier, later, "earlier outside, this inside"),
        (later, earlier, "this outside, earlier inside"),
    ):
        inner_cmd = "ls / /usr >/dev/null && echo nested"
        rc, out = run([shell(outer), "-c", f"{shell(inner)} -c '{inner_cmd}'"])
        step(f"nested, {name}", rc == 0 and out.strip() == "nested", out[-300:])

    print(f"compat: {'every step passed' if not fails else f'{len(fails)} steps failed'}")
    return len(fails)


if __name__ == "__main__":
    sys.exit(main())
