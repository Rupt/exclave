"""The exclave command while its commands move from Python to C (DESIGN.md 18 item 1).

    exclave_cmd.py COMMAND ARGS...

Runs build/exclave for the commands it answers and the Python package for the rest, so that every
driver, scripts/exclave and the matrix's VMs run each command as it is answered now.
EXCLAVE_TEST_TOOL names another build of the C command, build/exclave-asan for one.
"""

import os
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
# the commands build/exclave answers
PORTED: tuple[str, ...] = ("hash", "format", "unwrap", "relink", "check", "wrap", "prune")


def main() -> None:
    args = sys.argv[1:]
    if args and args[0] in PORTED:
        tool = os.environ.get("EXCLAVE_TEST_TOOL") or os.path.join(REPO, "build", "exclave")
        os.execv(tool, [tool, *args])  # noqa: S606 -- the command itself, an argument vector
    os.execv(sys.executable, [sys.executable, "-m", "exclave", *args])  # noqa: S606 -- as above


if __name__ == "__main__":
    main()
