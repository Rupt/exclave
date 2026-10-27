"""An exclave's files on disk, and the launcher's log (DESIGN.md 6.1, 6.2).

An exclave is a directory: `tree/` holds the software's own `/`, and `.exclave/` holds the launcher,
the manifest and the hashes file. Every executable in the tree is a wrapper, a hard link to the
launcher, with the original beside it in `.real/`. Paths inside the tree are handled in two
spellings: a real path on this machine, and a virtual path, the absolute path a program inside the
exclave would use.
"""

import filecmp
import hashlib
import os
import re
import shutil
import stat
from typing import NamedTuple
lazy from collections.abc import Iterable, Iterator

# The host's volatile directories (8.1): always the host's at run time, never shipped.
VOLATILE = ("/proc", "/dev", "/sys", "/tmp", "/var/tmp", "/run")  # noqa: S108 -- prefixes, not files


def manifest_path(ex: str) -> str:
    return os.path.join(ex, ".exclave", "manifest")


def hashes_path(ex: str) -> str:
    return os.path.join(ex, ".exclave", "hashes")


def launcher_path(ex: str) -> str:
    return os.path.join(ex, ".exclave", "launcher")


def under(vpath: str, prefix: str) -> bool:
    """Return whether vpath is prefix or lies below it."""
    return vpath == prefix or vpath.startswith(prefix.rstrip("/") + "/")


def under_any(vpath: str, prefixes: Iterable[str]) -> bool:
    return any(under(vpath, p) for p in prefixes)


def b2_file(path: str) -> str:
    """Return the file's BLAKE2b-256 hash as the hashes file spells it."""
    with open(path, "rb") as f:
        return "b2:" + hashlib.file_digest(f, lambda: hashlib.blake2b(digest_size=32)).hexdigest()


def walk_files(root: str) -> Iterator[tuple[str, str, os.stat_result]]:
    """Yield (real path, virtual path, lstat) for every entry under root but a directory.

    Symlinks to directories are included. The `.real/` directories of originals are skipped. Each
    directory's entries come sorted by their bytes, before the directories below it.
    """
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted((d for d in dirnames if d != ".real"), key=os.fsencode)
        links = [d for d in dirnames if os.path.islink(os.path.join(dirpath, d))]
        for name in sorted(filenames + links, key=os.fsencode):
            real = os.path.join(dirpath, name)
            yield real, "/" + os.path.relpath(real, root).replace(os.sep, "/"), os.lstat(real)


def link_or_copy(src: str, dst: str) -> None:
    """Hard-link src at dst where the filesystem allows it, and copy it otherwise."""
    try:
        os.link(src, dst)
    except OSError:
        shutil.copy2(src, dst)


def payload_path(real: str) -> str:
    """Return the file a wrapper stands for, its original in `.real/`, or real itself."""
    d, n = os.path.split(real)
    p = os.path.join(d, ".real", n)
    return p if os.path.exists(p) else real


class Launcher(NamedTuple):
    """An exclave's launcher: its path and the identity its wrappers share."""

    path: str
    dev: int
    ino: int
    size: int


def launcher_of(ex: str) -> Launcher:
    p = launcher_path(ex)
    st = os.stat(p)
    return Launcher(p, st.st_dev, st.st_ino, st.st_size)


def is_wrapper(real: str, launcher: Launcher) -> bool:
    """Return whether the file at real is a wrapper of this launcher.

    A wrapper is a hard link to the launcher, or, where a copy split the links, a file with the
    launcher's contents that has an original in `.real/`.
    """
    st = os.lstat(real)
    if not stat.S_ISREG(st.st_mode):
        return False
    if (st.st_dev, st.st_ino) == (launcher.dev, launcher.ino):
        return True
    d, n = os.path.split(real)
    return (
        st.st_size == launcher.size
        and os.path.exists(os.path.join(d, ".real", n))
        and filecmp.cmp(real, launcher.path, shallow=False)
    )


def log_lines(logs: Iterable[str]) -> Iterator[tuple[str, int, str]]:
    r"""Yield (call, result, path) for every line of the given EXCLAVE_LOG files (6.2).

    The path's `\n` and `\\` escapes are undone in one pass from left to right, so a backslash
    followed by an n stays a backslash.
    """
    for lp in logs:
        with open(lp, encoding="utf-8", errors="surrogateescape", newline="\n") as f:
            for line in f:
                parts = line.removesuffix("\n").split(" ", 2)
                if len(parts) != 3 or not re.fullmatch(r"-?[0-9]+", parts[1]):
                    continue
                result = int(parts[1])
                path = re.sub(r"\\([n\\])", lambda m: "\n" if m.group(1) == "n" else "\\", parts[2])
                yield parts[0], result, path
