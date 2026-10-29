"""A package file as unpack sees it, the reader that reads it, and the log every step writes to.

The readers (deb, apk, rpm) share one interface, `unpack.reader.Reader`, and a file's reader is
chosen by its name (DESIGN.md 10.1).
"""

import os
from dataclasses import dataclass
lazy from collections.abc import Callable

from unpack import apk, deb, rpm
lazy from unpack.reader import Reader

type Log = Callable[[str], object]


@dataclass(frozen=True, slots=True)
class Package:
    """A package file to unpack, with the control fields its reader gave."""

    name: str
    path: str
    fields: dict[str, str]

    @property
    def version(self) -> str:
        return self.fields.get("Version", "")

    @property
    def arch(self) -> str:
        return self.fields.get("Architecture", "")


class UnpackError(Exception):
    """A refusal: package files unpack will not make a tree from, or a step that cannot be done."""


def safe_rel(name: str) -> str:
    """Return a member's path relative to the tree, refusing `..` and the reserved `.real`."""
    parts = [p for p in name.split("/") if p not in ("", ".")]
    if any(p == ".." for p in parts):
        raise UnpackError("path escapes the tree: " + name)
    if ".real" in parts:
        raise UnpackError("the reserved name .real is shipped at " + name)
    return "/".join(parts)


READERS: dict[str, Reader] = {"deb": deb, "apk": apk, "rpm": rpm}


def package_format(path: str) -> str:
    """Return a package file's format, by its name: "apk", "rpm", or else "deb"."""
    return os.path.splitext(path)[1].removeprefix(".") if path.endswith((".apk", ".rpm")) else "deb"


def reader(path: str) -> Reader:
    """Return the reader for a package file, chosen by its name (10.1)."""
    return READERS[package_format(path)]
