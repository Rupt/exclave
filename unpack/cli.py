"""The unpack command line (DESIGN.md 10.1).

    unpack OUT PKG...    Make the unwrapped exclave OUT from package files: extract, synthesise
                         what maintainer scripts would have done, strip the volatile directories,
                         record every input in OUT/.exclave/hashes, report dependencies the set
                         does not satisfy.

`exclave wrap OUT` then makes it an exclave. Between the two OUT is a directory, and anything may
be done to it. Unpack never opens a network connection: the files it is given are its inputs,
whoever fetched them.
"""

import argparse
import os
import shutil
import sys
lazy from collections.abc import Sequence

from unpack import steps
from unpack.reader import PackageError
from unpack.steps import UnpackError


def unpack(out: str, paths: Sequence[str], log: steps.Log = print) -> None:
    """Make the unwrapped exclave out from package files (10.1).

    The packages are extracted, what their maintainer scripts would have made is synthesised, the
    volatile directories are stripped, each package file's hash is recorded, and unmet
    dependencies are logged. On any failure, out is removed.

    Raises:
        UnpackError: When out exists, or the packages mix formats, architectures or versions of one
            package.
    """
    if os.path.exists(out):
        msg = f"refusing: {out} exists"
        raise UnpackError(msg)
    if not paths:
        msg = "unpack needs at least one package file"
        raise UnpackError(msg)
    formats = {steps.package_format(p) for p in paths}
    if len(formats) > 1:
        msg = f"the package files mix formats {sorted(formats)}: one format per exclave"
        raise UnpackError(msg)
    rd = steps.reader(paths[0])
    packages: list[steps.Package] = []
    seen: dict[str, str] = {}
    for path in paths:
        fields, _ = rd.control(path)
        name = fields.get("Package")
        if not name or not fields.get("Version"):
            msg = f"{path}: no Package or Version in its control file"
            raise UnpackError(msg)
        if name in seen:
            msg = (
                f"{seen[name]} and {path} both carry package {name}: "
                "one version of a package per exclave"
            )
            raise UnpackError(msg)
        seen[name] = path
        packages.append(steps.Package(name, path, fields))
    arches = {p.arch for p in packages if p.arch and p.arch != "all"}
    if len(arches) > 1:
        msg = f"the packages mix architectures {sorted(arches)}"
        raise UnpackError(msg)
    os.makedirs(os.path.join(out, ".exclave"))
    root = os.path.join(out, "tree")
    try:
        steps.extract(root, packages, log=log)
        steps.synthesise(root, packages, log=log)
        for line in steps.notes(packages):
            log(line)
        steps.strip_volatile(root)
        # after synthesis, so that a file dependency is asked of the finished tree
        for line in steps.dependency_report(packages, rd, root):
            log("depends: " + line)
        steps.write_records(out, packages)
    except BaseException:
        shutil.rmtree(out, ignore_errors=True)
        raise
    log(f"unpacked {len(packages)} packages into {out}; exclave wrap {out} makes it an exclave")


def main(argv: list[str] | None = None) -> int:
    """Run the command line, and return its exit status."""
    parser = argparse.ArgumentParser(
        prog="unpack",
        description="Make the unwrapped exclave OUT from package files; exclave wrap OUT then "
        "makes it an exclave.",
    )
    parser.add_argument("out", metavar="OUT")
    parser.add_argument("packages", nargs="+", metavar="PACKAGE", help=".deb, .apk or .rpm files")
    args = parser.parse_args(argv)
    try:
        unpack(args.out, args.packages)
    except (UnpackError, PackageError, OSError) as e:
        sys.exit(f"unpack: {e}")
    return 0
