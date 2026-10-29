"""The steps that make a tree from package files (DESIGN.md 10.1).

Extraction, synthesis of what maintainer scripts would have made, the volatile directories
stripped, the dependency report, and the hashes file's pkg records.
"""

import contextlib
import functools
import hashlib
import os
import re
import shutil
lazy from collections.abc import Callable

from unpack import rules
from unpack.package import READERS, Log, Package, UnpackError, package_format, reader, safe_rel
from unpack.root import Root, RootError
lazy from unpack.reader import Reader

MERGED_USR = ["bin", "sbin", "lib", "lib32", "lib64", "libx32"]
# The host's volatile directories (8.1): always the host's at run time, never shipped.
VOLATILE = ("/proc", "/dev", "/sys", "/tmp", "/var/tmp", "/run")  # noqa: S108 -- prefixes, not files

__all__ = ["READERS", "Log", "Package", "UnpackError", "package_format", "reader"]


_ALIAS = re.compile(r"^(bin|sbin|lib|lib32|lib64|libx32)(/|$)")


def _refusing[**P, R](f: Callable[P, R]) -> Callable[P, R]:
    """A step whose tree cannot hold what the packages ask refuses them, as unpack's refusal."""

    @functools.wraps(f)
    def step(*args: P.args, **kwargs: P.kwargs) -> R:
        try:
            return f(*args, **kwargs)
        except RootError as e:
            raise UnpackError(str(e)) from e

    return step


@_refusing
def extract(root: str, packages: list[Package], log: Log = print) -> dict[str, str]:
    """Extract every package's payload into root, after making the merged-/usr links (10.1).

    Paths resolve with the tree as their root (unpack.root), so a symlink a package ships leads
    nowhere outside it. A regular file shipped by two packages is an error unless one declares
    Replaces on the other; the /lib and /usr/lib spellings of a path count as one. Renaming
    diversions are refused, and so is a file that would leave the output's filesystem short of
    room.

    Args:
        root: The tree directory to fill.
        packages: The packages, in the order given.
        log: Called with one line per special file skipped.

    Returns:
        The package that owns each extracted path, keyed by its /usr-merged spelling.

    Raises:
        UnpackError: On a conflict, a diversion, or a path the tree cannot hold.
    """
    os.makedirs(root, exist_ok=True)
    with Root(root) as r:
        return _extract(r, packages, log)


def _extract(r: Root, packages: list[Package], log: Log) -> dict[str, str]:
    r.makedirs("usr")
    # A symlink one package ships at a path other packages ship files under, Fedora 42's
    # usr/sbin -> bin, is made before anything is extracted, as the merged-usr links are, so that
    # those files land where the link points whatever the order of the packages; a package's own
    # files under its own link count too.
    links: dict[str, str] = {}
    parents: set[str] = set()
    # the files' declared sizes: a set that cannot fit is refused before it is written, the free
    # space asked once per package and whenever the total has grown by 64 MiB since it was asked
    total = asked = 0
    for pkg in packages:
        with reader(pkg.path).open_data(pkg.path) as t:
            for m in t:
                rel = safe_rel(m.name)
                if not rel:
                    continue
                if m.isfile():
                    total += m.size
                    if total - asked >= 64 << 20:
                        r.room(total, f"the files up to /{rel} in {pkg.name} declare")
                        asked = total
                if m.issym():
                    links[rel] = m.linkname
                elif not m.isdir():
                    parts = rel.split("/")
                    parents.update("/".join(parts[:i]) for i in range(1, len(parts)))
        r.room(total, f"the files of the packages up to {pkg.name} declare")
        asked = total
    merged = {"usr/" + d for d in MERGED_USR}
    # Debian's and Fedora's merged /usr; Alpine's directories are its own
    if all(reader(p.path).MERGED_USR for p in packages):
        for d in MERGED_USR:
            # unless a package ships usr/<d> itself as a link (Fedora 42's usr/sbin -> bin)
            if "usr/" + d not in links:
                r.makedirs("usr/" + d)
            if not r.lexists(d):
                r.symlink("usr/" + d, d)
    for rel in sorted(links):
        if (
            (rel in parents or rel in merged)
            and not links[rel].startswith("/")
            and ".." not in links[rel].split("/")
            and not r.lexists(rel)
        ):
            r.symlink(links[rel], rel)
    owner: dict[str, str] = {}
    replaces: dict[str, set[str]] = {}
    hardlinks_pending: list[tuple[str, str]] = []
    for pkg in packages:
        name, rd = pkg.name, reader(pkg.path)
        _fields, scripts = rd.control(pkg.path)
        # 10.1 step 2: a diversion that renames a file changes where the tree must hold it, and
        # dpkg's database is not reproduced here; those are refused. Diversions with --no-rename,
        # and the merged-usr and zutils transitions every noble closure carries, leave a fresh tree
        # unchanged.
        for sname in ("preinst", "postinst"):
            for line in scripts.get(sname, "").replace("\\\n", " ").split("\n"):
                if line.strip().startswith("#") or "dpkg-divert" not in line:
                    continue
                if (
                    re.search(r"--(remove|list|listpackage|truename)\b", line)
                    or "--no-rename" in line
                    or ".usr-is-merged" in line
                ):
                    continue
                msg = (
                    f"{name} adds a renaming diversion in its {sname} ({line.strip()[:100]}); "
                    "diversions are refused (10.1)"
                )
                raise UnpackError(msg)
        replaces[name] = {
            a[0] for alts in rd.parse_deps(pkg.fields.get("Replaces", "")) for a in alts
        }
        with rd.open_data(pkg.path) as t:
            for m in t:
                rel = safe_rel(m.name)
                if not rel:
                    continue
                key = _ALIAS.sub(r"usr/\1\2", rel)  # /lib/x and /usr/lib/x are one file
                if m.isdir():
                    if r.islink(rel) and r.isdir(rel):
                        continue
                    if r.lexists(rel) and not r.isdir(rel):
                        msg = f"{name} ships the directory /{rel} where a file stands"
                        raise UnpackError(msg)
                    r.makedirs(rel)
                    # the tar's mode; a tree must stay traversable by its owner
                    r.chmod_dir(rel, (m.mode & 0o777) | 0o700)
                    continue
                if r.lexists(rel) and (r.islink(rel) or not r.isdir(rel)):
                    prev = owner.get(key)
                    if m.issym() and r.islink(rel) and r.readlink(rel) == m.linkname:
                        # identical symlink from two packages, or a merged-usr link: normal
                        continue
                    if r.islink(rel) and r.isdir(rel) and not m.issym():
                        msg = f"{name} ships /{rel} over a directory symlink"
                        raise UnpackError(msg)
                    if prev and (prev in replaces[name]):
                        r.remove(rel)  # this package replaces the previous owner's file
                    elif prev and (name in replaces.get(prev, ())):
                        continue  # the previous owner replaces ours: keep theirs
                    elif prev:
                        msg = f"{prev} and {name} both ship /{rel} and neither declares Replaces"
                        raise UnpackError(msg)
                    else:
                        r.remove(rel)
                if m.issym():
                    r.symlink(m.linkname, rel)
                elif m.islnk():
                    hardlinks_pending.append((safe_rel(m.linkname), rel))
                elif m.isfile():
                    content = t.extractfile(m)
                    assert content is not None  # a regular file always has its content
                    with os.fdopen(r.create(rel, m.size), "wb") as f:
                        shutil.copyfileobj(content, f)
                        f.flush()
                        # setuid and setgid are meaningless under no_new_privs; a tree stays
                        # readable by its owner (Fedora ships /etc/gshadow as 0000)
                        os.fchmod(f.fileno(), (m.mode & 0o777) | 0o400)
                        os.utime(f.fileno(), (m.mtime, m.mtime))
                else:
                    log(f"skipping special file /{rel} from {name}")
                    continue
                owner[key] = name
    for src, dst in hardlinks_pending:
        if r.lexists(dst):
            r.remove(dst)
        # the member the archive names, never what a shipped symlink there points at
        r.link(src, dst)
    return owner


# ---------------------------------------------------------------- synthesis (step 3)
@_refusing
def synthesise(root: str, packages: list[Package], log: Log = print) -> None:
    """Make what the packages' maintainer scripts would have made, without running them (10.1).

    The rules are the table in unpack/rules.py, run in order, each logging what it made; the names
    of those that applied are logged last. Runs before wrapping, so that the tree's own ldconfig can
    run unwrapped. Every path a rule reads or writes resolves with the tree as its root.
    """
    with Root(root) as r:
        applied = [rule.name for rule in rules.RULES if rule.apply(r, packages, log)]
    log("synthesis rules applied: " + (", ".join(applied) or "none"))


def notes(packages: list[Package]) -> list[str]:
    """What the packages' trigger interests say the tree lacks, which no rule makes (10.1)."""
    return rules.notes(packages)


# ---------------------------------------------------------------- the volatile directories (step 4)
@_refusing
def strip_volatile(root: str) -> None:
    """Remove what the packages shipped in the volatile directories, which are the host's (8.1).

    A link standing at one is left as the package made it, and the path resolves with the tree as
    its root, so nothing outside it is removed. The empty directories, and the identity files, are
    the placeholders `exclave wrap` adds where the tree lacks them.
    """
    with Root(root) as r:
        for d in VOLATILE:
            if r.lexists(d) and not r.islink(d):
                r.rmtree(d)


# ---------------------------------------------------------------- the dependency report (10.1)
def dependency_report(packages: list[Package], rd: Reader, root: str | None = None) -> list[str]:
    """Return a line for every Depends or Pre-Depends that the set of packages does not satisfy.

    Provides and version constraints are honoured. A dependency spelt as a path, such as rpm's and
    apk's `/bin/sh`, is satisfied when it resolves in the tree under root, extracted and
    synthesised. This is a report, not a refusal: the set is the user's.

    Args:
        packages: The set.
        rd: The reader of its format.
        root: The tree, or None to take every path dependency as satisfied.
    """
    with Root(root) if root is not None else contextlib.nullcontext() as r:
        return _report(packages, rd, r)


def _report(packages: list[Package], rd: Reader, r: Root | None) -> list[str]:
    have = {p.name: p.version for p in packages}
    provides: dict[str, list[str | None]] = {}
    for p in packages:
        for alts in rd.parse_deps(p.fields.get("Provides", "")):
            for name, op, ver in alts:
                provides.setdefault(name, []).append(ver if op == "=" else None)
    out = []
    for p in sorted(packages, key=lambda p: p.name):
        for field in ("Pre-Depends", "Depends"):
            for alts in rd.parse_deps(p.fields.get(field, "")):
                ok = any(
                    name.startswith("/") and (r is None or r.exists(name)) for name, _, _ in alts
                )
                for name, op, ver in alts:
                    if (name in have and rd.satisfies(have[name], op, ver)) or (
                        name in provides
                        and any(
                            op is None or (pv and rd.satisfies(pv, op, ver))
                            for pv in provides[name]
                        )
                    ):
                        ok = True
                if not ok:
                    want = " | ".join(a[0] + (f" ({a[1]} {a[2]})" if a[1] else "") for a in alts)
                    out.append(f"{p.name} needs {want}, not in the set")
    return out


# ---------------------------------------------------------------- the inputs (step 5, 6.4)
def write_records(out: str, packages: list[Package]) -> None:
    """Write OUT/.exclave/hashes with one pkg record per package file, in canonical form (6.4).

    The record holds the name, version and architecture from the file's control data and the
    file's BLAKE2b-256. `exclave wrap` keeps the records and adds its own.

    Raises:
        UnpackError: When a field is not printable ASCII, which no package format allows.
    """
    rows = []
    for p in packages:
        with open(p.path, "rb") as f:
            h = hashlib.file_digest(f, lambda: hashlib.blake2b(digest_size=32)).hexdigest()
        row = (p.name, p.version, p.arch, "b2:" + h)
        for v in row:
            if not all(" " <= c <= "~" for c in v):
                msg = f"{p.path}: control field {v!r} is not printable ASCII"
                raise UnpackError(msg)
        rows.append(row)
    lines = ["hashes 1", ""]
    for row in sorted(rows):
        quoted = ('"' + v.replace("\\", "\\\\").replace('"', '\\"') + '"' for v in row)
        lines.append(" ".join(["pkg", *quoted]))
    with open(os.path.join(out, ".exclave", "hashes"), "w", encoding="ascii") as f:
        f.write("\n".join(lines) + "\n")
