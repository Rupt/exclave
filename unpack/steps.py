"""The steps that make a tree from package files (DESIGN.md 10.1).

Extraction, synthesis of what maintainer scripts would have made, the volatile directories
stripped, the dependency report, and the hashes file's pkg records.
"""

import contextlib
import fnmatch
import functools
import hashlib
import os
import re
import shutil
import subprocess
from dataclasses import dataclass
from typing import NamedTuple
lazy from collections.abc import Callable

from unpack import apk, deb, rpm
from unpack.root import Root, RootError
lazy from unpack.reader import Reader

MERGED_USR = ["bin", "sbin", "lib", "lib32", "lib64", "libx32"]
# The host's volatile directories (8.1): always the host's at run time, never shipped.
VOLATILE = ("/proc", "/dev", "/sys", "/tmp", "/var/tmp", "/run")  # noqa: S108 -- prefixes, not files

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


# ---------------------------------------------------------------- extraction (step 2)
def _safe_rel(name: str) -> str:
    """Return a member's path relative to the tree, refusing `..` and the reserved `.real`."""
    parts = [p for p in name.split("/") if p not in ("", ".")]
    if any(p == ".." for p in parts):
        raise UnpackError("path escapes the tree: " + name)
    if ".real" in parts:
        raise UnpackError("the reserved name .real is shipped at " + name)
    return "/".join(parts)


_ALIAS = re.compile(r"^(bin|sbin|lib|lib32|lib64|libx32)(/|$)")


READERS: dict[str, Reader] = {"deb": deb, "apk": apk, "rpm": rpm}


def package_format(path: str) -> str:
    """Return a package file's format, by its name: "apk", "rpm", or else "deb"."""
    return os.path.splitext(path)[1].removeprefix(".") if path.endswith((".apk", ".rpm")) else "deb"


def reader(path: str) -> Reader:
    """Return the reader for a package file, chosen by its name (10.1)."""
    return READERS[package_format(path)]


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
                rel = _safe_rel(m.name)
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
                rel = _safe_rel(m.name)
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
                    hardlinks_pending.append((_safe_rel(m.linkname), rel))
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
# Debian's and rpm's spellings
_UA = re.compile(
    r"(?:update-)?alternatives\s+(?:--(?:quiet|verbose|force)\s+)*--install\s+"
    r"(\S+)\s+(\S+)\s+(\S+)\s+(\d+)((?:\s+--slave\s+\S+\s+\S+\s+\S+)*)"
)
_SLAVE = re.compile(r"--slave\s+(\S+)\s+(\S+)\s+(\S+)")


def _link(r: Root, link: str, target: str, log: Log, *, replace: bool = False) -> None:
    """Make a symlink at a virtual path, unless something stands there.

    With replace, as alternatives --install does, a file or link standing there gives way; a
    directory never does. Fedora's binutils needs this: it ships gold at /usr/bin/ld and removes it
    in %post before installing the alternative.
    """
    if r.lexists(link):
        if not replace or (r.isdir(link) and not r.islink(link)):
            return
        if r.islink(link) and r.readlink(link) == target:
            return
        r.remove(link)
    r.symlink(target, link)
    log(f"synthesised {link} -> {target}")


class _Alternative(NamedTuple):
    """One `alternatives --install` line: its priority first, so max() picks the winner."""

    priority: int
    link: str
    target: str
    slaves: list[tuple[str, str, str]]  # (link, name, target)


@_refusing
def synthesise(root: str, packages: list[Package], log: Log = print) -> None:
    """Make what the packages' maintainer scripts would have made, without running them (10.1).

    Runs before wrapping, so that the tree's own ldconfig can run unwrapped. Every path it reads or
    writes resolves with the tree as its root.
    """
    with Root(root) as r:
        _synthesise(r, packages, log)


def _lines(text: str) -> list[str]:
    """The lines of text as a file iterates them, each with its newline."""
    return re.findall(r"[^\n]*\n|[^\n]+\Z", text)


def _synthesise(r: Root, packages: list[Package], log: Log) -> None:
    names = {p.name for p in packages}
    # update-alternatives: every --install line in a postinst; the highest priority wins, and its
    # slaves follow it
    groups: dict[str, list[_Alternative]] = {}
    for pkg in packages:
        _fields, scripts = reader(pkg.path).control(pkg.path)
        for m in _UA.finditer(scripts.get("postinst", "").replace("\\\n", " ")):
            link, gname, target, prio = m.group(1), m.group(2), m.group(3), int(m.group(4))
            if not r.lexists(target):
                continue
            slaves = _SLAVE.findall(m.group(5))
            groups.setdefault(gname, []).append(_Alternative(prio, link, target, slaves))
    for gname, cands in groups.items():
        _prio, link, target, slaves = max(cands)
        _link(r, "/etc/alternatives/" + gname, target, log, replace=True)
        _link(r, link, "/etc/alternatives/" + gname, log, replace=True)
        for slink, sname, starget in slaves:
            if r.lexists(starget):
                _link(r, "/etc/alternatives/" + sname, starget, log, replace=True)
                _link(r, slink, "/etc/alternatives/" + sname, log, replace=True)
    # busybox (Alpine): the applet links are made by its post-install from the paths it ships in
    # /etc/busybox-paths.d, one path per line, each a link to /bin/busybox. The links are relative,
    # as the dash rule makes /usr/bin/sh, so that a link run from outside the exclave reaches the
    # wrapper in the tree and not a host file of the same name; inside, a relative link resolves in
    # virtual space the same way. A path is a member's: `..` and .real are refused.
    bbd = "/etc/busybox-paths.d"
    if r.isdir(bbd) and r.isfile("/bin/busybox"):
        n = 0
        for f in r.listdir(bbd):
            for line in r.read_text(f"{bbd}/{f}").split("\n"):
                rel = _safe_rel(line.strip())
                if rel and not r.lexists(rel):
                    r.symlink(os.path.relpath("/bin/busybox", os.path.dirname("/" + rel)), rel)
                    n += 1
        log(f"synthesised {n} busybox applet links from /etc/busybox-paths.d")
    # Fedora 42's filesystem: its %posttrans merges sbin into bin, replacing /usr/sbin and
    # /usr/local/sbin by a link to bin when every entry there is a link ../bin/<name>; the script
    # says so in Lua, and this is its effect
    for pkg in packages:
        if pkg.name != "filesystem":
            continue
        _fields, scripts = reader(pkg.path).control(pkg.path)
        if 'posix.symlink("bin", path)' not in scripts.get("posttrans", ""):
            continue
        for sb in ("/usr/sbin", "/usr/local/sbin"):
            if not r.isdir(sb) or r.islink(sb):
                continue
            entries = r.listdir(sb)
            if all(
                r.islink(f"{sb}/{e}") and r.readlink(f"{sb}/{e}") == "../bin/" + e for e in entries
            ):
                for e in entries:
                    r.remove(f"{sb}/{e}")
                r.rmdir(sb)
                r.symlink("bin", sb)
                log(f"synthesised {sb} -> bin as filesystem's %posttrans does")
    # dash: /bin/sh is made by its postinst, not shipped
    if "dash" in names and r.lexists("/usr/bin/dash"):
        _link(r, "/usr/bin/sh", "dash", log)
    # ca-certificates: the bundle is generated by update-ca-certificates
    conf = "/etc/ca-certificates.conf"
    if "ca-certificates" in names and r.exists(conf):
        pems: list[bytes] = []
        for raw in _lines(r.read_text(conf)):
            line = raw.strip()
            if line and not line.startswith("#") and not line.startswith("!"):
                cert = "/usr/share/ca-certificates/" + line
                if r.exists(cert):
                    pems.append(r.read_bytes(cert).rstrip(b"\n") + b"\n")
        r.makedirs("/etc/ssl/certs")
        r.write_bytes("/etc/ssl/certs/ca-certificates.crt", b"".join(pems))
        log(f"synthesised /etc/ssl/certs/ca-certificates.crt from {len(pems)} certificates")
    # ca-certificates (Fedora, RHEL): the consumers' paths are links to
    # /etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem, which update-ca-trust extracts in %post
    # from the p11-kit trust source; the CA anchors trusted there are concatenated the same way. The
    # bundle is an identity file (8.4): the host's where it has one.
    extracted = "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem"
    sources = sorted(
        [
            f"{d}/{n}"
            for d, pattern in (
                ("/usr/share/pki/ca-trust-source", "*.p11-kit"),
                ("/etc/pki/ca-trust/source/anchors", "*"),
            )
            for n in r.listdir(d)
            if not n.startswith(".") and fnmatch.fnmatchcase(n, pattern)
        ]
    )
    if sources and not r.lexists(extracted):
        certs: list[str] = []
        for src in sources:
            text = r.read_text(src)
            if "[p11-kit-object-v1]" not in text:
                if "-----BEGIN CERTIFICATE-----" in text:
                    certs.append(text.strip() + "\n")
                continue
            # a certificate object: trust attributes, then its PEM
            for obj in text.split("[p11-kit-object-v1]")[1:]:
                head = obj.split("-----BEGIN", 1)[0]
                if "trusted: true" not in head or "x-distrusted: true" in head:
                    continue
                m = re.search(
                    r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", obj, re.DOTALL
                )
                # one object per purpose in the source: one PEM in the bundle
                if m and m.group(0) + "\n" not in certs:
                    certs.append(m.group(0) + "\n")
        r.makedirs(os.path.dirname(extracted))
        r.write_bytes(extracted, "".join(certs).encode())
        log(
            "synthesised /etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem "
            f"from {len(certs)} trusted certificates"
        )
    # libssl: OpenSSL's compiled-in trust paths are /usr/lib/ssl/cert.pem and /usr/lib/ssl/certs,
    # symlinks the openssl and ca-certificates packages ship and a library's closure lacks; without
    # them the host's bundle at the identity path (8.4) is never consulted
    if any(n.startswith("libssl") for n in names):
        _link(r, "/usr/lib/ssl/certs", "/etc/ssl/certs", log)
        _link(r, "/usr/lib/ssl/cert.pem", "/etc/ssl/certs/ca-certificates.crt", log)
    # base-passwd: /etc/passwd and /etc/group come from update-passwd, not the package; the host's
    # are used unless an own record names them (8.4), but the files must exist for tools that list
    # /etc
    for name_, master in (("passwd", "passwd.master"), ("group", "group.master")):
        src, dst = "/usr/share/base-passwd/" + master, "/etc/" + name_
        if "base-passwd" in names and r.exists(src) and not r.lexists(dst):
            r.write_bytes(dst, r.read_bytes(src))
            log(f"synthesised /etc/{name_} from base-passwd")
    # ldconfig: the exclave's own, static, before wrapping so the cache never indexes the launcher;
    # Fedora 42 has merged sbin into bin
    ld = None
    for cand in (
        "/usr/sbin/ldconfig.real",
        "/sbin/ldconfig.real",
        "/usr/sbin/ldconfig",
        "/sbin/ldconfig",
        "/usr/bin/ldconfig",
    ):
        if r.isfile(cand) and r.read_bytes(cand, 4) == b"\x7fELF":
            ld = cand
            break
    if ld:
        conf, tmp = "/etc/ld.so.conf", None
        # ldconfig -r refuses a relative include, which Red Hat's ld.so.conf has:
        # a copy with the pattern spelt from /etc is written in the tree for the run
        if r.isfile(conf):
            lines_out: list[str] = []
            changed = False
            for line in _lines(r.read_text(conf)):
                m = re.match(r"^(\s*include\s+)([^/\s][^\s]*)(.*)$", line)
                if m:
                    lines_out.append(m.group(1) + "/etc/" + m.group(2) + m.group(3) + "\n")
                    changed = True
                else:
                    lines_out.append(line)
            if changed:
                tmp = "/etc/ld.so.conf.exclave"
                r.write_bytes(tmp, "".join(lines_out).encode())
        try:
            # the tree's own ldconfig, run on this host, as wrapping requires (10.1)
            res = subprocess.run(  # noqa: S603 -- an argument vector, no shell
                [r.real(ld), "-r", r.path, "-f", tmp or "/etc/ld.so.conf"],
                capture_output=True,
                check=False,
            )
            if res.returncode:
                log("ldconfig failed: " + res.stderr.decode(errors="replace").strip())
            else:
                log("synthesised /etc/ld.so.cache with the exclave's ldconfig")
        except OSError as e:  # the tree's ldconfig is of another architecture: no cache here (10.1)
            log(
                f"the tree's ldconfig cannot run on this machine ({e.strerror}): no ld.so.cache; "
                "wrap the exclave on a machine of its architecture"
            )
        finally:
            if tmp:
                r.remove(tmp)
        # records inodes and mtimes: never reproducible, never needed
        aux = "/var/cache/ldconfig"
        if r.isdir(aux) and not r.islink(aux):
            r.rmtree(aux)
    elif "libc-bin" in names:
        log("libc-bin present but no static ldconfig found; no ld.so.cache")


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
