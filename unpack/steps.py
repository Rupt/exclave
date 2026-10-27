"""The steps that make a tree from package files (DESIGN.md 10.1).

Extraction, synthesis of what maintainer scripts would have made, the volatile directories
stripped, the dependency report, and the hashes file's pkg records.
"""

import glob
import hashlib
import os
import re
import shutil
import subprocess
from dataclasses import dataclass
from typing import NamedTuple
lazy from collections.abc import Callable

from unpack import apk, deb, rpm
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


def _inside(root_real: str, dst: str) -> None:
    """Refuse dst unless its parent, every symlink resolved, lies in the tree."""
    parent = os.path.realpath(os.path.dirname(dst))
    if parent != root_real and not parent.startswith(root_real + os.sep):
        msg = f"{dst} escapes the tree through a symlink (resolves under {parent})"
        raise UnpackError(msg)


READERS: dict[str, Reader] = {"deb": deb, "apk": apk, "rpm": rpm}


def package_format(path: str) -> str:
    """Return a package file's format, by its name: "apk", "rpm", or else "deb"."""
    return os.path.splitext(path)[1].removeprefix(".") if path.endswith((".apk", ".rpm")) else "deb"


def reader(path: str) -> Reader:
    """Return the reader for a package file, chosen by its name (10.1)."""
    return READERS[package_format(path)]


def extract(root: str, packages: list[Package], log: Log = print) -> dict[str, str]:
    """Extract every package's payload into root, after making the merged-/usr links (10.1).

    A regular file shipped by two packages is an error unless one declares Replaces on the other;
    the /lib and /usr/lib spellings of a path count as one. Renaming diversions are refused, and so
    is any member that would land outside the tree through a symlink.

    Args:
        root: The tree directory to fill.
        packages: The packages, in the order given.
        log: Called with one line per special file skipped.

    Returns:
        The package that owns each extracted path, keyed by its /usr-merged spelling.

    Raises:
        UnpackError: On a conflict, a diversion, or a member that escapes the tree.
    """
    os.makedirs(os.path.join(root, "usr"), exist_ok=True)
    root_real = os.path.realpath(root)
    # A symlink one package ships at a path other packages ship files under, Fedora 42's
    # usr/sbin -> bin, is made before anything is extracted, as the merged-usr links are, so that
    # those files land where the link points whatever the order of the packages; a package's own
    # files under its own link count too.
    links: dict[str, str] = {}
    parents: set[str] = set()
    for pkg in packages:
        with reader(pkg.path).open_data(pkg.path) as t:
            for m in t.getmembers():
                rel = _safe_rel(m.name)
                if not rel:
                    continue
                if m.issym():
                    links[rel] = m.linkname
                elif not m.isdir():
                    parts = rel.split("/")
                    parents.update("/".join(parts[:i]) for i in range(1, len(parts)))
    merged = {"usr/" + d for d in MERGED_USR}
    # Debian's and Fedora's merged /usr; Alpine's directories are its own
    if all(reader(p.path).MERGED_USR for p in packages):
        for d in MERGED_USR:
            # unless a package ships usr/<d> itself as a link (Fedora 42's usr/sbin -> bin)
            if "usr/" + d not in links:
                os.makedirs(os.path.join(root, "usr", d), exist_ok=True)
            p = os.path.join(root, d)
            if not os.path.lexists(p):
                os.symlink("usr/" + d, p)
    for rel in sorted(links):
        if (
            (rel in parents or rel in merged)
            and not links[rel].startswith("/")
            and ".." not in links[rel].split("/")
        ):
            dst = os.path.join(root, rel)
            if not os.path.lexists(dst):
                os.makedirs(os.path.dirname(dst), exist_ok=True)
                os.symlink(links[rel], dst)
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
            for m in t.getmembers():
                rel = _safe_rel(m.name)
                if not rel:
                    continue
                dst = os.path.join(root, rel)
                key = _ALIAS.sub(r"usr/\1\2", rel)  # /lib/x and /usr/lib/x are one file
                _inside(root_real, dst)
                if m.isdir():
                    if os.path.islink(dst) and os.path.isdir(dst):
                        continue
                    os.makedirs(dst, exist_ok=True)
                    # the tar's mode; a tree must stay traversable by its owner
                    os.chmod(dst, (m.mode & 0o777) | 0o700)
                    continue
                if os.path.lexists(dst) and (os.path.islink(dst) or not os.path.isdir(dst)):
                    prev = owner.get(key)
                    if m.issym() and os.path.islink(dst) and os.readlink(dst) == m.linkname:
                        # identical symlink from two packages, or a merged-usr link: normal
                        continue
                    if os.path.islink(dst) and os.path.isdir(dst) and not m.issym():
                        msg = f"{name} ships /{rel} over a directory symlink"
                        raise UnpackError(msg)
                    if prev and (prev in replaces[name]):
                        os.remove(dst)  # this package replaces the previous owner's file
                    elif prev and (name in replaces.get(prev, ())):
                        continue  # the previous owner replaces ours: keep theirs
                    elif prev:
                        msg = f"{prev} and {name} both ship /{rel} and neither declares Replaces"
                        raise UnpackError(msg)
                    else:
                        os.remove(dst)
                os.makedirs(os.path.dirname(dst), exist_ok=True)
                if m.issym():
                    os.symlink(m.linkname, dst)
                elif m.islnk():
                    hardlinks_pending.append((os.path.join(root, _safe_rel(m.linkname)), dst))
                elif m.isfile():
                    fd = os.open(dst, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
                    content = t.extractfile(m)
                    assert content is not None  # a regular file always has its content
                    with os.fdopen(fd, "wb") as f:
                        shutil.copyfileobj(content, f)
                    # setuid and setgid are meaningless under no_new_privs; a tree stays
                    # readable by its owner (Fedora ships /etc/gshadow as 0000)
                    os.chmod(dst, (m.mode & 0o777) | 0o400)
                    os.utime(dst, (m.mtime, m.mtime))
                else:
                    log(f"skipping special file /{rel} from {name}")
                    continue
                owner[key] = name
    for src, dst in hardlinks_pending:
        _inside(root_real, dst)
        _inside(root_real, src)  # a link to a file outside the tree would ship that file
        if os.path.lexists(dst):
            os.remove(dst)
        # the member the archive names, never what a shipped symlink there points at
        os.link(src, dst, follow_symlinks=False)
    return owner


# ---------------------------------------------------------------- synthesis (step 3)
# Debian's and rpm's spellings
_UA = re.compile(
    r"(?:update-)?alternatives\s+(?:--(?:quiet|verbose|force)\s+)*--install\s+"
    r"(\S+)\s+(\S+)\s+(\S+)\s+(\d+)((?:\s+--slave\s+\S+\s+\S+\s+\S+)*)"
)
_SLAVE = re.compile(r"--slave\s+(\S+)\s+(\S+)\s+(\S+)")


def _v(root: str, vpath: str) -> str:
    """Return the real path of a virtual path in root, symlinks unresolved."""
    return os.path.join(root, vpath.lstrip("/"))


def _link(root: str, link: str, target: str, log: Log, *, replace: bool = False) -> None:
    """Make a symlink at a virtual path, unless something stands there.

    With replace, as alternatives --install does, a file or link standing there gives way; a
    directory never does. Fedora's binutils needs this: it ships gold at /usr/bin/ld and removes it
    in %post before installing the alternative.
    """
    p = _v(root, link)
    if os.path.lexists(p):
        if not replace or (os.path.isdir(p) and not os.path.islink(p)):
            return
        if os.path.islink(p) and os.readlink(p) == target:
            return
        os.remove(p)
    os.makedirs(os.path.dirname(p), exist_ok=True)
    os.symlink(target, p)
    log(f"synthesised {link} -> {target}")


class _Alternative(NamedTuple):
    """One `alternatives --install` line: its priority first, so max() picks the winner."""

    priority: int
    link: str
    target: str
    slaves: list[tuple[str, str, str]]  # (link, name, target)


def synthesise(root: str, packages: list[Package], log: Log = print) -> None:
    """Make what the packages' maintainer scripts would have made, without running them (10.1).

    Runs before wrapping, so that the tree's own ldconfig can run unwrapped.
    """
    names = {p.name for p in packages}
    # update-alternatives: every --install line in a postinst; the highest priority wins, and its
    # slaves follow it
    groups: dict[str, list[_Alternative]] = {}
    for pkg in packages:
        _fields, scripts = reader(pkg.path).control(pkg.path)
        for m in _UA.finditer(scripts.get("postinst", "").replace("\\\n", " ")):
            link, gname, target, prio = m.group(1), m.group(2), m.group(3), int(m.group(4))
            if not os.path.lexists(_v(root, target)):
                continue
            slaves = _SLAVE.findall(m.group(5))
            groups.setdefault(gname, []).append(_Alternative(prio, link, target, slaves))
    for gname, cands in groups.items():
        _prio, link, target, slaves = max(cands)
        _link(root, "/etc/alternatives/" + gname, target, log, replace=True)
        _link(root, link, "/etc/alternatives/" + gname, log, replace=True)
        for slink, sname, starget in slaves:
            if os.path.lexists(_v(root, starget)):
                _link(root, "/etc/alternatives/" + sname, starget, log, replace=True)
                _link(root, slink, "/etc/alternatives/" + sname, log, replace=True)
    # busybox (Alpine): the applet links are made by its post-install from the paths it ships in
    # /etc/busybox-paths.d, one path per line, each a link to /bin/busybox. The links are relative,
    # as the dash rule makes /usr/bin/sh, so that a link run from outside the exclave reaches the
    # wrapper in the tree and not a host file of the same name; inside, a relative link resolves in
    # virtual space the same way.
    bbd = _v(root, "/etc/busybox-paths.d")
    if os.path.isdir(bbd) and os.path.isfile(_v(root, "/bin/busybox")):
        n = 0
        for f in sorted(os.listdir(bbd)):
            with open(os.path.join(bbd, f), encoding="utf-8", errors="replace") as lines:
                for line in lines:
                    rel = line.strip().lstrip("/")
                    if rel and not os.path.lexists(_v(root, "/" + rel)):
                        os.makedirs(os.path.dirname(_v(root, "/" + rel)), exist_ok=True)
                        os.symlink(
                            os.path.relpath("/bin/busybox", os.path.dirname("/" + rel)),
                            _v(root, "/" + rel),
                        )
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
            d = _v(root, sb)
            if not os.path.isdir(d) or os.path.islink(d):
                continue
            entries = os.listdir(d)
            if all(
                os.path.islink(os.path.join(d, e))
                and os.readlink(os.path.join(d, e)) == "../bin/" + e
                for e in entries
            ):
                for e in entries:
                    os.remove(os.path.join(d, e))
                os.rmdir(d)
                os.symlink("bin", d)
                log(f"synthesised {sb} -> bin as filesystem's %posttrans does")
    # dash: /bin/sh is made by its postinst, not shipped
    if "dash" in names and os.path.lexists(_v(root, "/usr/bin/dash")):
        _link(root, "/usr/bin/sh", "dash", log)
    # ca-certificates: the bundle is generated by update-ca-certificates
    conf = _v(root, "/etc/ca-certificates.conf")
    if "ca-certificates" in names and os.path.exists(conf):
        pems: list[bytes] = []
        with open(conf, encoding="utf-8", errors="replace") as lines:
            for raw in lines:
                line = raw.strip()
                if line and not line.startswith("#") and not line.startswith("!"):
                    p = _v(root, "/usr/share/ca-certificates/" + line)
                    if os.path.exists(p):
                        with open(p, "rb") as cert:
                            pems.append(cert.read().rstrip(b"\n") + b"\n")
        os.makedirs(_v(root, "/etc/ssl/certs"), exist_ok=True)
        with open(_v(root, "/etc/ssl/certs/ca-certificates.crt"), "wb") as f:
            f.writelines(pems)
        log(f"synthesised /etc/ssl/certs/ca-certificates.crt from {len(pems)} certificates")
    # ca-certificates (Fedora, RHEL): the consumers' paths are links to
    # /etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem, which update-ca-trust extracts in %post
    # from the p11-kit trust source; the CA anchors trusted there are concatenated the same way. The
    # bundle is an identity file (8.4): the host's where it has one.
    extracted = _v(root, "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem")
    sources = sorted(
        glob.glob(_v(root, "/usr/share/pki/ca-trust-source/*.p11-kit"))
        + glob.glob(_v(root, "/etc/pki/ca-trust/source/anchors/*"))
    )
    if sources and not os.path.lexists(extracted):
        certs: list[str] = []
        for src in sources:
            with open(src, encoding="utf-8", errors="replace") as f:
                text = f.read()
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
        os.makedirs(os.path.dirname(extracted), exist_ok=True)
        with open(extracted, "w", encoding="utf-8") as f:
            f.writelines(certs)
        log(
            "synthesised /etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem "
            f"from {len(certs)} trusted certificates"
        )
    # libssl: OpenSSL's compiled-in trust paths are /usr/lib/ssl/cert.pem and /usr/lib/ssl/certs,
    # symlinks the openssl and ca-certificates packages ship and a library's closure lacks; without
    # them the host's bundle at the identity path (8.4) is never consulted
    if any(n.startswith("libssl") for n in names):
        _link(root, "/usr/lib/ssl/certs", "/etc/ssl/certs", log)
        _link(root, "/usr/lib/ssl/cert.pem", "/etc/ssl/certs/ca-certificates.crt", log)
    # base-passwd: /etc/passwd and /etc/group come from update-passwd, not the package; the host's
    # are used unless an own record names them (8.4), but the files must exist for tools that list
    # /etc
    for name_, master in (("passwd", "passwd.master"), ("group", "group.master")):
        src, dst = _v(root, "/usr/share/base-passwd/" + master), _v(root, "/etc/" + name_)
        if "base-passwd" in names and os.path.exists(src) and not os.path.lexists(dst):
            shutil.copyfile(src, dst)
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
        p = _v(root, cand)
        if os.path.isfile(p):
            with open(p, "rb") as f:
                elf = f.read(4) == b"\x7fELF"
            if elf:
                ld = p
                break
    if ld:
        conf, tmp = _v(root, "/etc/ld.so.conf"), None
        # ldconfig -r refuses a relative include, which Red Hat's ld.so.conf has:
        # a copy with the pattern spelt from /etc is written in the tree for the run
        if os.path.isfile(conf):
            lines_out: list[str] = []
            changed = False
            with open(conf, encoding="utf-8", errors="replace") as lines:
                for line in lines:
                    m = re.match(r"^(\s*include\s+)([^/\s][^\s]*)(.*)$", line)
                    if m:
                        lines_out.append(m.group(1) + "/etc/" + m.group(2) + m.group(3) + "\n")
                        changed = True
                    else:
                        lines_out.append(line)
            if changed:
                tmp = _v(root, "/etc/ld.so.conf.exclave")
                with open(tmp, "w", encoding="utf-8") as f:
                    f.writelines(lines_out)
        try:
            # the tree's own ldconfig, run on this host, as wrapping requires (10.1)
            r = subprocess.run(  # noqa: S603 -- an argument vector, no shell
                [ld, "-r", root, "-f", "/etc/ld.so.conf.exclave" if tmp else "/etc/ld.so.conf"],
                capture_output=True,
                check=False,
            )
            if r.returncode:
                log("ldconfig failed: " + r.stderr.decode(errors="replace").strip())
            else:
                log("synthesised /etc/ld.so.cache with the exclave's ldconfig")
        except OSError as e:  # the tree's ldconfig is of another architecture: no cache here (10.1)
            log(
                f"the tree's ldconfig cannot run on this machine ({e.strerror}): no ld.so.cache; "
                "wrap the exclave on a machine of its architecture"
            )
        finally:
            if tmp:
                os.remove(tmp)
        # records inodes and mtimes: never reproducible, never needed
        aux = _v(root, "/var/cache/ldconfig")
        if os.path.isdir(aux):
            shutil.rmtree(aux)
    elif "libc-bin" in names:
        log("libc-bin present but no static ldconfig found; no ld.so.cache")


# ---------------------------------------------------------------- the volatile directories (step 4)
def strip_volatile(root: str) -> None:
    """Remove what the packages shipped in the volatile directories, which are the host's (8.1).

    A link standing at one is left as the package made it. The empty directories, and the identity
    files, are the placeholders `exclave wrap` adds where the tree lacks them.
    """
    for d in VOLATILE:
        p = _v(root, d)
        if os.path.lexists(p) and not os.path.islink(p):
            shutil.rmtree(p)


# ---------------------------------------------------------------- the dependency report (10.1)
def resolves(root: str, vpath: str) -> bool:
    """Return whether vpath names an entry in the tree, its symlinks resolved inside it."""
    cur, rest, hops = "", [p for p in vpath.split("/") if p], 0
    while rest:
        comp = rest.pop(0)
        if comp == ".":
            continue
        if comp == "..":
            cur = cur.rsplit("/", 1)[0] if "/" in cur else ""
            continue
        real = _v(root, cur + "/" + comp)
        if not os.path.lexists(real):
            return False
        if os.path.islink(real):
            hops += 1
            if hops > 40:  # the kernel's limit, ELOOP
                return False
            t = os.readlink(real)
            rest = [p for p in t.split("/") if p] + rest
            if t.startswith("/"):
                cur = ""
            continue
        cur += "/" + comp
    return True


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
                    name.startswith("/") and (root is None or resolves(root, name))
                    for name, _, _ in alts
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
