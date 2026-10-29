"""The synthesis rules: what maintainer scripts would have made, as a table (DESIGN.md 10.1).

Each rule in RULES is named, applies to a tree when its packages ask for it, says what it made
through the log, and returns whether it applied; synthesise runs them in order and logs the names
of those that did. A new effect of a maintainer script is a new rule here, never an option, and
nothing here runs a script. What the rules do not make is reported by notes: each package's
trigger interests, the paths whose caches and indexes a maintainer script would have built, are
read from the package (dpkg's `triggers` file, apk's `triggers` field) and named against the
INTERESTS table, and a postinst that calls `update-alternatives` in a form the alternatives rule
cannot read is noted too.
"""

import fnmatch
import os
import re
import subprocess
from typing import NamedTuple
lazy from collections.abc import Callable

from unpack.package import Log, Package, reader, safe_rel
lazy from unpack.root import Root


class Rule(NamedTuple):
    """A synthesis rule: its name in the log, what it makes, and the function that makes it."""

    name: str
    what: str
    apply: Callable[[Root, list[Package], Log], bool]


def _lines(text: str) -> list[str]:
    """The lines of text as a file iterates them, each with its newline."""
    return re.findall(r"[^\n]*\n|[^\n]+\Z", text)


def _link(r: Root, link: str, target: str, log: Log, *, replace: bool = False) -> bool:
    """Make a symlink at a virtual path, unless something stands there.

    With replace, as alternatives --install does, a file or link standing there gives way; a
    directory never does. Fedora's binutils needs this: it ships gold at /usr/bin/ld and removes it
    in %post before installing the alternative.
    """
    if r.lexists(link):
        if not replace or (r.isdir(link) and not r.islink(link)):
            return False
        if r.islink(link) and r.readlink(link) == target:
            return False
        r.remove(link)
    r.symlink(target, link)
    log(f"synthesised {link} -> {target}")
    return True


# ---------------------------------------------------------------- update-alternatives
# Debian's and rpm's spellings
_UA = re.compile(
    r"(?:update-)?alternatives\s+(?:--(?:quiet|verbose|force)\s+)*--install\s+"
    r"(\S+)\s+(\S+)\s+(\S+)\s+(\d+)((?:\s+--slave\s+\S+\s+\S+\s+\S+)*)"
)
_UA_SET = re.compile(
    r"(?:update-)?alternatives\s+(?:--(?:quiet|verbose|force)\s+)*--set\s+(\S+)\s+(\S+)"
)
_UA_ANY = re.compile(r"(?:update-)?alternatives\s+--(?:install|set)\b")
_SLAVE = re.compile(r"--slave\s+(\S+)\s+(\S+)\s+(\S+)")


class _Alternative(NamedTuple):
    """One `alternatives --install` line: its priority first, so max() picks the winner."""

    priority: int
    link: str
    target: str
    slaves: list[tuple[str, str, str]]  # (link, name, target)


def alternatives(r: Root, packages: list[Package], log: Log) -> bool:
    """Every `update-alternatives --install` line in a postinst, with its slaves.

    The highest priority wins, unless a `--set` names a candidate; a line the rule cannot read,
    one built from shell variables or in a loop, is noted, since its alternatives are not made.
    """
    groups: dict[str, list[_Alternative]] = {}
    chosen: dict[str, str] = {}
    for pkg in packages:
        _fields, scripts = reader(pkg.path).control(pkg.path)
        text = scripts.get("postinst", "").replace("\\\n", " ")
        matched = 0
        for m in _UA.finditer(text):
            link, gname, target, prio = m.group(1), m.group(2), m.group(3), int(m.group(4))
            matched += 1
            if "$" in link + gname + target:
                matched -= 1
                continue
            if not r.lexists(target):
                continue
            slaves = _SLAVE.findall(m.group(5))
            groups.setdefault(gname, []).append(_Alternative(prio, link, target, slaves))
        for m in _UA_SET.finditer(text):
            matched += 1
            chosen[m.group(1)] = m.group(2)
        if _UA_ANY.search(text) and not matched:
            log(
                f"note: {pkg.name}'s postinst calls update-alternatives in a form the "
                "alternatives rule does not read, variables or a loop: its alternatives are not "
                "made"
            )
    made = False
    for gname, cands in groups.items():
        _prio, link, target, slaves = max(cands)
        if gname in chosen:
            for c in cands:
                if c.target == chosen[gname]:
                    _prio, link, target, slaves = c
        made |= _link(r, "/etc/alternatives/" + gname, target, log, replace=True)
        made |= _link(r, link, "/etc/alternatives/" + gname, log, replace=True)
        for slink, sname, starget in slaves:
            if r.lexists(starget):
                made |= _link(r, "/etc/alternatives/" + sname, starget, log, replace=True)
                made |= _link(r, slink, "/etc/alternatives/" + sname, log, replace=True)
    return made


# ---------------------------------------------------------------- the other rules
def busybox_applets(r: Root, _packages: list[Package], log: Log) -> bool:
    """Alpine's busybox: the applet links its post-install makes from /etc/busybox-paths.d.

    One path per line, each a link to /bin/busybox. The links are relative, as the dash rule makes
    /usr/bin/sh, so that a link run from outside the exclave reaches the wrapper in the tree and not
    a host file of the same name; inside, a relative link resolves in virtual space the same way. A
    path is a member's: `..` and .real are refused.
    """
    bbd = "/etc/busybox-paths.d"
    if not (r.isdir(bbd) and r.isfile("/bin/busybox")):
        return False
    n = 0
    for f in r.listdir(bbd):
        for line in r.read_text(f"{bbd}/{f}").split("\n"):
            rel = safe_rel(line.strip())
            if rel and not r.lexists(rel):
                r.symlink(os.path.relpath("/bin/busybox", os.path.dirname("/" + rel)), rel)
                n += 1
    log(f"synthesised {n} busybox applet links from /etc/busybox-paths.d")
    return True


def sbin_merge(r: Root, packages: list[Package], log: Log) -> bool:
    """Fedora 42's filesystem: its %posttrans merges sbin into bin.

    It replaces /usr/sbin and /usr/local/sbin by a link to bin when every entry there is a link
    ../bin/<name>; the script says so in Lua, and this is its effect.
    """
    made = False
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
                made = True
    return made


def dash_sh(r: Root, packages: list[Package], log: Log) -> bool:
    """dash: /bin/sh is made by its postinst, not shipped."""
    names = {p.name for p in packages}
    if "dash" in names and r.lexists("/usr/bin/dash"):
        return _link(r, "/usr/bin/sh", "dash", log)
    return False


def ca_certificates(r: Root, packages: list[Package], log: Log) -> bool:
    """ca-certificates (Debian): the bundle update-ca-certificates makes from the enabled ones."""
    names = {p.name for p in packages}
    conf = "/etc/ca-certificates.conf"
    if "ca-certificates" not in names or not r.exists(conf):
        return False
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
    return True


def ca_trust(r: Root, _packages: list[Package], log: Log) -> bool:
    """ca-certificates (Fedora, RHEL): the bundle update-ca-trust extracts in %post.

    The consumers' paths are links to /etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem, extracted
    from the p11-kit trust source; the CA anchors trusted there are concatenated the same way. The
    bundle is an identity file (8.4): the host's where it has one.
    """
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
    if not sources or r.lexists(extracted):
        return False
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
    return True


def ssl_paths(r: Root, packages: list[Package], log: Log) -> bool:
    """libssl: OpenSSL's compiled-in trust paths, /usr/lib/ssl/cert.pem and /usr/lib/ssl/certs.

    They are symlinks the openssl and ca-certificates packages ship and a library's closure lacks;
    without them the host's bundle at the identity path (8.4) is never consulted.
    """
    if not any(p.name.startswith("libssl") for p in packages):
        return False
    a = _link(r, "/usr/lib/ssl/certs", "/etc/ssl/certs", log)
    b = _link(r, "/usr/lib/ssl/cert.pem", "/etc/ssl/certs/ca-certificates.crt", log)
    return a or b


def base_passwd(r: Root, packages: list[Package], log: Log) -> bool:
    """base-passwd: /etc/passwd and /etc/group come from update-passwd, not the package.

    The host's are used unless an own record names them (8.4), but the files must exist for tools
    that list /etc.
    """
    names = {p.name for p in packages}
    made = False
    for name_, master in (("passwd", "passwd.master"), ("group", "group.master")):
        src, dst = "/usr/share/base-passwd/" + master, "/etc/" + name_
        if "base-passwd" in names and r.exists(src) and not r.lexists(dst):
            r.write_bytes(dst, r.read_bytes(src))
            log(f"synthesised /etc/{name_} from base-passwd")
            made = True
    return made


def ldconfig(r: Root, packages: list[Package], log: Log) -> bool:
    """ld.so.cache by the exclave's own static ldconfig, run on this host.

    Before wrapping, so the cache never indexes the launcher; Fedora 42 has merged sbin into bin.
    The aux-cache is removed, since it records inodes and mtimes: never reproducible, never needed.
    """
    names = {p.name for p in packages}
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
    if not ld:
        if "libc-bin" in names:
            log("libc-bin present but no static ldconfig found; no ld.so.cache")
        return False
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
    made = False
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
            made = True
    except OSError as e:  # the tree's ldconfig is of another architecture: no cache here (10.1)
        log(
            f"the tree's ldconfig cannot run on this machine ({e.strerror}): no ld.so.cache; "
            "wrap the exclave on a machine of its architecture"
        )
    finally:
        if tmp:
            r.remove(tmp)
    aux = "/var/cache/ldconfig"
    if r.isdir(aux) and not r.islink(aux):
        r.rmtree(aux)
    return made


RULES: tuple[Rule, ...] = (
    Rule(
        "alternatives",
        "the links of every update-alternatives --install line, --set honoured",
        alternatives,
    ),
    Rule("busybox-applets", "busybox's applet links from /etc/busybox-paths.d", busybox_applets),
    Rule("sbin-merge", "Fedora's /usr/sbin and /usr/local/sbin as links to bin", sbin_merge),
    Rule("dash-sh", "dash's /bin/sh", dash_sh),
    Rule(
        "ca-certificates",
        "Debian's ca-certificates.crt from the enabled certificates",
        ca_certificates,
    ),
    Rule("ca-trust", "Fedora's tls-ca-bundle.pem from the p11-kit trust source", ca_trust),
    Rule("ssl-paths", "OpenSSL's compiled-in trust paths as links to /etc/ssl", ssl_paths),
    Rule("base-passwd", "/etc/passwd and /etc/group from base-passwd's masters", base_passwd),
    Rule("ldconfig", "ld.so.cache by the exclave's own ldconfig", ldconfig),
)

# ---------------------------------------------------------------- what the rules do not make
# A trigger interest, matched by its longest pattern: what a maintainer script would have built
# there and the tree lacks; None for what nothing needs, or what a rule makes.
INTERESTS: tuple[tuple[str, str | None], ...] = (
    (
        "/usr/lib/python3*",
        "Python bytecode: __pycache__ is not generated, so Python compiles each module on import",
    ),
    ("/usr/share/glib-2.0/schemas", "GSettings schemas are not compiled (gschemas.compiled)"),
    ("/usr/share/mime", "the MIME database is not built (mime.cache and the index files)"),
    (
        "/usr/share/fonts*",
        "font caches are not built; fontconfig builds its own under the user's cache",
    ),
    ("/etc/fonts*", "font caches are not built; fontconfig builds its own under the user's cache"),
    ("/usr/share/icons*", "icon caches are not built (icon-theme.cache)"),
    ("/usr/share/applications", "the desktop database is not built (mimeinfo.cache)"),
    ("/usr/lib/*/gio/modules", "GIO's module cache is not generated (giomodule.cache)"),
    ("/usr/lib/gio/modules", "GIO's module cache is not generated (giomodule.cache)"),
    ("/usr/lib/*/gdk-pixbuf-2.0*", "gdk-pixbuf's loader cache is not generated (loaders.cache)"),
    ("/usr/share/texmf*", "TeX's file index and formats are not generated (mktexlsr, fmtutil)"),
    ("/usr/share/texlive*", "TeX's file index and formats are not generated (mktexlsr, fmtutil)"),
    ("/usr/share/man*", None),
    ("/usr/share/info*", None),
    ("/usr/share/doc*", None),
    ("/usr/share/lintian*", None),
    ("/usr/share/bug*", None),
    ("ldconfig", None),
    ("/usr/share/ca-certificates*", None),
    ("/usr/local/share/ca-certificates*", None),
    ("/etc/ca-certificates*", None),
    ("/etc/ld.so.conf.d", None),
    ("/usr/lib/*/pkgconfig", None),
)


def notes(packages: list[Package]) -> list[str]:
    """What the packages' trigger interests say the tree lacks, one line each."""
    out: list[str] = []
    for pkg in packages:
        for path in reader(pkg.path).interests(pkg.path):
            what: str | None = "a cache or index its trigger would have built; the tree lacks it"
            best = -1
            for pattern, text in INTERESTS:
                if len(pattern) > best and (path == pattern or fnmatch.fnmatchcase(path, pattern)):
                    best, what = len(pattern), text
            if what:
                out.append(f"note: {pkg.name} triggers on {path}: {what}")
    return out
