"""build.py — the tool's build steps (DESIGN.md 10.1, 10.4, 6.4).

Extraction, synthesis, placeholders, the dependency report, pruning and the hashes file.
"""

import glob
import hashlib
import os
import re
import shutil
import stat
import subprocess
from collections.abc import Callable, Iterable, Iterator
lazy from types import ModuleType

from exclave import apk, deb, elfcheck, rpm
lazy from exclave import cli  # cli imports this module: lazily, so neither waits on the other

TOOL_VERSION = "0.1.0"
MERGED_USR = ["bin", "sbin", "lib", "lib32", "lib64", "libx32"]
# 8.1 / 6.1: volatile directories stripped, conventional host names shipped empty
PLACEHOLDERS = [
    "proc",
    "dev",
    "sys",
    "tmp",
    "run",
    "var/tmp",
    "home",
    "root",
    "boot",
    "mnt",
    "media",
    "opt",
    "srv",
]
VOLATILE = ["proc", "dev", "sys", "tmp", "run", "var/tmp"]

type Log = Callable[[str], object]
# A package as extract and synthesise take it: (name, path, control fields).
type Package = tuple[str, str, dict[str, str]]


class BuildError(Exception):
    pass


# ---------------------------------------------------------------- extraction (step 2)
def _safe_rel(name: str) -> str:
    parts = [p for p in name.split("/") if p not in ("", ".")]
    if any(p == ".." for p in parts):
        raise BuildError("path escapes the tree: " + name)
    if ".real" in parts:
        raise BuildError("the reserved name .real is shipped at " + name)
    return "/".join(parts)


_ALIAS = re.compile(r"^(bin|sbin|lib|lib32|lib64|libx32)(/|$)")


def _inside(root_real: str, dst: str) -> None:
    """The parent of dst, once the kernel has resolved every symlink, must be the tree."""
    parent = os.path.realpath(os.path.dirname(dst))
    if parent != root_real and not parent.startswith(root_real + os.sep):
        msg = f"{dst} escapes the tree through a symlink (resolves under {parent})"
        raise BuildError(msg)


def reader(path: str) -> ModuleType:
    """The reader for a package file, chosen by the file (10.1).

    deb.py, apk.py or rpm.py, one interface.
    """
    return apk if path.endswith(".apk") else rpm if path.endswith(".rpm") else deb


def extract(root: str, debs: list[Package], log: Log = print) -> dict[str, str]:
    """debs: [(name, path, stanza)]. Extracts every data.tar into tree/ after the merged-usr links.

    A regular file shipped by two packages is an error unless one declares Replaces on the other,
    with the merged-usr spellings of a path treated as one path; diversions in maintainer scripts
    are refused; a member whose path resolves outside the tree through a symlink is refused.
    Returns {relpath: owner}.
    """
    os.makedirs(os.path.join(root, "usr"), exist_ok=True)
    root_real = os.path.realpath(root)
    # A symlink one package ships at a path other packages ship files under, Fedora 42's
    # usr/sbin -> bin, is made before anything is extracted, as the merged-usr links are, so that
    # those files land where the link points whatever the order of the packages; a package's own
    # files under its own link count too.
    links: dict[str, str] = {}
    parents: set[str] = set()
    for _name, path, _st in debs:
        with reader(path).open_tar(path, "data.tar") as t:
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
    if all(getattr(reader(p), "MERGED_USR", True) for _, p, _ in debs):
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
    for name, path, _st in debs:
        rd = reader(path)
        fields, scripts = rd.control(path)
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
                raise BuildError(msg)
        replaces[name] = {a[0] for alts in rd.parse_deps(fields.get("Replaces", "")) for a in alts}
        with rd.open_tar(path, "data.tar") as t:
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
                        raise BuildError(msg)
                    if prev and (prev in replaces[name]):
                        os.remove(dst)  # this package replaces the previous owner's file
                    elif prev and (name in replaces.get(prev, ())):
                        continue  # the previous owner replaces ours: keep theirs
                    elif prev:
                        msg = f"{prev} and {name} both ship /{rel} and neither declares Replaces"
                        raise BuildError(msg)
                    else:
                        os.remove(dst)
                os.makedirs(os.path.dirname(dst), exist_ok=True)
                if m.issym():
                    os.symlink(m.linkname, dst)
                elif m.islnk():
                    hardlinks_pending.append((os.path.join(root, _safe_rel(m.linkname)), dst))
                elif m.isfile():
                    fd = os.open(dst, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
                    with os.fdopen(fd, "wb") as f:
                        shutil.copyfileobj(t.extractfile(m), f)
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
    return os.path.join(root, vpath.lstrip("/"))


def _link(root: str, link: str, target: str, log: Log, *, replace: bool = False) -> None:
    """A link at a virtual path.

    With replace, as alternatives --install does, a file or link standing there gives way (Fedora's
    binutils ships gold at /usr/bin/ld and removes it in %post before installing the alternative); a
    directory never does.
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


def synthesise(root: str, debs: list[Package], log: Log = print) -> None:
    """The effects of maintainer scripts, never the scripts (10.1 step 3). Runs before wrapping."""
    names = {n for n, _, _ in debs}
    # update-alternatives: every --install line in a postinst, highest priority wins, slaves follow
    groups: dict[str, list[tuple[int, str, str, list[tuple[str, str, str]]]]] = {}
    for _name, path, _st in debs:
        _fields, scripts = reader(path).control(path)
        # join continuation lines
        for m in _UA.finditer(scripts.get("postinst", "").replace("\\\n", " ")):
            link, gname, target, prio = m.group(1), m.group(2), m.group(3), int(m.group(4))
            if not os.path.lexists(_v(root, target)):
                continue
            slaves = _SLAVE.findall(m.group(5))
            groups.setdefault(gname, []).append((prio, link, target, slaves))
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
    # as dash's /bin/sh below is, so that a link run from outside the exclave reaches the wrapper in
    # the tree and not a host file of the same name; inside, a relative link resolves in virtual
    # space the same way.
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
    for name, path, _st in debs:
        if name != "filesystem":
            continue
        _fields, scripts = reader(path).control(path)
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
    # ldconfig: the exclave's own, static, before wrapping so the cache never indexes the launcher
    ld = None
    for cand in (
        "/usr/sbin/ldconfig.real",
        "/sbin/ldconfig.real",
        "/usr/sbin/ldconfig",
        "/sbin/ldconfig",
        "/usr/bin/ldconfig",
    ):  # Fedora 42 merged sbin into bin
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
            r = subprocess.run(
                [ld, "-r", root, "-f", "/etc/ld.so.conf.exclave" if tmp else "/etc/ld.so.conf"],
                capture_output=True,
                check=False,
            )
        except OSError as e:  # the tree's ldconfig is of another architecture: no cache here (10.1)
            r = None
            log(
                f"the tree's ldconfig cannot run on this machine ({e.strerror}): no ld.so.cache; "
                "wrap the exclave on a machine of its architecture"
            )
        if tmp:
            os.remove(tmp)
        if r is None:
            pass
        elif r.returncode:
            log("ldconfig failed: " + r.stderr.decode(errors="replace").strip())
        else:
            log("synthesised /etc/ld.so.cache with the exclave's ldconfig")
        # records inodes and mtimes: never reproducible, never needed
        aux = _v(root, "/var/cache/ldconfig")
        if os.path.isdir(aux):
            shutil.rmtree(aux)
    elif "libc-bin" in names:
        log("libc-bin present but no static ldconfig found; no ld.so.cache")


# ---------------------------------------------------------------- placeholders (step 4)
IDENTITY_FILES = [
    "/etc/passwd",
    "/etc/group",
    "/etc/nsswitch.conf",
    "/etc/host.conf",
    "/etc/resolv.conf",
    "/etc/hosts",
    "/etc/ssl/certs/ca-certificates.crt",
    "/etc/pki/tls/certs/ca-bundle.crt",
]


def placeholders(root: str, *, strip: bool = True, log: Log = print) -> None:
    """8.1: the conventional names as empty directories, the identity files as empty files.

    Each where the tree lacks them; with strip, the volatile directories are emptied first (unpack
    does, wrap does not).
    """
    if strip:
        for d in VOLATILE:
            p = os.path.join(root, d)
            if os.path.lexists(p) and not os.path.islink(p):
                shutil.rmtree(p)
    for d in PLACEHOLDERS:
        p = os.path.join(root, d)
        if not os.path.lexists(p):
            os.makedirs(p)
    tree = elfcheck.Tree(root)
    for f in IDENTITY_FILES:  # 8.4: shipped empty, the host's answer at run time
        d, b = os.path.split(f)
        # the directory as the tree resolves it: Fedora's /etc/ssl/certs is a link into /etc/pki
        rd = tree.resolve(d)
        if rd is None and os.path.islink(_v(root, d)):
            log(f"identity file {f} not placed: its directory is a dangling link in the tree")
            continue
        p = os.path.join(_v(root, rd or d), b)
        if not os.path.lexists(p):
            os.makedirs(os.path.dirname(p), exist_ok=True)
            open(p, "wb").close()


# ---------------------------------------------------------------- tree hash and hashes file (6.4)
def _payload(real: str) -> str:
    d, n = os.path.split(real)
    p = os.path.join(d, ".real", n)
    return p if os.path.exists(p) else real


def tree_hash(root: str) -> str:
    """BLAKE2b-256 of the serialised listing of 6.4.

    Originals in place of wrappers, .real/ excluded, except that an original without a wrapper is
    hashed under its own name so that nothing is ever invisible.
    """
    entries: list[bytes] = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d != ".real")
        strays = []
        if os.path.isdir(os.path.join(dirpath, ".real")):
            strays = [
                os.path.join(".real", n)
                for n in sorted(os.listdir(os.path.join(dirpath, ".real")))
                if not os.path.lexists(os.path.join(dirpath, n))
            ]
        for name in dirnames + filenames + strays:
            real = os.path.join(dirpath, name)
            rel = os.path.relpath(real, root).encode("utf-8", "surrogateescape")
            st = os.lstat(real)
            if stat.S_ISLNK(st.st_mode):
                entries.append(
                    rel + b"\0l\0" + os.readlink(real).encode("utf-8", "surrogateescape") + b"\0"
                )
            elif stat.S_ISDIR(st.st_mode):
                entries.append(rel + b"\0d\0\0")
            elif stat.S_ISREG(st.st_mode):
                kind = b"x" if st.st_mode & 0o111 else b"f"
                h = hashlib.blake2b(digest_size=32)
                if not os.access(_payload(real), os.R_OK):
                    msg = f"cannot read {_payload(real)}: the tree hash needs every file readable"
                    raise BuildError(msg)
                with open(_payload(real), "rb") as f:
                    for chunk in iter(lambda: f.read(1 << 20), b""):
                        h.update(chunk)
                entries.append(rel + b"\0" + kind + b"\0" + h.hexdigest().encode() + b"\0")
    entries.sort()
    return "b2:" + hashlib.blake2b(b"".join(entries), digest_size=32).hexdigest()


def write_lock(
    ex: str,
    pkgs: list[tuple[str, str, str, str]] | None,
    manifest_hash: str | None = None,
    *,
    tree: bool = False,
    keep_hashes: bool = False,
) -> None:
    """6.4: the hashes file is a record of inputs and output.

    pkgs: [(name, version, arch, b2)], or None to keep the pkg records already there. The wrapping
    step writes the launcher, manifest and tree hashes; keep_hashes keeps the manifest hash and
    recomputes the launcher and tree hashes (after prune or relink); otherwise they are dropped
    (after unwrap: an unwrapped exclave has no output yet).
    """
    record = cli.Record
    lock = os.path.join(ex, ".exclave", "hashes")
    old = cli.load(lock, "hashes") if os.path.exists(lock) else []
    if pkgs is None:
        pkgs = []
        for v in cli.values(old, "pkg"):
            name, ver, arch, h = (f.decode("utf-8", "surrogateescape") for f in v)
            pkgs.append((name, ver, arch, h))
    if keep_hashes:
        m = cli.values(old, "manifest")
        manifest_hash, tree = (m[0][0].decode() if m else None), bool(cli.values(old, "tree"))
    recs = [record("hashes", [("t", b"1")]), record("tool", [("s", TOOL_VERSION.encode())])]
    if manifest_hash or tree:
        recs.append(
            record(
                "launcher", [("s", cli.b2_file(os.path.join(ex, ".exclave", "launcher")).encode())]
            )
        )
    for name, ver, arch, h in sorted(pkgs):
        recs.append(
            record(
                "pkg",
                [
                    ("s", name.encode()),
                    ("s", ver.encode()),
                    ("s", arch.encode()),
                    ("s", h.encode()),
                ],
            )
        )
    if manifest_hash:
        recs.append(record("manifest", [("s", manifest_hash.encode())]))
    if tree:
        recs.append(record("tree", [("s", tree_hash(os.path.join(ex, "tree")).encode())]))
    data = cli.dump(recs, "hashes")
    cli.parse(data, "hashes")
    with open(lock, "wb") as f:
        f.write(data)


# ---------------------------------------------------------------- the dependency report (10.1)
def dependency_report(pkgs: list[tuple[str, dict[str, str]]], root: str | None = None) -> list[str]:
    """Lines naming every Depends or Pre-Depends the set does not satisfy.

    pkgs: [(name, control fields)]. With Provides and version constraints honoured; a dependency
    spelt as a path (rpm's and apk's `/bin/sh`) is satisfied when the tree under root, extracted and
    synthesised, resolves it. A report, not a refusal: the set is the user's.
    """
    tree = elfcheck.Tree(root) if root else None
    rd: ModuleType = {"apk": apk, "rpm": rpm}.get(pkgs[0][1].get("_format") if pkgs else None, deb)
    have = {n: f.get("Version", "") for n, f in pkgs}
    provides: dict[str, list[str | None]] = {}
    for _n, f in pkgs:
        for alts in rd.parse_deps(f.get("Provides", "")):
            for name, op, ver in alts:
                provides.setdefault(name, []).append(ver if op == "=" else None)
    out = []
    for n, f in sorted(pkgs):
        for field in ("Pre-Depends", "Depends"):
            for alts in rd.parse_deps(f.get(field, "")):
                ok = any(
                    name.startswith("/") and (tree is None or tree.resolve(name) is not None)
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
                    out.append(f"{n} needs {want}, not in the set")
    return out


# ------------------------------------------------------------- EXCLAVE_LOG as an input (10.3, 10.4)
def log_lines(logs: Iterable[str]) -> Iterator[tuple[str, int, str]]:
    r"""Yield (what, result, path) from EXCLAVE_LOG files.

    The path's \\n and \\\\ escapes are undone left to right (6.2), so that a backslash before an n
    stays a backslash.
    """
    for lp in logs:
        with open(lp, encoding="utf-8", errors="surrogateescape") as f:
            for line in f:
                parts = line.rstrip("\n").split(" ", 2)
                if len(parts) != 3:
                    continue
                try:
                    r = int(parts[1])
                except ValueError:
                    continue
                yield (
                    parts[0],
                    r,
                    re.sub(r"\\([n\\])", lambda m: "\n" if m.group(1) == "n" else "\\", parts[2]),
                )


# ---------------------------------------------------------------- the pruning (10.4)
def _resolve_keep(root: str, vpath: str, keep: set[str], hops: int = 0) -> str | None:
    """Walk vpath in the tree, adding every symlink met to keep.

    Returns the final virtual path, or None.
    """
    cur = ""
    parts = [p for p in vpath.split("/") if p]
    while parts:
        comp = parts.pop(0)
        if comp == ".":
            continue
        if comp == "..":
            cur = cur.rsplit("/", 1)[0] if "/" in cur else ""
            continue
        cand = cur + "/" + comp
        real = os.path.join(root, cand.lstrip("/"))
        if os.path.islink(real):
            if hops > 40:
                return None
            hops += 1
            keep.add(cand)
            t = os.readlink(real)
            parts = [p for p in t.split("/") if p] + parts
            cur = "" if t.startswith("/") else cur
            continue
        if not os.path.lexists(real):
            return None
        cur = cand
    return cur or "/"


def licence_files(root: str) -> list[str]:
    """The packages' licence texts in a tree, which prune keeps (10.4).

    Under every usr/share/ in it, a data directory's too: Debian's doc/PKG/copyright and the
    common-licenses those refer to, and licenses/, where RPM's %license files and Alpine's -doc
    packages put theirs.
    """
    found = []
    for dirpath, dirnames, _ in os.walk(root):
        if (
            os.path.basename(dirpath) != "share"
            or os.path.basename(os.path.dirname(dirpath)) != "usr"
        ):
            continue
        dirnames[:] = []  # below a usr/share/, only its licence texts
        found += sorted(glob.glob(os.path.join(dirpath, "doc", "*", "copyright")))
        for top in ("common-licenses", "licenses"):
            for d, _, filenames in os.walk(os.path.join(dirpath, top)):
                found += sorted(os.path.join(d, n) for n in filenames)
    return ["/" + os.path.relpath(f, root) for f in found]


def prune(
    ex: str, logs: Iterable[str], own: elfcheck.Owned, _log: Log = print
) -> tuple[int, int, int]:
    """Prune the tree to what the logged workloads touched (10.4).

    Keep what the logged workloads touched, the entries of directories they opened, the symlink
    chains that reach kept files, the libraries kept ELF files need, the placeholders and the
    licence texts; drop every other file and symlink. Directories are never removed, so ownership
    and `ls` do not change. Returns (kept, removed, bytes).
    """
    root = os.path.join(ex, "tree")
    keep: set[str] = set()
    whole: set[str] = set()
    programs = 0
    for what, r, v in log_lines(logs):
        if what == "launcher" or not v.startswith("/") or r < 0:
            continue
        if elfcheck.host_owned(v, own):
            continue
        final = _resolve_keep(root, v, keep)
        if final is None:
            continue
        real = os.path.join(root, final.lstrip("/"))
        if os.path.isdir(real):
            if what == "open":  # a directory a program opened may be listed: keep it whole
                whole.add(final)
        else:
            keep.add(final)
            if what in ("exec", "load"):
                programs += 1
    if not programs:  # an empty, foreign or failed log would empty the exclave
        msg = "the logs name no program in this exclave; nothing to prune to"
        raise BuildError(msg)
    for f in [*IDENTITY_FILES, "/etc/ld.so.cache"]:
        if os.path.lexists(_v(root, f)):
            keep.add(f)
    for v in licence_files(root):  # the packages' licence texts go with every copy (10.4)
        final = _resolve_keep(root, v, keep)
        if final:
            keep.add(final)
    for d in whole:  # its own entries: a getdents shows names, nothing below them
        for name in os.listdir(_v(root, d)):
            if not os.path.isdir(os.path.join(_v(root, d), name)) or os.path.islink(
                os.path.join(_v(root, d), name)
            ):
                keep.add("/" + os.path.relpath(os.path.join(_v(root, d), name), root))
    # the libraries every kept ELF needs, by the loader's own search (10.3)
    tree = elfcheck.Tree(root)
    elfs = []
    for v in sorted(keep):
        real = os.path.join(root, v.lstrip("/"))
        if os.path.isfile(real) and not os.path.islink(real) and "/.real/" not in v:
            with open(tree.payload(v), "rb") as f:
                if f.read(4) == b"\x7fELF":
                    elfs.append(v)
    for lib in elfcheck.needed_closure(tree, elfs, own):
        final = _resolve_keep(root, lib, keep)  # the chain of links, then the file they reach
        if final:
            keep.add(final)
    # the log names canonical paths, so every alias a program used is a symlink to keep:
    # every symlink in the tree that reaches a kept file, or a directory, stays with its chain;
    # the rest go
    for _real, v, st in cli.walk_files(root):
        if not stat.S_ISLNK(st.st_mode) or v in keep:
            continue
        chain: set[str] = set()
        final = _resolve_keep(root, v, chain)
        if final and (final in keep or os.path.isdir(os.path.join(root, final.lstrip("/")))):
            keep |= chain
            keep.add(v)
    kept = removed = freed = 0
    for dirpath, dirnames, filenames in os.walk(root):
        in_real = os.path.basename(dirpath) == ".real"
        for name in filenames + [x for x in dirnames if os.path.islink(os.path.join(dirpath, x))]:
            real = os.path.join(dirpath, name)
            v = "/" + os.path.relpath(real, root)
            w = (
                "/" + os.path.relpath(os.path.join(os.path.dirname(dirpath), name), root)
                if in_real
                else v
            )
            if w in keep:
                kept += 1
                continue
            st = os.lstat(real)
            is_wrap = not in_real and os.path.exists(os.path.join(dirpath, ".real", name))
            # originals and plain files; a wrapper is a link to the launcher
            if stat.S_ISREG(st.st_mode) and not is_wrap:
                freed += st.st_size
            os.remove(real)
            removed += 1
    return kept, removed, freed


def unwrap(ex: str, log: Log = print) -> int:
    """Undo wrapping: every .real/NAME moves back over its wrapper. Leaves a plain tree."""
    root = os.path.join(ex, "tree")
    n = 0
    for dirpath, _dirnames, filenames in os.walk(root, topdown=False):
        if os.path.basename(dirpath) != ".real":
            continue
        parent = os.path.dirname(dirpath)
        for name in filenames:
            w = os.path.join(parent, name)
            if os.path.lexists(w):
                os.remove(w)
            os.rename(os.path.join(dirpath, name), w)
            n += 1
        os.rmdir(dirpath)
    log(f"unwrapped {n} executables")
    return n
