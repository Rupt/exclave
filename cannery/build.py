"""build.py — extraction, synthesis, placeholders, lockfile and the from-packages orchestration
(PROPOSAL.md 10.1 steps 3 to 7, 6.4).
"""
import hashlib
import os
import re
import shutil
import stat
import subprocess
import sys
import tarfile

import deb

CANNERY_VERSION = "0.1.0"
MERGED_USR = ["bin", "sbin", "lib", "lib32", "lib64", "libx32"]
# 8.1 / 6.1: volatile directories stripped, conventional host names shipped empty
PLACEHOLDERS = ["proc", "dev", "sys", "tmp", "run", "var/tmp", "home", "root", "mnt", "media", "opt", "srv"]
VOLATILE = ["proc", "dev", "sys", "tmp", "run", "var/tmp"]


class BuildError(Exception):
    pass


# ---------------------------------------------------------------- extraction (step 3)
def _safe_rel(name):
    parts = [p for p in name.split("/") if p not in ("", ".")]
    if any(p == ".." for p in parts):
        raise BuildError("path escapes the tree: " + name)
    if ".real" in parts:
        raise BuildError("the reserved name .real is shipped at " + name)
    return "/".join(parts)


def extract(root, debs, log=print):
    """debs: [(name, path, stanza)]. Extracts every data.tar into root/ after the merged-usr links.
    A regular file shipped by two packages is an error unless one declares Replaces on the other;
    diversions in maintainer scripts are refused. Returns {relpath: owning package}."""
    os.makedirs(os.path.join(root, "usr"), exist_ok=True)
    for d in MERGED_USR:
        os.makedirs(os.path.join(root, "usr", d), exist_ok=True)
        p = os.path.join(root, d)
        if not os.path.lexists(p):
            os.symlink("usr/" + d, p)
    owner, replaces, hardlinks_pending = {}, {}, []
    for name, path, st in debs:
        fields, scripts = deb.control(path)
        # 10.1 step 3: a diversion that renames a file changes where the tree must hold it, and dpkg's
        # database is not reproduced here; those are refused. Diversions with --no-rename, and the
        # merged-usr and zutils transitions every noble closure carries, leave a fresh tree unchanged.
        for sname in ("preinst", "postinst"):
            for line in scripts.get(sname, "").replace("\\\n", " ").split("\n"):
                if line.strip().startswith("#") or "dpkg-divert" not in line:
                    continue
                if re.search(r"--(remove|list|listpackage|truename)\b", line) or "--no-rename" in line or ".usr-is-merged" in line:
                    continue
                raise BuildError("%s adds a renaming diversion in its %s (%s); diversions are refused (10.1)" % (name, sname, line.strip()[:100]))
        replaces[name] = set(a[0] for alts in deb.parse_deps(fields.get("Replaces", "")) for a in alts)
        with deb.open_tar(path, "data.tar") as t:
            for m in t.getmembers():
                rel = _safe_rel(m.name)
                if not rel:
                    continue
                dst = os.path.join(root, rel)
                if m.isdir():
                    if os.path.islink(dst) and os.path.isdir(dst):
                        continue
                    os.makedirs(dst, exist_ok=True)
                    os.chmod(dst, (m.mode & 0o777) | 0o700)                # the tar's mode; a tree must stay traversable by its owner
                    continue
                if os.path.lexists(dst) and (os.path.islink(dst) or not os.path.isdir(dst)):
                    prev = owner.get(rel)
                    if m.issym() and os.path.islink(dst) and os.readlink(dst) == m.linkname:
                        continue                                            # identical symlink from two packages, or a merged-usr link: normal
                    if os.path.islink(dst) and os.path.isdir(dst) and not m.issym():
                        raise BuildError("%s ships /%s over a directory symlink" % (name, rel))
                    if prev and (prev in replaces[name]):
                        os.remove(dst)                                      # this package replaces the previous owner's file
                    elif prev and (name in replaces.get(prev, ())):
                        continue                                            # the previous owner replaces ours: keep theirs
                    elif prev:
                        raise BuildError("%s and %s both ship /%s and neither declares Replaces" % (prev, name, rel))
                    else:
                        os.remove(dst)
                os.makedirs(os.path.dirname(dst), exist_ok=True)
                if m.issym():
                    os.symlink(m.linkname, dst)
                elif m.islnk():
                    hardlinks_pending.append((os.path.join(root, _safe_rel(m.linkname)), dst))
                elif m.isfile():
                    with open(dst, "wb") as f:
                        shutil.copyfileobj(t.extractfile(m), f)
                    os.chmod(dst, m.mode & 0o777)                           # setuid and setgid are meaningless under no_new_privs
                    os.utime(dst, (m.mtime, m.mtime))
                else:
                    log("skipping special file /%s from %s" % (rel, name))
                    continue
                owner[rel] = name
    for src, dst in hardlinks_pending:
        if os.path.lexists(dst):
            os.remove(dst)
        os.link(src, dst)
    return owner


# ---------------------------------------------------------------- synthesis (step 4)
_UA = re.compile(r"update-alternatives\s+(?:--(?:quiet|verbose|force)\s+)*--install\s+(\S+)\s+(\S+)\s+(\S+)\s+(\d+)((?:\s+--slave\s+\S+\s+\S+\s+\S+)*)")
_SLAVE = re.compile(r"--slave\s+(\S+)\s+(\S+)\s+(\S+)")


def _v(root, vpath):
    return os.path.join(root, vpath.lstrip("/"))


def _link(root, link, target, log):
    p = _v(root, link)
    if os.path.lexists(p):
        return
    os.makedirs(os.path.dirname(p), exist_ok=True)
    os.symlink(target, p)
    log("synthesised %s -> %s" % (link, target))


def synthesise(root, debs, log=print):
    """The effects of maintainer scripts, never the scripts (10.1 step 4). Runs before wrapping."""
    names = set(n for n, _, _ in debs)
    # update-alternatives: every --install line in a postinst, highest priority wins, slaves follow
    groups = {}
    for name, path, st in debs:
        fields, scripts = deb.control(path)
        for m in _UA.finditer(scripts.get("postinst", "").replace("\\\n", " ")):     # join continuation lines
            link, gname, target, prio = m.group(1), m.group(2), m.group(3), int(m.group(4))
            if not os.path.lexists(_v(root, target)):
                continue
            slaves = _SLAVE.findall(m.group(5))
            groups.setdefault(gname, []).append((prio, link, target, slaves))
    for gname, cands in groups.items():
        prio, link, target, slaves = max(cands)
        _link(root, "/etc/alternatives/" + gname, target, log)
        _link(root, link, "/etc/alternatives/" + gname, log)
        for slink, sname, starget in slaves:
            if os.path.lexists(_v(root, starget)):
                _link(root, "/etc/alternatives/" + sname, starget, log)
                _link(root, slink, "/etc/alternatives/" + sname, log)
    # dash: /bin/sh is made by its postinst, not shipped
    if "dash" in names and os.path.lexists(_v(root, "/usr/bin/dash")):
        _link(root, "/usr/bin/sh", "dash", log)
    # ca-certificates: the bundle is generated by update-ca-certificates
    conf = _v(root, "/etc/ca-certificates.conf")
    if "ca-certificates" in names and os.path.exists(conf):
        certs = []
        for line in open(conf, encoding="utf-8", errors="replace"):
            line = line.strip()
            if line and not line.startswith("#") and not line.startswith("!"):
                p = _v(root, "/usr/share/ca-certificates/" + line)
                if os.path.exists(p):
                    certs.append(open(p, "rb").read().rstrip(b"\n") + b"\n")
        os.makedirs(_v(root, "/etc/ssl/certs"), exist_ok=True)
        with open(_v(root, "/etc/ssl/certs/ca-certificates.crt"), "wb") as f:
            f.writelines(certs)
        log("synthesised /etc/ssl/certs/ca-certificates.crt from %d certificates" % len(certs))
    # libssl: OpenSSL's compiled-in trust paths are /usr/lib/ssl/cert.pem and /usr/lib/ssl/certs, symlinks the
    # openssl and ca-certificates packages ship and a library's closure lacks; without them the host's bundle
    # at the identity path (8.4) is never consulted
    if any(n.startswith("libssl") for n in names):
        _link(root, "/usr/lib/ssl/certs", "/etc/ssl/certs", log)
        _link(root, "/usr/lib/ssl/cert.pem", "/etc/ssl/certs/ca-certificates.crt", log)
    # base-passwd: /etc/passwd and /etc/group come from update-passwd, not the package; the host's are used
    # unless the manifest claims them (8.4), but the files must exist for tools that list /etc
    for name_, master in (("passwd", "passwd.master"), ("group", "group.master")):
        src, dst = _v(root, "/usr/share/base-passwd/" + master), _v(root, "/etc/" + name_)
        if "base-passwd" in names and os.path.exists(src) and not os.path.lexists(dst):
            shutil.copyfile(src, dst)
            log("synthesised /etc/%s from base-passwd" % name_)
    # ldconfig: the can's own, static, before wrapping so the cache never indexes the opener
    ld = None
    for cand in ("/usr/sbin/ldconfig.real", "/sbin/ldconfig.real", "/usr/sbin/ldconfig", "/sbin/ldconfig"):
        p = _v(root, cand)
        if os.path.isfile(p) and open(p, "rb").read(4) == b"\x7fELF":
            ld = p
            break
    if ld:
        r = subprocess.run([ld, "-r", root], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if r.returncode:
            log("ldconfig failed: " + r.stderr.decode(errors="replace").strip())
        else:
            log("synthesised /etc/ld.so.cache with the can's ldconfig")
        aux = _v(root, "/var/cache/ldconfig")                 # records inodes and mtimes: never reproducible, never needed
        if os.path.isdir(aux):
            shutil.rmtree(aux)
    elif "libc-bin" in names:
        log("libc-bin present but no static ldconfig found; no ld.so.cache")


def synthesise_in_can(can, debs, log=print):
    """Synthesis steps that run canned programs, after wrapping: python compileall. The tree is read-only from
    inside the can, so the bytecode goes to a host directory through PYTHONPYCACHEPREFIX and is moved in."""
    import tempfile
    root = os.path.join(can, "root")
    done = set()
    for name, _, _ in debs:
        m = re.search(r"python(3\.\d+)-minimal$", name)
        if not m or m.group(1) in done:
            continue
        ver = m.group(1)
        done.add(ver)
        py = os.path.join(root, "usr", "bin", "python" + ver)
        if not os.path.exists(py):
            continue
        with tempfile.TemporaryDirectory(prefix="cont-pyc-") as tmp:
            r = subprocess.run([py, "-m", "compileall", "-q", "/usr/lib/python" + ver], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               env={"PATH": "/usr/bin:/bin", "PYTHONPYCACHEPREFIX": tmp}, cwd=tmp)
            n = 0
            for dirpath, dirnames, filenames in os.walk(tmp):
                for f in filenames:
                    src = os.path.join(dirpath, f)
                    dst = os.path.join(root, os.path.relpath(src, tmp))
                    os.makedirs(os.path.dirname(dst), exist_ok=True)
                    shutil.move(src, dst)
                    n += 1
            log("compileall python%s: %s, %d files" % (ver, "ok" if r.returncode == 0 else r.stderr.decode(errors="replace")[-300:], n))


# ---------------------------------------------------------------- placeholders (step 5)
IDENTITY_FILES = ["/etc/passwd", "/etc/group", "/etc/nsswitch.conf", "/etc/host.conf", "/etc/localtime", "/etc/resolv.conf", "/etc/hosts",
                  "/etc/ssl/certs/ca-certificates.crt", "/etc/pki/tls/certs/ca-bundle.crt"]


def placeholders(root, log=print):
    for d in VOLATILE:
        p = os.path.join(root, d)
        if os.path.lexists(p) and not os.path.islink(p):
            shutil.rmtree(p)
    for d in PLACEHOLDERS:
        p = os.path.join(root, d)
        if not os.path.lexists(p):
            os.makedirs(p)
    for f in IDENTITY_FILES:                                  # 8.4: shipped empty, the host's answer at run time
        p = _v(root, f)
        if not os.path.lexists(p):
            os.makedirs(os.path.dirname(p), exist_ok=True)
            open(p, "wb").close()


# ---------------------------------------------------------------- tree hash and lockfile (6.4)
def _payload(real):
    d, n = os.path.split(real)
    p = os.path.join(d, ".real", n)
    return p if os.path.exists(p) else real


def tree_hash(root):
    """BLAKE2b-256 of the serialised listing of 6.4: payloads in place of wrappers, .real/ excluded."""
    entries = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d != ".real")
        for name in dirnames + filenames:
            real = os.path.join(dirpath, name)
            rel = os.path.relpath(real, root).encode("utf-8", "surrogateescape")
            st = os.lstat(real)
            if stat.S_ISLNK(st.st_mode):
                entries.append(rel + b"\0l\0" + os.readlink(real).encode("utf-8", "surrogateescape") + b"\0")
            elif stat.S_ISDIR(st.st_mode):
                entries.append(rel + b"\0d\0\0")
            elif stat.S_ISREG(st.st_mode):
                kind = b"x" if st.st_mode & 0o111 else b"f"
                h = hashlib.blake2b(digest_size=32)
                with open(_payload(real), "rb") as f:
                    for chunk in iter(lambda: f.read(1 << 20), b""):
                        h.update(chunk)
                entries.append(rel + b"\0" + kind + b"\0" + h.hexdigest().encode() + b"\0")
    entries.sort()
    return "b2:" + hashlib.blake2b(b"".join(entries), digest_size=32).hexdigest()


def write_lock(can, source, pkgs, recipes=(), modified=0):
    """pkgs: [(name, version, b2)]. source: list of strings."""
    import cannery
    R = cannery.Record
    recs = [R("lock", [("t", b"1")]), R("cannery", [("s", CANNERY_VERSION.encode())]), R("source", [("s", s.encode()) for s in source])]
    for name, ver, h in sorted(pkgs):
        recs.append(R("pkg", [("s", name.encode()), ("s", ver.encode()), ("s", h.encode())]))
    for path, h in recipes:
        recs.append(R("recipe", [("s", path.encode()), ("s", h.encode())]))
    recs.append(R("tree", [("s", tree_hash(os.path.join(can, "root")).encode())]))
    recs.append(R("modified", [("t", str(modified).encode())]))
    data = cannery.dump(recs, "lock")
    cannery.parse(data, "lock")
    with open(os.path.join(can, ".can", "lock"), "wb") as f:
        f.write(data)


def unwrap(can, log=print):
    """Undo wrapping: every .real/NAME moves back over its wrapper. Leaves a plain tree."""
    import cannery
    root = os.path.join(can, "root")
    n = 0
    for dirpath, dirnames, filenames in os.walk(root, topdown=False):
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
    log("unwrapped %d executables" % n)
    return n
