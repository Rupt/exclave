"""tree.py — what a tree says about itself, for the suite and the oracles (PROPOSAL.md 17): a test asserts what the
tree says, never what one distribution spells. Every function takes the tree's root directory."""
import os
import re


def vbin(root, name):
    """A tool's virtual path as the tree spells it: /usr/bin, or /bin where the tree is not merged."""
    for d in ("usr/bin", "bin"):
        if os.path.lexists(os.path.join(root, d, name)):
            return "/" + d + "/" + name
    return "/usr/bin/" + name


def compiler(root, machine):
    """The tree's C compiler by name: Debian's gcc-13 spellings, gcc, cc, clang, or a versioned clang; None if none."""
    clangs = sorted(n for d in ("usr/bin", "bin") if os.path.isdir(os.path.join(root, d)) for n in os.listdir(os.path.join(root, d)) if re.match(r"clang-\d+$", n))
    for name in ["%s-linux-gnu-gcc-13" % machine, "x86_64-linux-gnu-gcc-13", "gcc-13", "gcc", "cc", "clang"] + clangs:
        if os.path.lexists(os.path.join(root, vbin(root, name).lstrip("/"))):
            return name
    return None


def triplet(root, machine):
    """Debian's multiarch directory under /usr/lib where libc lives, or the machine's conventional name."""
    d = os.path.join(root, "usr", "lib")
    for n in sorted(os.listdir(d)) if os.path.isdir(d) else []:
        if n.endswith("-linux-gnu") and os.path.exists(os.path.join(d, n, "libc.so.6")):
            return n
    return "%s-linux-gnu" % machine


def resolve(root, vpath):
    """A virtual path with the tree's symlinks followed, as a chroot would resolve it; the path itself if a
    component is missing."""
    cur, rest, hops = "", [p for p in vpath.split("/") if p], 0
    while rest:
        comp = rest.pop(0)
        if comp == ".":
            continue
        if comp == "..":
            cur = cur.rsplit("/", 1)[0] if "/" in cur else ""
            continue
        cand = cur + "/" + comp
        real = os.path.join(root, cand.lstrip("/"))
        if not os.path.lexists(real):
            return vpath
        if os.path.islink(real):
            hops += 1
            if hops > 40:
                return vpath
            t = os.readlink(real)
            rest = [p for p in t.split("/") if p] + rest
            if t.startswith("/"):
                cur = ""
            continue
        cur = cand
    return cur or "/"


def libc(root, machine):
    """libc.so.6 as the loader names it, or musl's loader, which is its libc."""
    for v in ("/lib/%s/libc.so.6" % triplet(root, machine), "/lib64/libc.so.6", "/lib/libc.so.6", "/usr/lib/libc.so.6", "/lib/ld-musl-%s.so.1" % machine):
        if os.path.lexists(os.path.join(root, v.lstrip("/"))):
            return v
    return "/lib/libc.so.6"
