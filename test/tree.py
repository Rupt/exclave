"""tree.py — what a tree says about itself, for the suite and the oracles (PROPOSAL.md 17): a test asserts what the
tree says, never what one distribution spells. Every function takes the tree's root directory; and, at the end, the one
way a driver takes a can: a copy of its own, reopened with the build, so that the opener under test is always
build/opener and never the one a can was closed with."""
import filecmp
import os
import re
import shutil
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BUILD_OPENER = os.path.join(REPO, "build", "opener")
sys.path.insert(0, os.path.join(REPO, "cannery"))


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


# ---------------------------------------------------------------- a can for a driver (17)
def copy_can(src, dst):
    """A copy of a can for a driver or a test to alter: the tree's files hard-linked, the files under .can/ copied, since a
    manifest or lock written through a hard link would change the given can's."""
    import cannery
    shutil.copytree(src, dst, symlinks=True, copy_function=cannery.link_or_copy)
    for name in os.listdir(os.path.join(dst, ".can")):
        p = os.path.join(dst, ".can", name)
        if os.path.isfile(p) and not os.path.islink(p):
            data = open(p, "rb").read()
            mode = os.stat(p).st_mode
            os.remove(p)
            with open(p, "wb") as f:
                f.write(data)
            os.chmod(p, mode)
    return dst


def fresh_can(src, dst, opener=BUILD_OPENER):
    """copy_can, then every wrapper relinked to build/opener (cannery reopen, about a second for a gcc can): the opener a
    driver runs is always the checkout's build, never the one a can carries, which is the one it was closed with and
    which a rebuild leaves behind. The copy is made anew on every run, so nothing has to be remembered."""
    import cannery
    if not os.path.isfile(opener):
        sys.exit("no opener at %s: run make" % opener)
    copy_can(src, dst)
    cannery.cmd_reopen(dst, opener)
    return dst


def reopen_if_stale(can, opener=BUILD_OPENER):
    """A copy kept between runs, reopened again when the build has changed since it was made: the check is a byte
    comparison of two small files, the reopen a second, so a rebuild never has to be remembered by hand."""
    import cannery
    if not filecmp.cmp(opener, os.path.join(can, ".can", "opener"), shallow=False):
        cannery.cmd_reopen(can, opener)
        return True
    return False
