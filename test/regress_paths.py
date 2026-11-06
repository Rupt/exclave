"""Paths and the border: a group of the regression suite (DESIGN.md 17 item 4).

Run by test/run.py, on the fixtures test/suite.py makes.
"""

import errno
import os
import platform
import re
import shutil
import subprocess
lazy import ctypes

import kernel_answers
import tree
from harness import expect, read_bytes, read_text, run, skip, test
from suite import VOLATILE, Ctx, check, copy_exclave, hello_source, inside, wrapper

PATH_MAX = 4096


@test
def isolation(ctx: Ctx) -> str | None:
    """8.1: a compile under strace names no path of the exclave's to the kernel untranslated.

    Every syscall strace counts as taking a file name is judged, failed ones too, since a leaked
    lookup that fails on the host (a compiler probing its directories) is a leak all the same: a
    path the program gave is the exclave's own only in the trapped call, which its SIGSYS line
    marks, and the handler's re-issue names the tree's real path.
    """
    if not shutil.which("strace"):
        skip("no strace")
    tr = os.path.join(ctx.work, "trace")
    src = hello_source(ctx)
    rc, _out, err = run(
        [
            "strace",
            "-f",
            "-s",
            "4096",
            "-o",
            tr,
            "-e",
            "trace=%file",
            wrapper(ctx, ctx.gcc),
            "-O1",
            src,
            "-o",
            os.path.join(ctx.work, "hello2"),
        ],
        cwd=ctx.work,
        env=ctx.env,
    )
    if rc and "invalid system call '%file'" in err:
        skip("this strace has no %file class")
    expect(rc == 0, "compile under strace failed: " + err)
    bad, seen = [], 0
    # 8.1 as the launcher computes it: a top-level name outside it is the host's
    owned = tree.owned(ctx.exclave)
    # and the default host directories, each of which the launcher looks at once at startup
    allowed_files = set(tree.IDENTITY_FILES) | set(tree.HOST_DIRS)
    # the launcher resolves each identity file's host symlink chain at startup
    for f in tree.IDENTITY_FILES:
        p = f
        for _ in range(40):
            if not os.path.islink(p):
                break
            t = os.readlink(p)
            p = os.path.normpath(t if t.startswith("/") else os.path.join(os.path.dirname(p), t))
            allowed_files.add(p)
    # A trapped syscall appears in the trace too, at its exit stop, with the registers the kernel
    # rolled back (x86-64 shows the number as its result, aarch64 the first argument); its SIGSYS
    # line, naming it, follows. That call is the one the kernel skipped and the handler re-issued,
    # so a line followed by its own SIGSYS is not judged. A trapped syscall outside the traced set
    # prints no line, only the SIGSYS, hence the name.
    lines: list[str] = []
    pending: dict[str, str] = {}
    with open(tr) as trace:
        for line in trace:
            m = re.match(r"^(\d+)\s+(.*)", line)
            pid, rest = (m.group(1), m.group(2)) if m else ("", line)
            m = re.match(r"--- SIGSYS .*si_syscall=__NR_(\w+)", rest)
            if m:
                if pid in pending and re.match(r"^\d+\s+" + m.group(1) + r"\(", pending[pid]):
                    pending.pop(pid)
                continue
            if pid in pending:
                lines.append(pending.pop(pid))
            pending[pid] = line
    lines.extend(pending.values())
    for line in lines:
        m = re.match(r"^\d+\s+(\w+)\((.*)\)\s+=\s+(-?\d+)", line)
        if not m:
            continue
        name, args = m.group(1), m.group(2)
        paths = re.findall(r'"((?:[^"\\]|\\.)*)"', args)
        if name in ("execve", "execveat", "readlink", "readlinkat") and paths:
            # the rest are argv strings, or the link's text (Fedora's /usr/bin/ld ->
            # /etc/alternatives/ld)
            paths = paths[:1]
        elif name in ("symlink", "symlinkat") and paths:
            # the link's text is stored as written; only the link's own name is looked up
            paths = paths[-1:]
        for given in paths:
            seen += 1
            p = os.path.normpath(given) if given.startswith("/") else given
            # a top-level name the exclave does not own, absent or a placeholder,
            # is the host's (8.1)
            ok = (
                not p.startswith("/")
                or p.startswith((ctx.root, ctx.work, *VOLATILE))
                or p in allowed_files
                or ctx.work.startswith(p + "/")
                or "/" + p.split("/")[1] not in owned
            )
            if not ok:
                bad.append(f"{name} {p}")
    expect(seen > 50, f"trace looks empty ({seen} paths)")
    expect(not bad, "host paths touched: " + ", ".join(sorted(set(bad))[:10]))
    return None


@test
def ro_matrix(ctx: Ctx) -> None:
    d = os.path.join(ctx.work, "hostdir")
    os.makedirs(d, exist_ok=True)
    # the wrapper itself, behind a link
    rc, out, err = inside(
        ctx, os.path.join(ctx.progs, "ro_matrix"), [d, ctx.vreal(ctx.vbin(ctx.gcc))]
    )
    expect(rc == 0 and "FAIL" not in out, out + err)


@test
def coreutils_ro(ctx: Ctx) -> None:
    def w(name: str, *args: str) -> tuple[int, str, str]:
        return run([wrapper(ctx, name), *list(args)], cwd=ctx.work, env=ctx.env)

    rc, out, err = w("touch", "/usr/newfile")
    expect(rc and "Read-only" in err, err)
    rc, out, err = w("mkdir", "-p", "/usr/lib")
    expect(rc == 0, err)
    rc, out, err = w("install", "-d", "/usr/lib")
    # busybox's install -d chmods an existing directory, which the read-only rule refuses as a mount
    # would
    if ctx.busybox:
        expect(rc and "Read-only" in err, err)
    else:
        expect(rc == 0, err)
    rc, out, err = w("mkdir", "/usr/lib")
    expect(rc and "exists" in err, err)
    rc, out, err = w("rm", ctx.vbin(ctx.gcc))
    expect(rc and "Read-only" in err, err)
    rc, out, err = w("ln", ctx.vbin(ctx.gcc), os.path.join(ctx.work, "lnk-x"))
    expect(rc and "cross-device" in err.lower(), err)
    rc, out, err = w("cp", ctx.vbin(ctx.gcc), os.path.join(ctx.work, "gcc-copy"))
    expect(rc == 0, err)
    payload = ctx.payload(ctx.gcc)
    expect(
        os.path.getsize(os.path.join(ctx.work, "gcc-copy")) == os.path.getsize(payload),
        "cp of a wrapper did not copy the original",
    )
    expect(read_bytes(os.path.join(ctx.work, "gcc-copy"), 4) == b"\x7fELF", "copy is not ELF")
    rc, out, err = w("cat", "/usr/share/exclave-test-marker")
    expect(out == "marker\n", out + err)


@test
def host_walk_one_step(ctx: Ctx) -> None:
    """DESIGN.md 16.6 item 4: one openat2 stands in for a host walk's lstats.

    Where the directories ahead of a walk are all the host's, one openat2 with RESOLVE_NO_SYMLINKS
    stands in for their lstats, and anything it cannot vouch for is the walk's. A host symlink into
    /usr deep in the chain still reaches the exclave's /usr; a file where a directory should be is
    ENOTDIR and a missing directory ENOENT, as the walk answers; a plain deep path reads as it does
    natively.
    """
    base = os.path.join(ctx.work, f"deephost-{os.getpid()}")
    deep = os.path.join(base, "h1", "h2", "h3", "h4")
    os.makedirs(deep, exist_ok=True)
    with open(os.path.join(deep, "f"), "w") as f:
        f.write("deep\n")
    if not os.path.lexists(os.path.join(deep, "lnk")):
        os.symlink("/usr", os.path.join(deep, "lnk"))
    cat = wrapper(ctx, "cat")
    rc, out, err = run([cat, os.path.join(deep, "f")], cwd=ctx.work, env=ctx.env)
    expect(rc == 0 and out == "deep\n", f"a deep host file: rc={rc} {out!r} {err!r}")
    rc, out, err = run(
        [cat, os.path.join(deep, "lnk", "share", "exclave-test-marker")], cwd=ctx.work, env=ctx.env
    )
    expect(
        rc == 0 and out == "marker\n",
        "a host link into /usr deep in a host chain reaches the exclave's: "
        f"rc={rc} {out!r} {err!r}",
    )
    rc, out, err = run(
        [
            cat,
            os.path.join(
                f"deephost-{os.getpid()}",
                "h1",
                "h2",
                "h3",
                "h4",
                "lnk",
                "share",
                "exclave-test-marker",
            ),
        ],
        cwd=ctx.work,
        env=ctx.env,
    )
    expect(rc == 0 and out == "marker\n", f"the same, relative: rc={rc} {out!r} {err!r}")
    rc, out, err = run([cat, os.path.join(deep, "f", "x", "y")], cwd=ctx.work, env=ctx.env)
    expect(rc != 0 and "Not a directory" in err, f"a file in the middle: {err!r}")
    rc, out, err = run(
        [cat, os.path.join(base, "h1", "missing", "h3", "f")], cwd=ctx.work, env=ctx.env
    )
    expect(rc != 0 and "No such file" in err, f"a missing directory in the middle: {err!r}")
    # these answers hold with or without the one-step check; where the launcher would use it, it
    # must have run
    if shutil.which("strace") and has_openat2() and mounted_once(ctx.root):
        trace = os.path.join(ctx.work, f"deephost-{os.getpid()}.trace")
        run(
            ["strace", "-f", "-e", "trace=openat2", "-o", trace, cat, os.path.join(deep, "f")],
            cwd=ctx.work,
            env=ctx.env,
        )
        expect(
            "RESOLVE_NO_SYMLINKS" in read_text(trace),
            "the one-step check did not run where the tree's filesystem is mounted once",
        )


def has_openat2() -> bool:
    """The one-step check's other condition: the kernel has openat2 (5.6).

    Asked of the kernel, not of its version.
    """
    libc = ctypes.CDLL(None, use_errno=True)
    how = (ctypes.c_uint64 * 3)(0o10000000, 0, 0)  # O_PATH
    nr = {"x86_64": 437, "aarch64": 437}.get(os.uname().machine, 437)
    fd = libc.syscall(nr, -100, b"/", ctypes.byref(how), ctypes.c_size_t(24))
    if fd >= 0:
        os.close(fd)
        return True
    return False


def mounted_once(path: str) -> bool:
    """The one-step check's condition (canon.c tree_mounted_once).

    The mount holding path is its filesystem's only one in /proc/self/mountinfo, with path's own
    device number.
    """
    real = os.path.realpath(path)
    dev = os.stat(real).st_dev
    best, mm, lines = -1, None, []
    with open("/proc/self/mountinfo") as mountinfo:
        for entry in mountinfo:
            f = entry.split()
            mp = f[4].encode().decode("unicode_escape")
            lines.append(f[2])
            if (real == mp or real.startswith(mp.rstrip("/") + "/")) and len(mp) >= best:
                best, mm = len(mp), f[2]
    return mm is not None and lines.count(mm) == 1 and mm == f"{os.major(dev)}:{os.minor(dev)}"


@test
def rename_dots_order(ctx: Ctx) -> None:
    """7.4.3, 8.2: a rename whose last name is . or .., in do_renameat2's order.

    The parents are looked up, then the two mounts compared, EXDEV, then such a name refused,
    EBUSY, or EEXIST for the new name under RENAME_NOREPLACE, then the mount wanted writable,
    EROFS. Two names the host owns are the kernel's own, the name kept after its resolved parent,
    so a parent on another of the host's mounts, /proc or a tmpfs, is EXDEV before EBUSY; the
    launcher once answered EBUSY from the exclave's boundary alone. The other directory is a
    writable one on a different mount from the work directory where the host has one (/dev/shm,
    /tmp, /run/user/UID), and the answers follow it. Measured under bwrap, where /tmp is a mount
    of its own.
    """
    d = os.path.join(ctx.work, "rename_dots")
    os.makedirs(d, exist_ok=True)
    other = next(
        (
            c
            for c in ("/dev/shm", "/tmp", f"/run/user/{os.getuid()}")
            if os.access(c, os.W_OK) and tree.mount_of(c) != tree.mount_of(d)
        ),
        None,
    )
    across = other is not None
    if other is None:
        other = os.path.join(ctx.work, "rename_dots_same")
        os.makedirs(other, exist_ok=True)
    rc, out, err = inside(ctx, os.path.join(ctx.progs, "rename_dots"), [d, other])
    bad = kernel_answers.rename_dots_wrong(out, across=across)
    expect(rc == 0 and not bad, f"rename of . or .. (other {other}): {bad!r} {out + err}")


@test
def casefold_alias(ctx: Ctx) -> str | None:
    """The tree's other spellings on a case-insensitive filesystem stay the tree's.

    On a case-insensitive filesystem the tree's root has other spellings, x.exclave/TREE for
    X.exclave/tree, on the same mount; a host walk that stood in for its lstats with one openat2
    must still see the tree there, read-only. Made on a casefold tmpfs (6.13) in a user namespace;
    skipped where either is missing.
    """
    if subprocess.run(
        ["unshare", "-Urm", "true"],
        check=False,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    ).returncode:
        skip("no user namespaces")
    mnt = os.path.join(ctx.work, f"casefold-{os.getpid()}")
    os.makedirs(mnt, exist_ok=True)
    sh = wrapper(ctx, "sh")
    rel = os.path.relpath(sh, ctx.exclave)
    setup = (
        f"mount -t tmpfs -o casefold tmpfs {mnt} && mkdir {mnt}/cf && chattr +F {mnt}/cf "
        "|| exit 99; "
        # names that differ only in case (the kernel's headers) are skipped
        f"cp -a {ctx.exclave} {mnt}/cf/X.exclave 2>/dev/null; "
        f"test -x {mnt}/cf/X.exclave/{rel} || exit 98"
    )
    inner = (
        f"touch {mnt}/cf/x.exclave/TREE/usr/zz-cf; echo rc=$?; "
        f"cat {mnt}/cf/x.exclave/TREE/usr/share/exclave-test-marker; "
        f"cd {mnt}/cf/x.exclave/TREE/usr && touch zz-cf2; echo rc=$?"
    )
    # what reached the tree
    cmd = (
        f"{setup} && {mnt}/cf/X.exclave/{rel} -c '{inner}'; "
        f"ls {mnt}/cf/X.exclave/tree/usr | grep zz-cf"
    )
    rc, out, err = run(
        ["unshare", "-Urm", "sh", "-c", cmd], cwd=ctx.work, env=dict(ctx.env, PATH="/usr/bin:/bin")
    )
    if rc == 99:
        skip(f"no casefold tmpfs here: {err.strip()[-120:]}")
    expect(rc != 98, f"the exclave's shell did not copy onto the casefold tmpfs: {err[-300:]!r}")
    expect(
        out == "rc=1\nmarker\nrc=1\n" and err.count("Read-only") >= 2,
        f"a case-folded spelling of the tree's root: rc={rc} {out!r} {err!r}",
    )
    return None


@test
def cwd_rules(ctx: Ctx) -> str | None:
    rc, out, err = run([wrapper(ctx, "pwd")], cwd=os.path.join(ctx.root, "usr", "bin"), env=ctx.env)
    expect(out == "/usr/bin\n", f"cwd inside tree/: {out!r}")
    rc, out, err = run(
        [wrapper(ctx, "touch"), "x"], cwd=os.path.join(ctx.root, "usr", "bin"), env=ctx.env
    )
    expect(rc and "Read-only" in err, f"write in tree/ cwd: {err!r}")
    sub = os.path.join(ctx.work, "sub", "sub2")
    os.makedirs(sub, exist_ok=True)
    with open(os.path.join(sub, "file"), "w") as f:
        f.write("deep\n")
    rc, out, err = run(
        [wrapper(ctx, "sh"), "-c", "pwd; cd sub && pwd && cat sub2/file"], cwd=ctx.work, env=ctx.env
    )
    expect(out == f"{ctx.work}\n{ctx.work}/sub\ndeep\n", f"cwd given to the host: {out!r} {err!r}")
    inc, outd = os.path.join(ctx.work, "inc"), os.path.join(ctx.work, "out")
    os.makedirs(inc, exist_ok=True)
    os.makedirs(outd, exist_ok=True)
    with open(os.path.join(inc, "x.h"), "w") as f:
        f.write("#define X 41\n")
    with open(os.path.join(ctx.work, "sub", "y.c"), "w") as f:
        f.write(
            '#include "x.h"\n#include <stdio.h>\nint main(void){printf("%d\\n", X+1);return 0;}\n'
        )
    rc, out, err = run(
        [wrapper(ctx, ctx.gcc), "-Iinc", "sub/y.c", "-o", "out/y"], cwd=ctx.work, env=ctx.env
    )
    expect(rc == 0, "compile with subdirectory include and output: " + err)
    rc, out, err = inside(ctx, os.path.join(outd, "y"))
    expect(out == "42\n", f"built output run inside: {out!r} {err!r}")
    if not ctx.cwd_given:
        return "work dir under a volatile prefix; the cwd given to the host is not exercised"
    # a directory on the way to the working directory is the host's in every spelling: a trailing
    # slash names the same directory
    top = "/" + ctx.work.split("/")[1]
    rc, out, err = run(
        [wrapper(ctx, "sh"), "-c", f"stat -L -c %i {top} {top}/ {top}/."], cwd=ctx.work, env=ctx.env
    )
    expect(
        out.split() == [str(os.stat(top).st_ino)] * 3,
        f"{top}, {top}/ and {top}/. on the way to the working directory: {out!r} {err!r}",
    )
    # the launcher's line for rule 4 and the dynamic check's reading of it, both spellings at once:
    # a library the workload opened under that directory is its own output, a warning, where without
    # the line it would pass unseen
    log = os.path.join(ctx.work, f"cwd-given-{os.getpid()}.log")
    rc, out, err = run([wrapper(ctx, "true")], cwd=ctx.work, env=dict(ctx.env, EXCLAVE_LOG=log))
    expect(
        rc == 0 and f"launcher 2 cwd given to the host {ctx.work}\n" in read_text(log),
        f"the rule-4 log line: {read_text(log)[:400]!r}",
    )
    with open(log, "a") as f:
        f.write(f"open 3 {ctx.work}/sub/libown.so.1\n")
    _errors, warnings, out = check(ctx.exclave, log)
    expect(
        any("working directory" in w and "libown.so.1" in w for w in warnings)
        and re.search(r"dynamic check: \d+ log lines, 0 errors", out),
        f"the dynamic check's reading of the rule-4 line: {warnings!r} {out[-400:]!r}",
    )
    return None


@test
def real_root_is_the_tree(ctx: Ctx) -> None:
    """The tree's real root is an alias of /.

    A path spelt through <exclave>/tree/ obeys the same rules.
    """
    root = ctx.root
    _rc, out, err = run(
        [
            wrapper(ctx, "sh"),
            "-c",
            (
                "touch {}/usr/zz; echo rc=$?; rm {}{}; echo rc=$?; "
                "cat {}/usr/share/exclave-test-marker; ls -l {}{} | cut -c1 "
            ).format(root, root, ctx.vbin("true"), root, root, ctx.vbin("sh")),
        ],
        cwd="/",
        env=ctx.env,
    )
    expect(
        out == "rc=1\nrc=1\nmarker\nl\n" and "Read-only" in err,
        f"real-root spelling: {out!r} {err!r}",
    )
    expect(
        not os.path.exists(os.path.join(root, "usr", "zz"))
        and os.path.exists(os.path.join(root, ctx.vbin("true").lstrip("/"))),
        "the tree was written through its real path",
    )
    # other spellings of the same path, which the walk resolves rather than the shortcut for the
    # exact one: relative from a host working directory, and with a doubled slash (a mutant without
    # the walk's refusal of the root's name wrote)
    relp = os.path.relpath(os.path.join(root, "usr", "zz2"), ctx.work)
    slashed = root.replace("/", "//", 1) + "/usr/zz3"
    _rc, out, err = run(
        [wrapper(ctx, "sh"), "-c", f"touch {relp}; echo rc=$?; touch {slashed}; echo rc=$?"],
        cwd=ctx.work,
        env=ctx.env,
    )
    expect(
        out == "rc=1\nrc=1\n" and err.count("Read-only") == 2,
        f"relative and doubled-slash spellings: {out!r} {err!r}",
    )
    expect(
        not os.path.exists(os.path.join(root, "usr", "zz2"))
        and not os.path.exists(os.path.join(root, "usr", "zz3")),
        "the tree was written through another spelling of its real path",
    )


@test
def readlink_as_stored(ctx: Ctx) -> None:
    """7.4.3: a link's text is returned as stored, even when it names the tree's real location.

    Only /proc links and identity files answer in virtual terms; a host link made from outside
    toward the tree's real path reads as the kernel reads it, and still leads to the tree's file.
    """
    link = os.path.join(ctx.work, "to-tree-link")
    if os.path.lexists(link):
        os.remove(link)
    target = os.path.join(os.path.realpath(ctx.root), "usr", "share", "exclave-test-marker")
    os.symlink(target, link)
    rc, out, err = run(
        [wrapper(ctx, "sh"), "-c", f"readlink {link}; cat {link}"], cwd=ctx.work, env=ctx.env
    )
    os.remove(link)
    expect(
        rc == 0 and out == f"{target}\nmarker\n",
        f"readlink of a host link into the tree: {out!r} {err!r}",
    )


@test
def magic_links_to_pathless(ctx: Ctx) -> None:
    """7.4.3: a magic link to an object with no path reaches the object, as the kernel's walk does.

    stat, statx and faccessat2 through /proc/self/fd/N find the pipe, memfd, inotify descriptor or
    unlinked file fstat finds, /dev/stdin is the caller's pipe, and an O_TMPFILE file is linked by
    its magic link; a call fails only where the kernel itself, asked here, fails it. linkat with
    AT_EMPTY_PATH on such a descriptor is the kernel's own: an O_TMPFILE file is linked, an
    unlinked file is ENOENT, a memfd, a pipe and a socket are EXDEV, a removed directory EPERM,
    and a name in the tree EROFS. A tree directory named "... (deleted)" is a path all the same:
    creating under a descriptor on it is EROFS.
    """
    prog = os.path.join(ctx.progs, "magic_links")
    rc, out, err = inside(ctx, prog, ["pathless", ctx.work], inp=b"piped\n")
    bad = kernel_answers.magic_links_wrong(out, kernel_answers.magic_links_missing(ctx.work))
    expect(rc == 0 and out and not bad, f"magic links: rc={rc} {bad!r} {err!r}")
    # linkat with AT_EMPTY_PATH on a descriptor whose file has no path: the kernel's own, as given
    rc, out, err = inside(ctx, prog, ["link-empty", ctx.work])
    bad = kernel_answers.magic_links_wrong(out, kernel_answers.link_empty_allowed(ctx.work))
    expect(
        rc == 0 and out.count("\n") == len(kernel_answers.LINK_EMPTY) and not bad,
        f"linkat AT_EMPTY_PATH on pathless descriptors: rc={rc} {bad!r} {err!r}",
    )
    ex2 = os.path.join(ctx.work, "deleted-name.exclave")
    copy_exclave(ctx.exclave, ex2)
    os.makedirs(os.path.join(ex2, "tree", "usr", "share", "x (deleted)"))
    rc, out, err = run(
        [os.path.join(ex2, ".exclave", "launcher"), prog, "deleted-name", "/usr/share/x (deleted)"],
        cwd=ctx.work,
        env=ctx.env,
    )
    expect(
        out == f"create {errno.EROFS}\nmkdir {errno.EROFS}\n",
        f"a directory named ' (deleted)': rc={rc} {out!r} {err!r}",
    )
    expect(
        not os.listdir(os.path.join(ex2, "tree", "usr", "share", "x (deleted)")),
        "the tree was written through a descriptor on ' (deleted)'",
    )


@test
def proc_magic_links(ctx: Ctx) -> None:
    """/dev/stdin on a pipe, process substitution and /proc/self/fd of a file are reachable."""
    _rc, out, err = run(
        [wrapper(ctx, "sh"), "-c", "cat /dev/stdin"], cwd=ctx.work, env=ctx.env, inp=b"hi\n"
    )
    expect(out == "hi\n", f"/dev/stdin on a pipe: {out!r} {err!r}")
    if os.path.exists(wrapper(ctx, "bash")):
        _rc, out, err = run(
            [wrapper(ctx, "bash"), "-c", "cat <(echo psub)"], cwd=ctx.work, env=ctx.env
        )
        expect(out == "psub\n", f"process substitution: {out!r} {err!r}")
    _rc, out, err = run(
        [wrapper(ctx, "sh"), "-c", "exec 3</etc/passwd; head -1 /proc/self/fd/3 | cut -d: -f1"],
        cwd=ctx.work,
        env=ctx.env,
    )
    expect(out == "root\n", f"/proc/self/fd of a file: {out!r} {err!r}")


@test
def new_xattr_syscalls(ctx: Ctx) -> str | None:
    """The *at xattr syscalls of 6.13 are translated.

    Skips where the kernel, asked here natively, has no listxattrat.
    """
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.syscall(465, -100, b"/", 0, None, 0) < 0 and ctypes.get_errno() == errno.ENOSYS:
        skip("the kernel has no listxattrat (6.13 and later)")
    rc, out, err = inside(ctx, os.path.join(ctx.progs, "xattrat"))
    lines = out.splitlines()
    # an exclave that ships the file shows its own
    own = os.path.lexists(os.path.join(ctx.root, "etc", "hostname"))
    # SELinux hosts label every file
    ok = (
        rc == 0
        and len(lines) == 2
        and (lines[0] == "-1 2" if not own else int(lines[0].split()[0]) >= 0)
        and lines[1].endswith(" 0")
        and int(lines[1].split()[0]) >= 0
    )
    expect(ok, f"listxattrat sees the exclave, not the host: {out!r} {err!r}")
    return None


@test
def bind_mount_alias(ctx: Ctx) -> str | None:
    """A second spelling of the tree's root through a bind mount is the tree, read-only."""
    if subprocess.run(
        ["unshare", "-Urm", "true"],
        check=False,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    ).returncode:
        skip("no user namespaces")
    alias = os.path.join(ctx.work, "alias")
    os.makedirs(alias, exist_ok=True)
    cmd = (
        "mount --bind {} {} && {} -c 'touch {}/tree/usr/zz-alias; echo rc=$?; "
        "cat {}/tree/usr/share/exclave-test-marker'"
    ).format(ctx.exclave, alias, wrapper(ctx, "sh"), alias, alias)
    rc, out, err = run(
        ["unshare", "-Urm", "sh", "-c", cmd], cwd=ctx.work, env=dict(ctx.env, PATH="/usr/bin:/bin")
    )
    expect(out == "rc=1\nmarker\n" and "Read-only" in err, f"bind alias: rc={rc} {out!r} {err!r}")
    expect(
        not os.path.exists(os.path.join(ctx.root, "usr", "zz-alias")),
        "the tree was written through a bind mount",
    )
    # relative names from a working directory inside the alias: the walk that starts from the
    # kernel's name of the directory (DESIGN.md 16.6 item 5) must still see the tree there
    cmd = (
        "mount --bind {} {} && cd {}/tree/usr && {} -c 'touch zz-alias; echo rc=$?; "
        "cat share/exclave-test-marker'"
    ).format(ctx.exclave, alias, alias, wrapper(ctx, "sh"))
    rc, out, err = run(
        ["unshare", "-Urm", "sh", "-c", cmd], cwd=ctx.work, env=dict(ctx.env, PATH="/usr/bin:/bin")
    )
    expect(
        out == "rc=1\nmarker\n" and "Read-only" in err,
        f"bind alias, relative: rc={rc} {out!r} {err!r}",
    )
    expect(
        not os.path.exists(os.path.join(ctx.root, "usr", "zz-alias")),
        "the tree was written through a bind mount, relative",
    )
    return None


@test
def readlink_bad_buffer(ctx: Ctx) -> None:
    """7.5.6: an unwritable readlink buffer answers EFAULT, not SIGSEGV."""
    # a link in the tree; a directory would be EINVAL before the copy
    lib = "/lib" if os.path.islink(os.path.join(ctx.root, "lib")) else ctx.vbin("sh")
    rc, out, err = inside(
        ctx,
        os.path.join(ctx.progs, "readlink_fault"),
        [lib, "/proc/self/exe", ctx.vbin("sh"), "/nonexistent"],
    )
    expect(rc == 0 and out == "-1 14\n-1 14\n-1 14\n-1 2\n", f"bad buffer: rc={rc} {out!r} {err!r}")


@test
def protection_keys(ctx: Ctx) -> None:
    """7.5.6: a syscall into a buffer under a protection key answers as the program's own would.

    A key the program opened for itself is written, by a call the handler issues (stat,
    getdents64) and by one it copies out (readlink, getcwd); a key whose writes it denied is
    EFAULT for all four.
    """
    bindir = os.path.dirname(ctx.vbin("sh"))
    links = sorted(
        n
        for n in os.listdir(os.path.join(ctx.root, bindir.lstrip("/")))
        if os.path.islink(os.path.join(ctx.root, bindir.lstrip("/"), n))
    )
    if not links:
        skip(f"no symlink in {bindir}")
    rc, out, err = inside(
        ctx, os.path.join(ctx.progs, "pkeys"), [bindir, bindir, f"{bindir}/{links[0]}"]
    )
    if out == "no protection keys\n":
        skip("the machine or its kernel has no protection keys")
    calls = ("stat", "getdents64", "readlink", "getcwd")
    want = [f"{c} into a keyed buffer: {'0' if c == 'stat' else '1'} 0" for c in calls] + [
        f"{c} into a keyed buffer the program may not write: -1 14" for c in calls
    ]
    expect(rc == 0 and out.splitlines() == want, f"rc={rc} {out!r} {err!r}")


def fs_type(path: str) -> str:
    """The filesystem type of the mount path is on, from /proc/self/mountinfo."""
    path, best, kind = os.path.realpath(path), "", ""
    with open("/proc/self/mountinfo", encoding="utf-8") as f:
        for line in f:
            fields = line.split()
            point, fstype = fields[4], fields[fields.index("-") + 1]
            if (path == point or path.startswith(point.rstrip("/") + "/")) and len(point) > len(
                best
            ):
                best, kind = point, fstype
    return kind


@test
def directory_stats_hide_real(ctx: Ctx) -> None:
    """8.3: a directory of the tree stats as upstream's, without its .real/, by every stat call.

    One link fewer where links count subdirectories, and on ZFS, btrfs and tmpfs, whose directory
    sizes count entries, a size without .real's entry; a host directory's own .real/ stays counted.
    """
    bindir = os.path.dirname(ctx.vbin("sh"))
    hostdir = os.path.join(ctx.work, "host-real")
    os.makedirs(os.path.join(hostdir, ".real"), exist_ok=True)
    calls = (
        "stat",
        "lstat",
        "newfstatat",
        "fstat",
        "newfstatat AT_EMPTY_PATH",
        "statx",
        "statx AT_EMPTY_PATH",
        "fstat O_PATH",
    )
    rc, out, err = inside(ctx, os.path.join(ctx.progs, "dirstat"), [bindir, hostdir])
    # statx is 4.11's: on an older kernel both worlds fail it
    release = tuple(int(x) for x in re.findall(r"\d+", platform.release())[:2])
    old = release < (4, 11)

    def line(d: str, c: str, nlink: int, size: int) -> str:
        failed = old and c.startswith("statx")
        return f"{d} {c}: failed" if failed else f"{d} {c}: nlink={nlink} size={size}"

    want = []
    real = os.path.join(ctx.root, bindir.lstrip("/"))
    st = os.lstat(real)
    entry = {"zfs": 1, "btrfs": 10, "tmpfs": 20}.get(fs_type(real), 0)
    nlink = st.st_nlink - 1 if st.st_nlink >= 3 else st.st_nlink
    size = st.st_size - entry if entry and st.st_size >= entry else st.st_size
    want += [line(bindir, c, nlink, size) for c in calls]
    host = os.lstat(hostdir)
    want += [line(hostdir, c, host.st_nlink, host.st_size) for c in calls]
    expect(rc == 0 and out.splitlines() == want, f"rc={rc} {out!r}, wanted {want!r} {err!r}")


@test
def listings_hide_real(ctx: Ctx) -> None:
    """8.3: a listing of a wrapped directory is upstream's, as the kernel would give it.

    .real is in none, at any buffer size, through getdents64 and getdents: a buffer of the longest
    record, which holds .real alone when the names are short, too; the count is the unsigned int the
    kernel reads; a buffer the kernel can write only part of holds the records that fit, and one it
    can write none of is EFAULT, or the directory's end once .real alone is left; a record's d_off
    resumes the listing after it. The directory is the tree's wrapped one with the fewest bytes of
    records, where .real most often stands alone.
    """

    def record(name: str) -> int:  # getdents64's record: the header, the name and its NUL, in 8s
        return (19 + len(os.fsencode(name)) + 1 + 7) & ~7

    best: tuple[int, str, list[str]] | None = None
    for d, dirs, _files in os.walk(ctx.root):
        if ".real" in dirs:
            names = [*(n for n in os.listdir(d) if n != ".real"), ".", ".."]
            total = sum(record(n) for n in names)
            if best is None or total < best[0]:
                best = (total, d, names)
        dirs[:] = [x for x in dirs if x != ".real"]
    if best is None:
        skip("no wrapped directory in the tree")
    total, d, names = best
    vdir = "/" + os.path.relpath(d, ctx.root)
    rc, out, err = inside(ctx, os.path.join(ctx.progs, "listing"), [vdir])
    lines = out.splitlines()
    want = sorted(names, key=os.fsencode)
    expect(rc == 0 and lines[: len(want)] == want, f"{vdir}: rc={rc} {lines[:40]!r} {err!r}")
    calls = ["getdents64", *(["getdents"] if platform.machine() == "x86_64" else [])]
    cases = [
        f"{c} {at}: the same names, no .real"
        for c in calls
        for at in ("the longest record", "4096", "32768")
    ]
    cases += [
        "count with upper bits: read as 32",
        "into a buffer that meets a read-only page: some records 0",
    ]
    # the second read into an unwritable buffer: the end once every record fit in the first 100
    # bytes, EFAULT while one is left, and either near the edge, where padding decides
    second = "into a read-only buffer, after those:"
    after = "0 0" if total <= 93 else "-1 14" if total > 100 else None
    cases += [f"{second} {after}"] if after else []
    cases.append("into a read-only buffer, first: -1 14")
    if len(names) > 4:
        cases.append("resumed from a d_off: the names after it")
    got = [g for g in lines[len(want) :] if after or not g.startswith(second)]
    expect(got == cases, f"{vdir}: {got!r}, wanted {cases!r}")


@test
def host_symlink_into_usr(ctx: Ctx) -> None:
    lnk = os.path.join(ctx.work, "lnk")
    if os.path.lexists(lnk):
        os.remove(lnk)
    os.symlink("/usr/share", lnk)
    _rc, out, err = run(
        [wrapper(ctx, "cat"), os.path.join(lnk, "exclave-test-marker")], cwd=ctx.work, env=ctx.env
    )
    expect(out == "marker\n", f"host symlink into /usr resolves in the exclave: {out!r} {err!r}")


@test
def openat2_resolve(ctx: Ctx) -> str | None:
    """7.4.3: openat2 in the exclave's world.

    RESOLVE_IN_ROOT and RESOLVE_BENEATH scope the walk to the descriptor's directory,
    RESOLVE_NO_SYMLINKS refuses the tree's own links as a bind mount would, a magic link is ELOOP
    under RESOLVE_NO_MAGICLINKS and EXDEV under the scoped flags, RESOLVE_NO_XDEV refuses the
    exclave-to-host crossing, the read-only rule holds, and the struct's own rules answer EINVAL
    before any lookup. Skips on a kernel without openat2.
    """
    d = os.path.join(ctx.work, "o2host")
    os.makedirs(d, exist_ok=True)
    rc, out, err = inside(ctx, os.path.join(ctx.progs, "openat2"), [d])
    if rc == 3:
        skip("no openat2 on this kernel (5.6 and later)")
    expect(rc == 0 and "FAIL" not in out, out + err)
    return None


@test
def openat2_scoped_from_pathless(ctx: Ctx) -> str | None:
    """7.4.3: a scoped openat2 from a descriptor whose file has no path is the kernel's own.

    With RESOLVE_BENEATH or RESOLVE_IN_ROOT the kernel walks from the descriptor itself: a removed
    directory is its own "." and ".." in root, "" beyond it beneath, EISDIR for a write and ENOENT
    for a name in it, and a memfd, an O_TMPFILE file or a pipe is ENOTDIR. The handler cannot name
    such a scope, which the walk could never leave, and re-issues the call as given; it once
    answered ENOENT. Measured under bwrap. Skips on a kernel without openat2.
    """
    d = os.path.join(ctx.work, "o2pathless")
    os.makedirs(d, exist_ok=True)
    rc, out, err = inside(ctx, os.path.join(ctx.progs, "openat2"), ["pathless", d])
    if rc == 3:
        skip("no openat2 on this kernel (5.6 and later)")
    expect(rc == 0 and not kernel_answers.openat2_pathless_wrong(out), out + err)
    return None


@test
def openat2_xdev(ctx: Ctx) -> str | None:
    """13 item 22, 7.4.3: an openat2 whose walk never touches the exclave is re-issued as given.

    It keeps its resolve flags, so the kernel enforces RESOLVE_NO_XDEV across the host's own mounts,
    and the other flags, on host-only walks. The kernel's answers come from this harness itself,
    natively, for the same cases with the same descriptors (bwrap rebuilds /dev and cannot be the
    oracle for the host's mounts); the walks that touch the exclave assert the crossing rule. Skips
    on a kernel without openat2.
    """
    d = os.path.join(ctx.work, "xdevhost")
    shutil.rmtree(d, ignore_errors=True)
    os.makedirs(d)
    rc, out, err = inside(ctx, os.path.join(ctx.progs, "openat2_xdev"), [d])
    if rc == 3:
        skip("no openat2 on this kernel (5.6 and later)")
    expect(rc == 0, out + err)
    got = dict(line.split(": ", 1) for line in out.splitlines() if ": " in line)

    libc = ctypes.CDLL(None, use_errno=True)
    no_xdev, no_magic, no_symlinks, beneath, in_root = 1, 2, 4, 8, 16
    rd, rd_dir = os.O_RDONLY, os.O_RDONLY | os.O_DIRECTORY
    dev, proc, hd = (os.open(x, os.O_PATH | os.O_DIRECTORY) for x in ("/dev", "/proc", d))
    cases = [
        ("no_xdev cwd to .", -100, ".", rd_dir, no_xdev),
        ("no_xdev cwd to sub", -100, "sub", rd_dir, no_xdev),
        ("no_xdev cwd to ..", -100, "..", rd_dir, no_xdev),
        ("no_xdev /dev fd to null", dev, "null", rd, no_xdev),
        ("no_xdev /dev fd to shm", dev, "shm", rd_dir, no_xdev),
        ("no_xdev /dev fd to ..", dev, "..", rd_dir, no_xdev),
        ("no_xdev /proc fd to self/status", proc, "self/status", rd, no_xdev),
        ("no_xdev host fd to file", hd, "file", rd, no_xdev),
        ("no_symlinks host fd to lnk", hd, "lnk", rd, no_symlinks),
        ("no_symlinks host fd to file", hd, "file", rd, no_symlinks),
        ("no_magiclinks /proc fd to self/status", proc, "self/status", rd, no_magic),
        ("no_magiclinks /proc fd to version", proc, "version", rd, no_magic),
        ("beneath host fd to sub", hd, "sub", rd_dir, beneath),
        ("beneath host fd to ..", hd, "..", rd_dir, beneath),
        ("beneath host fd to sub/..", hd, "sub/..", rd_dir, beneath),
        ("in_root host fd to /etc/passwd", hd, "/etc/passwd", rd, in_root),
        ("in_root host fd to ../../../file", hd, "../../../file", rd, in_root),
        ("in_root /dev fd to /null", dev, "/null", rd, in_root),
        ("beneath|no_xdev /dev fd to shm", dev, "shm", rd_dir, beneath | no_xdev),
    ]
    here = os.getcwd()
    os.chdir(d)  # the AT_FDCWD cases start where the program started them
    try:
        bad = []
        for label, dfd, path, flags, resolve in cases:
            how = (ctypes.c_ulonglong * 3)(flags, 0, resolve)
            r = libc.syscall(437, dfd, path.encode(), how, 24)
            native = "ret=0 errno=0" if r >= 0 else f"ret=-1 errno={ctypes.get_errno()}"
            if r >= 0:
                os.close(r)
            if got.get(label) != native:
                bad.append(f"{label}: the exclave says {got.get(label)}, the kernel says {native}")
    finally:
        os.chdir(here)
        for fd in (dev, proc, hd):
            os.close(fd)
    expect(not bad, "; ".join(bad))
    # a .. that reaches the root is the walk's
    crossing = {
        "no_xdev cwd to /dev/null": "ret=-1 errno=18",
        "no_xdev cwd to /dev/shm": "ret=-1 errno=18",
        "no_xdev cwd to /proc/self/status": "ret=-1 errno=18",
        "no_xdev cwd to /usr/share (exclave)": "ret=0 errno=0",
        "no_xdev host fd to /dev/null (absolute)": "ret=-1 errno=18",
        "root by .. from host fd is the tree's": "yes",
        "no_xdev host fd to the root by ..": "ret=-1 errno=18",
    }
    bad = [f"{k}: {got.get(k)}, wanted {v}" for k, v in crossing.items() if got.get(k) != v]
    expect(not bad, "the exclave-to-host crossing under RESOLVE_NO_XDEV: " + "; ".join(bad))
    return None


@test
def path_length(ctx: Ctx) -> str | None:
    """13 item 13, 7.4.4: an exclave path too long for PATH_MAX is ENAMETOOLONG.

    An exclave path whose real spelling, the root prefix and the virtual path, would not fit
    PATH_MAX is refused with ENAMETOOLONG and never cut to a shorter name, which would answer
    ENOENT for the cut; its parent, and a sibling whose real spelling is a byte shorter and so
    fits with its terminating NUL, are fine. And a relative path from a working directory so deep
    that the two together pass PATH_MAX is ENAMETOOLONG too, where the kernel, walking
    relatively, succeeds: the stated limitation. On a private copy of the exclave, since the chain
    is made in the tree.
    """
    copy = os.path.join(ctx.work, "lengthexclave")
    shutil.rmtree(copy, ignore_errors=True)
    copy_exclave(ctx.exclave, copy)
    rootlen = len(os.path.join(copy, "tree"))
    if rootlen > 200:
        skip("the work directory's path is too long for the window")
    base = "/usr/share/exclave-deep"
    # /usr/share
    fd = os.open(os.path.join(copy, "tree", base.lstrip("/")[:9]), os.O_RDONLY | os.O_DIRECTORY)
    os.mkdir("exclave-deep", dir_fd=fd)
    nfd = os.open("exclave-deep", os.O_RDONLY | os.O_DIRECTORY, dir_fd=fd)
    os.close(fd)
    fd = nfd
    v = base
    for _i in range(19):  # 19 components of 200: 3839 characters
        os.mkdir("a" * 200, dir_fd=fd)
        nfd = os.open("a" * 200, os.O_RDONLY | os.O_DIRECTORY, dir_fd=fd)
        os.close(fd)
        fd = nfd
        v += "/" + "a" * 200
    parent = v
    # a directory whose real spelling is exactly PATH_MAX long, and one a byte shorter, which fits
    last = "b" * (PATH_MAX - rootlen - len(v) - 1)
    os.mkdir(last, dir_fd=fd)
    os.mkdir(last[1:], dir_fd=fd)
    nfd = os.open(last, os.O_RDONLY | os.O_DIRECTORY, dir_fd=fd)
    os.close(fd)
    fd = nfd
    with os.fdopen(os.open("f", os.O_WRONLY | os.O_CREAT, 0o644, dir_fd=fd), "w") as f:
        f.write("deep\n")
    os.close(fd)
    deep, dfile, fits = v + "/" + last, v + "/" + last + "/f", v + "/" + last[1:]
    expect(
        len(dfile) < PATH_MAX
        and rootlen + len(deep) == PATH_MAX
        and rootlen + len(fits) == PATH_MAX - 1,
        f"the window: root {rootlen}, dir {len(deep)}, file {len(dfile)}",
    )
    # the deep working directory on the host: 14 components of 200 below the work directory, then 7
    # more reached relatively
    d = "d" * 200
    hostdeep = os.path.join(ctx.work, "deepcwd")
    os.makedirs(hostdeep)
    fd = os.open(hostdeep, os.O_RDONLY | os.O_DIRECTORY)
    for _i in range(14):
        os.mkdir(d, dir_fd=fd)
        nfd = os.open(d, os.O_RDONLY | os.O_DIRECTORY, dir_fd=fd)
        os.close(fd)
        fd = nfd
        hostdeep = os.path.join(hostdeep, d)
    with os.fdopen(os.open("f", os.O_WRONLY | os.O_CREAT, 0o644, dir_fd=fd), "w") as f:
        f.write("here\n")
    rel = ""
    for _i in range(7):
        os.mkdir(d, dir_fd=fd)
        nfd = os.open(d, os.O_RDONLY | os.O_DIRECTORY, dir_fd=fd)
        os.close(fd)
        fd = nfd
        rel += d + "/"
    with os.fdopen(os.open("f", os.O_WRONLY | os.O_CREAT, 0o644, dir_fd=fd), "w") as f:
        f.write("below\n")
    os.close(fd)
    rel += "f"
    expect(
        len(hostdeep) < PATH_MAX and len(hostdeep) + 1 + len(rel) > PATH_MAX,
        f"the deep working directory: {len(hostdeep)} + {len(rel)}",
    )
    rc, out, err = run(
        [
            os.path.join(copy, ".exclave", "launcher"),
            os.path.join(ctx.progs, "path_length"),
            parent,
            fits,
            deep,
            dfile,
            "cd:" + hostdeep,
            rel,
            "f",
        ],
        cwd=ctx.work,
        env=ctx.env,
    )
    expect(rc == 0, f"path_length: rc={rc} {out!r} {err!r}")
    want = [
        "1: stat=ok open=ok",
        "2: stat=ok open=ok",
        "3: stat=ENAMETOOLONG open=ENAMETOOLONG",
        "4: stat=ENAMETOOLONG open=ENAMETOOLONG",
        "5: stat=ENAMETOOLONG open=ENAMETOOLONG",
        "6: stat=ok open=ok",
    ]
    expect(
        out.splitlines() == want,
        "the parent and a directory a byte under the limit fit, the directory at the limit and its "
        "file are ENAMETOOLONG, a relative "
        "path past PATH_MAX from a deep working directory is ENAMETOOLONG (13), a short one is "
        f"fine: {out!r}",
    )
    shutil.rmtree(copy, ignore_errors=True)
    return None


@test
def unix_socket(ctx: Ctx) -> None:
    """7.4.3, 13 item 31: a sockaddr_un's path is a path.

    bind and connect at a path of every class answer what the kernel answers on a read-only bind
    mount, as the namespace oracle asserts of the kernel: a bind on an exclave path is EADDRINUSE
    for an existing name and EROFS otherwise, from a working directory inside the tree too; a
    connect to an exclave path is ENOENT, ENOTDIR or ECONNREFUSED; host paths and abstract names
    work; the structure's own limits are EINVAL. A datagram destination in sendto stays as
    written (13), so only its host case is asserted.
    """
    # absolute host names a program can write in sun_path's 108 bytes
    d = f"/tmp/exclave-sockhost-{os.getpid()}"
    # relative ones from a working directory deeper than sun_path holds
    deep = os.path.join(ctx.work, "sockhost")
    deep = os.path.join(deep, "d" * max(1, 120 - len(deep)))
    shutil.rmtree(os.path.join(ctx.work, "sockhost"), ignore_errors=True)
    for p in (d, deep):
        shutil.rmtree(p, ignore_errors=True)
        os.makedirs(p)
    try:
        rc, out, err = inside(
            ctx,
            os.path.join(ctx.progs, "unix_socket"),
            [d, "/usr/share", ctx.vbin("true"), "/usr/share/exclave-test.sock", deep],
        )
    finally:
        shutil.rmtree(d, ignore_errors=True)
    expect(rc == 0, f"unix_socket: {out!r} {err!r}")
    bad = kernel_answers.unix_socket_wrong(out)
    expect(not bad, "; ".join(bad))
    expect(
        not os.path.exists(os.path.join(ctx.root, "usr", "share", "sock-rel")),
        "a relative bind from a working directory inside the tree wrote into the tree",
    )


@test
def open_flags_order(ctx: Ctx) -> None:
    """7.4.3: the open flags the kernel judges before the walk, and the directory it wants after it.

    build_open_flags refuses O_DIRECTORY with O_CREAT and O_TMPFILE without O_DIRECTORY or write
    access before getname, so before EFAULT and the read-only rules, and open's O_PATH drops every
    companion but its own; O_DIRECTORY on what is not a directory is ENOTDIR (do_open,
    path_lookupat) before may_open's answers and the write access a read-only mount refuses, the
    loaded program's ETXTBSY and an identity symlink's ELOOP included. Measured under bwrap; the
    launcher once answered these from its walk and its read-only rules.
    """
    d = os.path.join(ctx.work, "open_flags")
    os.makedirs(d, exist_ok=True)
    rc, out, err = inside(ctx, os.path.join(ctx.progs, "open_flags"), [d])
    expect(rc == 0 and not kernel_answers.open_flags_wrong(out), out + err)


@test
def program_perm_order(ctx: Ctx) -> None:
    """7.4.3, 13 item 29: the permission before the loaded program's ETXTBSY.

    The launcher protects the program it loaded from its own write-open or truncate, as the
    kernel protects the programs it executes, and in the kernel's order: may_open's permission
    check, EACCES on a file whose mode forbids writing, with O_TRUNC asking for write access under
    any access mode, comes before the ETXTBSY of do_dentry_open and handle_truncate, and
    vfs_truncate's before its own. The program makes its own file on a host path unwritable and
    puts it back. Measured under bwrap; the launcher once answered ETXTBSY first.
    """
    rc, out, err = inside(ctx, os.path.join(ctx.progs, "program_perm"))
    expect(rc == 0 and not kernel_answers.program_perm_wrong(out), out + err)


@test
def create_through_a_slashed_link(ctx: Ctx) -> None:
    """8.1: a slash ending the text of a final symlink is the path's trailing slash.

    The kernel walks the link's text as the rest of the path, so open with O_CREAT through a link
    whose text ends in a slash is EISDIR before any lookup, whether the target is missing or a
    directory; a plain open through it finds nothing, and O_EXCL does not follow the link.
    Measured natively and under bwrap; the launcher once answered EROFS or ELOOP.
    """
    d = os.path.join(ctx.work, "slashed")
    os.makedirs(d, exist_ok=True)
    rc, out, err = inside(ctx, os.path.join(ctx.progs, "creat_slash"), [d])
    expect(rc == 0 and not kernel_answers.creat_slash_wrong(out), out + err)


@test
def create_through_a_slashed_host_link(ctx: Ctx) -> None:
    """7.4.3: a trailing slash after a final symlink, for a call on the parent.

    A create, a delete, a rename, link's new name and open with O_CREAT walk the parent and look
    the last name up in it (filename_parentat), never following a symlink there, so mkdir of a
    dangling host link with a slash is EEXIST and creates nothing, rmdir and unlink of a link with
    a slash ENOTDIR, a rename onto it ENOTDIR or EEXIST under RENAME_NOREPLACE, and openat2 with
    O_CREAT EISDIR before RESOLVE_NO_SYMLINKS meets the link; a plain open follows the link, as
    lookup_last does. Measured under bwrap; the launcher once followed the link, mkdir made the
    dangling link's target and openat2 said ELOOP.
    """
    d = os.path.join(ctx.work, "slashed_host")
    shutil.rmtree(d, ignore_errors=True)
    os.makedirs(d)
    rc, out, err = inside(
        ctx,
        os.path.join(ctx.progs, "slash_links"),
        [d, ctx.vbin("true"), "/usr/share", tree.dir_link(ctx.root)],
    )
    expect(rc == 0, out + err)
    bad = kernel_answers.slash_links_wrong(out)
    expect(not bad, "; ".join(bad))
