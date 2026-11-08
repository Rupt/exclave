"""Ownership, identity files and the log: a group of the regression suite (DESIGN.md 17 item 4).

Run by test/run.py, on the fixtures test/suite.py makes.
"""

import os
import shutil
import subprocess
import sys

import tree
from harness import expect, read_bytes, read_text, run, skip, test
from suite import TOOL, Ctx, copy_exclave, hello_source, inside, wrapper


@test
def identity(ctx: Ctx) -> None:
    rc, out, err = run([wrapper(ctx, "cat"), "/etc/passwd"], cwd=ctx.work, env=ctx.env)
    expect(rc == 0 and out == read_text("/etc/passwd"), "passwd differs from the host")
    rc, out, err = run([wrapper(ctx, "cat"), "/etc/hostname"], cwd=ctx.work, env=ctx.env)
    if os.path.lexists(os.path.join(ctx.root, "etc", "hostname")):
        expect(
            rc == 0 and out == read_text(os.path.join(ctx.root, "etc", "hostname")),
            f"an exclave shipping /etc/hostname shows its own: {out!r} {err!r}",
        )
    else:
        expect(rc != 0 and "No such file" in err, f"host /etc/hostname must be invisible: {err!r}")
    # 6.2, 8.4: the time zone is the host's, read from /etc/localtime, and a TZ set outside is
    # dropped at the border; the host's own answer is the pinned Python's with TZ unset
    host = subprocess.run(
        [sys.executable, "-c", "import time; print(time.strftime('%Z %z'))"],
        env={k: v for k, v in os.environ.items() if k != "TZ"},
        capture_output=True,
        text=True,
        check=False,
    )
    rc, out, err = run(
        [wrapper(ctx, "sh"), "-c", 'date "+%Z %z"; echo "TZ=${TZ-unset}"'],
        cwd=ctx.work,
        env=dict(ctx.env, TZ="Asia/Tokyo"),
    )
    expect(
        rc == 0 and out == host.stdout.strip() + "\nTZ=unset\n",
        f"the zone inside is the host's and TZ is dropped: {out!r} {err!r}, host {host.stdout!r}",
    )
    if os.path.exists("/etc/localtime"):
        # the host's own bytes, whatever they are, rather than a TZif header: a host may keep an
        # odd file there, as GitHub's runners keep a world-writable one
        rc, out, err = run(
            [wrapper(ctx, "head"), "-c", "4", "/etc/localtime"], cwd=ctx.work, env=ctx.env
        )
        expect(
            rc == 0 and out.encode() == read_bytes("/etc/localtime", 4),
            f"the host's /etc/localtime is read inside: {out!r} {err!r}",
        )


@test
def exclave_directory_visible(ctx: Ctx) -> None:
    """8.1: the exclave's real location resolves as a host path from any working directory.

    It does so even under a prefix the exclave owns (/home here), so a program can reach its files
    relative to its executable's real path.
    """
    real = os.path.join(ctx.root, ctx.vbin("true").lstrip("/"))
    rc, out, err = run([wrapper(ctx, "ls"), real], cwd="/", env=ctx.env)
    expect(
        rc == 0 and out.strip() == real, f"real exclave path from cwd /: rc={rc} {out!r} {err!r}"
    )
    rc, out, err = run(
        [
            wrapper(ctx, "sh"),
            "-c",
            "cd {} && pwd && ls tree{}".format(ctx.exclave, ctx.vbin("true")),
        ],
        cwd="/",
        env=ctx.env,
    )
    expect(
        rc == 0 and out == "{}\ntree{}\n".format(ctx.exclave, ctx.vbin("true")),
        f"cd into the exclave dir: rc={rc} {out!r} {err!r}",
    )
    rc, out, err = run(
        [wrapper(ctx, "cat"), os.path.join(ctx.root, "usr", "share", "exclave-test-marker")],
        cwd="/",
        env=ctx.env,
    )
    expect(out == "marker\n", f"a file inside tree/ by its real path: {out!r} {err!r}")


@test
def identity_link_consistency(ctx: Ctx) -> str | None:
    """lstat, readlink and the link's target agree for each identity file that is a host symlink."""
    links = [f for f in tree.IDENTITY_FILES if os.path.islink(f)]
    if not links:
        skip("no host identity file is a symlink")
    for link in links:
        target = os.readlink(link)
        # the content is reached through the identity name; its host target is not an exclave path
        # (8.4): /etc/localtime's lies under the host's /usr, which inside is the exclave's
        head = read_bytes(link, 8)
        _rc, out, err = run(
            [
                wrapper(ctx, "sh"),
                "-c",
                f"test -L {link} && echo link; readlink {link}; head -c 8 {link}",
            ],
            cwd=ctx.work,
            env=ctx.env,
        )
        expect(
            out.encode() == b"link\n" + target.encode() + b"\n" + head,
            f"identity link {link}: {out!r} {err!r}",
        )
    return None


@test
def identity_retargeted(ctx: Ctx) -> None:
    """8.4, 13 item 18: an identity file follows the host's link as the host has it at each call.

    A VPN client or a change of resolver retargets /etc/resolv.conf, or replaces the link with a
    file, under programs already running. Made in a user namespace with a directory of the test's
    bound on /etc, the steps taken in turn through fifos: one shell inside the exclave reads
    /etc/resolv.conf, the host retargets the link, the shell reads it again, the host renames a file
    over the link, and the shell reads it and tests for a link a third time. Skipped without user
    namespaces.
    """
    if subprocess.run(
        ["unshare", "-Urm", "true"],
        check=False,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    ).returncode:
        skip("no user namespaces")
    pid = os.getpid()
    base = os.path.join(ctx.work, f"retarget-{pid}")
    shutil.rmtree(base, ignore_errors=True)
    etc = os.path.join(base, "etc")
    os.makedirs(etc)
    if os.path.exists("/etc/ld.so.cache"):  # the host's tools run under the bound /etc
        shutil.copy("/etc/ld.so.cache", etc)
    for name, n in (("a", 1), ("b", 2)):
        with open(os.path.join(base, name), "w") as f:
            f.write(f"nameserver 192.0.2.{n}\n")
    os.symlink(os.path.join(base, "a"), os.path.join(etc, "resolv.conf"))
    for fifo in ("ready1", "ready2", "go1", "go2"):
        os.mkfifo(os.path.join(base, fifo))
    inner = (
        'read l </etc/resolv.conf; echo "1 $l"; [ -L /etc/resolv.conf ] && echo "1 link"; '
        "echo >ready1; "
        'read x <go1; read l </etc/resolv.conf; echo "2 $l"; echo >ready2; '
        'read x <go2; read l </etc/resolv.conf; echo "3 $l"; '
        '[ -L /etc/resolv.conf ] || echo "3 file"'
    )
    script = (
        f"mount --bind {etc} /etc || exit 99; "
        f"{wrapper(ctx, 'sh')} -c '{inner}' & read x <ready1; "
        f"ln -sfn {base}/b /etc/resolv.conf.new && mv -T /etc/resolv.conf.new /etc/resolv.conf "
        "&& echo >go1; read x <ready2; "
        "echo 'nameserver 192.0.2.3' >/etc/resolv.conf.new && mv -T /etc/resolv.conf.new "
        "/etc/resolv.conf && echo >go2; wait"
    )
    rc, out, err = run(
        ["unshare", "-Urm", "sh", "-c", script], cwd=base, env=dict(ctx.env, PATH="/usr/bin:/bin")
    )
    if rc == 99:
        skip(f"no bind mount on /etc in a user namespace here: {err.strip()[-120:]}")
    want = [
        "1 nameserver 192.0.2.1",
        "1 link",
        "2 nameserver 192.0.2.2",
        "3 nameserver 192.0.2.3",
        "3 file",
    ]
    expect(out.splitlines() == want, f"/etc/resolv.conf retargeted under a shell: {out!r} {err!r}")


def native_identity_run(ctx: Ctx, hostdir: str, paths: list[str]) -> list[str]:
    """identity_nofollow's answers from the kernel itself: the program run natively.

    Through the tree's own loader and libc, as the probe's native run goes, since the host's libc
    is not the tree's. Returns the lines.
    """
    loader = ctx.payload(ctx.interp)
    libdir = os.path.dirname(ctx.payload(ctx.libc)) if ctx.libc else os.path.dirname(loader)
    prog = os.path.join(ctx.progs, "identity_nofollow")
    rc, out, err = run([loader, "--library-path", libdir, prog, hostdir, *paths], cwd=ctx.work)
    expect(rc == 0, f"identity_nofollow natively: rc={rc} {err!r}")
    return out.splitlines()


@test
def identity_link_nofollow(ctx: Ctx) -> str | None:
    """8.4: a call that does not follow the last component reaches an identity file's host link.

    An identity file that is a host symlink is the host's own link, so a no-follow call on it is the
    host's own call on that link, and the kernel answers for the link: EPERM for a user attribute,
    EOPNOTSUPP for its mode, a watch on the link, a hard link to the link, and a delete of the link
    that leaves its target. test/progs/identity_nofollow.c issues every such call, and the follow
    calls beside them, and the native run of the same program, on the same files, is the
    expectation line for line: on a link the test makes, given to a `host` record of a copy, which
    the launcher resolves at startup like an identity file (8.1 rule 5), and on the host's own
    identity files, which this user cannot write.
    """
    pid = os.getpid()
    ex2 = os.path.join(ctx.work, "idlink.exclave")
    copy_exclave(ctx.exclave, ex2)
    link, target = (
        os.path.join(ctx.work, f"idlink-{pid}"),
        os.path.join(ctx.work, f"idtarget-{pid}"),
    )
    with open(os.path.join(ex2, ".exclave", "manifest"), "w") as f:
        f.write(f'exclave 1\n\nhost "{link}"\n')
    hostdir = os.path.join(ctx.work, f"idhost-{pid}")

    def fresh() -> None:
        for p in (link, target):
            if os.path.lexists(p):
                os.remove(p)
        with open(target, "w") as f:
            f.write("target\n")
        os.symlink(target, link)
        if os.path.isdir(hostdir):
            for n in os.listdir(hostdir):
                os.remove(os.path.join(hostdir, n))
        else:
            os.makedirs(hostdir)

    def after(world: str) -> None:
        expect(not os.path.lexists(link), f"{world}: the delete of the link left it")
        expect(read_text(target) == "target\n", f"{world}: the delete of the link took its target")

    fresh()
    native = native_identity_run(ctx, hostdir, [link])
    after("natively")
    # the kernel's rules for a link, which the native run shows or the oracle is wrong
    for want in (
        f"{link} lstat: ret=0 errno=0 lnk",
        f"{link} lsetxattr: ret=-1 errno=1",
        f"{link} utimensat_nofollow: ret=0 errno=0 link_mtime=set",
        f"{link} inotify_dont_follow: ret=0 errno=0 distinct_from_follow",
        f"{link} linkat: ret=0 errno=0 new=lnk",
        f"{link} renameat: ret=0 errno=0 new=lnk old=absent",
        f"{link} unlink: ret=0 errno=0 after=absent",
    ):
        expect(want in native, f"the native run on the test's own link: {want!r} not in {native}")
    fresh()
    prog = os.path.join(ctx.progs, "identity_nofollow")
    rc, out, err = run(
        [os.path.join(ex2, ".exclave", "launcher"), prog, hostdir, link], cwd=ctx.work, env=ctx.env
    )
    expect(rc == 0, f"identity_nofollow on a host record's link: rc={rc} {err!r}")
    after("the launcher")
    got = out.splitlines()
    bad = [f"{o!r}, the kernel says {n!r}" for n, o in zip(native, got, strict=True) if n != o]
    expect(not bad, "a host record's link: " + "; ".join(bad))
    # the host's identity files: the ones the host has and this user cannot change, since the
    # native run changes what it may
    files = [f for f in tree.IDENTITY_FILES if os.path.lexists(f) and not os.access(f, os.W_OK)]
    if os.geteuid() == 0 or not files:
        return "the host's identity files not compared: this user could change them"
    fresh()
    native = native_identity_run(ctx, hostdir, files)
    fresh()
    rc, out, err = inside(ctx, prog, [hostdir, *files])
    expect(rc == 0, f"identity_nofollow on the host's identity files: rc={rc} {err!r}")
    got = out.splitlines()
    bad = [f"{o!r}, the kernel says {n!r}" for n, o in zip(native, got, strict=True) if n != o]
    expect(not bad, "the host's identity files: " + "; ".join(bad))
    return None if any(os.path.islink(f) for f in files) else "no host identity file is a symlink"


@test
def ownership_fails_closed(ctx: Ctx) -> None:
    """8.1: a top-level directory the launcher cannot list is the exclave's, not a placeholder.

    A spawn with no descriptor to spare fails loudly instead of running on the host.
    """
    ex2 = os.path.join(ctx.work, "perm.exclave")
    copy_exclave(ctx.exclave, ex2)
    secret = os.path.join(ex2, "tree", "secret")
    os.makedirs(secret)
    with open(os.path.join(secret, "file"), "w") as f:
        f.write("data\n")
    cat = os.path.join(ex2, "tree", ctx.vbin("cat").lstrip("/"))
    os.chmod(secret, 0)
    try:
        rc, out, err = run([cat, "/secret/file"], cwd=ctx.work, env=ctx.env)
        expect(
            "Permission denied" in err and "No such file" not in err,
            f"an unlistable directory must be the exclave's: {err!r}",
        )
    finally:
        os.chmod(secret, 0o755)
    # built by the exclave's gcc: runs inside, like every built program
    press = os.path.join(ctx.progs, "fdpress")
    # the exclave's libc as the maps show it
    libc_real = ".real/" + (os.path.basename(ctx.libc) if ctx.libc else ctx.ldso_name)
    rc, out, err = inside(ctx, press, ["1", cat, "/proc/self/maps"])
    # musl's posix_spawn wants a pipe first
    loud = (rc == 127 and "Too many open files" in err) or (
        ctx.musl and "No file descriptors" in err
    )
    expect(
        loud and libc_real not in out,
        "with one spare descriptor the launcher must fail loudly, never run the host's libc: "
        f"rc={rc} {out[:200]!r} {err!r}",
    )
    rc, out, err = inside(ctx, press, ["4", cat, "/proc/self/maps"])
    expect(
        rc == 0 and libc_real in out,
        f"with four spare descriptors the exclave runs: rc={rc} {err!r}",
    )


@test
def root_listing_is_the_tree(ctx: Ctx) -> None:
    """8.3: the root directory itself is the tree's.

    ls / lists the tree's entries, and cd into a placeholder works whether or not the host has the
    name; a new top-level name is the host's (8.1.2), so creating one is the host's refusal,
    Permission denied, not the exclave's read-only one.
    """
    rc, out, err = run([wrapper(ctx, "ls"), "-A", "/"], cwd=ctx.work, env=ctx.env)
    expect(
        rc == 0 and sorted(out.split()) == sorted(os.listdir(ctx.root)),
        f"ls / must list the tree: {out!r}",
    )
    rc, out, err = run(
        [
            wrapper(ctx, "sh"),
            "-c",
            "cd /srv && pwd && cd / && pwd && touch /x 2>&1 || echo refused",
        ],
        cwd=ctx.work,
        env=ctx.env,
    )
    expect(
        out.startswith("/srv\n/\n") and "refused" in out,
        f"cd into a placeholder and a create at the root: {out!r} {err!r}",
    )
    expect(
        "Permission denied" in out,
        f"a new top-level name is the host's, refused as the host refuses it: {out!r}",
    )


@test
def log_path_rules(ctx: Ctx) -> None:
    """6.2: EXCLAVE_LOG names a host file by its absolute path, never one inside the exclave.

    A relative value is refused by name, since each launcher would read it against the program's
    working directory, often inside the tree. A log in the exclave, made new, already there, under
    .exclave/ or reached through a symlink, is never written. An absolute log outside takes every
    launcher's lines, and /dev/stderr works as a log.
    """
    ex2 = os.path.join(ctx.work, "logpath.exclave")
    copy_exclave(ctx.exclave, ex2)
    sh = os.path.join(ex2, "tree", ctx.vbin("sh").lstrip("/"))
    share = os.path.join(ex2, "tree", "usr", "share")
    script = f"cd /usr/share && {ctx.vbin('true')}"

    def with_log(value: str) -> tuple[int, str, str]:
        return run([sh, "-c", script], cwd=ctx.work, env=dict(ctx.env, EXCLAVE_LOG=value))

    rc, _, err = with_log("rel.log")
    expect(
        rc == 127 and "EXCLAVE_LOG must be an absolute path" in err,
        f"a relative log: rc={rc} {err!r}",
    )
    expect(
        not os.path.exists(os.path.join(ctx.work, "rel.log"))
        and not os.path.exists(os.path.join(share, "rel.log")),
        "a refused relative log was made",
    )
    marker = os.path.join(share, "exclave-test-marker")
    before = read_text(marker)
    for value in (os.path.join(share, "new.log"), marker, os.path.join(ex2, ".exclave", "x.log")):
        rc, _, err = with_log(value)
        expect(
            rc == 127 and "EXCLAVE_LOG is inside the exclave" in err,
            f"a log in the exclave, {value}: rc={rc} {err!r}",
        )
    expect(
        not os.path.exists(os.path.join(share, "new.log"))
        and not os.path.exists(os.path.join(ex2, ".exclave", "x.log"))
        and read_text(marker) == before,
        "a log in the exclave was written",
    )
    # not named .log: the fixture is pruned from every .log in the work directory
    link = os.path.join(ctx.work, "logpath-link")
    if os.path.lexists(link):
        os.remove(link)
    os.symlink(os.path.join(share, "via.log"), link)
    with_log(link)
    os.remove(link)
    expect(
        not os.path.exists(os.path.join(share, "via.log")), "a symlink led the log into the tree"
    )
    log = os.path.join(ctx.work, "logpath.log")
    if os.path.exists(log):
        os.remove(log)
    rc, _, err = with_log(log)
    text = read_text(log) if os.path.exists(log) else ""
    expect(
        rc == 0 and "launcher 2 border" in text and "launcher 2 inside" in text,
        f"one log for every launcher: rc={rc} {err!r} {text[-300:]!r}",
    )
    rc, _, err = with_log("/dev/stderr")
    expect(
        rc == 0 and "launcher 2 border" in err, f"/dev/stderr as the log: rc={rc} {err[-300:]!r}"
    )


@test
def log_names_and_escapes(ctx: Ctx) -> None:
    """6.2, 13 item 34: a failed resolution logs the path as given.

    A path with a newline, a backslash or another control byte is escaped in the log, so no name
    can end a line or move a terminal's cursor, and the tool undoes the escapes, so prune keeps the
    file the workload opened; prune refuses a log that names no program.
    """
    log = os.path.join(ctx.work, "names.log")
    if os.path.exists(log):
        os.remove(log)
    rc, out, err = run(
        [wrapper(ctx, "cat"), "/usr/share/no/such/file"],
        cwd=ctx.work,
        env=dict(ctx.env, EXCLAVE_LOG=log),
    )
    text = read_text(log)
    expect(
        "open -2 /usr/share/no/such/file" in text,
        "a failed intermediate component must be logged by name: " + text[-300:],
    )
    ex2 = os.path.join(ctx.work, "odd.exclave")
    copy_exclave(ctx.exclave, ex2)
    odd = os.path.join(ex2, "tree", "usr", "share", "odd")
    os.makedirs(odd)
    # the third a backslash before an n, not a newline; the last a terminal's colour and a return
    names = ("with\nnewline", "back\\slash", "back\\nslash", "esc\x1b[31m\rred\x7f")
    for name in names:
        with open(os.path.join(odd, name), "w") as f:
            f.write(name)
    log2 = os.path.join(ctx.work, "odd.log")
    for name in names:
        rc, out, err = run(
            [os.path.join(ex2, "tree", ctx.vbin("cat").lstrip("/")), "/usr/share/odd/" + name],
            cwd=ctx.work,
            env=dict(ctx.env, EXCLAVE_LOG=log2),
        )
        expect(out == name, f"cat of the odd name: {out!r} {err!r}")
    lines = read_text(log2).split("\n")
    expect(
        any(line == "open 3 /usr/share/odd/with\\nnewline" for line in lines)
        and any(line == "open 3 /usr/share/odd/back\\\\slash" for line in lines)
        and any(line == "open 3 /usr/share/odd/esc\\x1b[31m\\x0dred\\x7f" for line in lines),
        f"escapes in the log: {[line for line in lines if 'odd' in line]!r}",
    )
    src = hello_source(ctx)
    rc, out, err = run(
        [
            os.path.join(ex2, "tree", ctx.vbin(ctx.gcc).lstrip("/")),
            "-O1",
            src,
            "-o",
            os.path.join(ctx.work, "hello-odd"),
        ],
        cwd=ctx.work,
        env=dict(ctx.env, EXCLAVE_LOG=log2),
    )
    expect(rc == 0, err)
    rc, o, e = run([*TOOL, "prune", ex2, log2])
    expect(rc == 0, "prune: " + o + e)
    expect(
        sorted(os.listdir(odd)) == sorted(names),
        f"the odd names must survive pruning: {os.listdir(odd)!r}",
    )
    empty = os.path.join(ctx.work, "empty.log")
    open(empty, "w").close()
    before = sum(1 for _ in tree.walk_files(os.path.join(ex2, "tree")))
    rc, o, e = run([*TOOL, "prune", ex2, empty])
    expect(
        rc != 0
        and "name no program" in o + e
        and sum(1 for _ in tree.walk_files(os.path.join(ex2, "tree"))) == before,
        f"an empty log must be refused: {o[-200:]} {e[-200:]}",
    )


@test
def ownership_from_tree(ctx: Ctx) -> None:
    """8.1: the ownership set is read from the tree at startup.

    A file added under a placeholder therefore makes the directory the exclave's with nothing to
    refresh; an empty placeholder stays the host's.
    """
    ex2 = os.path.join(ctx.work, "own.exclave")
    copy_exclave(ctx.exclave, ex2)
    sh = os.path.join(ex2, "tree", ctx.vbin("sh").lstrip("/"))
    _rc, out, err = run(
        [sh, "-c", "cat /opt/exclave-probe 2>&1; ls /srv"], cwd=ctx.work, env=ctx.env
    )
    expect(
        "No such file" in out,
        f"before: /opt is the host's, the probe does not exist there: {out!r}",
    )
    os.makedirs(os.path.join(ex2, "tree", "opt"), exist_ok=True)
    with open(os.path.join(ex2, "tree", "opt", "exclave-probe"), "w") as f:
        f.write("probe\n")
    _rc, out, err = run(
        [sh, "-c", "cat /opt/exclave-probe; touch /opt/x 2>&1 || echo refused"],
        cwd=ctx.work,
        env=ctx.env,
    )
    expect(
        out.startswith("probe\n") and "Read-only file system" in out and "refused" in out,
        f"after: /opt is the exclave's, read-only, with no index refreshed: {out!r} {err!r}",
    )
    _rc, out, err = run(
        [
            sh,
            "-c",
            (
                f"ls -d /srv && touch /srv/exclave-probe-{os.getpid()} "
                f"&& rm /srv/exclave-probe-{os.getpid()} && echo host"
            ),
        ],
        cwd=ctx.work,
        env=ctx.env,
    )
    expect(
        out.strip().endswith("host") or "Permission denied" in err,
        f"an empty placeholder stays the host's: {out!r} {err!r}",
    )


@test
def host_and_own_records(ctx: Ctx) -> str | None:
    """8.1: host and own records at run time, in the decision order.

    On a copy whose manifest holds both kinds, run from / so that the working directory gives the
    host nothing: a host record on a directory gives the host its subtree, read and refused as the
    host's own directory is; a host record wins over the tree's top-level directory of the same
    length; a volatile directory stays the host's whatever an own record says; own on an identity
    file gives the name back to the tree; a host record whose path the host lacks is dropped and
    the exclave answers, read-only; and a host record on a file stands for that file. Each answer
    is taken from the host or from the tree.
    """
    pid = os.getpid()
    ex2 = os.path.join(ctx.work, "records.exclave")
    copy_exclave(ctx.exclave, ex2)
    absent = f"/usr/share/zz-absent-{pid}"
    expect(not os.path.lexists(absent), f"{absent} exists on the host")
    records = [
        'host "/etc/hostname"',
        'host "/usr/share/doc"',
        f'host "{absent}"',
        'host "/var"',
        "",
        'own "/etc/hosts"',
        'own "/home"',
        'own "/tmp"',
    ]
    with open(os.path.join(ex2, ".exclave", "manifest"), "w") as f:
        f.write("exclave 1\n\n" + "".join(r + "\n" for r in records))
    # the tree's own /etc/hosts, unlike the host's; a new file, since the copy's are hard links
    hosts = os.path.join(ex2, "tree", "etc", "hosts")
    if os.path.lexists(hosts):
        os.remove(hosts)
    with open(hosts, "w") as f:
        f.write(f"the exclave's hosts {pid}\n")
    sh = os.path.join(ex2, "tree", ctx.vbin("sh").lstrip("/"))

    def at_root(cmd: str) -> tuple[int, str, str]:
        return run([sh, "-c", cmd], cwd="/", env=ctx.env)

    rc, out, err = at_root("ls -A /var")
    expect(
        rc == 0 and sorted(out.split("\n")[:-1]) == sorted(os.listdir("/var")),
        f'host "/var" wins over the tree\'s /var at equal length: {out[:200]!r} {err!r}',
    )
    if os.path.isdir("/usr/share/doc"):
        rc, out, err = at_root("ls -A /usr/share/doc")
        expect(
            rc == 0 and sorted(out.split("\n")[:-1]) == sorted(os.listdir("/usr/share/doc")),
            f'host "/usr/share/doc", the longer prefix, is the host\'s: {out[:200]!r} {err!r}',
        )
        if not os.access("/usr/share/doc", os.W_OK):
            rc, out, err = at_root(f"touch /usr/share/doc/x-{pid}")
            expect(
                rc and "Permission denied" in err,
                f"a create in the host's /usr/share/doc is the host's refusal: {err!r}",
            )
    tmp = f"/tmp/exclave-records-{pid}"
    try:
        rc, out, err = at_root(f"touch {tmp}")
        expect(
            rc == 0 and os.path.exists(tmp),
            f"/tmp stays the host's whatever own says (8.1.3): {err!r}",
        )
    finally:
        if os.path.exists(tmp):
            os.remove(tmp)
    rc, out, err = at_root("cat /etc/hosts")
    expect(
        out == f"the exclave's hosts {pid}\n",
        f"own on an identity file gives it back to the tree: {out[:200]!r} {err!r}",
    )
    rc, out, err = at_root(f"mkdir {absent}")
    expect(
        rc and "Read-only file system" in err and not os.path.lexists(absent),
        f"a host record the host lacks is dropped and the exclave answers: {err!r}",
    )
    if not os.path.isfile("/etc/hostname"):
        return 'host "/etc/hostname" not run: the host has no /etc/hostname'
    rc, out, err = at_root("cat /etc/hostname")
    expect(
        rc == 0 and out == read_text("/etc/hostname"),
        f'host "/etc/hostname" stands for the host\'s file: {out!r} {err!r}',
    )
    return None


@test
def directory_service_state(ctx: Ctx) -> None:
    """8.1.5, 13 item 17: SSSD's /var/lib/sss is the host's by default, and own gives it back.

    SSSD's lookup module finds the daemon by its socket and memory cache under /var/lib/sss, which
    the tree's /var would otherwise hide, so a user the host knows from LDAP was unknown inside.
    Made in a user namespace with a tmpfs on /var/lib holding a marker where the socket would be:
    the directory is seen inside; an own record makes it the tree's again; a host link there to a
    directory, by a relative or an absolute text, is followed to the host's directory; and a tree
    with a /var but no /var/lib reaches it all the same, its way made of directories as an identity
    file's is. Skipped without user namespaces.
    """
    if subprocess.run(
        ["unshare", "-Urm", "true"],
        check=False,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    ).returncode:
        skip("no user namespaces")
    pid = os.getpid()
    owned = os.path.join(ctx.work, "sss-own.exclave")
    copy_exclave(ctx.exclave, owned)
    with open(os.path.join(owned, ".exclave", "manifest"), "w") as f:
        f.write('exclave 1\n\nown "/var/lib/sss"\n')
    bare = os.path.join(ctx.work, "sss-novarlib.exclave")
    copy_exclave(ctx.exclave, bare)
    shutil.rmtree(os.path.join(bare, "tree", "var", "lib"), ignore_errors=True)
    expect(
        os.path.isdir(os.path.join(bare, "tree", "var")), "the copy without /var/lib keeps its /var"
    )

    def sh_of(ex: str) -> str:
        return os.path.join(ex, "tree", ctx.vbin("sh").lstrip("/"))

    show = "cat /var/lib/sss/pipes/marker"
    cases = [
        ("a directory", "mkdir -p /var/lib/sss/pipes", wrapper(ctx, "sh"), f"sss-{pid}"),
        ("a directory, own on it", ":", sh_of(owned), "rc=1"),
        ("a directory, the tree without /var/lib", ":", sh_of(bare), f"sss-{pid}"),
        (
            "a relative link",
            "rm -r /var/lib/sss && ln -s real /var/lib/sss",
            wrapper(ctx, "sh"),
            f"sss-{pid}",
        ),
        (
            "an absolute link",
            "rm /var/lib/sss && ln -s /var/lib/real /var/lib/sss",
            wrapper(ctx, "sh"),
            f"sss-{pid}",
        ),
    ]
    script = (
        "mount -t tmpfs tmpfs /var/lib && mkdir -p /var/lib/real/pipes && "
        f"echo sss-{pid} >/var/lib/real/pipes/marker || exit 99; "
    )
    for i, (_what, prepare, sh, _want) in enumerate(cases):
        mark = f" && echo sss-{pid} >/var/lib/sss/pipes/marker" if i == 0 else ""
        script += f"{prepare}{mark}; echo '== {i}'; {sh} -c '{show}' 2>&1 || echo rc=$?; "
    rc, out, err = run(
        ["unshare", "-Urm", "sh", "-c", script],
        cwd=ctx.work,
        env=dict(ctx.env, PATH="/usr/bin:/bin"),
    )
    if rc == 99:
        skip(f"no tmpfs on /var/lib in a user namespace here: {err.strip()[-120:]}")
    got = {}
    for block in out.split("== ")[1:]:
        n, _, rest = block.partition("\n")
        got[int(n)] = rest.strip().split("\n")
    for i, (what, _prepare, _sh, want) in enumerate(cases):
        expect(
            want in got.get(i, []), f"/var/lib/sss on the host as {what}: {got.get(i)!r} {err!r}"
        )


@test
def trust_directory_host(ctx: Ctx) -> None:
    """8.4, 13 item 55: the host's trust directory inside, its links followed on the host.

    test/progs/trustdir.c lists /etc/ssl/certs, follows a subject-hash link and the .pem link it
    names to the host's certificate, opens it through Debian's /usr/lib/ssl/certs, climbs out by ..,
    tries openat2's resolve flags from the directory and from the root, works from inside it and
    writes there. Natively the kernel answers each case on the host; inside, every answer is the
    same but where a read-only bind of the directory at its name answers otherwise, as the kernel
    would under bwrap: a .. at the directory climbs into the exclave, so ../openssl.cnf is the
    tree's /etc/ssl/openssl.cnf, and RESOLVE_NO_XDEV refuses the crossing into it. Skipped where the
    host has no hash link there.
    """
    found = tree.host_trust_link()
    if not found:
        skip("the host's /etc/ssl/certs has no subject-hash link to a .pem link")
    hash_, pem = found
    loader = ctx.payload(ctx.interp)
    libdir = os.path.dirname(ctx.payload(ctx.libc)) if ctx.libc else os.path.dirname(loader)
    prog = os.path.join(ctx.progs, "trustdir")
    rc, out, err = run([loader, "--library-path", libdir, prog, hash_, pem], cwd=ctx.work)
    expect(rc == 0, f"trustdir natively: rc={rc} {err!r}")
    native = dict(line.split(": ", 1) for line in out.splitlines())
    rc, out, err = inside(ctx, prog, [hash_, pem])
    expect(rc == 0, f"trustdir inside: rc={rc} {err!r}")
    got = dict(line.split(": ", 1) for line in out.splitlines())
    expect(list(native) == list(got), f"the cases differ: {list(native)} {list(got)}")
    # the bind's answers: the climb lands where /etc/ssl/openssl.cnf is inside, and the crossing
    # into the directory is a mount's
    cnf = got.get("stat cnf", "")
    bind = {
        "openat2 noxdev hash": "EXDEV",
        "openat2 noxdev dir": "EXDEV",
        "relative dotdot cnf": "ok" if cnf.startswith("file") else cnf,
    }
    for k in ("stat", "lstat", "readlink", "open"):
        bind[f"{k} dotdot_cnf"] = got.get(f"{k} cnf", "")
        bind[f"{k} cnf"] = got.get(f"{k} cnf", "")  # the tree's by rule, and the reference
    bad = [
        f"{case}: {got.get(case)!r}, the kernel says {bind.get(case, n)!r}"
        for case, n in native.items()
        if got.get(case) != bind.get(case, n)
    ]
    expect(not bad, "the trust directory: " + "; ".join(bad))
    expect(got.get("open hash", "").startswith("-----BEGIN"), f"the hash link's certificate: {got}")


@test
def trust_directory_rules(ctx: Ctx) -> None:
    """8.1 rule 5, 8.4: the identity directory's rules, on a trust directory made in a namespace.

    In a user namespace with tmpfs on /etc/ssl/certs and /usr/local/share/ca-certificates, as
    directory_service_state makes SSSD's: a hash link to a .pem link to an authority under
    /usr/local, which the tree lacks, reads the host's; a link to a directory there is passed by
    name; realpath resolves the link's text in the exclave, the limitation of 13 item 55; a create
    there is the host's own; the bundle the host lacks is the exclave's copy, not listed; Java's
    keystore the host lacks is the tree's; own on the directory gives it back, and own on a name in
    it gives that name back; and where the host's directory is a link, the names below it, the
    exclave's copy among them, answer the same, readlink answers the host's text and the directory
    it reaches is the host's at its own name. Skipped without user namespaces.
    """
    if subprocess.run(
        ["unshare", "-Urm", "true"],
        check=False,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    ).returncode:
        skip("no user namespaces")
    pid = os.getpid()
    marks = os.path.join(ctx.work, f"trust-{pid}.exclave")
    copy_exclave(ctx.exclave, marks)
    root = os.path.join(marks, "tree")
    certs = os.path.join(root, tree.resolve(root, "/etc/ssl/certs").lstrip("/"))
    os.makedirs(os.path.join(certs, "java"), exist_ok=True)
    for name, text in (("java/cacerts", f"tree-java-{pid}"), ("mine.pem", f"tree-mine-{pid}")):
        q = os.path.join(certs, name)
        if os.path.lexists(q):
            os.remove(q)
        with open(q, "w") as f:
            f.write(text + "\n")
    owned = os.path.join(ctx.work, f"trust-own-{pid}.exclave")
    copy_exclave(marks, owned)
    with open(os.path.join(owned, ".exclave", "manifest"), "w") as f:
        f.write('exclave 1\n\nown "/etc/ssl/certs"\n')
    mine = os.path.join(ctx.work, f"trust-mine-{pid}.exclave")
    copy_exclave(marks, mine)
    with open(os.path.join(mine, ".exclave", "manifest"), "w") as f:
        f.write('exclave 1\n\nown "/etc/ssl/certs/mine.pem"\n')

    def sh_of(ex: str) -> str:
        return os.path.join(ex, "tree", ctx.vbin("sh").lstrip("/"))

    sh = sh_of(marks)
    c = "/etc/ssl/certs"
    cases: list[tuple[str, str, str, str]] = [
        ("a hash link to the host's /usr/local", sh, f"cat {c}/abcd0000.0", f"local-{pid}"),
        ("the bundle", sh, f"cat {c}/ca-certificates.crt", f"bundle-{pid}"),
        ("a link to a directory, passed by name", sh, f"cat {c}/sub/local.crt", f"local-{pid}"),
        (
            "realpath, the link's text in the exclave",
            sh,
            f"realpath {c}/abcd0000.0 || echo none",
            "none",
        ),
        ("a create, the host's own", sh, f"touch {c}/new && echo made", "made"),
        ("Java's keystore the host lacks", sh, f"cat {c}/java/cacerts", f"tree-java-{pid}"),
        (
            "a name of the tree the host's directory hides",
            sh,
            f"cat {c}/mine.pem || echo hidden",
            "hidden",
        ),
        ("own on a name in it", sh_of(mine), f"cat {c}/mine.pem", f"tree-mine-{pid}"),
        ("own on the directory", sh_of(owned), f"cat {c}/java/cacerts; ls {c} | grep -c abcd", "0"),
        ("the bundle the host lacks", sh, f"rm {c}/ca-certificates.crt", ""),
        ("  is the exclave's copy", sh, f"test -e {c}/ca-certificates.crt && echo copy", "copy"),
        ("  and is not listed", sh, f"ls {c} | grep -c ca-certificates", "0"),
    ]
    local = "/usr/local/share/ca-certificates"
    script = (
        f"mount -t tmpfs tmpfs /etc/ssl/certs && mount -t tmpfs tmpfs {local} "
        f"&& echo local-{pid} >/usr/local/share/ca-certificates/local.crt "
        f"&& ln -s {local}/local.crt /etc/ssl/certs/x.pem "
        "&& ln -s x.pem /etc/ssl/certs/abcd0000.0 "
        f"&& ln -s {local} /etc/ssl/certs/sub "
        f"&& echo bundle-{pid} >/etc/ssl/certs/ca-certificates.crt || exit 99; "
    )
    for i, (_what, shell, cmd, _want) in enumerate(cases):
        script += f"echo '== {i}'; {shell} -c '{cmd}' 2>&1 || echo rc=$?; "
    # a host whose directory is a link at its name, as Red Hat's are: the same names below it
    link_cases = [
        ("a link at the name: readlink", f"readlink {c}", "real"),
        ("  a hash link below it", f"cat {c}/abcd0000.0", f"local-{pid}"),
        (
            "  the bundle the host lacks, the exclave's copy",
            f"test -e {c}/ca-certificates.crt && echo copy",
            "copy",
        ),
        (
            "  the directory it reaches, the host's at its name",
            f"cd {c} && pwd -P && ls | grep -c abcd",
            "1",
        ),
    ]
    script += (
        "mount -t tmpfs tmpfs /etc/ssl && mkdir /etc/ssl/real && ln -s real /etc/ssl/certs "
        "&& ln -s /usr/local/share/ca-certificates/local.crt /etc/ssl/real/x.pem "
        "&& ln -s x.pem /etc/ssl/real/abcd0000.0 || exit 98; "
    )
    for i, (_what, cmd, _want) in enumerate(link_cases, len(cases)):
        script += f"echo '== {i}'; {sh} -c '{cmd}' 2>&1 || echo rc=$?; "
    rc, out, err = run(
        ["unshare", "-Urm", "sh", "-c", script],
        cwd=ctx.work,
        env=dict(ctx.env, PATH="/usr/bin:/bin"),
    )
    if rc in (98, 99):
        skip(f"no tmpfs over the trust directory in a user namespace here: {err.strip()[-120:]}")
    got = {}
    for block in out.split("== ")[1:]:
        n, _, rest = block.partition("\n")
        got[int(n)] = rest.strip().split("\n") if rest.strip() else [""]
    wanted = [(w, want) for w, _, _, want in cases] + [(w, want) for w, _, want in link_cases]
    for i, (what, want) in enumerate(wanted):
        expect(
            want in got.get(i, []), f"the trust directory, {what.strip()}: {got.get(i)!r} {err!r}"
        )


@test
def nested_and_log(ctx: Ctx) -> None:
    log = os.path.join(ctx.work, "exclave.log")
    if os.path.exists(log):
        os.remove(log)
    rc, out, err = run(
        [wrapper(ctx, "sh"), "-c", ctx.gcc + " --version"],
        cwd=ctx.work,
        env=dict(ctx.env, EXCLAVE_LOG=log),
    )
    expect(rc == 0 and out.strip(), out + err)
    text = read_text(log)
    expect(
        "launcher 2 border " + ctx.sh_exe in text
        and "launcher 2 inside " + ctx.vreal(ctx.vbin(ctx.gcc)) in text,
        "log: " + text[:400],
    )
