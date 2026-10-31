"""Ownership, identity files and the log: a group of the regression suite (DESIGN.md 17 item 4).

Run by test/run.py, on the fixtures test/suite.py makes.
"""

import os

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
    # 6.2: the time zone is not the host's: UTC inside, whatever TZ and /etc/localtime say outside
    rc, out, err = run(
        [wrapper(ctx, "date"), "+%Z"], cwd=ctx.work, env=dict(ctx.env, TZ="Asia/Tokyo")
    )
    expect(out.strip() == "UTC", f"the zone inside an exclave is UTC: {out!r} {err!r}")
    if not os.path.lexists(os.path.join(ctx.root, "etc", "localtime")):
        rc, out, err = run([wrapper(ctx, "cat"), "/etc/localtime"], cwd=ctx.work, env=ctx.env)
        expect(
            rc != 0 and "No such file" in err,
            f"the host's /etc/localtime must be invisible: {err!r}",
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
    """lstat, readlink and the link's target agree for an identity file that is a host symlink."""
    link = next(
        (f for f in ("/etc/resolv.conf", "/etc/hosts", "/etc/nsswitch.conf") if os.path.islink(f)),
        None,
    )
    if not link:
        skip("no host identity file is a symlink")
    target = os.readlink(link)
    # the content is reached through the identity name; its host target is not an exclave path (8.4)
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
    name.
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
        f"cd into a placeholder and the read-only root: {out!r} {err!r}",
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
        rc == 0 and "launcher 0 border" in text and "launcher 0 inside" in text,
        f"one log for every launcher: rc={rc} {err!r} {text[-300:]!r}",
    )
    rc, _, err = with_log("/dev/stderr")
    expect(
        rc == 0 and "launcher 0 border" in err, f"/dev/stderr as the log: rc={rc} {err[-300:]!r}"
    )


@test
def log_names_and_escapes(ctx: Ctx) -> None:
    """6.2: a failed resolution logs the path as given.

    A path with a newline or backslash is escaped in the log and undone by the tool, so prune keeps
    the file the workload opened; prune refuses a log that names no program.
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
    # the last a backslash before an n, not a newline
    names = ("with\nnewline", "back\\slash", "back\\nslash")
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
        and any(line == "open 3 /usr/share/odd/back\\\\slash" for line in lines),
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
        out.startswith("probe\n") and "refused" in out,
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
        "launcher 0 border " + ctx.sh_exe in text
        and "launcher 0 inside " + ctx.vreal(ctx.vbin(ctx.gcc)) in text,
        "log: " + text[:400],
    )
