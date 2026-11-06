"""The tool's check and prune: a group of the regression suite (DESIGN.md 17 item 4).

Run by test/run.py, on the fixtures test/suite.py makes.
"""

import os
import shutil
lazy import tempfile

import tree
from harness import expect, read_bytes, run, test
from suite import TOOL, Ctx, check, copy_exclave, hello_source, inside, wrapper


@test
def wrap_refuses_unreadable(ctx: Ctx) -> None:
    """10.1, 10.3: a file the user cannot read is an error of the static check.

    Wrap therefore refuses before it wraps anything and the exclave stays the directory it was;
    check names the third state, a wrapped exclave without a hashes file (N4).
    """
    ex = os.path.join(ctx.work, "unread.exclave")
    shutil.rmtree(ex, ignore_errors=True)
    os.makedirs(os.path.join(ex, "tree", "usr", "bin"))
    os.makedirs(os.path.join(ex, "tree", "etc"))
    with open(os.path.join(ex, "tree", "usr", "bin", "hi"), "w") as f:
        f.write("#!/bin/sh\necho hi\n")
    os.chmod(os.path.join(ex, "tree", "usr", "bin", "hi"), 0o755)
    with open(os.path.join(ex, "tree", "etc", "private"), "w") as f:
        f.write("secret\n")
    os.chmod(os.path.join(ex, "tree", "etc", "private"), 0)
    try:
        rc, o, e = run([*TOOL, "wrap", ex])
        expect(
            rc != 0 and "unreadable file /etc/private" in o + e and "nothing was wrapped" in o + e,
            f"an unreadable file must refuse the wrap: {rc} {o[-300:]} {e[-300:]}",
        )
        expect(
            not os.path.exists(os.path.join(ex, "tree", "usr", "bin", ".real"))
            and not os.path.exists(os.path.join(ex, ".exclave", "hashes")),
            "a refused wrap leaves the tree as it was",
        )
        os.chmod(os.path.join(ex, "tree", "etc", "private"), 0o600)
        rc, o, e = run([*TOOL, "wrap", ex])
        expect(rc == 0, "readable again, the exclave is wrapped: " + o + e)
        os.remove(os.path.join(ex, ".exclave", "hashes"))
        rc, o, e = run([*TOOL, "check", ex])
        expect(
            rc != 0 and "wrap never finished" in o + e,
            f"a wrapped exclave without a hashes file is reported: {rc} {o[-300:]}",
        )
    finally:
        os.chmod(os.path.join(ex, "tree", "etc", "private"), 0o600)


@test
def prune_and_check_with_logs(ctx: Ctx) -> str:
    """10.3 and 10.4 take files.

    The shared exclave passes the check, its wrappers, its tree against its hashes, the static
    check and the dynamic check of the EXCLAVE_LOG files a workload wrote, and its manifest is
    canonical; prune keeps what the logs touched plus the libraries kept ELF files need and the
    packages' licence texts, those the tree has and three planted where Debian, RPM and Alpine put
    them, and drops the rest, a shortcut with the file it names, and the pruned exclave still
    compiles.
    """
    log = os.path.join(ctx.work, "prune.log")
    if os.path.exists(log):
        os.remove(log)
    src = hello_source(ctx)
    rc, out, err = run(
        [wrapper(ctx, ctx.gcc), "-O1", src, "-o", os.path.join(ctx.work, "hello-prune")],
        cwd=ctx.work,
        env=dict(ctx.env, EXCLAVE_LOG=log),
    )
    expect(rc == 0, err)
    rc, out, err = run([*TOOL, "check", ctx.exclave, log])
    expect(
        rc == 0
        and "0 wrapper problems" in out
        and "0 errors" in out
        and "dynamic check:" in out
        and "log lines" in out,
        "check with a log: " + out[-500:] + err,
    )
    rc, out, err = run(
        [*TOOL, "format", "--check", os.path.join(ctx.exclave, ".exclave", "manifest")]
    )
    expect(rc == 0, "manifest not canonical: " + out + err)
    ex2 = os.path.join(ctx.work, "pruned.exclave")
    copy_exclave(ctx.exclave, ex2)
    planted = [
        "/usr/share/doc/exclave-planted/copyright",
        "/usr/share/licenses/exclave-planted/COPYING",
        "/lib/apk/db/installed",
    ]
    for v in planted:
        os.makedirs(os.path.dirname(os.path.join(ex2, "tree", v.lstrip("/"))), exist_ok=True)
        with open(os.path.join(ex2, "tree", v.lstrip("/")), "w") as f:
            f.write("a licence no workload reads\n")
    # a shortcut to a program the workload ran, and one to a file it never touched
    unused = os.path.join(ex2, "tree", "usr", "share", "exclave-unused")
    with open(unused, "w") as f:
        f.write("no workload reads this\n")
    os.symlink("tree" + ctx.vbin(ctx.gcc), os.path.join(ex2, "cc"))
    os.symlink("tree/usr/share/exclave-unused", os.path.join(ex2, "unused"))
    licences = tree.licence_files(os.path.join(ex2, "tree"))
    before = sum(1 for _ in tree.walk_files(os.path.join(ex2, "tree")))
    rc, out, err = run([*TOOL, "prune", ex2, log])
    expect(rc == 0 and "pruned" in out, "prune: " + out + err)
    expect(
        "removed the shortcut unused" in out
        and not os.path.lexists(os.path.join(ex2, "unused"))
        and os.path.exists(os.path.join(ex2, "cc")),
        "prune keeps a shortcut to a kept file and removes one whose file it removed: " + out,
    )
    after = sum(1 for _ in tree.walk_files(os.path.join(ex2, "tree")))
    expect(after < before // 2, f"pruning removed little: {after} of {before} files remain")
    expect(
        os.path.isdir(os.path.join(ex2, "tree", "usr", "share"))
        and os.path.exists(os.path.join(ex2, "tree", "etc", "passwd")),
        "directories and placeholders stay",
    )
    lost = sorted(
        v for v in licences if not os.path.exists(os.path.join(ex2, "tree", v.lstrip("/")))
    )
    expect(
        not lost and set(planted) <= licences,
        f"the licence texts stay: {len(lost)} of {len(licences)} lost, {lost[:3]}",
    )
    gcc2 = os.path.join(ex2, "tree", ctx.vbin(ctx.gcc).lstrip("/"))
    rc, out, err = run(
        [gcc2, "-O1", src, "-o", os.path.join(ctx.work, "hello-pruned")], cwd=ctx.work, env=ctx.env
    )
    expect(rc == 0, "the pruned exclave compiles: " + err[-500:])
    rc, out, err = inside(ctx, os.path.join(ctx.work, "hello-pruned"))
    expect(rc == 0 and out.startswith("hello "), f"the output runs: {out!r} {err!r}")
    rc, out, err = run([*TOOL, "check", ex2])
    expect(rc == 0, "the pruned exclave passes the static check: " + out[-600:])
    return f"{after} of {before} files kept, {len(licences)} licence texts among them"


@test
def static_check_loader_model(ctx: Ctx) -> str | None:
    """10.3: the static check models the loader.

    DT_RPATH is inherited down the chain, ld.so.cache is read, a search directory the exclave does
    not own is refused; a hand-made glibc layout is wrapped, a truncated ELF is an error by name, a
    host record is applied as the launcher applies it, a library a workload built in its own
    directory is a note; the loader asked for its directories is the tree's own file behind an
    absolute link in the tree, and a link is judged in the tree though the host has a directory
    where it points; a separate debug file, whose segments carry no bytes, is not a program; a
    DT_NEEDED that is a path through $ORIGIN resolves where glibc's loader expands it, and not under
    musl's, which does not; a soname no search finds is a warning naming where the tree has it,
    as the JVM's libjvm.so, which it opens by path before the libraries that need it.
    """
    # the libraries are placed in a copy's tree, which the shared exclave's must not see
    model = os.path.join(ctx.work, f"loader-model-{os.getpid()}.exclave")
    shutil.rmtree(model, ignore_errors=True)
    copy_exclave(ctx.exclave, model)
    x = os.path.join(model, "tree", "usr", "local", "x")
    base = os.path.join(x, "lib")
    os.makedirs(base, exist_ok=True)
    src = os.path.join(ctx.work, "rp")
    os.makedirs(src, exist_ok=True)
    with open(os.path.join(src, "bar.c"), "w") as f:
        f.write("int bar(void) { return 1; }\n")
    with open(os.path.join(src, "foo.c"), "w") as f:
        f.write("int bar(void); int foo(void) { return bar(); }\n")
    with open(os.path.join(src, "prog.c"), "w") as f:
        f.write("int foo(void); int main(void) { return foo(); }\n")
    with open(os.path.join(src, "dst.c"), "w") as f:
        f.write("int bar(void); int main(void) { return bar(); }\n")
    gcc = wrapper(ctx, ctx.gcc)
    built = os.path.join(src, "out")  # built on the host side, then placed in the tree by hand:
    # from inside the exclave the tree's real path is the read-only exclave
    os.makedirs(built, exist_ok=True)
    try:
        for cmd in (
            [
                "-shared",
                "-fPIC",
                "-Wl,-soname,libbar.so.1",
                "-o",
                os.path.join(built, "libbar.so.1"),
                "bar.c",
            ],
            [
                "-shared",
                "-fPIC",
                "-Wl,-soname,libfoo.so.1",
                "-o",
                os.path.join(built, "libfoo.so.1"),
                "foo.c",
                "-L" + built,
                "-l:libbar.so.1",
            ],
            [
                "-o",
                os.path.join(built, "prog"),
                "prog.c",
                "-L" + built,
                "-l:libfoo.so.1",
                "-Wl,-rpath-link," + built,
                "-Wl,--disable-new-dtags",
                "-Wl,-rpath,/usr/local/x/lib",
            ],
            [
                "-o",
                os.path.join(built, "hostprog"),
                "prog.c",
                "-L" + built,
                "-l:libfoo.so.1",
                "-Wl,-rpath-link," + built,
                "-Wl,-rpath,/tmp/exclave-hostlib",
            ],
            [
                "-shared",
                "-fPIC",
                "-Wl,-soname,$ORIGIN/../lib/libdst.so",
                "-o",
                os.path.join(built, "libdst.so"),
                "bar.c",
            ],
            ["-o", os.path.join(built, "dstprog"), "dst.c", "-L" + built, "-l:libdst.so"],
            [
                "-shared",
                "-fPIC",
                "-Wl,-soname,libjvmish.so",
                "-o",
                os.path.join(built, "libjvmish.so"),
                "bar.c",
            ],
            [
                "-shared",
                "-fPIC",
                "-o",
                os.path.join(built, "libneed.so"),
                "foo.c",
                "-L" + built,
                "-l:libjvmish.so",
            ],
        ):
            rc, out, err = run([gcc, *cmd], cwd=src, env=ctx.env)
            expect(rc == 0, err)
        rc, out, err = run(
            [
                wrapper(ctx, "objcopy"),
                "--only-keep-debug",
                os.path.join(built, "prog"),
                os.path.join(built, "prog.debug"),
            ],
            cwd=src,
            env=ctx.env,
        )
        expect(rc == 0, "objcopy: " + err)
        # as /usr/lib/debug holds them: an empty PT_INTERP
        shutil.copy2(os.path.join(built, "prog.debug"), os.path.join(x, "prog.debug"))
        for f in ("libbar.so.1", "libfoo.so.1", "libdst.so"):
            shutil.copy2(os.path.join(built, f), os.path.join(base, f))
        # $ORIGIN/../lib from /usr/local/x/bin is /usr/local/x/lib
        os.makedirs(os.path.join(x, "bin"), exist_ok=True)
        shutil.copy2(os.path.join(built, "dstprog"), os.path.join(x, "bin", "dstprog"))
        for f in ("prog", "hostprog"):
            shutil.copy2(os.path.join(built, f), os.path.join(x, f))
        # the soname found only where no search reaches: a library in a directory of its own
        for d, f in (("server", "libjvmish.so"), ("jvmlib", "libneed.so")):
            os.makedirs(os.path.join(x, d), exist_ok=True)
            shutil.copy2(os.path.join(built, f), os.path.join(x, d, f))
        errors, warnings, _out = check(model)
        expect(
            not [e for e in errors if "libjvmish" in e]
            and any(
                "libneed.so needs libjvmish.so, which no search finds" in w
                and "/usr/local/x/server/libjvmish.so" in w
                for w in warnings
            ),
            f"a soname the tree has where no search reaches is a warning: {errors[:2]!r}",
        )
        bad = [
            e for e in errors if "/usr/local/x/prog" in e or ("libfoo" in e and "hostprog" not in e)
        ]
        expect(not bad, "RPATH inheritance: " + "; ".join(bad))
        debug = [e for e in errors if "prog.debug" in e]
        expect(not debug, f"a separate debug file is not a program: {debug!r}")
        expect(
            any("hostprog" in e and "does not own" in e for e in errors),
            f"a host RPATH must be refused: {errors[:3]!r}",
        )
        dst = [e for e in errors if "libdst" in e]
        expect(
            bool(dst) == ctx.musl,
            "a DT_NEEDED through $ORIGIN ({}): {!r}".format(
                "unexpanded by musl" if ctx.musl else "expanded by glibc", dst
            ),
        )
    finally:
        shutil.rmtree(model, ignore_errors=True)
    # a hand-made tree with the loader at /usr/lib64 and no ld.so.cache is wrapped; the loader
    # satisfies its own soname and its default directories come from the loader itself. without /lib
    # the host's would be searched.
    if not ctx.libc:
        return "no libc.so.6 in the tree (musl): the hand-made glibc layout is not made"
    hand2 = os.path.join(ctx.work, "hand2.exclave")
    shutil.rmtree(hand2, ignore_errors=True)
    # where the tree keeps libc: usr/lib/<triplet>, or usr/lib64
    libdir = os.path.dirname(ctx.vreal(ctx.libc)).lstrip("/")
    for d in ("usr/" + ctx.ldso_dir, libdir, "usr/bin", "etc"):
        os.makedirs(os.path.join(hand2, "tree", d), exist_ok=True)
    # the tree's own top-level links, as the loader's defaults expect
    for top in ("lib", "lib64", "lib32"):
        if os.path.islink(os.path.join(ctx.root, top)):
            os.symlink(os.readlink(os.path.join(ctx.root, top)), os.path.join(hand2, "tree", top))
    # the loader where PT_INTERP names it
    shutil.copy2(
        ctx.payload(ctx.interp), os.path.join(hand2, "tree", "usr", ctx.ldso_dir, ctx.ldso_name)
    )
    shutil.copy2(ctx.payload(ctx.libc), os.path.join(hand2, "tree", libdir, "libc.so.6"))
    shutil.copy2(ctx.payload("true"), os.path.join(hand2, "tree", "usr", "bin", "true"))
    # the loader asked for its directories is the tree's own behind an absolute link in the tree,
    # never a host file the link's text names
    hand3 = os.path.join(ctx.work, f"hand3-{os.getpid()}.exclave")
    shutil.rmtree(hand3, ignore_errors=True)
    shutil.copytree(os.path.join(hand2, "tree"), os.path.join(hand3, "tree"), symlinks=True)
    ld3 = os.path.join(hand3, "tree", "usr", ctx.ldso_dir, ctx.ldso_name)
    os.makedirs(os.path.join(hand3, "tree", "opt", "exclave-ld"))
    os.rename(ld3, os.path.join(hand3, "tree", "opt", "exclave-ld", "ld.so"))
    os.symlink("/opt/exclave-ld/ld.so", ld3)
    rc, out, err = run([*TOOL, "wrap", hand3])
    expect(
        rc == 0 and "lists no search directories" not in out,
        f"the loader behind an absolute link must list its own directories: {out[-600:]!r}",
    )
    rc, out, err = run([*TOOL, "wrap", hand2])
    expect(rc == 0, "a tree with the loader in /usr/lib64 and no cache must wrap: " + out[-500:])
    rc, out, err = run(
        [os.path.join(hand2, "tree", "usr", "bin", "true")], cwd=ctx.work, env=ctx.env
    )
    expect(rc == 0, f"and run: {err!r}")
    top = ctx.libc.split("/")[1]  # the top-level link libc is reached through: lib, or lib64
    os.remove(os.path.join(hand2, "tree", top))
    errors, _warnings, _out = check(hand2)
    expect(
        any(
            (os.path.dirname(ctx.libc) in e_ and "does not own" in e_)
            or (ctx.ldso_dir == top and "loader" in e_)
            for e_ in errors
        ),
        f"a tree without /{top} searches the host's: {errors[:3]!r}",
    )
    os.symlink(os.readlink(os.path.join(ctx.root, top)), os.path.join(hand2, "tree", top))
    shutil.rmtree(os.path.join(hand2, "tree", "etc"))
    os.makedirs(os.path.join(hand2, "tree", "etc"))
    errors, _warnings, _out = check(hand2)
    expect(
        any("/etc is the host's" in e_ for e_ in errors),
        f"a tree without /etc would read the host's ld.so.cache: {errors[:3]!r}",
    )
    # a link is judged in the tree, though the host has a directory where its text points
    dangling = os.path.join(hand2, "tree", "usr", "bin", "exclave-dangling")
    os.symlink("/usr/sbin", dangling)
    _errors, warnings, _out = check(hand2)
    expect(
        "dangling symlink /usr/bin/exclave-dangling -> /usr/sbin" in warnings,
        f"a link dangling in the tree, to a host directory: {warnings[:4]!r}",
    )
    os.remove(dangling)
    # a truncated ELF is an error by name, not a traceback
    bad = os.path.join(hand2, "tree", "usr", "bin", "broken")
    with open(bad, "wb") as f:
        f.write(b"\x7fELF\x02\x01\x01\x00garbage")
    os.chmod(bad, 0o755)
    errors, _warnings, _out = check(hand2)
    expect(
        any("broken" in e_ and ("malformed" in e_ or "not ELF64" in e_) for e_ in errors),
        f"a truncated ELF must be reported by name: {errors[:3]!r}",
    )
    # a host record takes a path back from the tree by the launcher's longest prefix (8.1): over the
    # loader's directory it leaves the exclave no loader the launcher will take, and the check must
    # say so rather than read the tree alone
    with open(os.path.join(hand2, ".exclave", "manifest"), "w") as f:
        f.write(f'exclave 1\n\nhost "/usr/{ctx.ldso_dir}"\n')
    errors, _warnings, _out = check(hand2)
    expect(
        any("/usr/bin/true wants interpreter" in e_ and "does not own" in e_ for e_ in errors),
        f"a host record over the loader: {errors[:3]!r}",
    )
    # a library the workload built in its own directory is a note, not an error
    bld = os.path.join(ctx.work, "bld")
    os.makedirs(bld, exist_ok=True)
    with open(os.path.join(bld, "foo.c"), "w") as f:
        f.write("int foo(void) { return 42; }\n")
    with open(os.path.join(bld, "usefoo.c"), "w") as f:
        f.write(
            "#include <stdio.h>\n"
            'int foo(void); int main(void) { printf("%d\\n", foo()); return 0; }\n'
        )
    gcc = wrapper(ctx, ctx.gcc)
    rc, out, err = run([gcc, "-shared", "-fPIC", "-o", "libfoo.so", "foo.c"], cwd=bld, env=ctx.env)
    rc2, out, err2 = run(
        [gcc, "usefoo.c", "-L.", "-lfoo", "-Wl,-rpath,$ORIGIN", "-o", "usefoo"],
        cwd=bld,
        env=ctx.env,
    )
    expect(rc == 0 and rc2 == 0, err + err2)
    log = os.path.join(ctx.work, "bld.log")
    if os.path.exists(log):
        os.remove(log)
    rc, out, err = run(
        [wrapper(ctx, "sh"), "-c", "./usefoo"], cwd=bld, env=dict(ctx.env, EXCLAVE_LOG=log)
    )
    expect(out == "42\n", f"usefoo: {out!r} {err!r}")
    rc, out, err = run([*TOOL, "check", ctx.exclave, log])
    expect(
        rc == 0 and "working directory" in out and "0 errors" in out.splitlines()[-1],
        "a build-directory library is a note, not an error: " + out[-500:],
    )
    # the same library, in a directory the host owns by rule 3, opened by a workload run from /: the
    # check must still report it (nothing is given to the host from /), where a run from that
    # directory would note it as the build's own
    tmp = tempfile.mkdtemp(prefix="exclave-bld-", dir="/tmp")
    try:
        for f in ("libfoo.so", "usefoo"):
            shutil.copy2(os.path.join(bld, f), os.path.join(tmp, f))
        log2 = os.path.join(ctx.work, "bld-root.log")
        rc, out, err = run(
            [wrapper(ctx, "sh"), "-c", f"{tmp}/usefoo"],
            cwd="/",
            env=dict(ctx.env, EXCLAVE_LOG=log2),
        )
        expect(out == "42\n", f"usefoo from /: {out!r} {err!r}")
        rc, out, err = run([*TOOL, "check", ctx.exclave, log2])
        expect(
            rc != 0 and "library opened on the host" in out and tmp + "/libfoo.so" in out,
            "a workload run from / must not excuse a host library: " + out[-500:],
        )
        # and a run from that directory, the host's by rule 3 with nothing to give, notes it as the
        # build's own
        log3 = os.path.join(ctx.work, "bld-tmp.log")
        rc, out, err = run(
            [wrapper(ctx, "sh"), "-c", "./usefoo"], cwd=tmp, env=dict(ctx.env, EXCLAVE_LOG=log3)
        )
        expect(out == "42\n", f"usefoo from its /tmp directory: {out!r} {err!r}")
        rc, out, err = run([*TOOL, "check", ctx.exclave, log3])
        expect(
            rc == 0 and "working directory" in out and "0 errors" in out.splitlines()[-1],
            "a build directory under /tmp is a note, not an error: " + out[-500:],
        )
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


@test
def mixed_tree_refused(ctx: Ctx) -> None:
    """10.3: a tree whose ELF files name two loaders is refused by the static check.

    The check reads the loaders from the files; nothing declares one.
    """
    mixed = os.path.join(ctx.work, "mixed.exclave")
    d = os.path.join(mixed, "tree")
    os.makedirs(os.path.join(d, "usr", "bin"), exist_ok=True)
    src = read_bytes(ctx.payload("true"))
    interp = ctx.interp.encode() + b"\0"
    i = src.index(interp)
    other = (ctx.other_interp.encode() + b"\0").ljust(len(interp), b"\0")
    with open(os.path.join(d, "usr", "bin", "true"), "wb") as f:
        f.write(src[:i] + other + src[i + len(interp) :])
    with open(os.path.join(d, "usr", "bin", "false"), "wb") as f:
        f.write(src)
    for n in ("true", "false"):
        os.chmod(os.path.join(d, "usr", "bin", n), 0o755)
    os.symlink(ctx.interp, os.path.join(d, "usr", "bin", "ld-glibc"))  # so that one loader resolves
    os.makedirs(os.path.join(d, ctx.ldso_dir), exist_ok=True)
    shutil.copy2(ctx.payload(ctx.interp), os.path.join(d, ctx.interp.lstrip("/")))
    # the other loader's directory
    os.makedirs(os.path.dirname(os.path.join(d, ctx.other_interp.lstrip("/"))), exist_ok=True)
    shutil.copy2(ctx.payload(ctx.interp), os.path.join(d, ctx.other_interp.lstrip("/")))
    rc, out, err = run([*TOOL, "wrap", mixed])
    expect(
        rc == 1 and any("mixes loaders" in x for x in out.splitlines() if x.startswith("error: ")),
        f"a tree with two loaders was not refused: {out[-600:]!r} {err[-200:]!r}",
    )
