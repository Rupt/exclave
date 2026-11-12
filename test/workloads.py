"""Real workloads in their own exclaves, run where the kernel answers and under the launcher (17).

    test/workloads.py --inputs DIR [--work DIR] [-k NAME]

DIR is the directory scripts/inputs filled: each workload takes its exclave from there, and the
PDF and zlib's sources from DIR/src. Each runs in the same work directory twice, first under bwrap
with the exclave's unwrapped tree read-only at / (test/oracle_ns.py), then under the launcher with
EXCLAVE_LOG set, and its output is compared byte for byte; what a build makes is hashed into the
output, so a difference in a compiled file is one too, the work directory's path being the same in
both worlds. The workloads, each a program with its own syscall layer, caches or many processes:

  valgrind  memcheck over a program with an invalid write and a leak, compiled inside
  poppler   pdftotext and pdffonts of a PDF with embedded fonts, and pdftoppm of a page whose
            Times-Roman is not embedded, so that fontconfig finds a substitute and caches it
  rust      cargo new, a build with two jobs, and the program run
  cmake     zlib configured by CMake for ninja, built with four jobs, its test programs run
  java      java -version, a single-file program, javac and the class run, through
            /usr/bin/java's alternatives link, and the trusted entries of the keystore counted
  python    a Python process's threads, subprocesses, sqlite and files, a fixed amount of each
  tex       pdflatex, bibtex and pdflatex twice on an article with a citation, the PDF dated by
            SOURCE_DATE_EPOCH and hashed, in TeX Live's exclave after exclave caches made its
            indexes and formats
  buildimage  a Hutter Prize entry's unmodified build.sh (cmix-neif 1.0: clang-18, lld-18, a
            PGO training run, make -j) in an exclave of the judging image's packages at the
            Ubuntu snapshot the entry pins; its comp9 is hashed, the published hash beside it

Prints a line per workload with both times and the failed opens the log names; the exit status is
the number of workloads whose outputs differ. A workload whose exclave is missing is skipped with
its reason.
"""

import argparse
import os
import re
import shutil
import subprocess
import sys
import tarfile
import time

import oracle_ns

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)

LEAK_C = r"""#include <stdio.h>
#include <stdlib.h>
int main(void)
{
    char *p = malloc(16);
    p[16] = 1;
    void *q = malloc(32);
    (void)q;
    printf("done\n");
    free(p);
    return 0;
}
"""

HELLO_JAVA = """public class Hello {
    public static void main(String[] a) {
        System.out.println("hello " + System.getProperty("java.home") + " " + a.length);
    }
}
"""

DOC_TEX = r"""\documentclass{article}
\usepackage{amsmath}
\begin{document}
Hello, exclave: $\int_0^1 x\,dx = \tfrac12$ \cite{knuth}.
\bibliographystyle{plain}
\bibliography{refs}
\end{document}
"""

REFS_BIB = """@book{knuth, author={Donald E. Knuth}, title={The {\\TeX}book},
  publisher={Addison-Wesley}, year={1984}}
"""

# a fixed amount of work, so that the output is the same in both worlds
PYTHON = r"""import hashlib, json, os, sqlite3, subprocess, threading
seen = []
db = sqlite3.connect("work.db")
db.execute("create table t (i integer, v text)")
lock = threading.Lock()
def worker(n):
    for i in range(200):
        p = f"w{n}-{i % 10}.json"
        with open(p, "w") as f:
            json.dump({"n": n, "i": i}, f)
        with open(p) as f:
            v = json.load(f)
        with lock:
            seen.append(json.dumps(v, sort_keys=True))
for round in range(100):
    ts = [threading.Thread(target=worker, args=(k,)) for k in range(4)]
    for t in ts:
        t.start()
    for t in ts:
        t.join()
    cmd = f"echo round {round}; ls | wc -l"
    out = subprocess.run(["sh", "-c", cmd], capture_output=True, text=True).stdout
    db.execute("insert into t values (?, ?)", (round, out))
    db.commit()
rows = db.execute("select count(*), sum(i) from t").fetchone()
# in an order of its own, the threads' being the scheduler's
digest = hashlib.blake2b("\n".join(sorted(seen)).encode(), digest_size=16).hexdigest()
print("rounds", rows, "digest", digest, "files", len(os.listdir(".")))
"""

# name: (exclave, files to put in the work directory, the shell command)
WORKLOADS: dict[str, tuple[str, tuple[str, ...], str]] = {
    "valgrind": (
        "valgrind",
        ("leak.c",),
        (
            "gcc -g -O0 -o leak leak.c && valgrind --leak-check=full ./leak 2>&1 "
            "| sed 's/^==[0-9]*==/==PID==/' | grep -v '^==PID== Command:'"
        ),
    ),
    "poppler": (
        "poppler",
        ("src/attention.pdf",),
        (
            "pdftotext attention.pdf - | b2sum; pdffonts attention.pdf; "
            "pdftoppm -r 40 -f 1 -l 1 attention.pdf | b2sum"
        ),
    ),
    "rust": (
        "rust",
        (),
        (
            "export CARGO_HOME=$W/.cargo; cargo new --vcs none -q hello && cd hello && "
            "cargo build --offline -q -j 2 && ./target/debug/hello && b2sum target/debug/hello"
        ),
    ),
    "cmake": (
        "cmake",
        ("src/zlib-1.3.1.tar.gz",),
        (
            "cmake -S zlib-1.3.1 -B zb -G Ninja -DCMAKE_BUILD_TYPE=Release >/dev/null && "
            "ninja -C zb -j 4 >/dev/null && cd zb && ./example && ./example64 && "
            "b2sum libz.so.1.3.1 example"
        ),
    ),
    "java": (
        "java",
        ("Hello.java",),
        (
            "java -version 2>&1; java Hello.java x y && javac -d out Hello.java && "
            "java -cp out Hello && b2sum out/Hello.class; readlink -f /usr/bin/java; "
            "keytool -list -cacerts -storepass changeit | grep -c trustedCertEntry"
        ),
    ),
    "python": ("realsoft", ("work.py",), "python3 work.py"),
    "tex": (
        "tex",
        ("doc.tex", "refs.bib"),
        (
            "export SOURCE_DATE_EPOCH=0 FORCE_SOURCE_DATE=1; pdflatex -interaction=nonstopmode "
            "doc.tex >/dev/null; bibtex doc; pdflatex -interaction=nonstopmode doc.tex >/dev/null; "
            "pdflatex -interaction=nonstopmode doc.tex | tail -2; cat doc.bbl; b2sum doc.pdf; "
            "kpsewhich article.cls pdftex.map"
        ),
    ),
    "buildimage": (
        "buildimage",
        ("src/cmix-neif-1.0.tar.gz",),
        (
            "cd cmix-neif-1.0 && sh ./build.sh >build.log 2>&1; echo build rc=$?; "
            "echo published 8b07d85f0a374b55688fd08d1a464222f766efbb5bfefc2bc94d6abb201133d7; "
            "sha256sum comp9 | sed 's/  .*//'"
        ),
    ),
}


def run_launcher(
    ex: str, work: str, cmd: str, sp: oracle_ns.Spellings, log: str
) -> tuple[int, str]:
    """The command by the tree's shell under the launcher, logged to log; status and output."""
    env = {
        "PATH": "/usr/bin:/bin",
        "HOME": work,
        "W": work,
        **sp.workload_env(),
        "LANG": "en_GB.UTF-8",
        "TZ": "Asia/Tokyo",
        "EXCLAVE_LOG": log,
    }
    p = subprocess.run(
        [os.path.join(ex, "tree", sp.sh.lstrip("/")), "-c", cmd],
        cwd=work,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
        timeout=900,
    )
    return p.returncode, p.stdout.decode(errors="replace")


def failed_opens(log: str) -> list[str]:
    """The opens the launcher's log records as failed, as `errno path`."""
    out = []
    try:
        with open(log, errors="replace") as f:
            for line in f:
                m = re.match(r"open (-\d+) (.*)", line.rstrip("\n"))
                if m:
                    out.append(f"{m.group(1)} {m.group(2)}")
    except FileNotFoundError:
        pass
    return out


def fresh(work: str, inputs: str, files: tuple[str, ...]) -> None:
    """The work directory as each world starts it: its inputs and nothing else."""
    shutil.rmtree(work, ignore_errors=True)
    os.makedirs(work)
    texts = {
        "leak.c": LEAK_C,
        "Hello.java": HELLO_JAVA,
        "work.py": PYTHON,
        "doc.tex": DOC_TEX,
        "refs.bib": REFS_BIB,
    }
    for f in files:
        if f in texts:
            with open(os.path.join(work, f), "w") as out:
                out.write(texts[f])
        elif f.endswith(".tar.gz"):
            with tarfile.open(os.path.join(inputs, f)) as t:
                t.extractall(work, filter="data")
        else:
            shutil.copyfile(os.path.join(inputs, f), os.path.join(work, os.path.basename(f)))


def main() -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument("--inputs", required=True, help="the directory scripts/inputs filled")
    ap.add_argument("--work", default=os.path.join(REPO, "build", "workloads"))
    ap.add_argument("-k", default="", help="only the workloads whose name contains this")
    args = ap.parse_args()
    why = oracle_ns.bwrap_unusable()
    if why:
        print(f"{why}; the workloads cannot be compared here")
        return 0
    inputs, top = os.path.abspath(args.inputs), os.path.abspath(args.work)
    differ = 0
    for name, (exname, files, cmd) in WORKLOADS.items():
        if args.k not in name:
            continue
        given = os.path.join(inputs, exname + ".exclave")
        if not os.path.isdir(os.path.join(given, ".exclave")):
            print(f"{name:<9} SKIP: no {given}; scripts/inputs DIR examples makes it")
            continue
        base = os.path.join(top, name)
        shutil.rmtree(base, ignore_errors=True)
        os.makedirs(base)
        ex, root = oracle_ns.worlds(given, base)
        sp = oracle_ns.Spellings.of(root)
        work = os.path.join(base, "w")
        fresh(work, inputs, files)
        t0 = time.monotonic()
        rc_k, out_k, err_k = oracle_ns.run_bwrap(root, work, cmd + " 2>&1", sp)
        tk = time.monotonic() - t0
        kernel = out_k + err_k
        fresh(work, inputs, files)
        log = os.path.join(base, "exclave.log")
        t0 = time.monotonic()
        rc_l, launcher = run_launcher(ex, work, cmd + " 2>&1", sp, log)
        tl = time.monotonic() - t0
        failed = failed_opens(log)
        same = rc_k == rc_l and kernel == launcher
        differ += not same
        last = (launcher.strip().splitlines() or [""])[-1]
        print(
            f"{name:<9} {'same' if same else 'DIFFER'}: kernel {tk:.1f} s, launcher {tl:.1f} s, "
            f"{len(failed)} failed opens logged; the output ends {last[:70]!r}"
        )
        if not same:
            print(f"  rc kernel={rc_k} launcher={rc_l}")
            for a, b in zip(kernel.splitlines(), launcher.splitlines(), strict=False):
                if a != b:
                    print(f"  kernel:   {a[:150]}\n  launcher: {b[:150]}")
                    break
            print(f"  kernel's tail:   {kernel[-300:]!r}\n  launcher's tail: {launcher[-300:]!r}")
        else:
            shutil.rmtree(base, ignore_errors=True)
    print(f"workloads: {differ} differ")
    return min(differ, 255)


if __name__ == "__main__":
    sys.exit(main())
