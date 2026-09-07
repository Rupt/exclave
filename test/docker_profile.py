#!/usr/bin/env python3
"""docker_profile.py — a can under Docker's default seccomp profile (PROPOSAL.md 12, 17 item 5).

Docker's default profile (a JSON allow-list with a default errno) is assembled here into a classic BPF
program and installed by bwrap around a can workload, with the host's tree visible read-only, the way a
CI container would run it. The opener then stacks its own filter on top. Needs bwrap and user
namespaces; says so and exits 0 when it cannot run.

    test/docker_profile.py --can CAN --profile docker-seccomp.json [--work DIR]
"""
import argparse
import json
import os
import re
import shutil
import struct
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)

# seccomp's architecture word and Docker's names for this machine, whose profile entries name arches
import platform  # noqa: E402
MACHINE = platform.machine()
AUDIT_ARCH = {"x86_64": 0xC000003E, "aarch64": 0xC00000B7}[MACHINE]
ARCH_NAMES = {"x86_64": ("amd64", "x86_64"), "aarch64": ("arm64", "aarch64")}[MACHINE]
RET_ALLOW, RET_ERRNO, RET_KILL, RET_LOG = 0x7fff0000, 0x00050000, 0x80000000, 0x7ffc0000
# the capabilities a default Docker container holds
DEFAULT_CAPS = {"CAP_CHOWN", "CAP_DAC_OVERRIDE", "CAP_FSETID", "CAP_FOWNER", "CAP_MKNOD", "CAP_NET_RAW", "CAP_SETGID",
                "CAP_SETUID", "CAP_SETFCAP", "CAP_SETPCAP", "CAP_NET_BIND_SERVICE", "CAP_SYS_CHROOT", "CAP_KILL", "CAP_AUDIT_WRITE"}


def kernel_table(can=None):
    """The machine's syscall table from the can's headers (a gcc can ships linux-libc-dev) or the host's."""
    from syscalls import kernel_table as table
    return table(roots=([os.path.join(can, "root")] if can else []) + ["/"])


class BPF:
    """A tiny classic-BPF assembler with forward labels."""
    LD_ABS, JEQ_K, JGT_K, JGE_K, JSET_K, RET_K, JA, AND_K = 0x20, 0x15, 0x25, 0x35, 0x45, 0x06, 0x05, 0x54

    def __init__(self):
        self.insns, self.fixups = [], []

    def emit(self, code, jt, jf, k):
        self.insns.append([code, jt, jf, k & 0xffffffff])
        return len(self.insns) - 1

    def label(self):
        return len(self.insns)

    def jump_to(self, i, field, target):
        self.fixups.append((i, field, target))

    def pack(self):
        for i, field, target in self.fixups:
            off = target() - (i + 1)
            if off < 0 or off > 255:
                raise ValueError("jump out of range")
            self.insns[i][field] = off
        return b"".join(struct.pack("<HBBI", c, jt, jf, k) for c, jt, jf, k in self.insns)


def build(profile, table):
    default = profile.get("defaultAction", "SCMP_ACT_ERRNO")
    default_errno = int(profile.get("defaultErrnoRet", 1))
    b = BPF()
    b.emit(BPF.LD_ABS, 0, 0, 4)                                  # arch
    b.emit(BPF.JEQ_K, 1, 0, AUDIT_ARCH)
    b.emit(BPF.RET_K, 0, 0, RET_KILL)
    b.emit(BPF.LD_ABS, 0, 0, 0)                                  # nr
    rules = []
    for entry in profile.get("syscalls", []):
        inc, exc = entry.get("includes", {}), entry.get("excludes", {})
        if inc.get("caps") and not set(inc["caps"]) & DEFAULT_CAPS:
            continue
        if exc.get("caps") and set(exc["caps"]) & DEFAULT_CAPS:
            continue
        if inc.get("arches") and not set(inc["arches"]) & set(ARCH_NAMES):
            continue
        if exc.get("arches") and set(exc["arches"]) & set(ARCH_NAMES):
            continue
        action = entry.get("action", "SCMP_ACT_ALLOW")
        ret = {"SCMP_ACT_ALLOW": RET_ALLOW, "SCMP_ACT_LOG": RET_ALLOW, "SCMP_ACT_TRACE": RET_ALLOW,
               "SCMP_ACT_ERRNO": RET_ERRNO | int(entry.get("errnoRet", 1)), "SCMP_ACT_KILL": RET_KILL,
               "SCMP_ACT_KILL_PROCESS": RET_KILL}[action]
        for name in entry.get("names", [entry.get("name")] if entry.get("name") else []):
            if name in table:
                rules.append((table[name], entry.get("args") or [], ret))
    # one block per rule: jeq nr -> [arg checks] -> ret ; the rules are few enough for short jumps
    for nr, args, ret in rules:
        skip = []
        j = b.emit(BPF.JEQ_K, 0, 0, nr)
        skip.append((j, 2))
        for cond in args:
            idx, val, val2, op = cond["index"], int(cond["value"]), int(cond.get("valueTwo", 0)), cond["op"]
            lo, hi = 16 + 8 * idx, 16 + 8 * idx + 4
            if op == "SCMP_CMP_MASKED_EQ":
                b.emit(BPF.LD_ABS, 0, 0, lo)
                b.emit(BPF.AND_K, 0, 0, val & 0xffffffff)
                j = b.emit(BPF.JEQ_K, 0, 0, val2 & 0xffffffff); skip.append((j, 2))
                b.emit(BPF.LD_ABS, 0, 0, hi)
                b.emit(BPF.AND_K, 0, 0, (val >> 32) & 0xffffffff)
                j = b.emit(BPF.JEQ_K, 0, 0, (val2 >> 32) & 0xffffffff); skip.append((j, 2))
            elif op in ("SCMP_CMP_EQ", "SCMP_CMP_NE"):
                b.emit(BPF.LD_ABS, 0, 0, hi)
                j1 = b.emit(BPF.JEQ_K, 0, 0, (val >> 32) & 0xffffffff)
                b.emit(BPF.LD_ABS, 0, 0, lo)
                j2 = b.emit(BPF.JEQ_K, 0, 0, val & 0xffffffff)
                if op == "SCMP_CMP_EQ":
                    skip += [(j1, 2), (j2, 2)]
                else:                                              # NE: equal means the rule does not apply
                    b.jump_to(j1, 2, lambda: b.label())            # hi differs: applies
                    b.jump_to(j2, 1, lambda b=b, j2=j2: j2 + 1)     # placeholder, replaced below
                    # simpler: treat NE as "hi differs or lo differs"; jump past the ret when both equal
                    skip_eq = b.emit(BPF.JA, 0, 0, 0)
                    b.jump_to(skip_eq, 3, None)
            elif op in ("SCMP_CMP_LT", "SCMP_CMP_LE", "SCMP_CMP_GT", "SCMP_CMP_GE"):
                b.emit(BPF.LD_ABS, 0, 0, lo)                       # 32-bit compare: enough for the profile's uses
                if op == "SCMP_CMP_GE":
                    j = b.emit(BPF.JGE_K, 0, 0, val); skip.append((j, 2))
                elif op == "SCMP_CMP_GT":
                    j = b.emit(BPF.JGT_K, 0, 0, val); skip.append((j, 2))
                elif op == "SCMP_CMP_LT":
                    j = b.emit(BPF.JGE_K, 0, 0, val); skip.append((j, 1))
                else:
                    j = b.emit(BPF.JGT_K, 0, 0, val); skip.append((j, 1))
            else:
                raise ValueError("unsupported op " + op)
        b.emit(BPF.RET_K, 0, 0, ret)
        end = b.label()
        for j, field in skip:
            b.jump_to(j, field, lambda end=end: end)
        b.emit(BPF.LD_ABS, 0, 0, 0)                              # reload nr for the next rule
    if default == "SCMP_ACT_ALLOW":
        b.emit(BPF.RET_K, 0, 0, RET_ALLOW)
    else:
        b.emit(BPF.RET_K, 0, 0, RET_ERRNO | default_errno)
    return b


def assemble(profile_path, can=None):
    profile = json.load(open(profile_path))
    table = kernel_table(can)
    b = BPF()
    # the NE case above is awkward; the default profile has no NE rules, so refuse rather than guess
    for entry in profile.get("syscalls", []):
        for cond in entry.get("args") or []:
            if cond["op"] == "SCMP_CMP_NE":
                raise SystemExit("profile uses SCMP_CMP_NE, which this assembler does not implement")
    return build(profile, table).pack()


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--can", required=True)
    ap.add_argument("--profile", required=True)
    ap.add_argument("--work", default=os.path.join(REPO, "build", "docker-work"))
    a = ap.parse_args()
    if not shutil.which("bwrap") or subprocess.run(["bwrap", "--ro-bind", "/", "/", "true"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode:
        print("bwrap or user namespaces unavailable; the Docker-profile run cannot happen here")
        return 0
    prog = assemble(a.profile, os.path.abspath(a.can))
    work = os.path.abspath(a.work)
    if os.path.exists(work):
        shutil.rmtree(work)
    os.makedirs(work)
    with open(os.path.join(work, "hello.c"), "w") as f:
        f.write('#include <stdio.h>\n#include <pthread.h>\n#include <spawn.h>\n#include <sys/wait.h>\nextern char **environ;\n'
                'static void *t(void *a) { return a; }\n'
                'int main(void) { pthread_t th; pthread_create(&th, 0, t, 0); pthread_join(th, 0); pid_t p; char *av[] = {"true", 0};\n'
                ' if (posix_spawn(&p, "/usr/bin/true", 0, 0, av, environ)) return 2; int st; waitpid(p, &st, 0); printf("hello under docker profile %d\\n", st); return st; }\n')
    can = os.path.abspath(a.can)
    r, w = os.pipe()
    os.write(w, prog)
    os.close(w)
    cmd = ["bwrap", "--ro-bind", "/", "/", "--dev", "/dev", "--proc", "/proc", "--bind", work, work, "--chdir", work, "--seccomp", str(r),
           "--setenv", "PATH", "/usr/bin:/bin", os.path.join(can, "root", "usr", "bin", "sh"), "-c",
           "gcc-13 -O1 -pthread hello.c -o hello && ./hello && ls /usr/lib/gcc >/dev/null && cat /etc/passwd | head -1 && touch /usr/x 2>&1; readlink /proc/self/exe"]
    p = subprocess.run(cmd, pass_fds=[r], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    out, err = p.stdout.decode(errors="replace"), p.stderr.decode(errors="replace")
    ok = p.returncode == 0 and "hello under docker profile 0" in out and "Read-only" in out and out.strip().endswith("/usr/bin/readlink")
    print(("PASS" if ok else "FAIL") + " can under Docker's default profile (%d BPF instructions): rc=%d\n%s%s" % (len(prog) // 8, p.returncode, out, err))
    if ok:
        shutil.rmtree(work, ignore_errors=True)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
