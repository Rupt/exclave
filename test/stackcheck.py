#!/usr/bin/env python3
"""Stack budget check (PROPOSAL.md 7.5.4): reads gcc -fstack-usage output of the current build.

Fails if any function on the handler path has a frame above 512 bytes or an unbounded dynamic frame, if a
name listed here appears in no .su file and nowhere in src/*.c (a rename or a deletion must be loud, review
O3-12; an inlined name counts in its caller), or if the handler path's worst case exceeds 3072 bytes. The path
is the deepest chain: on_sigsys -> dispatch -> do_execve -> exec_target x6 (a #! chain of host scripts nests
exec_target and exec_script, five interpreters deep as binfmt_script allows) -> the resolution and probing
helpers. gcc's .isra/.constprop/.part clones count under their base names.
"""
import re
import sys

LIMIT_FRAME = 512
LIMIT_PATH = 3072                # 7.5.4: under 3 KB with a five-deep chain of host scripts, about 1.3 KB otherwise
# (names, multiplier): the largest frame among the names, times the multiplier
PATH = [
    (["on_sigsys"], 1), (["dispatch"], 1),
    (["do_open", "do_execve", "do_readlink", "do_sigprocmask", "do_pselect6", "do_sockaddr", "exec_env"], 1),
    (["exec_descriptor"], 1),
    (["exec_target"], 6), (["exec_script"], 6),
    (["resolve", "canon", "delete_overlong", "fd_virtual", "cwd_virtual", "ro_create", "ro_attr", "exists_can", "to_real", "to_real_exec", "vis_is_host", "elf_probe", "vec_read"], 1),
    (["copy_str_in", "copy_in", "copy_out", "pipe_copy", "scratch_get", "nest_enter", "is_wrapper_real", "payload_of", "from_real", "cache_classify", "cache_get", "cache_put", "log_line", "log_msg"], 1),
]
frames, seen_dynamic = {}, {}
for f in sys.argv[1:]:
    for line in open(f):
        m = re.match(r"^(\S+?):\d+:\d+:(\S+)\s+(\d+)\s+(\w+(?:,\w+)?)", line)
        if not m:
            continue
        name = re.sub(r"\.(isra|constprop|part|cold)\.?\d*$", "", m.group(2))
        size, kind = int(m.group(3)), m.group(4)
        frames[name] = max(frames.get(name, 0), size)
        if kind not in ("static", "dynamic,bounded"):
            seen_dynamic[name] = kind
import glob
import os
listed = {n for names, _ in PATH for n in names}
sources = "".join(open(f).read() for f in glob.glob(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src", "*.c")))
fails = []
for n in sorted(listed - set(frames)):
    if re.search(r"\b%s\s*\(" % re.escape(n), sources):
        continue                              # inlined into its caller: its frame is counted there
    fails.append("%s is on the handler path but neither in a .su file nor in the sources (renamed or deleted)" % n)
for n in sorted(listed & set(seen_dynamic)):
    fails.append("%s: unbounded dynamic frame (%s)" % (n, seen_dynamic[n]))
for n in sorted(listed):
    if frames.get(n, 0) > LIMIT_FRAME:
        fails.append("%s: frame %d over %d" % (n, frames[n], LIMIT_FRAME))
worst = sum(max(frames.get(n, 0) for n in names) * mult for names, mult in PATH)
print("handler path worst case: %d bytes; largest handler-path frames: %s" % (
    worst, ", ".join("%s=%d" % (n, frames[n]) for n in sorted(listed & set(frames), key=lambda x: -frames[x])[:8])))
if worst > LIMIT_PATH:
    fails.append("handler path %d > %d" % (worst, LIMIT_PATH))
for f in fails:
    print("FAIL " + f)
print("stack budget OK" if not fails else "stack budget FAILED")
sys.exit(1 if fails else 0)
