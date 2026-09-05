#!/usr/bin/env python3
"""Stack budget check (PROPOSAL.md 7.5.4): reads gcc -fstack-usage output.

Fails if any function on the handler path has a frame above 512 bytes, or a
dynamic frame, or if the handler path's worst-case sum exceeds 2048 bytes.
The path is: on_sigsys -> dispatch -> do_* -> resolve -> canon -> to_real ->
is_wrapper_real -> payload_of, plus copy_str_in/copy_in and scratch_get.
"""
import sys, re, collections

LIMIT_FRAME = 512
LIMIT_PATH = 2048
PATH = [
    ["on_sigsys"], ["dispatch"], ["do_open", "do_execve", "do_readlink", "do_sigprocmask", "do_pselect6", "exec_target", "exec_script", "exec_loader_mode"],
    ["resolve", "canon", "fd_virtual", "cwd_virtual", "ro_create", "ro_attr", "exists_can", "to_real", "to_real_exec", "vis_is_host"],
    ["copy_str_in", "copy_in", "scratch_get", "is_wrapper_real", "payload_of", "from_real", "wrapper_of_payload", "log_line"],
]
frames = {}
for f in sys.argv[1:]:
    for line in open(f):
        m = re.match(r"^(\S+?):\d+:\d+:(\S+)\s+(\d+)\s+(\w+)", line)
        if not m:
            continue
        name, size, kind = m.group(2), int(m.group(3)), m.group(4)
        frames[name] = max(frames.get(name, 0), size)
        if kind != "static" and "bounded" not in line and name in {n for lvl in PATH for n in lvl}:
            print(f"FAIL {name}: unbounded dynamic frame ({kind})"); sys.exit(1)
bad = [(n, s) for n, s in frames.items() if s > LIMIT_FRAME and n in {x for lvl in PATH for x in lvl}]
worst = 0
for lvl in PATH:
    worst += max(frames.get(n, 0) for n in lvl)
print(f"handler path worst case: {worst} bytes over {len(PATH)} levels; largest frames: " +
      ", ".join(f"{n}={frames[n]}" for n in sorted(frames, key=frames.get, reverse=True)[:8]))
if bad:
    print("FAIL frames over %d: %s" % (LIMIT_FRAME, bad)); sys.exit(1)
if worst > LIMIT_PATH:
    print(f"FAIL handler path {worst} > {LIMIT_PATH}"); sys.exit(1)
print("stack budget OK")
