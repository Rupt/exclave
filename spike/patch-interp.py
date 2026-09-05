#!/usr/bin/env python3
"""Rewrite PT_INTERP of every ELF under ROOT to /proc/self/fd/999 (in place, reversible: originals listed to stdout)."""
import os, struct, sys
root = sys.argv[1]; new = b"/proc/self/fd/999\0"
n = skipped = 0
for d, _, fs in os.walk(root):
    for f in fs:
        p = os.path.join(d, f)
        if os.path.islink(p) or not os.path.isfile(p): continue
        try:
            with open(p, "r+b") as fh:
                h = fh.read(64)
                if len(h) < 64 or h[:4] != b"\x7fELF" or h[4] != 2: continue
                phoff, = struct.unpack_from("<Q", h, 32); phentsize, phnum = struct.unpack_from("<HH", h, 54)
                fh.seek(phoff); ph = fh.read(phentsize * phnum)
                for i in range(phnum):
                    ptype, = struct.unpack_from("<I", ph, i * phentsize)
                    if ptype != 3: continue
                    off, = struct.unpack_from("<Q", ph, i * phentsize + 8); sz, = struct.unpack_from("<Q", ph, i * phentsize + 32)
                    fh.seek(off); old = fh.read(sz)
                    if old == new.ljust(sz, b"\0"): break
                    if sz < len(new): skipped += 1; print("SKIP short interp", p, old, file=sys.stderr); break
                    fh.seek(off); fh.write(new.ljust(sz, b"\0")); n += 1
                    print(os.path.relpath(p, root), old.rstrip(b"\0").decode())
                    break
        except PermissionError: skipped += 1
print(f"patched {n}, skipped {skipped}", file=sys.stderr)
