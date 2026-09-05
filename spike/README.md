# Spike: the trap backend on a stock gcc

Prototype written to retire the risks in `docs/PROPOSAL.md` section 14
before building the opener. Not the application; kept as evidence and as
the reference for the resident handler and the userland loader.

Reproduce (needs an Ubuntu/Debian host for the package extraction only):

    ./make-tree.sh /tmp/gccroot            # ~350 MB, no root needed
    ./build.sh                             # 31 KB static, freestanding
    cc -O2 -o /tmp/hello tests/hello.c     # any C file will do
    aa-exec -p unconfined \                # simulate a plain terminal on Ubuntu 24.04
      env -i PATH=/usr/bin:/bin ./spike -r /tmp/gccroot -p /tmp:/proc:/dev:/sys:/run \
      -- /usr/bin/gcc-13 tests/hello.c -o /tmp/hello_can && /tmp/hello_can

Options: `-d` debug to stderr, `-t FILE` append every translated path,
`-p` colon-separated host passthrough prefixes, `-r` root (omit for identity).

Results on 2026-09-05, Ubuntu 24.04, kernel 7.0, 16 cores: see PROPOSAL.md
section 17.

## Spike 2: the opener as the can's ELF interpreter

`spike2.c` is built as an `ET_DYN` object with no `PT_INTERP` (`build2.sh`),
so the same file runs as the entry program, serves as the `PT_INTERP` of every
patched ELF in the tree through `/proc/self/fd/999`, and loads itself for
targets that have no usable interpreter. `patch-interp.py ROOT` rewrites the
interpreter string of every ELF under ROOT in place and prints the originals.

    cp -a /tmp/gccroot /tmp/gccroot2 && ./patch-interp.py /tmp/gccroot2 > interp.txt
    ./build2.sh
    aa-exec -p unconfined env -i PATH=/usr/bin:/bin ./spike2 -r /tmp/gccroot2 \
      -p /tmp:/proc:/dev:/sys:/run:/etc/localtime -- /usr/bin/gcc-13 tests/hello.c -o /tmp/h

`-i INTERP` names the can's real `ld.so` (default `/lib64/ld-linux-x86-64.so.2`;
use `/lib/ld-musl-x86_64.so.1` for a musl tree). Results: PROPOSAL.md section 16.
