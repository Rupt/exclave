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
