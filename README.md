# cont

`cont` turns environment-dependent Linux software, compilers first, into
a directory that behaves like a single static executable: copy it
anywhere, run any program inside it by path, and it never touches a host
library, header, loader or configuration file. No daemon, no image store,
no privileges, no host binaries, no run-time options.

A **can** is that directory: an unmodified filesystem tree plus one
static, freestanding binary, the **opener**, which every executable in
the tree is a hard link to. The opener projects the tree onto `/` with a
seccomp filter and a resident `SIGSYS` handler that rewrites every
path-taking syscall inside the process, and loads the original program
and the can's own `ld.so` itself. The **cannery** builds cans from
distribution packages or from source, and is itself a can.

## Status

Design settled; no application code yet. Two prototype spikes validated
the mechanism on a stock Ubuntu gcc 13, and four adversarial reviews
shaped the design. The next step is milestone 1a, the opener.

## Read in this order

1. `docs/PROPOSAL.md`: the design, self-contained. Sections 6 to 8 are
   the specification; 17 the tests; 18 the milestones; 19 the decisions.
2. `docs/REVIEW-RESPONSE.md`: every review finding and where it landed.
3. `docs/PRIOR-ART.md`: twenty related systems and the primary sources
   for the kernel and loader facts relied on.
4. `spike/README.md`: the prototypes, how to run them, and the defects
   they still contain.
5. `docs/reviews/`: the four review reports, historical.

## Layout

```
docs/PROPOSAL.md         the design (revision 6)
docs/REVIEW-RESPONSE.md  findings to changes
docs/PRIOR-ART.md        survey
docs/reviews/            adversarial review reports of revisions 4 and 5
spike/                   frozen prototypes and their tests
```

The opener will live in `src/`, the cannery in `cannery/`, tests in
`test/`; none exist yet.

## Names

`cont` is the codename and repository. `can` is the format and the
directory suffix. `opener` is the launcher. `cannery` is the build tool.
The environment knob is `CAN_LOG`.
