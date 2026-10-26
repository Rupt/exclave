/* launcher.c — entry point (PROPOSAL.md 7.2, 7.6, 9).
 *
 * The launcher is an ET_DYN object with no interpreter: it relocates itself,
 * finds its exclave from its own path, reads the manifest, decides whether it is at the
 * border (no filter inherited) and prepares the environment
 * accordingly, installs the handler and, unless one of this version or newer is inherited, the filter, then
 * loads the program it stands for: the original of the wrapper it was run as,
 * or the EXCLAVE_EXEC target when re-exec'd in loader mode, by a handler or by its own positional entry.
 */
#include "common.h"

extern char __ehdr_start[] __attribute__((visibility("hidden"))), _etext[] __attribute__((visibility("hidden"))), _DYNAMIC[] __attribute__((visibility("hidden")));

#if defined(__x86_64__)
__asm__(".text\n.globl _start\n.type _start,@function\n_start:\n"
        " mov %rsp, %rdi\n and $-16, %rsp\n call start_c\n hlt\n");
#elif defined(__aarch64__)
__asm__(".text\n.globl _start\n.type _start,%function\n_start:\n"
        " mov x0, sp\n bl start_c\n brk #0\n");
#endif
/* 7, 7.4.5: the notes by which a launcher recognises another in a file; their word is PAGE_GENERATION (7.4.2). The second,
 * named cont, is the one an opener of revision 17 or earlier looks for, so that each runs the other as another launcher */
#define NOTE_WORD_(g) #g
#define NOTE_WORD(g) NOTE_WORD_(g)
__asm__(".section .note.exclave,\"a\"\n .balign 4\n"
        " .long 8\n .long 4\n .long 1\n .asciz \"exclave\"\n .balign 4\n .long " NOTE_WORD(PAGE_GENERATION) "\n"
        " .long 5\n .long 4\n .long 1\n .asciz \"cont\"\n .balign 4\n .long " NOTE_WORD(PAGE_GENERATION) "\n .text\n");

/* the launcher is the part of exclave every exclave holds, so it carries the licence's text, which the MIT licence asks to go
 * with every copy; not loaded, and kept by the strip (Makefile). readelf -p .exclave.license shows it */
__asm__(".pushsection .exclave.license,\"\",@progbits\n"
        " .incbin \"LICENSE\"\n"
        " .byte 0\n"
        ".popsection\n");

/* before the page and the version check: a message and an exit, raw, as nothing else is allowed yet */
static void raw_fatal(const char *msg, long len)
{
    __sc6_raw(NR_write, 2, (long)msg, len, 0, 0, 0);
    for (;;) __sc6_raw(NR_exit_group, 127, 0, 0, 0, 0, 0);
}

/* 7.4.2: map the syscall page. Raw syscalls only: nothing else may run before this. */
static void page_init(void)
{
    long m = __sc6_raw(NR_mmap, (long)SC_PAGE, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);
    if (m != (long)SC_PAGE) {
        if (m >= 0) __sc6_raw(NR_munmap, m, 4096, 0, 0, 0, 0);
        static const char msg[] = "launcher: cannot map the syscall page\n";
        static const char busy[] = "launcher: another launcher is already resident in this process\n";
        if (m == -EEXIST) raw_fatal(busy, sizeof busy - 1);
        raw_fatal(msg, sizeof msg - 1);
    }
#if defined(__x86_64__)
    unsigned char *p = (unsigned char *)SC_PAGE; p[0] = 0x0f; p[1] = 0x05; p[2] = 0xc3;   /* syscall; ret */
#elif defined(__aarch64__)
    uint32_t *w = (uint32_t *)SC_PAGE; w[0] = 0xd4000001u; w[1] = 0xd65f03c0u;              /* svc #0; ret */
    __asm__ volatile ("dc cvau, %0\n dsb ish\n ic ivau, %0\n dsb ish\n isb\n" : : "r"(SC_PAGE) : "memory");   /* the written words reach the instruction fetch */
#endif
    __sc6_raw(NR_mprotect, (long)SC_PAGE, 4096, PROT_READ | PROT_EXEC, 0, 0, 0);
}

typedef struct { uint64_t r_offset, r_info; int64_t r_addend; } Rela;
static void reloc_self(void)
{
    unsigned long base = (unsigned long)__ehdr_start; long *d = (long *)_DYNAMIC;
    Rela *rela = 0; unsigned long relasz = 0, relaent = sizeof(Rela);
    for (; d[0]; d += 2) {
        if (d[0] == 7) rela = (Rela *)(base + (unsigned long)d[1]);   /* DT_RELA */
        else if (d[0] == 8) relasz = (unsigned long)d[1];             /* DT_RELASZ */
        else if (d[0] == 9) relaent = (unsigned long)d[1];            /* DT_RELAENT */
    }
    if (!rela) return;
    for (unsigned long i = 0; i < relasz / relaent; i++) {
        if ((rela[i].r_info & 0xffffffff) != R_NATIVE_RELATIVE) die("unexpected relocation in the launcher", 0, 0);   /* R_*_RELATIVE only */
        *(unsigned long *)(base + rela[i].r_offset) = base + (unsigned long)rela[i].r_addend;
    }
}

static const char *find_env(char **envp, const char *name)
{
    size_t l = xstrlen(name);
    for (char **e = envp; *e; e++) if (xstrncmp(*e, name, l) == 0 && (*e)[l] == '=') return *e + l + 1;
    return 0;
}

/* 6.2: at the border the host's environment passes through minus the variables that would rebind the
 * loader, the libc or the compiler to the host, and minus four that name what the exclave decides for itself:
 * the search path, the locale, the time zone and the shell. Those four are set to the same values in every
 * exclave on every host, what a reproducible build fixes by hand; what an exclave wants on PATH lives in its own
 * /usr/local/bin, and an exclave that wants another locale or zone ships the data and a wrapper script. */
static const char *denied[] = { "GLIBC_TUNABLES", "GCONV_PATH", "LOCPATH", "NLSPATH", "RESOLV_HOST_CONF", "HOSTALIASES",
                                "TZDIR", "GCC_EXEC_PREFIX", "COMPILER_PATH", "LIBRARY_PATH",
                                "PATH", "LANG", "LANGUAGE", "TZ", "SHELL", 0 };
static const char *fixed[] = { "PATH=/usr/local/bin:/usr/bin:/bin", "LANG=C.UTF-8", "TZ=UTC0", "SHELL=/bin/sh", 0 };
/* the launcher's protocol with itself (7.4.5): EXCLAVE_EXEC names a loader-path target, EXCLAVE_EXECFN and EXCLAVE_COMM the identity the
 * kernel would give the program; set by a handler or the positional entry, read by the launcher they exec, removed from the environment a program is given (the kernel's copy in
 * /proc/<pid>/environ keeps them, 13 item 46) */
static int internal_var(const char *e) { return xstarts(e, "EXCLAVE_EXEC=") || xstarts(e, "EXCLAVE_EXECFN=") || xstarts(e, "EXCLAVE_COMM="); }
static int env_denied(const char *e)
{
    if (xstarts(e, "LD_") || xstarts(e, "LC_") || internal_var(e)) return 1;
    for (int i = 0; denied[i]; i++) { size_t l = xstrlen(denied[i]); if (xstrncmp(e, denied[i], l) == 0 && e[l] == '=') return 1; }
    return 0;
}
static char **env_prepare(char **envp, int boundary)
{
    long n = 0; while (envp[n]) n++;
    char **out = arena_alloc((size_t)(n + 6) * sizeof(char *)); long k = 0;
    for (long i = 0; i < n; i++) {
        if (boundary ? env_denied(envp[i]) : internal_var(envp[i])) continue;
        out[k++] = envp[i];
    }
    if (boundary) for (int i = 0; fixed[i]; i++) out[k++] = (char *)arena_str(fixed[i], xstrlen(fixed[i]));   /* writable: bash writes into its environment strings (F3-23) */
    out[k] = 0;
    return out;
}

/* the descriptor room borrowed at startup (7.4.5), given back before the launcher execs another launcher, which borrows for itself */
static void unborrow(void) { if (C.borrowed) { SC4(NR_prlimit64, 0, RLIMIT_NOFILE, C.rlim, 0); C.borrowed = 0; } }

static void find_exclave(const char *exe)
{
    char d[PATH_MAX]; scpy(d, exe, PATH_MAX);
    for (;;) {
        char *s = xstrrchr(d, '/'); if (!s || s == d) die("not inside an exclave: a launcher runs from its exclave's .exclave/ or as a program in its tree/, and no directory above this one has .exclave/manifest", exe, 0);
        *s = 0;
        char p[PATH_MAX]; scpy(p, d, PATH_MAX); scat(p, "/.exclave/manifest", PATH_MAX);
        struct kstat st;
        if (sys_stat(p, &st) == 0) break;
    }
    scpy(C.dir, d, PATH_MAX);
    scpy(C.root, d, PATH_MAX); scat(C.root, "/tree", PATH_MAX); C.rootlen = (long)xstrlen(C.root);
    scpy(C.launcher, d, PATH_MAX); scat(C.launcher, "/.exclave/launcher", PATH_MAX);
    struct kstat st;
    if (sys_stat(C.launcher, &st) < 0) die("exclave has no launcher", C.launcher, 0);
    C.launcher_dev = st.st_dev; C.launcher_ino = st.st_ino; C.launcher_size = st.st_size;
    if (sys_stat(C.root, &st) < 0 || (st.st_mode & S_IFMT) != S_IFDIR) die("exclave has no tree/", C.root, 0);
    C.root_dev = st.st_dev; C.root_ino = st.st_ino;
}

static void read_manifest(unsigned long *auxv)
{
    char p[PATH_MAX]; scpy(p, C.dir, PATH_MAX); scat(p, "/.exclave/manifest", PATH_MAX);
    long fd = sys_open(p, O_RDONLY | O_CLOEXEC, 0); if (fd < 0) die("cannot open manifest", p, fd);
    struct kstat st; if (SC2(NR_fstat, fd, &st) < 0) die("cannot stat manifest", p, 0);
    if (st.st_size == 0) die("manifest is empty", p, 0);
    long m = sys_mmap(0, (size_t)st.st_size, PROT_READ, MAP_PRIVATE, (int)fd, 0);
    if (m < 0 && m > -4096) die("cannot map manifest", p, m);
    sys_close((int)fd);
    char err[256];
    if (manifest_parse((const char *)m, (size_t)st.st_size, &C, err, sizeof err) < 0) die("bad manifest", err, 0);
    SC2(NR_munmap, m, st.st_size);
    int ok = isa_supported(C.cpu, auxv);
    if (ok < 0) die("the exclave names a CPU level this launcher does not know", C.cpu, 0);
    if (ok == 0) die("this CPU lacks the exclave's CPU level", C.cpu, 0);
}

/* 7.2: the launcher run as a program rather than as a wrapper, `.exclave/launcher PROGRAM ARGS...`, takes the program
 * as its first argument and re-execs itself once the way a handler does for a program on the loader path
 * (7.4.5): the target carried in EXCLAVE_EXEC, which is the launcher's own protocol and is removed from the program's environment, and
 * argv shifted, so that the program's argv, cmdline and comm are its own. A relative program path is taken
 * from the working directory as execve would take it. */
static __attribute__((noreturn)) void entry_exec(long argc, char **argv, char **envp)
{
    if (argc < 2) die("this is an exclave's launcher, behind every program in tree/: run one of those by path, or .exclave/launcher PROGRAM [ARGS...] to run another inside the exclave; the exclave's README says more", 0, 0);
    if (xstrlen(argv[1]) >= PATH_MAX) die("program path too long", 0, ENAMETOOLONG);
    char *t = arena_alloc(PATH_MAX);
    if (argv[1][0] == '/') scpy(t, argv[1], PATH_MAX);
    else {
        if (cwd_virtual(t) < 0) die("cannot read the working directory", 0, 0);
        if (xstrlen(t) + xstrlen(argv[1]) + 2 > PATH_MAX) die("program path too long", argv[1], 0);
        if (xstrcmp(t, "/") != 0) scat(t, "/", PATH_MAX);
        scat(t, argv[1], PATH_MAX);
    }
    char *var = arena_alloc(PATH_MAX + 13); scpy(var, "EXCLAVE_EXEC=", PATH_MAX + 13); scat(var, t, PATH_MAX + 13);
    char *fn = arena_alloc(PATH_MAX + 15); scpy(fn, "EXCLAVE_EXECFN=", PATH_MAX + 15); scat(fn, argv[1], PATH_MAX + 15);   /* the name as given: AT_EXECFN, comm, a script's $0 (7.6) */
    long n = 0; while (envp[n]) n++;
    char **env = arena_alloc((size_t)(n + 3) * sizeof(char *)); long k = 0;
    env[k++] = var; env[k++] = fn;
    for (long i = 0; i < n; i++) if (!internal_var(envp[i])) env[k++] = envp[i];
    env[k] = 0;
    unborrow();
    long r = sys_execve(C.launcher, argv + 1, env);
    die("cannot re-exec the launcher", C.launcher, r);
}

/* 7.4.5 for a target that arrived by EXCLAVE_EXEC, the positional entry's or a handler's: the checks exec_target makes before
 * loading anything, in its order, so that the entry refuses what an exec inside refuses (review O5-1, F5-1): the target is
 * resolved as an exec resolves it, a data directory is EACCES, a directory or a special file EACCES, the kernel's own answer
 * to X_OK is final, and a wrapper is exec'd as itself so that the kernel gives the program its identity (F5-9). The exit
 * status is a shell's: 126 for a file that exists and cannot run, 127 for one that does not. */
static void loader_mode_check(char **argv, char **env2)
{
    struct scratch *S = scratch_get((pid_t)sys_getpid(), (pid_t)sys_gettid(), 0); if (!S) die("out of memory", 0, ENOMEM);
    scpy(S->b1, C.program, PATH_MAX);                         /* the target as given, for the wrapper exec below */
    long r = canon(S, C.program, AT_FDCWD, 1, S->v); if (r < 0) die_status(r == -ENOENT ? 127 : 126, "cannot execute", C.program, r);
    scpy(C.program, S->v, PATH_MAX);
    if (vis_in_data(C.program)) die_status(126, "cannot execute", C.program, EACCES);   /* 6.2: a data directory is never executed */
    to_real_exec(C.program, S->real);
    struct kstat st;
    if (sys_stat(S->real, &st) < 0) die_status(127, "cannot execute", C.program, ENOENT);
    if ((st.st_mode & S_IFMT) != S_IFREG) die_status(126, "cannot execute", C.program, EACCES);
    long ok = sys_faccessat(AT_FDCWD, S->real, X_OK); if (ok < 0) die_status(126, "cannot execute", C.program, ok);
    if (is_wrapper_real(S->real, S->tmp) && payload_of(S->real, S->tmp)) {   /* a wrapper: the kernel runs the launcher under the program's name,
                                                                              * exec'd by the name the caller spelt, /bin/sh, so that comm is the
                                                                              * kernel's answer for that name; the kernel follows the last link */
        if (canon(S, S->b1, AT_FDCWD, 0, S->v2) < 0) scpy(S->v2, C.program, PATH_MAX);
        to_real_exec(S->v2, S->b2);
        unborrow();
        long e = sys_execve(S->b2, argv, env2);
        die("cannot exec the wrapper", C.program, e);
    }
    scratch_put(S);
}

/* 7.3, 7.4.5: load the program at virtual path v; scripts go through their interpreter (kernel convention) */
static __attribute__((noreturn)) void run(const char *v, const char *given, long argc, char **argv, char **envp, unsigned long *auxv, int depth)
{
    static char real[PATH_MAX], payload[PATH_MAX];
    if (depth > 5) die_status(126, "interpreter chain too deep", v, ELOOP);   /* as binfmt_script: five may nest (7.4.5) */
    to_real_exec(v, real);
    if (is_wrapper_real(real, payload) && payload_of(real, payload)) scpy(real, payload, PATH_MAX);
    long fd = sys_open(real, O_RDONLY | O_CLOEXEC, 0); if (fd < 0) die("cannot open program", v, fd);
    char *line = arena_alloc(256); long n = sys_read((int)fd, line, 255); sys_close((int)fd);
    if (n >= 4 && line[0] == 0x7f && line[1] == 'E' && line[2] == 'L' && line[3] == 'F') { if (!C.exe_fixed) scpy(C.exe, v, PATH_MAX); loader_run(v, real, argc, argv, envp, auxv); }
    if (n < 0) n = 0;
    line[n] = 0;
    /* a script: the kernel's argv convention, with buffers that outlive this level of the interpreter chain */
    long cap = argc + 4;
    long m = sys_mmap(0, ((size_t)cap * sizeof(char *) + 0xfff) & ~(size_t)0xfff, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (m < 0 && m > -4096) die("out of memory", 0, ENOMEM);
    char **nargv = (char **)m; char *script = arena_alloc(PATH_MAX);       /* sized from argc, never from a fixed pool (F3-2) */
    scpy(script, given, PATH_MAX);                            /* the script's path as it was spelt, as the kernel passes it (7.4.5) */
    long k = shebang_argv(line, script, argv, argc, nargv, cap);
    if (k == -1) die_status(126, "not an executable", v, ENOEXEC);
    if (k == -2) die_status(126, "argument list too long", v, E2BIG);
    struct scratch *S = scratch_get((pid_t)sys_getpid(), (pid_t)sys_gettid(), 0); if (!S) die("out of memory", 0, ENOMEM);
    char *iv = arena_alloc(PATH_MAX);
    if (canon(S, nargv[0], AT_FDCWD, 1, iv) < 0) die_status(127, "cannot resolve interpreter", nargv[0], 0);
    scratch_put(S);
    run(iv, nargv[0], k, nargv, envp, auxv, depth + 1);
}

void start_c(unsigned long *sp)
{
    page_init();
    reloc_self();
    /* 7.4.2: the probe comes before any syscall an inherited filter could trap. A filter from before the page moved allows
     * a launcher's syscalls from the old page only and would trap every one of this launcher's, so it is refused by name */
    int have = filter_probe();                                /* a filter inherited: exec'd from inside an exclave, by a handler or a program */
    if (have && have < FILTER_PAGE_SINCE) {
        static const char old[] = "launcher: a launcher from before the syscall page moved runs this process; relink its exclave with the current tool, converting a can from before revision 18 first (README)\n";
        raw_fatal(old, sizeof old - 1);
    }
    long argc = (long)sp[0]; char **argv = (char **)(sp + 1); char **envp = argv + argc + 1;
    char **e = envp; while (*e) e++;
    unsigned long *auxv = (unsigned long *)(e + 1);
    C.pagesz = 4096;                                          /* the loader maps at the kernel's page size (7.3); a power of two, or 4 KB */
    for (long i = 0; auxv[i * 2] != AT_NULL; i++)
        if (auxv[i * 2] == AT_PAGESZ && auxv[i * 2 + 1] >= 4096 && !(auxv[i * 2 + 1] & (auxv[i * 2 + 1] - 1))) C.pagesz = auxv[i * 2 + 1];

    unsigned long m = 1UL << (SIGSYS - 1);                    /* 7.5.2: SIGSYS must never be blocked */
    sys_rt_sigprocmask(SIG_UNBLOCK, &m, 0, 8);
    /* a program at its descriptor limit may still exec, since the kernel's exec needs no descriptor (7.4.5): the launcher's
     * own opens, the manifest, the tree's top level, the program and its loader, borrow two under the hard limit, given
     * back in loader_run before the program runs */
    if (SC4(NR_prlimit64, 0, RLIMIT_NOFILE, 0, C.rlim) == 0 && C.rlim[0] < 16 && C.rlim[0] < C.rlim[1]) {
        unsigned long more[2] = { C.rlim[0] + 2 < C.rlim[1] ? C.rlim[0] + 2 : C.rlim[1], C.rlim[1] };
        C.borrowed = SC4(NR_prlimit64, 0, RLIMIT_NOFILE, more, 0) == 0;
    }
    log_open(envp);

    static char exe[PATH_MAX];
    long n = sys_readlink("/proc/self/exe", exe, PATH_MAX - 1); if (n < 0) die("cannot read /proc/self/exe", 0, n);
    exe[n] = 0;
    find_exclave(exe);
    read_manifest(auxv);

    const char *target, *fn, *cm;
    if (starts_dir(exe, C.root)) {                            /* a wrapper: the kernel ran the launcher under the program's name. Decided first,
                                                              * so that EXCLAVE_EXEC in anyone's environment is inert for the whole tree (review O5-3, F5-4) */
        scpy(C.program, exe, PATH_MAX); from_real(C.program);
        /* the identity the kernel would have given the program (7.6): the name a handler exec'd this wrapper by, as the kernel spells it,
         * carried in EXCLAVE_EXECFN and EXCLAVE_COMM by that handler, which only a launcher sets; from the host, the kernel's own AT_EXECFN, a
         * real path, and its last component */
        fn = have ? find_env(envp, "EXCLAVE_EXECFN") : 0; cm = have ? find_env(envp, "EXCLAVE_COMM") : 0;
        if (fn) scpy(C.execfn, fn, PATH_MAX);
        else {
            for (long i = 0; auxv[i * 2] != AT_NULL; i++) if (auxv[i * 2] == AT_EXECFN) fn = (const char *)auxv[i * 2 + 1];
            scpy(C.execfn, fn ? fn : C.program, PATH_MAX); if (fn) from_real(C.execfn);
        }
        scpy(C.comm, cm ? cm : base_name(C.execfn), sizeof C.comm);
    } else if ((target = find_env(envp, "EXCLAVE_EXEC"))) {       /* the internal protocol of 7.4.5: re-exec'd by a handler, or by entry_exec below */
        if (target[0] != '/') die("EXCLAVE_EXEC must be an absolute path", target, 0);
        C.loader_mode = 1; scpy(C.program, target, PATH_MAX);
        fn = find_env(envp, "EXCLAVE_EXECFN"); cm = find_env(envp, "EXCLAVE_COMM");   /* the name the program was exec'd by, and its comm, as the kernel spells them (7.6) */
        scpy(C.execfn, fn ? fn : target, PATH_MAX);
        scpy(C.comm, cm ? cm : base_name(C.execfn), sizeof C.comm);
        C.descfd = -1;
        if (xstarts(target, "/proc/self/fd/")) {               /* a descriptor with no path (13 item 25): the kernel's identity for the
                                                              * program is the link's text; the dup is closed once the segments are mapped */
            long n = sys_readlink(target, C.exe, PATH_MAX - 1); if (n > 0) { C.exe[n] = 0; C.exe_fixed = 1; }
            long m = 0; for (const char *q = target + 14; *q >= '0' && *q <= '9'; q++) m = m * 10 + (*q - '0');
            C.descfd = (int)m;
        }
    } else {
        entry_exec(argc, argv, envp);                          /* the launcher run by hand: .exclave/launcher PROGRAM ARGS... */
    }

    C.boundary = have == 0;
    char **env2 = env_prepare(envp, C.boundary);
    vis_init();
    if (C.loader_mode) loader_mode_check(argv, env2);
    C.text_lo = (unsigned long)__ehdr_start; C.text_hi = (unsigned long)_etext;
    handler_install();
    if (have < FILTER_VERSION) filter_install();
    log_msg(C.boundary ? "border" : "inside", C.program);
    run(C.program, C.execfn, argc, argv, env2, auxv, 0);
}
