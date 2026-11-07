/* launcher.c — entry point (DESIGN.md 7.2, 7.4.5, 7.6).
 *
 * The launcher is an ET_DYN object with no interpreter: it relocates itself, finds its exclave from its own path, reads
 * the manifest, decides whether it is at the border (no filter inherited) and prepares the environment accordingly,
 * installs the handler and, unless one of this version or newer is inherited, the filter, then loads the program it
 * stands for: the original of the wrapper it was run as, or the EXCLAVE_EXEC target when re-exec'd in loader mode, by
 * a handler or by its own positional entry.
 */
#include "common.h"

extern char __ehdr_start[] __attribute__((visibility("hidden"))), _etext[] __attribute__((visibility("hidden"))),
    _DYNAMIC[] __attribute__((visibility("hidden")));

#if defined(__x86_64__)
__asm__(".text\n.globl _start\n.type _start,@function\n_start:\n"
        " mov %rsp, %rdi\n and $-16, %rsp\n call start_c\n hlt\n");
#elif defined(__aarch64__)
__asm__(".text\n.globl _start\n.type _start,%function\n_start:\n"
        " mov x0, sp\n bl start_c\n brk #0\n");
#endif
/* 7, 7.4.5: the note by which a launcher recognises another in a file; its first word is PAGE_GENERATION, its second
 * FILTER_VERSION, which a launcher before version 10 does not write and a reader of one word does not read (7.4.2) */
#define NOTE_WORD_(g) #g
#define NOTE_WORD(g) NOTE_WORD_(g)
/* clang-format off */
__asm__(".section .note.exclave,\"a\"\n .balign 4\n"
        " .long 8\n .long 8\n .long 1\n .asciz \"exclave\"\n .balign 4\n .long " NOTE_WORD(PAGE_GENERATION) "\n .long "
        NOTE_WORD(FILTER_VERSION) "\n .text\n");
/* clang-format on */

/* the launcher is the part of exclave every exclave holds, so it carries the licence's text, which the MIT licence asks
 * to go with every copy; not loaded, and kept by the strip (scripts/build). readelf -p .exclave.license shows it */
__asm__(".pushsection .exclave.license,\"\",@progbits\n"
        " .incbin \"LICENSE\"\n"
        " .byte 0\n"
        ".popsection\n");
/* the build the launcher is from (7): the project's version and the commit, as `exclave version` prints it;
 * scripts/build defines it, and readelf -p .exclave.version shows it */
#ifndef EXCLAVE_VERSION
#define EXCLAVE_VERSION "unversioned" /* a compile outside scripts/build, as scripts/check makes */
#endif
__asm__(".pushsection .exclave.version,\"\",@progbits\n"
        " .asciz \"exclave " EXCLAVE_VERSION "\"\n"
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
    long m = __sc6_raw(NR_mmap, (long)SC_PAGE, 4096, PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);
    if (m != (long)SC_PAGE) {
        if (m >= 0) __sc6_raw(NR_munmap, m, 4096, 0, 0, 0, 0);
        static const char msg[] = "launcher: cannot map the syscall page\n";
        static const char busy[] = "launcher: another launcher is already resident in this process\n";
        if (m == -EEXIST) raw_fatal(busy, sizeof busy - 1);
        raw_fatal(msg, sizeof msg - 1);
    }
#if defined(__x86_64__)
    unsigned char *p = (unsigned char *)SC_PAGE;
    /* syscall; ret at the start and in the judge slot; mov $15, %eax; syscall, the restorer (sys.h) */
    static const unsigned char call[3] = {0x0f, 0x05, 0xc3}, restorer[7] = {0xb8, 15, 0, 0, 0, 0x0f, 0x05};
    for (unsigned long i = 0; i < 3; i++) p[i] = p[SC_JUDGE - SC_PAGE + i] = call[i];
    for (unsigned long i = 0; i < 7; i++) p[SC_RESTORER - SC_PAGE + i] = restorer[i];
#elif defined(__aarch64__)
    uint32_t *w = (uint32_t *)SC_PAGE;
    /* svc #0; ret at the start and in the judge slot; mov x8, #139; svc #0, the restorer (sys.h) */
    w[0] = w[(SC_JUDGE - SC_PAGE) / 4] = 0xd4000001U;
    w[1] = w[(SC_JUDGE - SC_PAGE) / 4 + 1] = 0xd65f03c0U;
    w[(SC_RESTORER - SC_PAGE) / 4] = 0xd2801168U;
    w[(SC_RESTORER - SC_PAGE) / 4 + 1] = 0xd4000001U;
    /* the written words reach the instruction fetch, a slot at a time, whatever the cache line's size */
    for (unsigned long a = SC_PAGE; a < SC_RESTORER + 16; a += 16)
        __asm__ volatile("dc cvau, %0\n dsb ish\n ic ivau, %0\n dsb ish\n" : : "r"(a) : "memory");
    __asm__ volatile("isb\n" : : : "memory");
#endif
    __sc6_raw(NR_mprotect, (long)SC_PAGE, 4096, PROT_READ | PROT_EXEC, 0, 0, 0);
}

typedef struct {
    uint64_t r_offset, r_info;
    int64_t r_addend;
} Rela;
static void reloc_self(void)
{
    unsigned long base = (unsigned long)__ehdr_start;
    long *d = (long *)_DYNAMIC;
    Rela *rela = 0;
    unsigned long relasz = 0, relaent = sizeof(Rela);
    for (; d[0]; d += 2) {
        if (d[0] == 7) rela = (Rela *)(base + (unsigned long)d[1]);   /* DT_RELA */
        else if (d[0] == 8) relasz = (unsigned long)d[1];             /* DT_RELASZ */
        else if (d[0] == 9) relaent = (unsigned long)d[1];            /* DT_RELAENT */
    }
    if (!rela) return;
    for (unsigned long i = 0; i < relasz / relaent; i++) {
        /* R_*_RELATIVE only */
        if ((rela[i].r_info & 0xffffffff) != R_NATIVE_RELATIVE) die("unexpected relocation in the launcher", 0, 0);
        *(unsigned long *)(base + rela[i].r_offset) = base + (unsigned long)rela[i].r_addend;
    }
}

static const char *find_env(char **envp, const char *name)
{
    size_t l = xstrlen(name);
    for (char **e = envp; *e; e++)
        if (xstrncmp(*e, name, l) == 0 && (*e)[l] == '=') return *e + l + 1;
    return 0;
}

/* 6.2: at the border the host's environment passes through minus the variables that would rebind the loader, the libc
 * or the compiler to the host, and minus four that name what the exclave decides for itself: the search path, the
 * locale, the time zone and the shell. Those four are set to the same values in every exclave on every host, what a
 * reproducible build fixes by hand; what an exclave wants on PATH lives in its own /usr/local/bin, and an exclave that
 * wants another locale or zone ships the data and a wrapper script. */
static const char *denied[] = {"GLIBC_TUNABLES",   "GCONV_PATH",   "LOCPATH", "NLSPATH",
                               "RESOLV_HOST_CONF", "HOSTALIASES",  "TZDIR",   "GCC_EXEC_PREFIX",
                               "COMPILER_PATH",    "LIBRARY_PATH", "PATH",    "LANG",
                               "LANGUAGE",         "TZ",           "SHELL",   0};
static const char *fixed[] = {"PATH=/usr/local/bin:/usr/bin:/bin", "LANG=C.UTF-8", "TZ=UTC0", "SHELL=/bin/sh", 0};
/* the launcher's protocol with itself (7.4.5): EXCLAVE_EXEC names a loader-path target, EXCLAVE_EXECFN and
 * EXCLAVE_COMM the identity the kernel would give the program, EXCLAVE_TRACED a process newly traced (retrace); set
 * by a handler or the positional entry, read by the launcher they exec, removed from the environment a program is
 * given (the kernel's copy in /proc/<pid>/environ keeps them, 13 item 46) */
static int internal_var(const char *e)
{
    return xstarts(e, "EXCLAVE_EXEC=") || xstarts(e, "EXCLAVE_EXECFN=") || xstarts(e, "EXCLAVE_COMM=") ||
           xstarts(e, "EXCLAVE_TRACED=");
}
static int env_denied(const char *e)
{
    if (xstarts(e, "LD_") || xstarts(e, "LC_") || internal_var(e)) return 1;
    for (int i = 0; denied[i]; i++) {
        size_t l = xstrlen(denied[i]);
        if (xstrncmp(e, denied[i], l) == 0 && e[l] == '=') return 1;
    }
    return 0;
}
/* an array of n pointers, mapped: as long as the environment or the arguments, which no limit of the arena's bounds */
static char **pointers(long n)
{
    long m = sys_mmap(0, ((size_t)n * sizeof(char *) + 0xfff) & ~(size_t)0xfff, PROT_READ | PROT_WRITE,
                      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (m < 0 && m > -4096) die("out of memory", 0, ENOMEM);
    return (char **)m;
}
static char **env_prepare(char **envp, int boundary)
{
    long n = 0;
    while (envp[n]) n++;
    char **out = pointers(n + 6);
    long k = 0;
    for (long i = 0; i < n; i++) {
        if (boundary ? env_denied(envp[i]) : internal_var(envp[i])) continue;
        out[k++] = envp[i];
    }
    /* writable: bash writes into its environment strings */
    if (boundary)
        for (int i = 0; fixed[i]; i++) out[k++] = arena_str(fixed[i], xstrlen(fixed[i]));
    out[k] = 0;
    return out;
}

/* a program at its descriptor limit may still exec, since the kernel's exec needs no descriptor (7.4.5): the launcher's
 * own opens, the manifest, the tree's top level, the program and its loader, borrow under the hard limit, the soft one
 * raised to it since the lowest free number may lie anywhere above a limit the program lowered below its open
 * descriptors, and given back in loader_run before the program runs. C.rlim holds the program's limits */
static void borrow(void)
{
    if (C.rlim[0] < 16 && C.rlim[0] < C.rlim[1]) {
        unsigned long more[2] = {C.rlim[1], C.rlim[1]};
        C.borrowed = SC4(NR_prlimit64, 0, RLIMIT_NOFILE, more, 0) == 0;
    }
}
/* the descriptor room borrowed at startup, given back before the launcher execs another launcher, which borrows for
 * itself */
static void unborrow(void)
{
    if (C.borrowed) {
        SC4(NR_prlimit64, 0, RLIMIT_NOFILE, C.rlim, 0);
        C.borrowed = 0;
    }
}

/* 7.6: a process a handler's exec has left newly traced, by a vfork child's deferred PTRACE_TRACEME, as a debugger
 * starts its program, execs the file the kernel ran, by its real path, once more with the same arguments and the
 * marker's value 2, which that launcher takes for the second exec and gdb's script reads. A debugger counts the
 * execs its start expects, the shell's and the program's, and takes the program's image for the file it was given; it
 * reads /proc/<pid>/exe only at an exec past that count, where it reads the launcher (7.6), loads its symbols and the
 * script it carries. Nothing when no tracer remains, a request the kernel refused or a tracer gone since; an exec that
 * fails runs the program without the second. */
static void retrace(const char *exe, char **argv, char **envp)
{
    if (!tracer_of("/proc/self/status")) return;
    long k = 0;
    while (envp[k]) k++;
    static char again[] = "EXCLAVE_TRACED=2";
    char **env = pointers(k + 1);
    for (long i = 0; i < k; i++) env[i] = xstarts(envp[i], "EXCLAVE_TRACED=") ? again : envp[i];
    env[k] = 0;
    int had = C.borrowed;
    unborrow();
    sys_execve(exe, argv, env);
    /* the exec failed: the room borrowed again for the launcher's own opens, the vector given back */
    if (had) borrow();
    SC2(NR_munmap, env, ((size_t)(k + 1) * sizeof(char *) + 0xfff) & ~(size_t)0xfff);
}

static long manifest_fd;
static void find_exclave(const char *exe)
{
    char d[PATH_MAX];
    scpy(d, exe, PATH_MAX);
    for (;;) {
        char *s = xstrrchr(d, '/');
        if (!s || s == d)
            die("not inside an exclave: a launcher runs from its exclave's .exclave/ or as a program in its tree/, and "
                "no directory above this one has .exclave/manifest",
                exe, 0);
        *s = 0;
        char p[PATH_MAX];
        scpy(p, d, PATH_MAX);
        scat(p, "/.exclave/manifest", PATH_MAX);
        /* opened where it is found, for read_manifest; one that fails to open for another reason than its absence
         * is still found, and read_manifest says why it cannot be read */
        manifest_fd = sys_open(p, O_RDONLY | O_CLOEXEC, 0);
        if (manifest_fd >= 0) break;
        struct kstat st;
        if (manifest_fd != -ENOENT && manifest_fd != -ENOTDIR && sys_stat(p, &st) == 0) break;
    }
    scpy(C.dir, d, PATH_MAX);
    scpy(C.root, d, PATH_MAX);
    scat(C.root, "/tree", PATH_MAX);
    C.rootlen = (long)xstrlen(C.root);
    scpy(C.launcher, d, PATH_MAX);
    scat(C.launcher, "/.exclave/launcher", PATH_MAX);
    struct kstat st;
    if (sys_stat(C.launcher, &st) < 0) die("exclave has no launcher", C.launcher, 0);
    C.launcher_dev = st.st_dev;
    C.launcher_ino = st.st_ino;
    C.launcher_size = st.st_size;
    if (sys_stat(C.root, &st) < 0 || (st.st_mode & S_IFMT) != S_IFDIR) die("exclave has no tree/", C.root, 0);
    C.root_dev = st.st_dev;
    C.root_ino = st.st_ino;
}

static void read_manifest(unsigned long *auxv)
{
    char p[PATH_MAX];
    scpy(p, C.dir, PATH_MAX);
    scat(p, "/.exclave/manifest", PATH_MAX);
    long fd = manifest_fd;
    if (fd < 0) die("cannot open manifest", p, fd);
    /* one that fits a page, as most do, is read whole, with no stat and no mapping (16.4); a longer one is mapped */
    static char small[4096];
    long n = 0, r = 0;
    while (n < (long)sizeof small && (r = sys_read((int)fd, small + n, sizeof small - (size_t)n)) > 0) n += r;
    if (r < 0) die("cannot read manifest", p, r);
    const char *m = small;
    size_t size = (size_t)n;
    if (n == (long)sizeof small) {
        struct kstat st;
        if (SC2(NR_fstat, fd, &st) < 0) die("cannot stat manifest", p, 0);
        long a = sys_mmap(0, (size_t)st.st_size, PROT_READ, MAP_PRIVATE, (int)fd, 0);
        if (a < 0 && a > -4096) die("cannot map manifest", p, a);
        m = (const char *)a;
        size = (size_t)st.st_size;
    }
    sys_close((int)fd);
    if (size == 0) die("manifest is empty", p, 0);
    char err[256];
    if (manifest_parse(m, size, &C, err, sizeof err) < 0) die("bad manifest", err, 0);
    if (m != small) SC2(NR_munmap, m, size);
    int ok = isa_supported(C.cpu, auxv);
    if (ok < 0) die("the exclave names a CPU level this launcher does not know", C.cpu, 0);
    if (ok == 0) die("this CPU lacks the exclave's CPU level", C.cpu, 0);
}

/* 7.2: the launcher run as a program rather than as a wrapper, `.exclave/launcher PROGRAM ARGS...`, takes the program
 * as its first argument and re-execs itself once the way a handler does for a program on the loader path (7.4.5): the
 * target carried in EXCLAVE_EXEC, which is the launcher's own protocol and is removed from the program's environment,
 * and argv shifted, so that the program's argv, cmdline and comm are its own. A relative program path is taken from
 * the working directory as execve would take it. */
static __attribute__((noreturn)) void entry_exec(long argc, char **argv, char **envp)
{
    if (argc < 2)
        die("this is an exclave's launcher, behind every program in tree/: run one of those by path, or "
            ".exclave/launcher PROGRAM [ARGS...] to run another inside the exclave; the exclave's README says more",
            0, 0);
    if (xstrlen(argv[1]) >= PATH_MAX) die("program path too long", 0, ENAMETOOLONG);
    char *t = arena_alloc(PATH_MAX);
    if (argv[1][0] == '/') scpy(t, argv[1], PATH_MAX);
    else {
        if (cwd_virtual(t) < 0) die("cannot read the working directory", 0, 0);
        if (xstrlen(t) + xstrlen(argv[1]) + 2 > PATH_MAX) die("program path too long", argv[1], 0);
        if (xstrcmp(t, "/") != 0) scat(t, "/", PATH_MAX);
        scat(t, argv[1], PATH_MAX);
    }
    char *var = arena_alloc(PATH_MAX + 13);
    scpy(var, "EXCLAVE_EXEC=", PATH_MAX + 13);
    scat(var, t, PATH_MAX + 13);
    /* the name as given: AT_EXECFN, comm, a script's $0 (7.6) */
    char *fn = arena_alloc(PATH_MAX + 15);
    scpy(fn, "EXCLAVE_EXECFN=", PATH_MAX + 15);
    scat(fn, argv[1], PATH_MAX + 15);
    long n = 0;
    while (envp[n]) n++;
    char **env = pointers(n + 3);
    long k = 0;
    for (long i = 0; i < n; i++)
        if (!internal_var(envp[i])) env[k++] = envp[i];
    /* after the program's own, as a handler places them (exec_env), so that the kernel lays the program's strings out
     * contiguously after its arguments */
    env[k++] = var;
    env[k++] = fn;
    env[k] = 0;
    unborrow();
    long r = sys_execve(C.launcher, argv + 1, env);
    die("cannot re-exec the launcher", C.launcher, r);
}

/* 7.4.5: what exec_target checks of a resolved file before it reads it, in its order: a data directory is EACCES (6.2),
 * then the name's own error, a directory or a special file EACCES, and the kernel's own answer to X_OK is final. The
 * exit status is a shell's: 126 for a file that exists and cannot run, 127 for one that does not. real receives the
 * file's real path. */
static void exec_checks(const char *v, char *real)
{
    if (vis_in_data(v)) die_status(126, "cannot execute", v, EACCES);
    to_real_exec(v, real);
    struct kstat st;
    long e = sys_stat(real, &st);
    if (e < 0) die_status(e == -ENOENT ? 127 : 126, "cannot execute", v, e);
    if ((st.st_mode & S_IFMT) != S_IFREG) die_status(126, "cannot execute", v, EACCES);
    long ok = sys_faccessat(AT_FDCWD, real, X_OK);
    if (ok < 0) die_status(126, "cannot execute", v, ok);
}

/* 7.4.5 for a target that arrived by EXCLAVE_EXEC, the positional entry's or a handler's: the checks exec_target makes
 * before loading anything, so that the entry refuses what an exec inside refuses: the target is resolved as an exec
 * resolves it and checked (exec_checks), and a wrapper is exec'd as itself so that the kernel gives the program its
 * identity. */
static void loader_mode_check(char **argv, char **env2)
{
    struct scratch *S = scratch_get((pid_t)sys_getpid(), (pid_t)sys_gettid(), 0);
    if (!S) die("out of memory", 0, ENOMEM);
    scpy(S->arg, C.program, PATH_MAX);                        /* the target as given, for the wrapper's exec */
    long r = canon(S, C.program, AT_FDCWD, 1, S->v);
    if (r < 0) die_status(r == -ENOENT ? 127 : 126, "cannot execute", C.program, r);
    scpy(C.program, S->v, PATH_MAX);
    exec_checks(C.program, S->real);
    /* a wrapper: the kernel runs the launcher under the program's name, exec'd by the name the caller spelt, /bin/sh,
     * so that comm is the kernel's answer for that name, and the kernel follows the last link. It follows it on the
     * host, though, where an absolute link of the tree leads to the host's file: the spelling is exec'd only when it
     * reaches this wrapper, and the wrapper by its own path otherwise (13 item 39) */
    if (is_wrapper_real(S->real, S->tmp) && payload_of(S->real, S->tmp)) {
        /* 7.4.2: under a program's own filter a launcher without the judge rule is not run, as a handler refuses it */
        int gen, version;
        if (program_filters &&
            (elf_probe(S->real, S->rest, &gen, &version, S->extra) < 0 || version < FILTER_JUDGE_SINCE))
            die("a launcher before filter version 10 is not run under a program's own seccomp filter", C.program, 0);
        if (canon(S, S->arg, AT_FDCWD, 0, S->v2) < 0) scpy(S->v2, C.program, PATH_MAX);
        to_real_exec(S->v2, S->real2);
        long fd = sys_open(S->real2, O_PATH | O_CLOEXEC, 0);
        long n = fd < 0 ? fd : fd_real_path((int)fd, S->cur);
        if (fd >= 0) sys_close((int)fd);
        if (n < 0 || xstrcmp(S->cur, S->real) != 0) scpy(S->real2, S->real, PATH_MAX);
        unborrow();
        long e = sys_execve(S->real2, argv, env2);
        die("cannot exec the wrapper", C.program, e);
    }
    scratch_put(S);
}

/* joins dir and name into out, PATH_MAX bytes; 0 when it does not fit */
static int join_path(char *out, const char *dir, const char *name)
{
    if (xstrlen(dir) + xstrlen(name) + 2 > PATH_MAX) return 0;
    scpy(out, dir, PATH_MAX);
    if (xstrcmp(dir, "/") != 0) scat(out, "/", PATH_MAX);
    scat(out, name, PATH_MAX);
    return 1;
}

/* 13 item 39: the $0 of a wrapped script run from outside, written to out. The spelling the kernel was given,
 * AT_EXECFN, names the file in the host's world; its chain of host links is followed, each name's directory resolved
 * on the host, to the first name that lies in the tree, and that name's virtual path, its last component kept, is $0
 * when it leads to the script, v. A script a link in the tree names, as /usr/bin/psql names postgresql-common's
 * pg_wrapper, which dispatches on its $0, thus gets the link's name, the last component the kernel would give it;
 * otherwise $0 is v. */
static void outside_spelling(const char *v, const unsigned long *auxv, char *out)
{
    scpy(out, v, PATH_MAX);
    const char *fn = 0;
    for (long i = 0; auxv[i * 2] != AT_NULL; i++)
        if (auxv[i * 2] == AT_EXECFN) fn = (const char *)auxv[i * 2 + 1];
    if (!fn || !fn[0]) return;
    char *p = arena_alloc(PATH_MAX), *dir = arena_alloc(PATH_MAX), *at = arena_alloc(PATH_MAX);
    char *text = arena_alloc(PATH_MAX);
    if (fn[0] == '/') {
        if (xstrlen(fn) >= PATH_MAX) return;
        scpy(p, fn, PATH_MAX);
    } else {
        if (sys_getcwd(dir, PATH_MAX) < 0 || !join_path(p, dir, fn)) return;
    }
    for (int hop = 0; hop < 40; hop++) {
        long slash = (long)xstrlen(p) - 1;
        while (slash > 0 && p[slash] != '/') slash--;
        const char *base = p + slash + 1;
        if (!base[0] || xstrcmp(base, ".") == 0 || xstrcmp(base, "..") == 0) return;
        if (slash == 0) scpy(dir, "/", PATH_MAX);
        else {
            xmemcpy(dir, p, (size_t)slash);
            dir[slash] = 0;
        }
        long fd = sys_open(dir, O_PATH | O_DIRECTORY | O_CLOEXEC, 0);
        if (fd < 0) return;
        long n = fd_real_path((int)fd, text);
        sys_close((int)fd);
        if (n < 0 || !join_path(at, text, base)) return;
        if (starts_dir(at, C.root) && xstrcmp(at, C.root) != 0) {
            from_real(at);
            struct scratch *S = scratch_get((pid_t)sys_getpid(), (pid_t)sys_gettid(), 0);
            if (!S) return;
            if (canon(S, at, AT_FDCWD, 1, S->v) >= 0 && xstrcmp(S->v, v) == 0) scpy(out, at, PATH_MAX);
            scratch_put(S);
            return;
        }
        struct kstat st;
        if (sys_lstat(at, &st) < 0 || (st.st_mode & S_IFMT) != S_IFLNK) return;
        long len = sys_readlink(at, text, PATH_MAX - 1);
        if (len <= 0) return;
        text[len] = 0;
        if (text[0] == '/') scpy(p, text, PATH_MAX);
        else {
            /* the link's directory, resolved above, is at without its last component */
            at[xstrlen(at) - xstrlen(base) - 1] = 0;
            if (!join_path(p, at[0] ? at : "/", text)) return;
        }
    }
}

/* 7.3, 7.4.5: load the program at virtual path v; scripts go through their interpreter (kernel convention) */
static __attribute__((noreturn)) void run(const char *v, const char *given, long argc, char **argv, char **envp,
                                          unsigned long *auxv, int depth)
{
    static char real[PATH_MAX], payload[PATH_MAX];
    /* as binfmt_script: five may nest (7.4.5) */
    if (depth > 5) die_status(126, "interpreter chain too deep", v, ELOOP);
    to_real_exec(v, real);
    if (is_wrapper_real(real, payload) && payload_of(real, payload)) scpy(real, payload, PATH_MAX);
    long fd = sys_open(real, O_RDONLY | O_CLOEXEC, 0);
    if (fd < 0) die("cannot open program", v, fd);
    /* the head the loader reads its headers from, of which a #! line is the first BINPRM_BUF_SIZE bytes */
    const char *head;
    long n = loader_head((int)fd, &head);
    if (n >= 4 && head[0] == 0x7f && head[1] == 'E' && head[2] == 'L' && head[3] == 'F') {
        if (!C.exe_fixed) scpy(C.exe, v, PATH_MAX);
        loader_run(v, real, (int)fd, argc, argv, envp, auxv);
    }
    sys_close((int)fd);
    if (n > BINPRM_BUF_SIZE) n = BINPRM_BUF_SIZE;
    char *line = arena_alloc(BINPRM_BUF_SIZE + 1);
    xmemcpy(line, head, (size_t)n);
    /* a script: the kernel's argv convention, with buffers that outlive this level of the interpreter chain */
    long cap = argc + 4;
    char **nargv = pointers(cap);
    char *script = arena_alloc(PATH_MAX);
    /* the script's path as it was spelt, as the kernel passes it (7.4.5); a wrapped script run from outside the
     * exclave gets a virtual path instead, since the spelling names the file in the host's world, where "$0.bin"
     * and $(dirname "$0")/sibling are not (13 item 39) */
    if (depth == 0 && C.boundary && !C.loader_mode) outside_spelling(v, auxv, script);
    else scpy(script, given, PATH_MAX);
    long k = shebang_argv(line, n, script, argv, argc, nargv, cap);
    if (k == -1) die_status(126, "not an executable", v, ENOEXEC);
    if (k == -2) die_status(126, "argument list too long", v, E2BIG);
    struct scratch *S = scratch_get((pid_t)sys_getpid(), (pid_t)sys_gettid(), 0);
    if (!S) die("out of memory", 0, ENOMEM);
    char *iv = arena_alloc(PATH_MAX);
    if (canon(S, nargv[0], AT_FDCWD, 1, iv) < 0) die_status(127, "cannot resolve interpreter", nargv[0], 0);
    scratch_put(S);
    /* the interpreter is checked as an exec of it would be: one under a data directory is never run (6.2) */
    exec_checks(iv, real);
    run(iv, nargv[0], k, nargv, envp, auxv, depth + 1);
}

__attribute__((used)) static void start_c(unsigned long *sp) /* called by _start */
{
    page_init();
    reloc_self();
    /* 7.4.2: the probe comes before any syscall an inherited filter could trap. have is the inherited
     * filter's version, nonzero when exec'd from inside an exclave, by a handler or a program. A filter older
     * than FILTER_PAGE_SINCE allows a launcher's syscalls from another page only and would trap every one of
     * this launcher's, so it is refused by name */
    int have = filter_probe();
    if (have && have < FILTER_PAGE_SINCE) {
        static const char old[] =
            "launcher: a launcher from before the syscall page moved runs this process; relink its exclave with the "
            "current launcher (docs/DESIGN.md 13 item 45)\n";
        raw_fatal(old, sizeof old - 1);
    }
    /* 7.4.2: a program's own filter inherited, made by a launcher's handler: the probe from the judge slot, which its
     * prologue answers MARK_PRESENT, outranking the launcher filter's answer; every trapped call is then judged */
    if (have >= FILTER_JUDGE_SINCE && __sc6_judge(NR_uname, (long)MAGIC, 0, 0, 0, 0, 0) == -MARK_PRESENT)
        program_filters = 1;
    long argc = (long)sp[0];
    char **argv = (char **)(sp + 1);
    char **envp = argv + argc + 1;
    char **e = envp;
    while (*e) e++;
    unsigned long *auxv = (unsigned long *)(e + 1);
    /* the loader maps at the kernel's page size (7.3); a power of two, or 4 KB */
    C.pagesz = 4096;
    for (long i = 0; auxv[i * 2] != AT_NULL; i++)
        if (auxv[i * 2] == AT_PAGESZ && auxv[i * 2 + 1] >= 4096 && !(auxv[i * 2 + 1] & (auxv[i * 2 + 1] - 1)))
            C.pagesz = auxv[i * 2 + 1];

    unsigned long m = SIGSYS_BIT;                    /* 7.5.2: SIGSYS must never be blocked */
    sys_rt_sigprocmask(SIG_UNBLOCK, &m, 0, 8);
    if (SC4(NR_prlimit64, 0, RLIMIT_NOFILE, 0, C.rlim) == 0) borrow();
    static char exe[PATH_MAX];
    long n = sys_readlink("/proc/self/exe", exe, PATH_MAX - 1);
    if (n < 0) die("cannot read /proc/self/exe", 0, n);
    exe[n] = 0;
    /* 7.6: only from inside, where a handler sets it, as the launcher's other variables are read. A process whose
     * arguments are -c and a command beginning "exec ", the shape of a debugger's shell (gdb's startup-with-shell runs
     * SHELL -c "exec PROGRAM ARGS"), leaves the second exec to its next, which its handler marks, since the debugger
     * counts the shell's exec among its start's */
    const char *traced = have ? find_env(envp, "EXCLAVE_TRACED") : 0;
    if (traced && traced[0] == '1') {
        if (argc >= 3 && xstrcmp(argv[1], "-c") == 0 && xstarts(argv[2], "exec ")) C.traced_pid = sys_getpid();
        else retrace(exe, argv, envp);
    }
    find_exclave(exe);
    log_open(envp);
    read_manifest(auxv);

    const char *target, *fn, *cm;
    C.descfd = -1;
    /* a wrapper: the kernel ran the launcher under the program's name. Decided first, so that EXCLAVE_EXEC in anyone's
     * environment is inert for the whole tree */
    if (starts_dir(exe, C.root)) {
        scpy(C.program, exe, PATH_MAX);
        from_real(C.program);
        /* the identity the kernel would have given the program (7.6): the name a handler exec'd this wrapper by, as the
         * kernel spells it, carried in EXCLAVE_EXECFN and EXCLAVE_COMM by that handler, which only a launcher sets;
         * from the host, the kernel's own AT_EXECFN, a real path, and its last component */
        fn = have ? find_env(envp, "EXCLAVE_EXECFN") : 0;
        cm = have ? find_env(envp, "EXCLAVE_COMM") : 0;
        if (fn) scpy(C.execfn, fn, PATH_MAX);
        else {
            for (long i = 0; auxv[i * 2] != AT_NULL; i++)
                if (auxv[i * 2] == AT_EXECFN) fn = (const char *)auxv[i * 2 + 1];
            scpy(C.execfn, fn ? fn : C.program, PATH_MAX);
            if (fn) from_real(C.execfn);
        }
        scpy(C.comm, cm ? cm : base_name(C.execfn), sizeof C.comm);
    } else if ((target = find_env(envp, "EXCLAVE_EXEC"))) {
        /* the internal protocol of 7.4.5: re-exec'd by a handler, or by entry_exec */
        if (target[0] != '/') die("EXCLAVE_EXEC must be an absolute path", target, 0);
        C.loader_mode = 1;
        scpy(C.program, target, PATH_MAX);
        /* the name the program was exec'd by, and its comm, as the kernel spells them (7.6) */
        fn = find_env(envp, "EXCLAVE_EXECFN");
        cm = find_env(envp, "EXCLAVE_COMM");
        scpy(C.execfn, fn ? fn : target, PATH_MAX);
        scpy(C.comm, cm ? cm : base_name(C.execfn), sizeof C.comm);
        /* a descriptor with no path (13 item 25): the kernel's identity for the program is the link's text; the dup is
         * closed once the segments are mapped */
        if (xstarts(target, "/proc/self/fd/")) {
            long len = sys_readlink(target, C.exe, PATH_MAX - 1);
            if (len > 0) {
                C.exe[len] = 0;
                C.exe_fixed = 1;
            }
            long fd = 0;
            for (const char *q = target + 14; *q >= '0' && *q <= '9'; q++) fd = fd * 10 + (*q - '0');
            C.descfd = (int)fd;
        }
    } else {
        /* the launcher run by hand: .exclave/launcher PROGRAM ARGS... */
        entry_exec(argc, argv, envp);
    }

    C.boundary = have == 0;
    char **env2 = env_prepare(envp, C.boundary);
    vis_init();
    cache_init();
    if (C.loader_mode) loader_mode_check(argv, env2);
    C.text_lo = (unsigned long)__ehdr_start;
    C.text_hi = (unsigned long)_etext;
    handler_install();
    /* a filter of this version stacked over a program's would answer the judge slot newer than it, hiding its
     * refusals (7.4.2) */
    if (have < FILTER_VERSION && program_filters)
        die("a launcher newer than the one that installed a program's own seccomp filter cannot run under it", 0, 0);
    if (have < FILTER_VERSION) filter_install();
    log_msg(C.boundary ? "border" : "inside", C.program);
    run(C.program, C.execfn, argc, argv, env2, auxv, 0);
}
