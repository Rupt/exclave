/* opener.c — entry point (PROPOSAL.md 7.2, 7.6, 9).
 *
 * The opener is an ET_DYN object with no interpreter: it relocates itself,
 * finds its can from its own path, reads the manifest, decides whether it is the
 * can boundary (no filter inherited) and prepares the environment
 * accordingly, installs the handler and, at the boundary, the filter, then
 * loads the program it stands for: the payload of the wrapper it was run as,
 * or the CAN_EXEC target when re-exec'd in loader mode.
 */
#include "common.h"

extern char __ehdr_start[] __attribute__((visibility("hidden"))), _etext[] __attribute__((visibility("hidden"))), _DYNAMIC[] __attribute__((visibility("hidden")));

__asm__(".text\n.globl _start\n.type _start,@function\n_start:\n"
        " mov %rsp, %rdi\n and $-16, %rsp\n call start_c\n hlt\n");
/* 6.1: the note by which the opener recognises itself in a file */
__asm__(".section .note.cont,\"a\"\n .balign 4\n .long 5\n .long 4\n .long 1\n .asciz \"cont\"\n .balign 4\n .long 1\n .text\n");

/* 7.4.2: map the syscall page. Raw syscalls only: nothing else may run before this. */
static void page_init(void)
{
    long m = __sc6_raw(NR_mmap, (long)SC_PAGE, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);
    if (m != (long)SC_PAGE) {
        if (m >= 0) __sc6_raw(NR_munmap, m, 4096, 0, 0, 0, 0);
        static const char msg[] = "opener: cannot map the syscall page\n";
        static const char busy[] = "opener: another opener is already resident in this process\n";
        if (m == -EEXIST) __sc6_raw(NR_write, 2, (long)busy, sizeof busy - 1, 0, 0, 0);
        else __sc6_raw(NR_write, 2, (long)msg, sizeof msg - 1, 0, 0, 0);
        for (;;) __sc6_raw(NR_exit_group, 127, 0, 0, 0, 0, 0);
    }
    unsigned char *p = (unsigned char *)SC_PAGE; p[0] = 0x0f; p[1] = 0x05; p[2] = 0xc3;   /* syscall; ret */
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
        if ((rela[i].r_info & 0xffffffff) != 8) die("unexpected relocation in the opener", 0, 0);   /* R_X86_64_RELATIVE */
        *(unsigned long *)(base + rela[i].r_offset) = base + (unsigned long)rela[i].r_addend;
    }
}

static const char *find_env(char **envp, const char *name)
{
    size_t l = xstrlen(name);
    for (char **e = envp; *e; e++) if (xstrncmp(*e, name, l) == 0 && (*e)[l] == '=') return *e + l + 1;
    return 0;
}

/* 6.2: at the boundary the host's environment passes through minus the variables that would rebind
 * the loader, the libc or the compiler to the host; PATH is the can's, always the same: what a can wants
 * on it lives in its own /usr/local/bin. */
static const char *denied[] = { "GLIBC_TUNABLES", "GCONV_PATH", "LOCPATH", "NLSPATH", "RESOLV_HOST_CONF", "HOSTALIASES",
                                "TZDIR", "GCC_EXEC_PREFIX", "COMPILER_PATH", "LIBRARY_PATH", 0 };
static int env_denied(const char *e)
{
    if (xstarts(e, "LD_") || xstarts(e, "CAN_EXEC=") || xstarts(e, "PATH=")) return 1;   /* PATH is the can's (6.2, 13.7) */
    for (int i = 0; denied[i]; i++) { size_t l = xstrlen(denied[i]); if (xstrncmp(e, denied[i], l) == 0 && e[l] == '=') return 1; }
    return 0;
}
static char **env_prepare(char **envp, int boundary)
{
    long n = 0; while (envp[n]) n++;
    char **out = arena_alloc((size_t)(n + 2) * sizeof(char *)); long k = 0;
    for (long i = 0; i < n; i++) {
        if (boundary ? env_denied(envp[i]) : xstarts(envp[i], "CAN_EXEC=")) continue;
        out[k++] = envp[i];
    }
    if (boundary) out[k++] = (char *)arena_str("PATH=/usr/local/bin:/usr/bin:/bin", 33);   /* writable: bash writes into its environment strings (F3-23) */
    out[k] = 0;
    return out;
}

static void find_can(const char *exe)
{
    char d[PATH_MAX]; scpy(d, exe, PATH_MAX);
    for (;;) {
        char *s = xstrrchr(d, '/'); if (!s || s == d) die("not inside a can", exe, 0);
        *s = 0;
        char p[PATH_MAX]; scpy(p, d, PATH_MAX); scat(p, "/.can/manifest", PATH_MAX);
        struct kstat st;
        if (sys_stat(p, &st) == 0) break;
    }
    scpy(C.dir, d, PATH_MAX);
    scpy(C.root, d, PATH_MAX); scat(C.root, "/root", PATH_MAX); C.rootlen = (long)xstrlen(C.root);
    scpy(C.opener, d, PATH_MAX); scat(C.opener, "/.can/opener", PATH_MAX);
    struct kstat st;
    if (sys_stat(C.opener, &st) < 0) die("can has no opener", C.opener, 0);
    C.opener_dev = st.st_dev; C.opener_ino = st.st_ino; C.opener_size = st.st_size;
    if (sys_stat(C.root, &st) < 0 || (st.st_mode & S_IFMT) != S_IFDIR) die("can has no root/", C.root, 0);
    C.root_dev = st.st_dev; C.root_ino = st.st_ino;
}

static void read_manifest(void)
{
    char p[PATH_MAX]; scpy(p, C.dir, PATH_MAX); scat(p, "/.can/manifest", PATH_MAX);
    long fd = sys_open(p, O_RDONLY | O_CLOEXEC, 0); if (fd < 0) die("cannot open manifest", p, fd);
    struct kstat st; if (SC2(NR_fstat, fd, &st) < 0) die("cannot stat manifest", p, 0);
    if (st.st_size == 0) die("manifest is empty", p, 0);
    long m = sys_mmap(0, (size_t)st.st_size, PROT_READ, MAP_PRIVATE, (int)fd, 0);
    if (m < 0 && m > -4096) die("cannot map manifest", p, m);
    sys_close((int)fd);
    char err[256];
    if (manifest_parse((const char *)m, (size_t)st.st_size, &C, err, sizeof err) < 0) die("bad manifest", err, 0);
    SC2(NR_munmap, m, st.st_size);
    int ok = isa_supported(C.isa);
    if (ok < 0) die("can names an ISA level this opener does not know", C.isa, 0);
    if (ok == 0) die("this CPU lacks the can's ISA level", C.isa, 0);
}

/* 7.6: load the program at virtual path v; scripts go through their interpreter (kernel convention) */
static __attribute__((noreturn)) void run(const char *v, long argc, char **argv, char **envp, unsigned long *auxv, int depth)
{
    static char real[PATH_MAX], payload[PATH_MAX];
    if (depth > 4) die("interpreter chain too deep", v, ELOOP);
    to_real_exec(v, real);
    if (is_wrapper_real(real, payload) && payload_of(real, payload)) scpy(real, payload, PATH_MAX);
    long fd = sys_open(real, O_RDONLY | O_CLOEXEC, 0); if (fd < 0) die("cannot open program", v, fd);
    char *line = arena_alloc(256); long n = sys_read((int)fd, line, 255); sys_close((int)fd);
    if (n >= 4 && line[0] == 0x7f && line[1] == 'E' && line[2] == 'L' && line[3] == 'F') { scpy(C.exe, v, PATH_MAX); loader_run(v, real, argc, argv, envp, auxv); }
    if (n < 0) n = 0;
    line[n] = 0;
    /* a script: the kernel's argv convention, with buffers that outlive this level of the interpreter chain */
    long cap = argc + 4;
    long m = sys_mmap(0, ((size_t)cap * sizeof(char *) + 0xfff) & ~(size_t)0xfff, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (m < 0 && m > -4096) die("out of memory", 0, ENOMEM);
    char **nargv = (char **)m; char *script = arena_alloc(PATH_MAX);       /* sized from argc, never from a fixed pool (F3-2) */
    scpy(script, v, PATH_MAX);
    long k = shebang_argv(line, script, argv, argc, nargv, cap);
    if (k == -1) die("not an executable", v, ENOEXEC);
    if (k == -2) die("argument list too long", v, E2BIG);
    struct scratch *S = scratch_get((pid_t)sys_getpid(), (pid_t)sys_gettid(), 0); if (!S) die("out of memory", 0, ENOMEM);
    char *iv = arena_alloc(PATH_MAX);
    if (canon(S, nargv[0], AT_FDCWD, 1, iv) < 0) die("cannot resolve interpreter", nargv[0], 0);
    scratch_put(S);
    run(iv, k, nargv, envp, auxv, depth + 1);
}

void start_c(unsigned long *sp)
{
    page_init();
    reloc_self();
    long argc = (long)sp[0]; char **argv = (char **)(sp + 1); char **envp = argv + argc + 1;
    char **e = envp; while (*e) e++;
    unsigned long *auxv = (unsigned long *)(e + 1);

    unsigned long m = 1UL << (SIGSYS - 1);                    /* 7.5.2: SIGSYS must never be blocked */
    sys_rt_sigprocmask(SIG_UNBLOCK, &m, 0, 8);
    log_open(envp);

    static char exe[PATH_MAX];
    long n = sys_readlink("/proc/self/exe", exe, PATH_MAX - 1); if (n < 0) die("cannot read /proc/self/exe", 0, n);
    exe[n] = 0;
    find_can(exe);
    read_manifest();

    const char *target = find_env(envp, "CAN_EXEC");
    if (target) {
        if (target[0] != '/') die("CAN_EXEC must be an absolute path", target, 0);
        C.loader_mode = 1; scpy(C.program, target, PATH_MAX);
    } else {
        if (!starts_dir(exe, C.root)) die("run a wrapper inside root/, or set CAN_EXEC", exe, 0);
        scpy(C.program, exe, PATH_MAX); from_real(C.program);
    }

    int have = filter_probe();
    C.boundary = have == 0;
    char **env2 = env_prepare(envp, C.boundary);
    vis_init(env2);
    C.text_lo = (unsigned long)__ehdr_start; C.text_hi = (unsigned long)_etext;
    handler_install();
    if (have < FILTER_VERSION) filter_install();
    log_msg(C.boundary ? "boundary" : "inside", C.program);
    run(C.program, argc, argv, env2, auxv, 0);
}
