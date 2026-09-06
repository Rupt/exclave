/* handler.c — the SIGSYS handler (PROPOSAL.md 7.4.3, 7.5, 8.2).
 *
 * Runs in the program's thread on every trapped syscall. It canonicalises
 * the path in virtual space, decides host or can, applies the read-only rule
 * for the can, re-issues the syscall through the syscall page, and writes the result into
 * the frame. It owns about 2 KB of the program's stack; everything larger
 * lives in scratch memory. It never blocks a signal, and it edits the
 * program's signal mask only through the frame the kernel restores. Its
 * own syscalls go through the syscall page (sys.h), so a signal handler
 * that interrupts one of them cannot inherit a marker that would let its
 * syscalls bypass translation.
 */
#include "common.h"

#define IN_DONT_FOLLOW 0x02000000
#define FAN_MARK_DONT_FOLLOW 0x4
#define SIGSYS_BIT (1UL << (SIGSYS - 1))
#define STATFS_FLAGS_OFF 80

static inline long *gregs(void *uc) { return (long *)((char *)uc + UC_GREGS_OFF); }
static inline unsigned long *frame_mask(void *uc) { return (unsigned long *)((char *)uc + UC_SIGMASK_OFF); }
#define RE5(nr, a, b, c, d, e) __sc6((nr), (long)(a), (long)(b), (long)(c), (long)(d), (long)(e), 0)
#define RE6(nr, a, b, c, d, e, f) __sc6((nr), (long)(a), (long)(b), (long)(c), (long)(d), (long)(e), (long)(f))

/* ---------- copying from the program's memory with EFAULT fidelity (7.5.4) ---------- */
static int no_readv;                                         /* process_vm_readv refused: direct reads, a bad pointer faults (13) */
static pid_t cur_pid;                                        /* set per trap; one pid per process, so a plain static; no TLS in the opener */
static long copy_in(void *dst, const void *src, size_t n)
{
    unsigned long p = (unsigned long)src;
    if (!p) return -EFAULT;
    if (no_readv) { xmemcpy(dst, src, n); return (long)n; }
    struct iovec l = { dst, n }, r[2]; unsigned long rn = 1;
    unsigned long first = 4096 - (p & 4095); if (first > n) first = n;
    r[0].iov_base = (void *)p; r[0].iov_len = first;
    if (first < n) { r[1].iov_base = (void *)(p + first); r[1].iov_len = n - first; rn = 2; }
    long got = sys_process_vm_readv(cur_pid, &l, 1, r, rn, 0);
    if (got == -ENOSYS || got == -EPERM) { no_readv = 1; log_msg("process_vm_readv refused; direct reads", 0); return copy_in(dst, src, n); }
    return got < 0 ? -EFAULT : got;
}
/* NUL-terminated string into dst[PATH_MAX]; returns its length or -EFAULT/-ENAMETOOLONG */
static long copy_str_in(char *dst, const char *src)
{
    if (no_readv) { long i = 0; for (; i < PATH_MAX; i++) { dst[i] = src[i]; if (!dst[i]) return i; } return -ENAMETOOLONG; }
    long got = copy_in(dst, src, 256); if (got < 0) return got;
    for (long i = 0; i < got; i++) if (!dst[i]) return i;
    if (got < 256) return -EFAULT;
    long more = copy_in(dst + 256, src + 256, PATH_MAX - 256); if (more < 0) return more;
    for (long i = 256; i < 256 + more; i++) if (!dst[i]) return i;
    return more == PATH_MAX - 256 ? -ENAMETOOLONG : -EFAULT;
}
static long copy_exact(void *dst, const void *src, size_t n) { long g = copy_in(dst, src, n); return g == (long)n ? 0 : -EFAULT; }
/* the mirror of copy_in: the only writes into program memory the kernel has not just validated (review O3-1) */
static long copy_out(void *dst, const void *src, size_t n)
{
    unsigned long p = (unsigned long)dst;
    if (!p) return -EFAULT;
    if (no_readv) { xmemcpy(dst, src, n); return 0; }
    struct iovec l = { (void *)src, n }, r[2]; unsigned long rn = 1;
    unsigned long first = 4096 - (p & 4095); if (first > n) first = n;
    r[0].iov_base = (void *)p; r[0].iov_len = first;
    if (first < n) { r[1].iov_base = (void *)(p + first); r[1].iov_len = n - first; rn = 2; }
    long got = sys_process_vm_writev(cur_pid, &l, 1, r, rn, 0);
    if (got == -ENOSYS || got == -EPERM) { no_readv = 1; return copy_out(dst, src, n); }
    return got == (long)n ? 0 : -EFAULT;
}

/* ---------- path resolution ---------- */
/* args[pi] relative to args[di] (or the cwd when di < 0) into S->v; 1 means "empty path with AT_EMPTY_PATH: fd-based" */
static long resolve(struct scratch *S, long *a, int pi, int di, int follow, int allow_empty)
{
    if (!a[pi] && allow_empty) return 1;                       /* NULL with AT_EMPTY_PATH: the descriptor itself (6.11+) */
    long r = copy_str_in(S->b1, (const char *)a[pi]); if (r < 0) return r;
    if (S->b1[0] == 0) return allow_empty ? 1 : -ENOENT;
    r = canon(S, S->b1, di < 0 ? AT_FDCWD : (int)a[di], follow, S->v);
    if (r < 0) scpy(S->v, S->b1, PATH_MAX);                    /* the log names what was asked for, as given (review O4-6) */
    return r;
}
static int exists_can(struct scratch *S, const char *v, struct kstat *st)
{
    to_real_exec(v, S->real);
    if (is_can_owned(v)) {                                     /* 7.4.4: the answer is stable for a can-owned path */
        int k = cache_classify(v, S->real, S->tmp);
        if (k == CK_NONE) return 0;
        if (k) { st->st_mode = k == CK_DIR ? S_IFDIR : k == CK_LINK ? S_IFLNK : S_IFREG; return 1; }
    }
    return sys_lstat(S->real, st) == 0;
}

/* 8.2: the kernel-matching answers for a read-only can; S->real is set either way for the re-issue */
static long ro_create(struct scratch *S, const char *v)
{ struct kstat st; int ex = exists_can(S, v, &st); if (!is_can_owned(v)) return 0; return ex ? -EEXIST : -EROFS; }
static long ro_attr(struct scratch *S, const char *v)
{ struct kstat st; int ex = exists_can(S, v, &st); if (!is_can_owned(v)) return 0; return ex ? -EROFS : -ENOENT; }
static long ro_delete(struct scratch *S, const char *v) { to_real_exec(v, S->real); return is_can_owned(v) ? -EROFS : 0; }

/* ---------- open ---------- */
static long do_open(struct scratch *S, long *a, int pi, int di, long flags, long mode)
{
    int follow = !(flags & O_NOFOLLOW) && !((flags & O_CREAT) && (flags & O_EXCL));
    long r = resolve(S, a, pi, di, follow, 0); if (r < 0) return r;
    int acc = (int)(flags & O_ACCMODE);
    int wr = acc == O_WRONLY || acc == O_RDWR || (flags & O_TRUNC) || (flags & O_TMPFILE) == O_TMPFILE;
    int creat = (flags & O_CREAT) != 0;
    if (flags & O_PATH) wr = creat = 0;
    if (is_can_owned(S->v)) {
        struct kstat st; int ex = exists_can(S, S->v, &st);
        if ((flags & O_TMPFILE) == O_TMPFILE) return ex ? -EROFS : -ENOENT;
        if (creat && (flags & O_EXCL)) return ex ? -EEXIST : -EROFS;
        if (creat && ex && (st.st_mode & S_IFMT) == S_IFDIR) return -EISDIR;
        if (wr) { if (!ex) return creat ? -EROFS : -ENOENT; if ((st.st_mode & S_IFMT) == S_IFDIR) return -EISDIR; return -EROFS; }
        if (creat && !ex) return -EROFS;
        flags &= ~O_CREAT;                                   /* O_CREAT on an existing file, read-only: succeeds */
    }
    to_real(S->v, S->real, S->tmp);
    if (!follow) flags |= O_NOFOLLOW;
    return RE5(NR_openat, AT_FDCWD, S->real, flags, mode, 0);
}

/* ---------- exec (7.6): scripts and host programs run inside the can's world ---------- */
static long exec_target(struct scratch *S, const char *v, const char *given, char **argv, char **envp, int depth, struct scratch **Sp);

/* A pointer vector of n entries: a scratch region when it fits, an anonymous mapping otherwise (F3-2:
 * vectors are sized from their counts). A mapping made by a vfork child stays in the parent, unused. */
static char **vector(void *region, size_t region_size, long n, void **big)
{
    *big = 0;
    if ((size_t)n * sizeof(char *) <= region_size) return (char **)region;
    long m = sys_mmap(0, ((size_t)n * sizeof(char *) + 0xfff) & ~(size_t)0xfff, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (m < 0 && m > -4096) return 0;
    *big = (void *)m; return (char **)m;
}
static void vector_free(void *big, long n) { if (big) SC2(NR_munmap, big, ((size_t)n * sizeof(char *) + 0xfff) & ~(size_t)0xfff); }

/* The program's argv or envp, read through copy_in as the paths are (review O3-11, F3-14): a NULL vector is
 * empty, a bad pointer is EFAULT, an unterminated one is E2BIG. Returns the count; *out has count + extra + 1
 * slots, the entries first, then a NULL. S->tmp is the probe buffer. */
#define VEC_MAX (1L << 20)
static long vec_read(struct scratch *S, void *region, size_t region_size, char **user, long extra, char ***out, void **big)
{
    long n = 0;
    if (user) for (;;) {
        long got = copy_in(S->tmp, user + n, PATH_MAX); if (got < (long)sizeof(char *)) return -EFAULT;
        long k = got / (long)sizeof(char *), i; char **p = (char **)S->tmp;
        for (i = 0; i < k && p[i]; i++) ;
        n += i;
        if (i < k) break;
        if (n > VEC_MAX) return -E2BIG;
    }
    char **v = vector(region, region_size, n + extra + 1, big); if (!v) return -ENOMEM;
    if (n && copy_in(v, user, (size_t)n * sizeof(char *)) != n * (long)sizeof(char *)) { vector_free(*big, n + extra + 1); return -EFAULT; }
    v[n] = 0; *out = v; return n;
}

static long exec_loader_mode(struct scratch *S, const char *v, char **argv, char **envp, struct scratch **Sp)
{
    void *big; char **env; long envc = vec_read(S, S->extra, sizeof S->extra, envp, 1, &env, &big);
    if (envc < 0) return envc;
    scpy(S->b1, "CAN_EXEC=", PATH_MAX); scat(S->b1, v, PATH_MAX);
    long n = 0; char head[10];
    for (long i = 0; i < envc; i++) {                        /* drop an inherited CAN_EXEC; the strings are the kernel's to validate */
        if (copy_in(head, env[i], 9) == 9 && xmemcmp(head, "CAN_EXEC=", 9) == 0) continue;
        env[n++] = env[i];
    }
    for (long i = n; i > 0; i--) env[i] = env[i - 1];
    env[0] = S->b1; env[n + 1] = 0;
    log_line("exec", 0, v);
    long r = RE5(NR_execve, C.opener, argv, env, 0, 0);
    vector_free(big, envc + 2);                              /* only reached when execve failed */
    return r;
}

/* a script that is not a wrapper (a host script, 7.6): the interpreter is resolved in the can's world,
 * the script is passed by its virtual path. Kernel convention: argv = interp [arg] script args... */
static long exec_script(struct scratch *S, const char *v, const char *given, char **argv, char **envp, int depth, struct scratch **Sp)
{
    struct scratch *S2 = scratch_get(S->pid, S->tid, (unsigned long)__builtin_frame_address(0)); if (!S2) return -ENOMEM;
    char *line = S2->b1, *vcopy = S2->b2;
    void *big1, *big2; char **av, **nargv;
    long argc = vec_read(S, S->extra, sizeof S->extra, argv, 0, &av, &big1);
    if (argc < 0) { scratch_put(S2); return argc; }
    nargv = vector(S2->rest, 6 * PATH_MAX, argc + 4, &big2);
    if (!nargv) { vector_free(big1, argc + 1); scratch_put(S2); return -ENOMEM; }
    long fd = sys_open(S->real, O_RDONLY | O_CLOEXEC, 0);
    long n = fd < 0 ? fd : sys_read((int)fd, line, 255); if (fd >= 0) sys_close((int)fd);
    long r = -ENOEXEC;
    if (n < 0) r = n;
    else {
        line[n < 0 ? 0 : n] = 0;
        scpy(vcopy, given, PATH_MAX);                        /* the script's path as the caller spelt it, as the kernel passes it (7.4.5, review F5-8) */
        long k = shebang_argv(line, vcopy, av, argc, nargv, argc + 4);
        if (k == -1) r = -ENOEXEC; else if (k == -2) r = -E2BIG;
        else if ((r = canon(S, nargv[0], AT_FDCWD, 1, S->v)) >= 0) r = exec_target(S, S->v, nargv[0], nargv, envp, depth + 1, Sp);
    }
    vector_free(big2, argc + 4); vector_free(big1, argc + 1);
    scratch_put(S2);                                         /* only reached when no exec happened */
    return r;
}

static long exec_target(struct scratch *S, const char *v, const char *given, char **argv, char **envp, int depth, struct scratch **Sp)
{
    if (depth > 4) return -ELOOP;
    if (vis_in_data(v)) return -EACCES;                          /* 6.2: a data prefix is never executed (review O4-3) */
    to_real_exec(v, S->real);
    struct kstat st;
    if (sys_stat(S->real, &st) < 0) return -ENOENT;
    if ((st.st_mode & S_IFMT) == S_IFDIR) return -EACCES;
    if ((st.st_mode & S_IFMT) != S_IFREG) return -EACCES;
    long ok = sys_faccessat(AT_FDCWD, S->real, X_OK);           /* the kernel's answer for this process, triads and search included (O3-4) */
    if (ok < 0) return ok;
    int wrapper = is_wrapper_real(S->real, S->tmp) && payload_of(S->real, S->tmp);
    long fd = sys_open(wrapper ? S->tmp : S->real, O_RDONLY | O_CLOEXEC, 0); if (fd < 0) return fd;
    unsigned char h[4]; long n = sys_read((int)fd, h, 4); sys_close((int)fd);
    if (wrapper) {
        if (!(n >= 2 && h[0] == '#' && h[1] == '!') && !(n == 4 && h[0] == 0x7f && h[1] == 'E' && h[2] == 'L' && h[3] == 'F')) return -ENOEXEC;
        log_line("exec", 0, v);
        return RE5(NR_execve, S->real, argv, envp, 0, 0);    /* the kernel runs the opener under the program's name */
    }
    /* not a wrapper: a host program, or an unwrapped can file */
    if (n >= 2 && h[0] == '#' && h[1] == '!') return exec_script(S, v, given, argv, envp, depth, Sp);
    if (n == 4 && h[0] == 0x7f && h[1] == 'E' && h[2] == 'L' && h[3] == 'F') {
        int another;                                         /* 7.4.5: a file carrying .note.cont is another opener: exec it as it is */
        if (elf_probe(S->real, S->tmp, &another, S->extra) >= 0 && another) { log_line("exec", 0, v); return RE5(NR_execve, S->real, argv, envp, 0, 0); }
        return exec_loader_mode(S, v, argv, envp, Sp);
    }
    return -ENOEXEC;
}

static long do_execve(struct scratch *S, long *a, int pi, int di, long flags, char **argv, char **envp, struct scratch **Sp)
{
    long r = resolve(S, a, pi, di, !(flags & AT_SYMLINK_NOFOLLOW), (flags & AT_EMPTY_PATH) != 0);
    if (r < 0) return r;
    if (r == 1) { r = fd_virtual((int)a[di], S->v); if (r < 0) return r; }
    else if (flags & AT_SYMLINK_NOFOLLOW) {                    /* the kernel refuses to run a symlink itself (F3-20) */
        struct kstat st; to_real_exec(S->v, S->real);
        if (sys_lstat(S->real, &st) == 0 && (st.st_mode & S_IFMT) == S_IFLNK) return -ELOOP;
    }
    return exec_target(S, S->v, r == 1 ? S->v : S->b1, argv, envp, 0, Sp);   /* S->b1: the path as given (resolve); a descriptor exec has none */
}

/* ---------- readlink: /proc links and identity files answer in virtual terms (8.4) ---------- */
static long do_readlink(struct scratch *S, long *a, int pi, int di, char *buf, long bufsiz)
{
    long r = resolve(S, a, pi, di, 0, di >= 0); if (r < 0) return r;
    if (bufsiz <= 0) return -EINVAL;
    char *ans = 0;
    if (r == 1) {                                             /* readlinkat(fd, ""): the kernel reads the descriptor's own link (F3-8) */
        r = RE5(NR_readlinkat, a[di], "", S->tmp, PATH_MAX - 1, 0);
        if (r < 0) return r;
        S->tmp[r] = 0; if (starts_dir(S->tmp, C.root)) from_real(S->tmp); ans = S->tmp;
    }
    if ((C.loader_mode || xstrcmp(C.exe, C.program) != 0) && is_self_exe(S->v, S->pid)) ans = C.exe;
    if (!ans) {
        r = vis_readlink_identity(S->v, S->tmp);
        if (r < 0) return r;
        if (r == 1) ans = S->tmp;
    }
    if (!ans) {
        to_real_exec(S->v, S->real);
        r = RE5(NR_readlinkat, AT_FDCWD, S->real, S->tmp, PATH_MAX - 1, 0);
        if (r < 0) return r;
        S->tmp[r] = 0;
        if (xstrncmp(S->v, "/proc/", 6) == 0 || starts_dir(S->tmp, C.root)) from_real(S->tmp);
        ans = S->tmp;
        /* another process's exe link that names a wrapped script: that process runs the script's interpreter,
         * which is what the kernel would report natively (F3-22) */
        if (xstrncmp(S->v, "/proc/", 6) == 0 && xstrlen(S->v) > 4 && xstrcmp(S->v + xstrlen(S->v) - 4, "/exe") == 0 && is_can_owned(ans)) {
            scpy(S->v2, ans, PATH_MAX);
            to_real_exec(S->v2, S->real);
            if (is_wrapper_real(S->real, S->b2) && payload_of(S->real, S->b2)) {
                long fd = sys_open(S->b2, O_RDONLY | O_CLOEXEC, 0);
                long n = fd < 0 ? -1 : sys_read((int)fd, S->b2, 255); if (fd >= 0) sys_close((int)fd);
                if (n > 2 && S->b2[0] == '#' && S->b2[1] == '!') {
                    S->b2[n] = 0; char *p = S->b2 + 2; while (*p == ' ' || *p == '\t') p++;
                    char *e = p; while (*e && *e != ' ' && *e != '\t' && *e != '\n') e++; *e = 0;
                    scpy(S->b1, p, PATH_MAX);
                    if (canon(S, S->b1, AT_FDCWD, 1, S->v) == 0) { scpy(S->tmp, S->v, PATH_MAX); ans = S->tmp; }
                }
            }
        }
    }
    long l = (long)xstrlen(ans); if (l > bufsiz) l = bufsiz;
    if (l && copy_out(buf, ans, (size_t)l)) return -EFAULT;   /* the program's buffer is never validated by the kernel here */
    return l;
}

/* ---------- signal masks (7.5.2): SIGSYS is never blocked, never handled by the program ---------- */
static long do_sigaction(long *a, void *uc)
{
    int sig = (int)a[0]; const void *act = (const void *)a[1]; void *old = (void *)a[2]; long size = a[3];
    if (size != 8) return RE5(NR_rt_sigaction, sig, act, old, size, 0);
    if (sig == SIGSYS) return old ? RE5(NR_rt_sigaction, sig, 0, old, size, 0) : 0;   /* accepted, ignored; old reports the truth */
    if (!act) return RE5(NR_rt_sigaction, sig, 0, old, size, 0);
    unsigned long k[4]; long r = copy_exact(k, act, sizeof k); if (r) return r;
    k[3] &= ~SIGSYS_BIT;
    return RE5(NR_rt_sigaction, sig, k, old, size, 0);
}
static long do_sigprocmask(long *a, void *uc)
{
    int how = (int)a[0]; const void *set = (const void *)a[1]; void *old = (void *)a[2]; long size = a[3];
    if (!set || size != 8) return RE5(NR_rt_sigprocmask, how, set, old, size, 0);
    unsigned long m; long r = copy_exact(&m, set, 8); if (r) return r;
    if (how == SIG_BLOCK || how == SIG_SETMASK) m &= ~SIGSYS_BIT;
    r = RE5(NR_rt_sigprocmask, how, &m, old, size, 0);
    if (r == 0) { unsigned long cur; if (sys_rt_sigprocmask(SIG_BLOCK, 0, &cur, 8) == 0) *frame_mask(uc) = cur; }
    return r;
}
static long do_sigsuspend(long *a)
{
    unsigned long m; long size = a[1];
    if (size != 8) return -EINVAL;
    long r = copy_exact(&m, (const void *)a[0], 8); if (r) return r;
    m &= ~SIGSYS_BIT;
    return RE5(NR_rt_sigsuspend, &m, size, 0, 0, 0);
}
static long do_ppoll(long *a)
{
    unsigned long m; if (a[4] != 8) return -EINVAL;
    long r = copy_exact(&m, (const void *)a[3], 8); if (r) return r;
    m &= ~SIGSYS_BIT;
    return RE5(NR_ppoll, a[0], a[1], a[2], &m, a[4]);
}
static long do_pselect6(long *a)
{
    struct { const unsigned long *ss; unsigned long len; } sp; unsigned long m;
    long r = copy_exact(&sp, (const void *)a[5], sizeof sp); if (r) return r;
    if (!sp.ss) return RE6(NR_pselect6, a[0], a[1], a[2], a[3], a[4], a[5]);
    if (sp.len != 8) return -EINVAL;
    r = copy_exact(&m, sp.ss, 8); if (r) return r;
    m &= ~SIGSYS_BIT; sp.ss = &m;
    return RE6(NR_pselect6, a[0], a[1], a[2], a[3], a[4], &sp);
}
static long do_epoll_pwait(long *a, int nr)          /* epoll_pwait and epoll_pwait2: mask in a[4], size in a[5] */
{
    unsigned long m; if (a[5] != 8) return -EINVAL;
    long r = copy_exact(&m, (const void *)a[4], 8); if (r) return r;
    m &= ~SIGSYS_BIT;
    return RE6(nr, a[0], a[1], a[2], a[3], &m, a[5]);
}
static long do_io_pgetevents(long *a)
{
    struct { const unsigned long *ss; unsigned long len; } sp; unsigned long m;
    long r = copy_exact(&sp, (const void *)a[5], sizeof sp); if (r) return r;
    if (!sp.ss) return RE6(NR_io_pgetevents, a[0], a[1], a[2], a[3], a[4], a[5]);
    if (sp.len != 8) return -EINVAL;
    r = copy_exact(&m, sp.ss, 8); if (r) return r;
    m &= ~SIGSYS_BIT; sp.ss = &m;
    return RE6(NR_io_pgetevents, a[0], a[1], a[2], a[3], a[4], &sp);
}

/* ---------- descriptors that name can files ---------- */
static long fd_can(struct scratch *S, int fd)
{
    long r = fd_virtual(fd, S->v);
    if (r < 0) return 0;                                     /* pipes, sockets, deleted: the kernel decides */
    return S->v[0] == '/' && is_can_owned(S->v);
}

/* the real path for a stat: with no-follow, an identity file is the host's own symlink, so that lstat and
 * readlink agree about it (F3-9); otherwise the resolved file, wrapper redirect included */
static void real_nofollow(struct scratch *S, int nofollow)
{
    if (nofollow && vis_readlink_identity(S->v, S->tmp) == 1) { scpy(S->real, S->v, PATH_MAX); return; }
    to_real(S->v, S->real, S->tmp);
}

static long dispatch(struct scratch *S, int nr, long *a, void *uc, struct scratch **Sp)
{
    long r;
    switch (nr) {
    case NR_open:   return do_open(S, a, 0, -1, a[1], a[2]);
    case NR_openat: return do_open(S, a, 1, 0, a[2], a[3]);
    case NR_creat:  return do_open(S, a, 0, -1, O_CREAT | O_WRONLY | O_TRUNC, a[1]);
    case NR_stat: case NR_lstat:
        if ((r = resolve(S, a, 0, -1, nr == NR_stat, 0)) < 0) return r;
        real_nofollow(S, nr == NR_lstat);
        return RE5(NR_newfstatat, AT_FDCWD, S->real, a[1], nr == NR_stat ? 0 : AT_SYMLINK_NOFOLLOW, 0);
    case NR_newfstatat:
        if ((r = resolve(S, a, 1, 0, !(a[3] & AT_SYMLINK_NOFOLLOW), (a[3] & AT_EMPTY_PATH) != 0)) < 0) return r;
        if (r == 1) return RE5(nr, a[0], a[1], a[2], a[3], 0);
        real_nofollow(S, (a[3] & AT_SYMLINK_NOFOLLOW) != 0);
        return RE5(nr, AT_FDCWD, S->real, a[2], a[3] | AT_SYMLINK_NOFOLLOW, 0);
    case NR_statx:
        if ((r = resolve(S, a, 1, 0, !(a[2] & AT_SYMLINK_NOFOLLOW), (a[2] & AT_EMPTY_PATH) != 0)) < 0) return r;
        if (r == 1) return RE5(nr, a[0], a[1], a[2], a[3], a[4]);
        real_nofollow(S, (a[2] & AT_SYMLINK_NOFOLLOW) != 0);
        return RE5(nr, AT_FDCWD, S->real, a[2] | AT_SYMLINK_NOFOLLOW, a[3], a[4]);
    case NR_access: case NR_faccessat: case NR_faccessat2: {
        int pi = nr == NR_access ? 0 : 1, di = nr == NR_access ? -1 : 0; long mode = a[pi + 1], fl = nr == NR_faccessat2 ? a[3] : 0;
        if ((r = resolve(S, a, pi, di, !(fl & AT_SYMLINK_NOFOLLOW), 0)) < 0) return r;
        if ((mode & W_OK) && is_can_owned(S->v)) return ro_attr(S, S->v);
        to_real(S->v, S->real, S->tmp);
        if (nr == NR_faccessat2) return RE5(nr, AT_FDCWD, S->real, mode, fl | AT_SYMLINK_NOFOLLOW, 0);
        return RE5(NR_faccessat, AT_FDCWD, S->real, mode, 0, 0);
    }
    case NR_readlink:   return do_readlink(S, a, 0, -1, (char *)a[1], a[2]);
    case NR_readlinkat: return do_readlink(S, a, 1, 0, (char *)a[2], a[3]);
    case NR_getcwd:
        r = RE5(NR_getcwd, S->tmp, PATH_MAX, 0, 0, 0);
        if (r <= 0) return r;
        if (starts_dir(S->tmp, C.root)) from_real(S->tmp);
        r = (long)xstrlen(S->tmp) + 1;
        if (r > a[1]) return -ERANGE;
        if (copy_out((void *)a[0], S->tmp, (size_t)r)) return -EFAULT;
        return r;
    case NR_chdir:
        if ((r = resolve(S, a, 0, -1, 1, 0)) < 0) return r;
        to_real_exec(S->v, S->real);
        return RE5(NR_chdir, S->real, 0, 0, 0, 0);
    case NR_execve:   return do_execve(S, a, 0, -1, 0, (char **)a[1], (char **)a[2], Sp);
    case NR_execveat: return do_execve(S, a, 1, 0, a[4], (char **)a[2], (char **)a[3], Sp);
    case NR_truncate:
        if ((r = resolve(S, a, 0, -1, 1, 0)) < 0) return r;
        if ((r = ro_attr(S, S->v))) return r;
        return RE5(nr, S->real, a[1], 0, 0, 0);
    case NR_mkdir: case NR_mkdirat: {
        int pi = nr == NR_mkdir ? 0 : 1, di = nr == NR_mkdir ? -1 : 0;
        if ((r = resolve(S, a, pi, di, 0, 0)) < 0) return r;
        if ((r = ro_create(S, S->v))) return r;
        return RE5(NR_mkdirat, AT_FDCWD, S->real, a[pi + 1], 0, 0);
    }
    case NR_mknod: case NR_mknodat: {
        int pi = nr == NR_mknod ? 0 : 1, di = nr == NR_mknod ? -1 : 0;
        if ((r = resolve(S, a, pi, di, 0, 0)) < 0) return r;
        if ((r = ro_create(S, S->v))) return r;
        return RE5(NR_mknodat, AT_FDCWD, S->real, a[pi + 1], a[pi + 2], 0);
    }
    case NR_rmdir: case NR_unlink: case NR_unlinkat: {
        int pi = nr == NR_unlinkat ? 1 : 0, di = nr == NR_unlinkat ? 0 : -1;
        long fl = nr == NR_rmdir ? AT_REMOVEDIR : nr == NR_unlinkat ? a[2] : 0;
        if ((r = resolve(S, a, pi, di, 0, 0)) < 0) return r;
        if ((r = ro_delete(S, S->v))) return r;
        return RE5(NR_unlinkat, AT_FDCWD, S->real, fl, 0, 0);
    }
    case NR_symlink: case NR_symlinkat: {
        int pi = nr == NR_symlink ? 1 : 2, di = nr == NR_symlink ? -1 : 1;
        if ((r = resolve(S, a, pi, di, 0, 0)) < 0) return r;
        if ((r = ro_create(S, S->v))) return r;
        return RE5(NR_symlinkat, a[0], AT_FDCWD, S->real, 0, 0);
    }
    case NR_rename: case NR_renameat: case NR_renameat2: {
        int opi = nr == NR_rename ? 0 : 1, odi = nr == NR_rename ? -1 : 0, npi = nr == NR_rename ? 1 : 3, ndi = nr == NR_rename ? -1 : 2;
        long fl = nr == NR_renameat2 ? a[4] : 0; struct kstat st;
        if ((r = resolve(S, a, opi, odi, 0, 0)) < 0) return r;
        scpy(S->v2, S->v, PATH_MAX);                         /* old */
        if ((r = resolve(S, a, npi, ndi, 0, 0)) < 0) return r;
        /* the kernel's order (oracle 17.1): different mounts first, then the write check, then the lookups */
        int oc = is_can_owned(S->v2), nc = is_can_owned(S->v);
        if (oc != nc) return -EXDEV;
        if (oc && nc) return -EROFS;
        (void)st;
        to_real_exec(S->v2, S->b1); to_real_exec(S->v, S->real);
        if (nr != NR_renameat2 && fl == 0) return RE5(NR_renameat, AT_FDCWD, S->b1, AT_FDCWD, S->real, 0);   /* renameat2 is 3.15+ */
        return RE5(NR_renameat2, AT_FDCWD, S->b1, AT_FDCWD, S->real, fl);
    }
    case NR_link: case NR_linkat: {
        int opi = nr == NR_link ? 0 : 1, odi = nr == NR_link ? -1 : 0, npi = nr == NR_link ? 1 : 3, ndi = nr == NR_link ? -1 : 2;
        long fl = nr == NR_linkat ? a[4] : 0; struct kstat st;
        if ((r = resolve(S, a, opi, odi, (fl & AT_SYMLINK_FOLLOW) != 0, (fl & AT_EMPTY_PATH) != 0)) < 0) return r;
        if (r == 1) { if ((r = fd_virtual((int)a[odi], S->v)) < 0) return r; }
        scpy(S->v2, S->v, PATH_MAX);                         /* old */
        if ((r = resolve(S, a, npi, ndi, 0, 0)) < 0) return r;
        if (!exists_can(S, S->v2, &st)) return -ENOENT;
        if (is_can_owned(S->v)) return -EROFS;
        if (is_can_owned(S->v2)) return -EXDEV;
        to_real_exec(S->v2, S->b1); to_real_exec(S->v, S->real);
        return RE5(NR_linkat, AT_FDCWD, S->b1, AT_FDCWD, S->real, fl & ~AT_SYMLINK_FOLLOW & ~AT_EMPTY_PATH);
    }
    case NR_chmod: case NR_fchmodat: case NR_fchmodat2: {
        int pi = nr == NR_chmod ? 0 : 1, di = nr == NR_chmod ? -1 : 0; long fl = nr == NR_fchmodat2 ? a[3] : 0;
        if ((r = resolve(S, a, pi, di, !(fl & AT_SYMLINK_NOFOLLOW), 0)) < 0) return r;
        if ((r = ro_attr(S, S->v))) return r;
        to_real(S->v, S->real, S->tmp);
        if (nr == NR_fchmodat2) return RE5(nr, AT_FDCWD, S->real, a[2], fl | AT_SYMLINK_NOFOLLOW, 0);
        return RE5(NR_fchmodat, AT_FDCWD, S->real, a[pi + 1], 0, 0);
    }
    case NR_chown: case NR_lchown: case NR_fchownat: {
        int pi = nr == NR_fchownat ? 1 : 0, di = nr == NR_fchownat ? 0 : -1; long fl = nr == NR_fchownat ? a[4] : nr == NR_lchown ? AT_SYMLINK_NOFOLLOW : 0;
        if ((r = resolve(S, a, pi, di, !(fl & AT_SYMLINK_NOFOLLOW), (fl & AT_EMPTY_PATH) != 0)) < 0) return r;
        if (r == 1) return fd_can(S, (int)a[0]) ? -EROFS : RE5(nr, a[0], a[1], a[2], a[3], a[4]);
        if ((r = ro_attr(S, S->v))) return r;
        to_real(S->v, S->real, S->tmp);
        return RE5(NR_fchownat, AT_FDCWD, S->real, a[pi + 1], a[pi + 2], AT_SYMLINK_NOFOLLOW);
    }
    case NR_utime: case NR_utimes: case NR_futimesat: case NR_utimensat: {
        int pi = nr == NR_utime || nr == NR_utimes ? 0 : 1, di = nr == NR_utime || nr == NR_utimes ? -1 : 0;
        long fl = nr == NR_utimensat ? a[3] : 0;
        if (nr == NR_utimensat && a[1] == 0) return fd_can(S, (int)a[0]) ? -EROFS : RE5(nr, a[0], 0, a[2], a[3], 0);
        if ((r = resolve(S, a, pi, di, !(fl & AT_SYMLINK_NOFOLLOW), 0)) < 0) return r;
        if ((r = ro_attr(S, S->v))) return r;
        to_real(S->v, S->real, S->tmp);
        if (nr == NR_utime) return RE5(NR_utime, S->real, a[1], 0, 0, 0);
        if (nr == NR_utimes) return RE5(NR_utimes, S->real, a[1], 0, 0, 0);
        if (nr == NR_futimesat) return RE5(NR_futimesat, AT_FDCWD, S->real, a[2], 0, 0);
        return RE5(NR_utimensat, AT_FDCWD, S->real, a[2], fl | AT_SYMLINK_NOFOLLOW, 0);
    }
    case NR_setxattrat: case NR_removexattrat:               /* (dfd, path, at_flags, name, [value, size]) */
        if ((r = resolve(S, a, 1, 0, !(a[2] & AT_SYMLINK_NOFOLLOW), (a[2] & AT_EMPTY_PATH) != 0)) < 0) return r;
        if (r == 1) return fd_can(S, (int)a[0]) ? -EROFS : RE6(nr, a[0], a[1], a[2], a[3], a[4], a[5]);
        if ((r = ro_attr(S, S->v))) return r;
        to_real(S->v, S->real, S->tmp);
        return RE6(nr, AT_FDCWD, S->real, a[2] | AT_SYMLINK_NOFOLLOW, a[3], a[4], a[5]);
    case NR_getxattrat: case NR_listxattrat:
        if ((r = resolve(S, a, 1, 0, !(a[2] & AT_SYMLINK_NOFOLLOW), (a[2] & AT_EMPTY_PATH) != 0)) < 0) return r;
        if (r == 1) return RE6(nr, a[0], a[1], a[2], a[3], a[4], a[5]);
        to_real(S->v, S->real, S->tmp);
        return RE6(nr, AT_FDCWD, S->real, a[2] | AT_SYMLINK_NOFOLLOW, a[3], a[4], a[5]);
#ifndef CONT_TEST_OLD                                        /* build/opener-old: the previous version, which does not know these (17.4) */
    case NR_file_getattr: case NR_file_setattr:              /* (dfd, path, attr, size, at_flags): the chattr ioctls as syscalls */
        if ((r = resolve(S, a, 1, 0, !(a[4] & AT_SYMLINK_NOFOLLOW), (a[4] & AT_EMPTY_PATH) != 0)) < 0) return r;
        if (r == 1) return (nr == NR_file_setattr && fd_can(S, (int)a[0])) ? -EROFS : RE5(nr, a[0], a[1], a[2], a[3], a[4]);
        if (nr == NR_file_setattr && (r = ro_attr(S, S->v))) return r;
        to_real(S->v, S->real, S->tmp);
        return RE5(nr, AT_FDCWD, S->real, a[2], a[3], a[4] | AT_SYMLINK_NOFOLLOW);
#endif
    case NR_setxattr: case NR_lsetxattr: case NR_removexattr: case NR_lremovexattr:
        if ((r = resolve(S, a, 0, -1, nr == NR_setxattr || nr == NR_removexattr, 0)) < 0) return r;
        if ((r = ro_attr(S, S->v))) return r;
        to_real(S->v, S->real, S->tmp);
        return RE5(nr, S->real, a[1], a[2], a[3], a[4]);
    case NR_getxattr: case NR_lgetxattr: case NR_listxattr: case NR_llistxattr:
        if ((r = resolve(S, a, 0, -1, nr == NR_getxattr || nr == NR_listxattr, 0)) < 0) return r;
        to_real(S->v, S->real, S->tmp);
        return RE5(nr, S->real, a[1], a[2], a[3], 0);
    case NR_statfs:
        if ((r = resolve(S, a, 0, -1, 1, 0)) < 0) return r;
        to_real(S->v, S->real, S->tmp);
        r = RE5(NR_statfs, S->real, a[1], 0, 0, 0);
        if (r == 0 && is_can_owned(S->v)) *(long *)((char *)a[1] + STATFS_FLAGS_OFF) |= ST_RDONLY;
        return r;
    case NR_fstatfs:
        r = RE5(NR_fstatfs, a[0], a[1], 0, 0, 0);
        if (r == 0 && fd_can(S, (int)a[0])) *(long *)((char *)a[1] + STATFS_FLAGS_OFF) |= ST_RDONLY;
        return r;
    case NR_inotify_add_watch:
        if ((r = resolve(S, a, 1, -1, !(a[2] & IN_DONT_FOLLOW), 0)) < 0) return r;
        to_real(S->v, S->real, S->tmp);
        return RE5(nr, a[0], S->real, a[2] | IN_DONT_FOLLOW, 0, 0);
    case NR_fanotify_mark:
        if (a[4] == 0) return RE5(nr, a[0], a[1], a[2], a[3], 0);
        if ((r = resolve(S, a, 4, 3, !(a[1] & FAN_MARK_DONT_FOLLOW), 0)) < 0) return r;
        to_real(S->v, S->real, S->tmp);
        return RE5(nr, a[0], a[1] | FAN_MARK_DONT_FOLLOW, a[2], AT_FDCWD, S->real);
    case NR_fchmod: case NR_fchown: case NR_fsetxattr: case NR_fremovexattr: case NR_ioctl:
        if (fd_can(S, (int)a[0])) return -EROFS;
        return RE5(nr, a[0], a[1], a[2], a[3], a[4]);
    case NR_rt_sigaction:   return do_sigaction(a, uc);
    case NR_rt_sigprocmask: return do_sigprocmask(a, uc);
    case NR_rt_sigsuspend:  return do_sigsuspend(a);
    case NR_ppoll:          return do_ppoll(a);
    case NR_pselect6:       return do_pselect6(a);
    case NR_epoll_pwait: case NR_epoll_pwait2: return do_epoll_pwait(a, nr);
    case NR_io_pgetevents:  return do_io_pgetevents(a);
    default:
        return -ENOSYS;                                      /* 7.4.3: a trapped syscall the handler does not know */
    }
}

/* names for the log: one line per trapped syscall, "<name> <result> <virtual path>" */
static const char *sysname(int nr)
{
    switch (nr) {
    case NR_open: case NR_openat: case NR_creat: return "open";
    case NR_stat: case NR_lstat: case NR_newfstatat: case NR_statx: return "stat";
    case NR_access: case NR_faccessat: case NR_faccessat2: return "access";
    case NR_readlink: case NR_readlinkat: return "readlink";
    case NR_execve: case NR_execveat: return "exec";
    case NR_chdir: return "chdir";
    case NR_getcwd: return "getcwd";
    case NR_mkdir: case NR_mkdirat: return "mkdir";
    case NR_unlink: case NR_unlinkat: case NR_rmdir: return "unlink";
    case NR_rename: case NR_renameat: case NR_renameat2: return "rename";
    case NR_link: case NR_linkat: return "link";
    case NR_symlink: case NR_symlinkat: return "symlink";
    case NR_chmod: case NR_fchmodat: case NR_fchmodat2: case NR_chown: case NR_lchown: case NR_fchownat:
    case NR_utime: case NR_utimes: case NR_futimesat: case NR_utimensat: case NR_truncate: return "attr";
    case NR_setxattr: case NR_lsetxattr: case NR_getxattr: case NR_lgetxattr: case NR_listxattr: case NR_llistxattr:
    case NR_removexattr: case NR_lremovexattr: return "xattr";
    case NR_statfs: case NR_fstatfs: return "statfs";
    case NR_rt_sigaction: case NR_rt_sigprocmask: case NR_rt_sigsuspend: case NR_ppoll: case NR_pselect6:
    case NR_epoll_pwait: case NR_epoll_pwait2: case NR_io_pgetevents: return "signal";
    default: return "trap";
    }
}

static void on_sigsys(int sig, void *info, void *uc)
{
    long *g = gregs(uc);
    if (*(int *)((char *)info + SI_CODE_OFF) != SYS_SECCOMP) {
        /* a real SIGSYS (kill -SYS): the program's default disposition applies, so re-raise it under SIG_DFL */
        unsigned long dfl[4] = { 0, 0, 0, 0 };
        sys_rt_sigaction(SIGSYS, dfl, 0, 8);
        sys_tgkill((pid_t)sys_getpid(), (pid_t)sys_gettid(), SIGSYS);
        return;
    }
    int nr = *(int *)((char *)info + SI_SYSCALL_OFF);
    unsigned long ip = *(unsigned long *)((char *)info + SI_CALL_ADDR_OFF);
    pid_t pid = (pid_t)sys_getpid(), tid = (pid_t)sys_gettid();
    unsigned long frame = (unsigned long)__builtin_frame_address(0);
    int depth = nest_enter(pid, tid, frame);
    if (depth > 1 && ip >= C.text_lo && ip < C.text_hi) die("the opener trapped its own syscall", 0, nr);
    if (depth > 64) die("signal handlers nested too deep (or left behind by longjmp on another stack)", 0, 0);
    long a[6] = { g[REG_RDI], g[REG_RSI], g[REG_RDX], g[REG_R10], g[REG_R8], g[REG_R9] };
    struct scratch *S = scratch_get(pid, tid, frame);
    cur_pid = pid;
    if (S) S->v[0] = 0;
    long r = S ? dispatch(S, nr, a, uc, &S) : -ENOMEM;
    if (C.logfd >= 0 && S) log_line(sysname(nr), r, S->v[0] ? S->v : 0);
    if (S) scratch_put(S);
    g[REG_RAX] = r;
    nest_leave();
}

__asm__(".text\n.globl sig_restorer\n.type sig_restorer,@function\nsig_restorer:\n mov $15, %eax\n syscall\n");

void handler_install(void)
{
    struct { void *h; unsigned long flags; void *restorer; unsigned long mask; } sa =
        { (void *)on_sigsys, SA_SIGINFO | SA_ONSTACK | SA_RESTORER | SA_NODEFER, (void *)sig_restorer, 0 };
    if (sys_rt_sigaction(SIGSYS, &sa, 0, 8) < 0) die("cannot install the SIGSYS handler", 0, 0);
    unsigned long m = SIGSYS_BIT;
    sys_rt_sigprocmask(SIG_UNBLOCK, &m, 0, 8);
}
