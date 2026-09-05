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
static long copy_in(void *dst, const void *src, size_t n)
{
    unsigned long p = (unsigned long)src;
    if (!p) return -EFAULT;
    if (no_readv) { xmemcpy(dst, src, n); return (long)n; }
    struct iovec l = { dst, n }, r[2]; unsigned long rn = 1;
    unsigned long first = 4096 - (p & 4095); if (first > n) first = n;
    r[0].iov_base = (void *)p; r[0].iov_len = first;
    if (first < n) { r[1].iov_base = (void *)(p + first); r[1].iov_len = n - first; rn = 2; }
    long got = sys_process_vm_readv((pid_t)sys_getpid(), &l, 1, r, rn, 0);
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

/* ---------- path resolution ---------- */
/* args[pi] relative to args[di] (or the cwd when di < 0) into S->v; 1 means "empty path with AT_EMPTY_PATH: fd-based" */
static long resolve(struct scratch *S, long *a, int pi, int di, int follow, int allow_empty)
{
    long r = copy_str_in(S->b1, (const char *)a[pi]); if (r < 0) return r;
    if (S->b1[0] == 0) return allow_empty ? 1 : -ENOENT;
    return canon(S, S->b1, di < 0 ? AT_FDCWD : (int)a[di], follow, S->v);
}
static int exists_can(struct scratch *S, const char *v, struct kstat *st)
{ to_real_exec(v, S->real); return sys_lstat(S->real, st) == 0; }

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
        if (wr) { if (!ex) return creat ? -EROFS : -ENOENT; if ((st.st_mode & S_IFMT) == S_IFDIR) return -EISDIR; return -EROFS; }
        if (creat && !ex) return -EROFS;
        flags &= ~O_CREAT;                                   /* O_CREAT on an existing file, read-only: succeeds */
    }
    to_real(S->v, S->real, S->tmp);
    if (!follow) flags |= O_NOFOLLOW;
    r = RE5(NR_openat, AT_FDCWD, S->real, flags, mode, 0);
    log_line("open", r, S->v);
    return r;
}

/* ---------- exec (7.6): scripts and host programs run inside the can's world ---------- */
static long exec_target(struct scratch *S, const char *v, char **argv, char **envp, int depth, struct scratch **Sp);

static long exec_loader_mode(struct scratch *S, const char *v, char **argv, char **envp, struct scratch **Sp)
{
    long envc = 0; while (envp[envc]) envc++;
    char **nenv = (char **)S->extra; long cap = (long)(sizeof S->extra / sizeof(char *));
    struct scratch *S2 = 0;
    if (envc + 2 > cap) { S2 = scratch_get(); if (!S2) return -E2BIG; nenv = (char **)S2; cap = (long)(sizeof *S2 / sizeof(char *)); if (envc + 2 > cap) { scratch_put(S2); return -E2BIG; } }
    scpy(S->b1, "CAN_EXEC=", PATH_MAX); scat(S->b1, v, PATH_MAX);
    long n = 0; nenv[n++] = S->b1;
    for (long i = 0; i < envc; i++) if (!xstarts(envp[i], "CAN_EXEC=")) nenv[n++] = envp[i];
    nenv[n] = 0;
    log_line("exec", 0, v);
    long r = RE5(NR_execve, C.opener, argv, nenv, 0, 0);
    if (S2) scratch_put(S2);                                 /* only reached when execve failed */
    return r;
}

/* a script that is not a wrapper (a host script, 7.6): the interpreter is resolved in the can's world,
 * the script is passed by its virtual path. Kernel convention: argv = interp [arg] script args... */
static long exec_script(struct scratch *S, const char *v, char **argv, char **envp, int depth, struct scratch **Sp)
{
    struct scratch *S2 = scratch_get(); if (!S2) return -ENOMEM;
    char *line = S2->b1, *vcopy = S2->b2; char **nargv = (char **)S2->rest;
    long cap = (long)((sizeof *S2 - 2 * PATH_MAX) / sizeof(char *));
    long fd = sys_open(S->real, O_RDONLY | O_CLOEXEC, 0);
    long n = fd < 0 ? fd : sys_read((int)fd, line, 255); if (fd >= 0) sys_close((int)fd);
    long r = -ENOEXEC;
    if (n < 0) r = n;
    else {
        line[n < 0 ? 0 : n] = 0;
        long argc = 0; while (argv[argc]) argc++;
        scpy(vcopy, v, PATH_MAX);
        long k = shebang_argv(line, vcopy, argv, argc, nargv, cap);
        if (k == -1) r = -ENOEXEC; else if (k == -2) r = -E2BIG;
        else if ((r = canon(S, nargv[0], AT_FDCWD, 1, S->v)) >= 0) r = exec_target(S, S->v, nargv, envp, depth + 1, Sp);
    }
    scratch_put(S2);                                         /* only reached when no exec happened */
    return r;
}

static long exec_target(struct scratch *S, const char *v, char **argv, char **envp, int depth, struct scratch **Sp)
{
    if (depth > 4) return -ELOOP;
    to_real_exec(v, S->real);
    struct kstat st;
    if (sys_stat(S->real, &st) < 0) return -ENOENT;
    if ((st.st_mode & S_IFMT) == S_IFDIR) return -EACCES;
    if ((st.st_mode & S_IFMT) != S_IFREG || !(st.st_mode & 0111)) return -EACCES;
    int wrapper = is_wrapper_real(S->real, S->tmp) && payload_of(S->real, S->tmp);
    long fd = sys_open(wrapper ? S->tmp : S->real, O_RDONLY | O_CLOEXEC, 0); if (fd < 0) return fd;
    unsigned char h[4]; long n = sys_read((int)fd, h, 4); sys_close((int)fd);
    if (wrapper) {
        if (!(n >= 2 && h[0] == '#' && h[1] == '!') && !(n == 4 && h[0] == 0x7f && h[1] == 'E' && h[2] == 'L' && h[3] == 'F')) return -ENOEXEC;
        log_line("exec", 0, v);
        return RE5(NR_execve, S->real, argv, envp, 0, 0);    /* the kernel runs the opener under the program's name */
    }
    /* not a wrapper: a host program, or an unwrapped can file */
    if (n >= 2 && h[0] == '#' && h[1] == '!') return exec_script(S, v, argv, envp, depth, Sp);
    if (n == 4 && h[0] == 0x7f && h[1] == 'E' && h[2] == 'L' && h[3] == 'F') return exec_loader_mode(S, v, argv, envp, Sp);
    return -ENOEXEC;
}

static long do_execve(struct scratch *S, long *a, int pi, int di, long flags, char **argv, char **envp, struct scratch **Sp)
{
    long r = resolve(S, a, pi, di, !(flags & AT_SYMLINK_NOFOLLOW), (flags & AT_EMPTY_PATH) != 0);
    if (r < 0) return r;
    if (r == 1) { r = fd_virtual((int)a[di], S->v); if (r < 0) return r; }
    return exec_target(S, S->v, argv, envp, 0, Sp);
}

/* ---------- readlink: /proc links and identity files answer in virtual terms (8.4) ---------- */
static long do_readlink(struct scratch *S, long *a, int pi, int di, char *buf, long bufsiz)
{
    long r = resolve(S, a, pi, di, 0, 0); if (r < 0) return r;
    if (bufsiz <= 0) return -EINVAL;
    char *ans = 0;
    if (C.loader_mode && is_self_exe(S->v)) ans = C.program;
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
    }
    long l = (long)xstrlen(ans); if (l > bufsiz) l = bufsiz;
    xmemcpy(buf, ans, (size_t)l);                            /* buf was validated by the kernel only in the re-issued case */
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

static long dispatch(struct scratch *S, int nr, long *a, void *uc, struct scratch **Sp)
{
    long r;
    switch (nr) {
    case NR_open:   return do_open(S, a, 0, -1, a[1], a[2]);
    case NR_openat: return do_open(S, a, 1, 0, a[2], a[3]);
    case NR_creat:  return do_open(S, a, 0, -1, O_CREAT | O_WRONLY | O_TRUNC, a[1]);
    case NR_stat: case NR_lstat:
        if ((r = resolve(S, a, 0, -1, nr == NR_stat, 0)) < 0) return r;
        to_real(S->v, S->real, S->tmp);
        return RE5(NR_newfstatat, AT_FDCWD, S->real, a[1], nr == NR_stat ? 0 : AT_SYMLINK_NOFOLLOW, 0);
    case NR_newfstatat:
        if ((r = resolve(S, a, 1, 0, !(a[3] & AT_SYMLINK_NOFOLLOW), (a[3] & AT_EMPTY_PATH) != 0)) < 0) return r;
        if (r == 1) return RE5(nr, a[0], a[1], a[2], a[3], 0);
        to_real(S->v, S->real, S->tmp);
        return RE5(nr, AT_FDCWD, S->real, a[2], a[3] | AT_SYMLINK_NOFOLLOW, 0);
    case NR_statx:
        if ((r = resolve(S, a, 1, 0, !(a[2] & AT_SYMLINK_NOFOLLOW), (a[2] & AT_EMPTY_PATH) != 0)) < 0) return r;
        if (r == 1) return RE5(nr, a[0], a[1], a[2], a[3], a[4]);
        to_real(S->v, S->real, S->tmp);
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
        r = RE5(NR_getcwd, a[0], a[1], 0, 0, 0);
        if (r > 0) { char *b = (char *)a[0]; if (starts_dir(b, C.root)) { from_real(b); r = (long)xstrlen(b) + 1; } }
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
        if (!exists_can(S, S->v2, &st)) return -ENOENT;
        int oc = is_can_owned(S->v2), nc = is_can_owned(S->v);
        if (oc && nc) return -EROFS;
        if (oc != nc) return -EXDEV;
        to_real_exec(S->v2, S->b1); to_real_exec(S->v, S->real);
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
    int depth = nest_enter();
    if (depth > 1 && ip >= C.text_lo && ip < C.text_hi) die("the opener trapped its own syscall", 0, nr);
    if (depth > 64) die("signal handlers nested too deep", 0, 0);
    long a[6] = { g[REG_RDI], g[REG_RSI], g[REG_RDX], g[REG_R10], g[REG_R8], g[REG_R9] };
    struct scratch *S = scratch_get();
    long r = S ? dispatch(S, nr, a, uc, &S) : -ENOMEM;
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
