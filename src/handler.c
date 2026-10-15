/* handler.c — the SIGSYS handler (PROPOSAL.md 7.4.3, 7.5, 8.2).
 *
 * Runs in the program's thread on every trapped syscall. It canonicalises
 * the path in virtual space, decides host or can, applies the read-only rule
 * for the can, re-issues the syscall through the syscall page, and writes the result into
 * the frame. It uses at most 3 KB of the program's stack (7.5.4); everything larger
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
#define RENAME_NOREPLACE 1
#define F_GETFL 3
#define UTIME_OMIT ((1L << 30) - 2)
#define UTIME_NOW ((1L << 30) - 1)
static int nsec_valid(long ns) { return ns == UTIME_OMIT || ns == UTIME_NOW || (ns >= 0 && ns <= 999999999); }   /* fs/utimes.c */

static inline long *gregs(void *uc) { return (long *)((char *)uc + UC_GREGS_OFF); }
static inline unsigned long *frame_mask(void *uc) { return (unsigned long *)((char *)uc + UC_SIGMASK_OFF); }
#define RE5(nr, a, b, c, d, e) __sc6((nr), (long)(a), (long)(b), (long)(c), (long)(d), (long)(e), 0)
#define RE6(nr, a, b, c, d, e, f) __sc6((nr), (long)(a), (long)(b), (long)(c), (long)(d), (long)(e), (long)(f))

/* ---------- copying from the program's memory with EFAULT fidelity (7.5.6) ---------- */
static int no_readv;                                         /* process_vm_readv refused: copies go through a pipe (13) */
/* every copy names the pid of the trap it serves, recorded in the trap's own chunk: a process-wide value would be a vfork child's
 * while a thread of the parent is in its handler, and name the child's new image once it has exec'd (7.5.4) */
/* where process_vm_readv is refused, EPERM under a seccomp profile that gates it on a capability, as Docker's does before
 * kernel 4.8, the copy goes through a pipe: write() from program memory and read() into it fault exactly as the syscall's
 * own copy would, EFAULT or short at the boundary; the pipe lives for the copy alone, a page a step (13) */
static long pipe_copy(void *dst, const void *src, size_t n)
{
    int fds[2]; long done = 0, e = sys_pipe2(fds, O_CLOEXEC | O_NONBLOCK);
    if (e < 0) return e;                                     /* no descriptor left: the syscall answers that, never a raw copy that could fault the handler */
    while (done < (long)n) {
        size_t chunk = n - (size_t)done; if (chunk > 4096) chunk = 4096;   /* a page always fits an empty pipe */
        long w = sys_write(fds[1], (const char *)src + done, chunk);
        long r = w > 0 ? sys_read(fds[0], (char *)dst + done, (size_t)w) : w;
        if (r <= 0) break;
        done += r;
        if (r < (long)chunk) break;
    }
    sys_close(fds[0]); sys_close(fds[1]);
    return done;
}
static long copy_in(pid_t pid, void *dst, const void *src, size_t n)
{
    unsigned long p = (unsigned long)src;
    if (!p) return -EFAULT;
    if (!no_readv) {
        struct iovec l = { dst, n }, r[2]; unsigned long rn = 1;
        unsigned long first = 4096 - (p & 4095); if (first > n) first = n;
        r[0].iov_base = (void *)p; r[0].iov_len = first;
        if (first < n) { r[1].iov_base = (void *)(p + first); r[1].iov_len = n - first; rn = 2; }
        long got = sys_process_vm_readv(pid, &l, 1, r, rn, 0);
        if (got != -ENOSYS && got != -EPERM) return got < 0 ? -EFAULT : got;
        no_readv = 1; log_msg("process_vm_readv refused; copies through a pipe", 0);
    }
    long g = pipe_copy(dst, src, n); return g < 0 ? g : g > 0 || n == 0 ? g : -EFAULT;
}
/* NUL-terminated string into dst[PATH_MAX]; returns its length or -EFAULT/-ENAMETOOLONG */
static long copy_str_in(pid_t pid, char *dst, const char *src)
{
    long got = copy_in(pid, dst, src, 256); if (got < 0) return got;
    for (long i = 0; i < got; i++) if (!dst[i]) return i;
    if (got < 256) return -EFAULT;
    long more = copy_in(pid, dst + 256, src + 256, PATH_MAX - 256); if (more < 0) return more;
    for (long i = 256; i < 256 + more; i++) if (!dst[i]) return i;
    return more == PATH_MAX - 256 ? -ENAMETOOLONG : -EFAULT;
}
static long copy_exact(pid_t pid, void *dst, const void *src, size_t n) { long g = copy_in(pid, dst, src, n); return g == (long)n ? 0 : -EFAULT; }
/* the mirror of copy_in: the only writes into program memory the kernel has not just validated (review O3-1) */
static long copy_out(pid_t pid, void *dst, const void *src, size_t n)
{
    unsigned long p = (unsigned long)dst;
    if (!p) return -EFAULT;
    if (!no_readv) {
        struct iovec l = { (void *)src, n }, r[2]; unsigned long rn = 1;
        unsigned long first = 4096 - (p & 4095); if (first > n) first = n;
        r[0].iov_base = (void *)p; r[0].iov_len = first;
        if (first < n) { r[1].iov_base = (void *)(p + first); r[1].iov_len = n - first; rn = 2; }
        long got = sys_process_vm_writev(pid, &l, 1, r, rn, 0);
        if (got != -ENOSYS && got != -EPERM) return got == (long)n ? 0 : -EFAULT;
        no_readv = 1;
    }
    long g = pipe_copy(dst, src, n); return g == (long)n ? 0 : g < 0 ? g : -EFAULT;
}

/* ---------- path resolution ---------- */
/* args[pi] relative to args[di] (or the cwd when di < 0) into S->v; 1 means "empty path with AT_EMPTY_PATH: fd-based".
 * allow_empty: 1 accepts the empty string, 2 also a NULL path, as getname_maybe_null does under AT_EMPTY_PATH for
 * newfstatat and statx (6.11+), the *xattrat calls and file_getattr and file_setattr; every other syscall answers
 * EFAULT for NULL, AT_EMPTY_PATH or not (oracle 17.7) */
static long resolve(struct scratch *S, long *a, int pi, int di, int follow, int allow_empty)
{
    if (!a[pi] && allow_empty == 2) return 1;
    long r = copy_str_in(S->pid, S->b1, (const char *)a[pi]); if (r < 0) return r;
    if (S->b1[0] == 0) return allow_empty ? 1 : -ENOENT;
    int dfd = di < 0 ? AT_FDCWD : (int)a[di];
    if (S->b1[0] != '/') {                                     /* a relative path starts with the kernel's search check on the directory it
                                                                * starts from (link_path_walk): EACCES, ENOTDIR or EBADF before any lookup,
                                                                * which the absolute re-issue would otherwise skip (oracle 17.7) */
        r = sys_faccessat(dfd, ".", X_OK); if (r < 0) return r;
    }
    r = canon(S, S->b1, dfd, follow, S->v);
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

/* the lstat error behind "absent", which the kernel reports before EROFS wherever it looks the name up first:
 * ENOTDIR for a trailing slash on a file, EILSEQ from a filesystem that refuses the name, ENOENT otherwise */
static long absent_errno(struct scratch *S)
{
    long r = sys_lstat(S->real, (struct kstat *)S->b2);      /* b2: canon's component buffer, free once the path is resolved */
    return r < 0 && r != -ENOENT ? r : -ENOENT;
}
/* the kernel classifies a path's last component before it looks it up (fs/namei.c): "." and ".." are never
 * created, deleted or renamed, and neither is the root; each syscall has its own answer */
static int last_special(const char *p)                       /* 0: a name; 1: "."; 2: ".."; 3: the root */
{
    size_t n = xstrlen(p);
    while (n > 1 && p[n - 1] == '/') n--;
    if (n == 1 && p[0] == '/') return 3;
    size_t s = n; while (s > 0 && p[s - 1] != '/') s--;
    if (n - s == 1 && p[s] == '.') return 1;
    if (n - s == 2 && p[s] == '.' && p[s + 1] == '.') return 2;
    return 0;
}

/* 8.2: the kernel-matching answers for a read-only can, in the kernel's order (oracle 17.7); S->real is set
 * either way for the re-issue. A create (filename_create): the name is looked up first, so EEXIST for what
 * exists and the name's own error come before EROFS, and a trailing slash on something that is not a directory
 * being made is ENOENT. An attribute change: the file must exist. A delete: EROFS before the last component
 * is looked up at all. */
static long ro_create(struct scratch *S, const char *v, int is_dir)
{
    if (!is_can_owned(v)) { to_real_exec(v, S->real); return 0; }
    scpy(S->cur, v, PATH_MAX);
    size_t l = xstrlen(S->cur); int slash = l > 1 && S->cur[l - 1] == '/';
    if (slash) S->cur[l - 1] = 0;                            /* the lookup is of the name; the slash only says "a directory" */
    int ex = exists_can(S, S->cur, (struct kstat *)S->b2);
    if (ex) return -EEXIST;
    long e = absent_errno(S); if (e != -ENOENT) return e;
    return slash && !is_dir ? -ENOENT : -EROFS;
}
static long ro_attr(struct scratch *S, const char *v)
{ struct kstat st; int ex = exists_can(S, v, &st); if (!is_can_owned(v)) return 0; return ex ? -EROFS : absent_errno(S); }
/* an overlong last component of a delete: do_unlinkat and do_rmdir take the write lock on the parent before they look the
 * name up, so a can-owned parent answers EROFS first, where an overlong earlier component fails in the walk (oracle 17.7) */
static long delete_overlong(struct scratch *S, int dfd)
{
    char *p = S->b1; size_t n = 0;                              /* the path as given, from resolve */
    while (n < PATH_MAX && p[n]) n++;
    if (n >= PATH_MAX) return -ENAMETOOLONG;                  /* getname's own answer: no NUL within PATH_MAX */
    while (n > 1 && p[n - 1] == '/') n--;                     /* a trailing slash names the same component */
    size_t s = n; while (s > 0 && p[s - 1] != '/') s--;      /* p[s..n) is the last component */
    if (n - s <= NAME_MAX) return -ENAMETOOLONG;              /* an earlier component was the overlong one */
    for (size_t i = 0, cl = 0; i < s; i++) { if (p[i] == '/') cl = 0; else if (++cl > NAME_MAX) return -ENAMETOOLONG; }
    char c = p[s]; p[s] = 0;                                  /* the parent: what precedes the component, or the directory itself */
    long r = canon(S, s ? p : ".", dfd, 1, S->v);
    p[s] = c;
    r = r < 0 ? -ENAMETOOLONG : is_can_owned(S->v) ? -EROFS : -ENAMETOOLONG;
    scpy(S->v, S->b1, PATH_MAX);                              /* the log names what was asked for */
    return r;
}
static long ro_delete(struct scratch *S, const char *v) { to_real_exec(v, S->real); return is_can_owned(v) ? -EROFS : 0; }
static void real_nofollow(struct scratch *S, int nofollow);
static int dfd_virtual(int fd, char *out);

/* ---------- open ---------- */
static long do_open(struct scratch *S, long *a, int pi, int di, long flags, long mode, int nr)
{
    int follow = !(flags & O_NOFOLLOW) && !((flags & O_CREAT) && (flags & O_EXCL));
    long r = resolve(S, a, pi, di, follow, 0);
    if (nr == NR_openat2 && r <= 0 && !S->touched_can) {     /* a walk that never touched the can is the kernel's own to make, with every
                                                              * resolve flag, on the host's own mounts (13 item 22); RESOLVE_CACHED dropped */
        S->how0[2] &= ~(unsigned long)RESOLVE_CACHED;
        return RE5(NR_openat2, a[0], a[1], S->how0, 24, 0);
    }
    if (r < 0) return r;
    int acc = (int)(flags & O_ACCMODE);
    int wr = acc == O_WRONLY || acc == O_RDWR || (flags & O_TRUNC) || (flags & O_TMPFILE) == O_TMPFILE;
    int creat = (flags & O_CREAT) != 0;
    if (flags & O_PATH) wr = creat = 0;
    size_t vl = xstrlen(S->v);
    if (creat && vl > 1 && S->v[vl - 1] == '/') return -EISDIR;   /* open_last_lookups: O_CREAT with a trailing slash, before any lookup */
    if (wr && (flags & O_TMPFILE) != O_TMPFILE && C.loader_mode && xstrcmp(S->v, C.program) == 0) return -ETXTBSY;   /* the kernel protects a running program; the opener protects the one it loaded (13) */
    if ((flags & O_NOFOLLOW) && !(flags & O_PATH) && vis_readlink_identity(S->v, S->tmp) == 1) return -ELOOP;   /* an identity file that is a host symlink (8.4) */
    if (is_can_owned(S->v)) {
        struct kstat st; int ex = exists_can(S, S->v, &st);
        long ae = ex ? 0 : absent_errno(S);                  /* the lookup's own error comes before the read-only answers */
        int dir = ex && (st.st_mode & S_IFMT) == S_IFDIR;
        if ((flags & O_TMPFILE) == O_TMPFILE) return !ex ? ae : dir ? -EROFS : -ENOTDIR;
        if (creat && (flags & O_EXCL)) return ex ? -EEXIST : ae != -ENOENT ? ae : -EROFS;
        if (creat && dir) return -EISDIR;
        if (wr) {
            if (!ex) return ae != -ENOENT ? ae : creat ? -EROFS : -ENOENT;
            if (dir) return -EISDIR;
            /* do_open, may_open, do_dentry_open: a special file is opened as the kernel opens it, since the read-only mount does not
             * protect it (ENXIO for a socket, a FIFO's own rules); on a regular file O_TRUNC wants the mount writable before anything,
             * EROFS, and otherwise the permission comes first, EACCES, and the mount after it */
            struct kstat rs; to_real(S->v, S->real, S->tmp);
            if (sys_lstat(S->real, &rs) < 0 || (rs.st_mode & S_IFMT) == S_IFREG) {
                if (flags & O_TRUNC) return -EROFS;
                long pe = sys_faccessat(AT_FDCWD, S->real, acc == O_RDWR ? R_OK | W_OK : W_OK);
                return pe < 0 ? pe : -EROFS;
            }
        }
        if (creat && !ex) return ae != -ENOENT ? ae : -EROFS;
        flags &= ~O_CREAT;                                   /* O_CREAT on an existing file, read-only: succeeds */
    }
    real_nofollow(S, !follow);                               /* O_PATH|O_NOFOLLOW on an identity symlink opens the host's link itself */
    if (!follow) flags |= O_NOFOLLOW;
    if (nr == NR_openat2) {                                  /* re-issued as itself, so a kernel without it answers ENOSYS as it would natively */
        unsigned long *how = (unsigned long *)S->b2; how[0] = (unsigned long)flags; how[2] = 0;
        how[1] = (flags & O_CREAT) || (flags & O_TMPFILE) == O_TMPFILE ? (unsigned long)mode : 0;   /* build_open_flags: a mode only with a create */
        return RE5(NR_openat2, AT_FDCWD, S->real, how, 24, 0);
    }
    return RE5(NR_openat, AT_FDCWD, S->real, flags, mode, 0);
}

/* openat2 (7.4.3): the kernel's checks on struct open_how first, in its order (build_open_flags), then the
 * same open as openat with the resolve flags honoured by the walk (canon.c) and dropped from the re-issue;
 * RESOLVE_CACHED is dropped, which openat2(2) permits, since a resolved path is opened without it */
static long do_openat2(struct scratch *S, long *a)
{
    unsigned long how[3]; long size = a[3], r;
    if (size < 24) return -EINVAL;
    if (size > 24) {                                         /* an extended struct: the tail must be zero (copy_struct_from_user) */
        if (size > 4096) return -E2BIG;
        if (copy_in(S->pid, S->extra, (const void *)a[2], (size_t)size) != size) return -EFAULT;
        for (long i = 24; i < size; i++) if (S->extra[i]) return -E2BIG;
        xmemcpy(how, S->extra, 24);
    } else if ((r = copy_exact(S->pid, how, (const void *)a[2], 24))) return r;
    unsigned long flags = how[0], mode = how[1], rf = how[2];
    if (flags & ~VALID_OPEN_FLAGS) return -EINVAL;
    if (rf & ~RESOLVE_ALL) return -EINVAL;
    if ((rf & RESOLVE_BENEATH) && (rf & RESOLVE_IN_ROOT)) return -EINVAL;   /* the scoping flags are exclusive */
    int creating = (flags & O_CREAT) || (flags & O_TMPFILE) == O_TMPFILE;
    if (creating ? (mode & ~07777UL) != 0 : mode != 0) return -EINVAL;
    if ((flags & (O_DIRECTORY | O_CREAT)) == (O_DIRECTORY | O_CREAT)) return -EINVAL;
    if (flags & (O_TMPFILE & ~O_DIRECTORY)) {
        if ((flags & O_TMPFILE) != O_TMPFILE) return -EINVAL;
        if ((flags & O_ACCMODE) == O_RDONLY) return -EINVAL;
    }
    if ((flags & O_PATH) && (flags & ~O_PATH_FLAGS)) return -EINVAL;
    if (rf & (RESOLVE_IN_ROOT | RESOLVE_BENEATH)) {         /* the scope: the descriptor's directory, a directory it must be */
        int dfd = (int)a[0];
        if ((r = copy_str_in(S->pid, S->b1, (const char *)a[1])) < 0) return r;   /* getname first: EFAULT, ENAMETOOLONG */
        if (S->b1[0] == 0) return -ENOENT;                   /* an empty path, before the descriptor is looked at */
        if ((rf & RESOLVE_BENEATH) && S->b1[0] == '/') return -EXDEV;   /* nd_jump_root: an absolute path, likewise */
        if (dfd != AT_FDCWD) {
            struct kstat *st = (struct kstat *)S->b2;
            if ((r = SC2(NR_fstat, dfd, st)) < 0) return r;
            if ((st->st_mode & S_IFMT) != S_IFDIR && (rf & RESOLVE_IN_ROOT)) return -ENOTDIR;
        }
        if ((r = dfd_virtual(dfd, S->v2)) < 0) return r;
    }
    S->resolve = (unsigned)rf;
    S->how0[0] = flags; S->how0[1] = mode; S->how0[2] = rf; S->touched_can = 1;   /* as given, for a host-only walk; canon decides */
    r = do_open(S, a, 1, 0, (long)flags, (long)mode, NR_openat2);
    S->resolve = 0;
    return r;
}

/* ---------- exec (7.4.5): scripts and host programs run inside the can's world ---------- */
static long exec_target(struct scratch *S, const char *v, const char *given, char **argv, char **envp, int depth, int cloexec, struct scratch **Sp);

/* the first bytes of a file the exec must look at: the kernel needs no descriptor for its own exec, so a program at its
 * descriptor limit may still exec; the handler needs one and borrows it, the soft limit raised by one for the open when
 * the hard limit allows, then put back (7.4.5) */
static long open_header(const char *real)
{
    long fd = sys_open(real, O_RDONLY | O_CLOEXEC, 0);
    if (fd != -EMFILE) return fd;
    unsigned long lim[2], one[2];
    if (SC4(NR_prlimit64, 0, RLIMIT_NOFILE, 0, lim) < 0 || lim[0] >= lim[1]) return fd;
    one[0] = lim[0] + 1; one[1] = lim[1];
    if (SC4(NR_prlimit64, 0, RLIMIT_NOFILE, one, 0) < 0) return fd;
    fd = sys_open(real, O_RDONLY | O_CLOEXEC, 0);
    SC4(NR_prlimit64, 0, RLIMIT_NOFILE, lim, 0);
    return fd;
}

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
        long got = copy_in(S->pid, S->tmp, user + n, PATH_MAX); if (got < (long)sizeof(char *)) return -EFAULT;
        long k = got / (long)sizeof(char *), i; char **p = (char **)S->tmp;
        for (i = 0; i < k && p[i]; i++) ;
        n += i;
        if (i < k) break;
        if (n > VEC_MAX) return -E2BIG;
    }
    char **v = vector(region, region_size, n + extra + 1, big); if (!v) return -ENOMEM;
    if (n && copy_in(S->pid, v, user, (size_t)n * sizeof(char *)) != n * (long)sizeof(char *)) { vector_free(*big, n + extra + 1); return -EFAULT; }
    v[n] = 0; *out = v; return n;
}

/* The exec of a wrapper, or of the opener for a program on the loader path, with the identity the kernel would give
 * the program carried in the opener's own variables (7.4.5, 7.6): CAN_EXEC names the loader-path target, CAN_EXECFN
 * the path the program is exec'd by as the kernel spells it, CAN_COMM the name the kernel would set as comm. S->v2
 * and S->comm hold the last two from do_execve; an inherited copy of any of the three is dropped, and every opener
 * strips them before a program runs. The strings are the kernel's to validate. */
static long exec_env(struct scratch *S, const char *path, char **argv, char **envp, const char *v, int loader)
{
    void *big; char **env; long envc = vec_read(S, S->extra, sizeof S->extra, envp, 3, &env, &big);
    if (envc < 0) return envc;
    /* the head of every variable, 12 bytes, read in one process_vm_readv for up to 256 at a time rather than one call
     * each (PERFORMANCE.md 2.5); a variable the batch could not read whole, near the end of a mapping, is read on its own
     * as before, and the batch resumes after it (review O7). tmp holds the heads, rest the iovecs: both free until the end */
    long n = 0; char head[12], *heads = S->tmp; struct iovec *riov = (struct iovec *)S->rest;
    for (long i = 0; i < envc;) {
        long k = envc - i, done = 0; if (k > 256) k = 256;
        if (!no_readv) {
            for (long j = 0; j < k; j++) { riov[j].iov_base = env[i + j]; riov[j].iov_len = sizeof head; }
            struct iovec l = { heads, (size_t)k * sizeof head };
            long got = sys_process_vm_readv(S->pid, &l, 1, riov, (unsigned long)k, 0);
            if (got > 0) done = got / (long)sizeof head;
        }
        if (!done) done = -1;                                /* one variable the slow way */
        for (long j = 0; j < (done < 0 ? 1 : done); j++, i++) {
            const char *h = heads + j * (long)sizeof head; long got = sizeof head;
            if (done < 0) { got = copy_in(S->pid, head, env[i], sizeof head); h = head; }
            if (got >= 9 && (xmemcmp(h, "CAN_EXEC=", 9) == 0 || xmemcmp(h, "CAN_COMM=", 9) == 0 || (got >= 11 && xmemcmp(h, "CAN_EXECFN=", 11) == 0))) continue;
            env[n++] = env[i];
        }
    }
    int k = loader ? 3 : 2;
    for (long i = n; i > 0; i--) env[i + k - 1] = env[i - 1];
    scpy(S->cur, "CAN_EXECFN=", PATH_MAX); scat(S->cur, S->v2, PATH_MAX);
    scpy(S->rest, "CAN_COMM=", PATH_MAX); scat(S->rest, S->comm, PATH_MAX);
    if (loader) { scpy(S->b1, "CAN_EXEC=", PATH_MAX); scat(S->b1, v, PATH_MAX); env[0] = S->b1; }
    env[k - 2] = S->cur; env[k - 1] = S->rest; env[n + k] = 0;
    log_line("exec", 0, v);
    long r = RE5(NR_execve, path, argv, env, 0, 0);
    vector_free(big, envc + 4);                              /* only reached when execve failed */
    return r;
}

/* a script that is not a wrapper (a host script, 7.4.5): the interpreter is resolved in the can's world,
 * the script is passed by its virtual path. Kernel convention: argv = interp [arg] script args... */
static inline __attribute__((always_inline)) long exec_script(struct scratch *S, const char *v, const char *given, char **argv, char **envp, int depth, struct scratch **Sp)   /* inlined into both callers: one frame per script level (7.5.4) */
{
    struct scratch *S2 = scratch_get(S->pid, S->tid, (unsigned long)__builtin_frame_address(0)); if (!S2) return -ENOMEM;
    char *line = S2->b1, *vcopy = S2->b2;
    void *big1, *big2; char **av, **nargv;
    long argc = vec_read(S, S->extra, sizeof S->extra, argv, 0, &av, &big1);
    if (argc < 0) { scratch_put(S2); return argc; }
    nargv = vector(S2->rest, 6 * PATH_MAX, argc + 4, &big2);   /* rest, cur, real, tmp and v of S2, contiguous, hold six PATH_MAXes */
    if (!nargv) { vector_free(big1, argc + 1); scratch_put(S2); return -ENOMEM; }
    long fd = open_header(S->real);
    long n = fd < 0 ? fd : sys_read((int)fd, line, 255); if (fd >= 0) sys_close((int)fd);
    long r = -ENOEXEC;
    if (n < 0) r = n;
    else {
        line[n < 0 ? 0 : n] = 0;
        scpy(vcopy, given, PATH_MAX);                        /* the script's path as the caller spelt it, as the kernel passes it (7.4.5, review F5-8) */
        long k = shebang_argv(line, vcopy, av, argc, nargv, argc + 4);
        if (k == -1) r = -ENOEXEC; else if (k == -2) r = -E2BIG;
        else if ((r = canon(S, nargv[0], AT_FDCWD, 1, S->v)) >= 0) r = exec_target(S, S->v, nargv[0], nargv, envp, depth + 1, 0, Sp);
    }
    vector_free(big2, argc + 4); vector_free(big1, argc + 1);
    scratch_put(S2);                                         /* only reached when no exec happened */
    return r;
}

/* cloexec: the script came through a close-on-exec descriptor, which its interpreter could not open: the kernel refuses
 * such an exec with ENOENT before it runs anything (fs/exec.c, BINPRM_FLAGS_PATH_INACCESSIBLE) */
static long exec_target(struct scratch *S, const char *v, const char *given, char **argv, char **envp, int depth, int cloexec, struct scratch **Sp)
{
    if (depth > 5) return -ELOOP;                            /* binfmt_script: five interpreters may nest, the sixth is ELOOP (measured) */
    if (vis_in_data(v)) return -EACCES;                          /* 6.2: a data prefix is never executed (review O4-3) */
    to_real_exec(v, S->real);
    struct kstat *st = (struct kstat *)S->b2; long e;           /* in the scratch, not the frame: six of these frames may nest (7.5.4) */
    if ((e = sys_stat(S->real, st)) < 0) return e;           /* ENOENT, ENOTDIR for a trailing slash, the name's own error */
    if ((st->st_mode & S_IFMT) != S_IFREG) return -EACCES;
    long ok = sys_faccessat(AT_FDCWD, S->real, X_OK);           /* the kernel's answer for this process, triads and search included (O3-4) */
    if (ok < 0) return ok;
    int wrapper = (is_can_owned(v) ? cache_classify(v, S->real, S->tmp) == CK_WRAPPER : is_wrapper_real(S->real, S->tmp))   /* remembered by the walk (7.4.4) */
                  && payload_of(S->real, S->tmp);
    long fd = open_header(wrapper ? S->tmp : S->real); if (fd < 0) return fd;
    unsigned char h[4]; long n = sys_read((int)fd, h, 4); sys_close((int)fd);
    int script = n >= 2 && h[0] == '#' && h[1] == '!', elf = n == 4 && h[0] == 0x7f && h[1] == 'E' && h[2] == 'L' && h[3] == 'F';
    if (script && cloexec) return -ENOENT;
    if (wrapper) {
        if (!script && !elf) return -ENOEXEC;
        return exec_env(S, S->real, argv, envp, v, 0);      /* the kernel runs the opener under the program's name */
    }
    /* not a wrapper: a host program, or an unwrapped can file */
    if (script) return exec_script(S, v, given, argv, envp, depth, Sp);
    if (!elf) return -ENOEXEC;
    int another;                                             /* 7.4.5: a file carrying .note.cont is another opener: exec it as it is */
    int pr = elf_probe(S->real, S->tmp, &another, S->extra);
    if (pr < 0) return -ENOEXEC;                             /* a class, machine or header the loader (7.3) cannot load: the kernel's answer for a foreign file */
    if (another >= PAGE_GENERATION) { log_line("exec", 0, v); return RE5(NR_execve, S->real, argv, envp, 0, 0); }
    if (another) return exec_env(S, C.opener, argv, envp, v, 1);   /* an opener whose page this filter traps: the child refuses it by name */
    if (pr == 1) {                                           /* the loader the header names, resolved as loader_run resolves it (7.3): one that is not there
                                                              * is ENOENT here, as the kernel's open_exec answers; one that exists but is not the can's own
                                                              * file, a host path or a data prefix, is left to the child opener, which refuses it by name */
        scpy(S->b1, S->tmp, PATH_MAX);
        if ((e = canon(S, S->b1, AT_FDCWD, 1, S->tmp)) < 0) return e;
        if (is_can_owned(S->tmp) && !vis_in_data(S->tmp)) {
            if ((e = sys_stat(to_real(S->tmp, S->real, S->b2), st)) < 0) return e;   /* to_real is done with b2 before the stat fills it */
            if ((st->st_mode & S_IFMT) != S_IFREG) return -EACCES;  /* do_open_execat: a loader that is not a regular file */
        }
    }
    return exec_env(S, C.opener, argv, envp, v, 1);
}

/* a descriptor with no path (13 item 25): a memfd, or a file unlinked since it was opened. The kernel runs the file
 * behind the descriptor; the opener runs it on the loader path named through /proc/self/fd, by a dup without
 * close-on-exec that the child opener closes once the segments are mapped, and the child answers the link's text for
 * /proc/self/exe as the kernel does. A script goes to its interpreter as /dev/fd/N, the kernel's spelling, and a
 * close-on-exec script is ENOENT, since the interpreter could not open it (execveat(2)) */
#ifndef F_DUPFD
#define F_DUPFD 0
#define F_GETFD 1
#define FD_CLOEXEC 1
#endif
static long exec_descriptor(struct scratch *S, int fd, char **argv, char **envp, struct scratch **Sp)
{
    char *n = S->cur; ltoa_(fd, n);                          /* buffers from the scratch (7.5.4): the number, the stat, the header */
    scpy(S->real, "/proc/self/fd/", PATH_MAX); scat(S->real, n, PATH_MAX);
    struct kstat *st = (struct kstat *)S->b2; long e;
    if ((e = sys_stat(S->real, st)) < 0) return e;
    if ((st->st_mode & S_IFMT) != S_IFREG) return -EACCES;
    long ok = sys_faccessat(AT_FDCWD, S->real, X_OK); if (ok < 0) return ok;
    long l = sys_readlink(S->real, S->tmp, PATH_MAX - 1); if (l < 0) return l;   /* comm is the file's own name (7.6), which the link spells with " (deleted)" */
    S->tmp[l] = 0; if (l > 10 && xstrcmp(S->tmp + l - 10, " (deleted)") == 0) S->tmp[l - 10] = 0;
    scpy(S->comm, base_name(S->tmp), sizeof S->comm);
    long h = open_header(S->real); if (h < 0) return h;
    unsigned char *head = (unsigned char *)S->tmp; long k = sys_read((int)h, head, 4); sys_close((int)h);
    if (k >= 2 && head[0] == '#' && head[1] == '!') {
        long fl = sys_fcntl(fd, F_GETFD, 0); if (fl < 0) return fl;
        if (fl & FD_CLOEXEC) return -ENOENT;
        scpy(S->v, S->v2, PATH_MAX);                         /* S->real is read; /dev/fd/N, the kernel's spelling, is what the interpreter gets */
        return exec_script(S, S->v, S->v, argv, envp, 0, Sp);
    }
    if (!(k == 4 && head[0] == 0x7f && head[1] == 'E' && head[2] == 'L' && head[3] == 'F')) return -ENOEXEC;
    long m = sys_fcntl(fd, F_DUPFD, 3); if (m < 0) return m;   /* inherited by the child opener, which closes it after the mapping */
    ltoa_(m, n); scpy(S->v, "/proc/self/fd/", PATH_MAX); scat(S->v, n, PATH_MAX);
    long r = exec_env(S, C.opener, argv, envp, S->v, 1);
    sys_close((int)m);                                       /* only reached when the exec failed */
    return r;
}

static long do_execve(struct scratch *S, long *a, int pi, int di, long flags, char **argv, char **envp, struct scratch **Sp)
{
    long r = resolve(S, a, pi, di, !(flags & AT_SYMLINK_NOFOLLOW), (flags & AT_EMPTY_PATH) != 0);
    if (r < 0) return r;
    int dfd = di < 0 ? AT_FDCWD : (int)a[di], byfd = r == 1, cloexec = 0;
    /* the name the program is exec'd by, spelt as the kernel spells it (fs/exec.c, alloc_bprm): the path as given, or
     * through a descriptor /dev/fd/N and /dev/fd/N/rel; a script's $0, AT_EXECFN and comm come from it (7.6) */
    if (dfd != AT_FDCWD && (byfd || S->b1[0] != '/')) {
        char *num = S->tmp; ltoa_(dfd, num);
        scpy(S->v2, "/dev/fd/", PATH_MAX); scat(S->v2, num, PATH_MAX);
        if (!byfd) { if (xstrlen(S->v2) + 1 + xstrlen(S->b1) >= PATH_MAX) return -ENAMETOOLONG; scat(S->v2, "/", PATH_MAX); scat(S->v2, S->b1, PATH_MAX); }
    } else scpy(S->v2, S->b1, PATH_MAX);
    if (byfd) {
        struct kstat st;                                     /* a descriptor on a symlink itself (O_PATH|O_NOFOLLOW) cannot be run (fs/exec.c) */
        if (dfd != AT_FDCWD) {                               /* AT_FDCWD with an empty path is the working directory, no descriptor */
            if (SC2(NR_fstat, dfd, &st) == 0) {
                int m = st.st_mode & S_IFMT;
                if (m == S_IFLNK) return -ELOOP;             /* a symlink descriptor (O_PATH|O_NOFOLLOW) cannot be run */
                if (m != S_IFREG) return -EACCES;            /* do_open_execat: only a regular file is exec'd; a pipe or socket has no path to spell */
            }
            r = sys_fcntl(dfd, F_GETFD, 0); if (r < 0) return r;
            cloexec = (r & FD_CLOEXEC) != 0;
        }
        r = dfd_virtual(dfd, S->v);
        if (r == -ENOENT) return exec_descriptor(S, dfd, argv, envp, Sp);   /* fd_virtual: the link ends " (deleted)": no path */
        if (r < 0) return r;
        scpy(S->comm, base_name(S->v), sizeof S->comm);     /* through a descriptor, comm is the file's own name (fs/exec.c since 6.12) */
    } else {
        if (flags & AT_SYMLINK_NOFOLLOW) {                    /* the kernel refuses to run a symlink itself (F3-20) */
            struct kstat st; to_real_exec(S->v, S->real);
            if (sys_lstat(S->real, &st) == 0 && (st.st_mode & S_IFMT) == S_IFLNK) return -ELOOP;
        }
        scpy(S->comm, base_name(S->v2), sizeof S->comm);    /* kbasename of the name as spelt */
    }
    return exec_target(S, S->v, S->v2, argv, envp, 0, cloexec, Sp);
}

/* ---------- readlink: /proc links and identity files answer in virtual terms (8.4) ---------- */
static long do_readlink(struct scratch *S, long *a, int pi, int di, char *buf, long bufsiz)
{
    if (bufsiz <= 0) return -EINVAL;                          /* do_readlinkat: before the path is read at all */
    long r = resolve(S, a, pi, di, 0, di >= 0); if (r < 0) return r;
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
    if (l && (r = copy_out(S->pid, buf, ans, (size_t)l))) return r;   /* the program's buffer is never validated by the kernel here */
    return l;
}

/* ---------- signal masks (7.5.2): SIGSYS is never blocked, never handled by the program ---------- */
static long do_sigaction(struct scratch *S, long *a, void *uc)
{
    int sig = (int)a[0]; const void *act = (const void *)a[1]; void *old = (void *)a[2]; long size = a[3];
    if (size != 8) return RE5(NR_rt_sigaction, sig, act, old, size, 0);
    if (sig == SIGSYS) return old ? RE5(NR_rt_sigaction, sig, 0, old, size, 0) : 0;   /* accepted, ignored; old reports the truth */
    if (!act) return RE5(NR_rt_sigaction, sig, 0, old, size, 0);
    unsigned long k[4]; long r = copy_exact(S->pid, k, act, sizeof k); if (r) return r;
    k[3] &= ~SIGSYS_BIT;
    return RE5(NR_rt_sigaction, sig, k, old, size, 0);
}
static long do_sigprocmask(struct scratch *S, long *a, void *uc)
{
    int how = (int)a[0]; const void *set = (const void *)a[1]; void *old = (void *)a[2]; long size = a[3];
    if (!set || size != 8) return RE5(NR_rt_sigprocmask, how, set, old, size, 0);
    unsigned long m; long r = copy_exact(S->pid, &m, set, 8); if (r) return r;
    if (how == SIG_BLOCK || how == SIG_SETMASK) m &= ~SIGSYS_BIT;
    r = RE5(NR_rt_sigprocmask, how, &m, old, size, 0);
    if (r == 0) { unsigned long cur; if (sys_rt_sigprocmask(SIG_BLOCK, 0, &cur, 8) == 0) *frame_mask(uc) = cur; }
    return r;
}
static long do_sigsuspend(struct scratch *S, long *a)
{
    unsigned long m; long size = a[1];
    if (size != 8) return -EINVAL;
    long r = copy_exact(S->pid, &m, (const void *)a[0], 8); if (r) return r;
    m &= ~SIGSYS_BIT;
    return RE5(NR_rt_sigsuspend, &m, size, 0, 0, 0);
}
static long do_ppoll(struct scratch *S, long *a)
{
    unsigned long m; if (a[4] != 8) return -EINVAL;
    long r = copy_exact(S->pid, &m, (const void *)a[3], 8); if (r) return r;
    m &= ~SIGSYS_BIT;
    return RE5(NR_ppoll, a[0], a[1], a[2], &m, a[4]);
}
static long do_pselect6(struct scratch *S, long *a)
{
    struct { const unsigned long *ss; unsigned long len; } sp; unsigned long m;
    long r = copy_exact(S->pid, &sp, (const void *)a[5], sizeof sp); if (r) return r;
    if (!sp.ss) return RE6(NR_pselect6, a[0], a[1], a[2], a[3], a[4], a[5]);
    if (sp.len != 8) return -EINVAL;
    r = copy_exact(S->pid, &m, sp.ss, 8); if (r) return r;
    m &= ~SIGSYS_BIT; sp.ss = &m;
    return RE6(NR_pselect6, a[0], a[1], a[2], a[3], a[4], &sp);
}
static long do_epoll_pwait(struct scratch *S, long *a, int nr)          /* epoll_pwait and epoll_pwait2: mask in a[4], size in a[5] */
{
    unsigned long m; if (a[5] != 8) return -EINVAL;
    long r = copy_exact(S->pid, &m, (const void *)a[4], 8); if (r) return r;
    m &= ~SIGSYS_BIT;
    return RE6(nr, a[0], a[1], a[2], a[3], &m, a[5]);
}
static long do_io_pgetevents(struct scratch *S, long *a)
{
    struct { const unsigned long *ss; unsigned long len; } sp; unsigned long m;
    long r = copy_exact(S->pid, &sp, (const void *)a[5], sizeof sp); if (r) return r;
    if (!sp.ss) return RE6(NR_io_pgetevents, a[0], a[1], a[2], a[3], a[4], a[5]);
    if (sp.len != 8) return -EINVAL;
    r = copy_exact(S->pid, &m, sp.ss, 8); if (r) return r;
    m &= ~SIGSYS_BIT; sp.ss = &m;
    return RE6(NR_io_pgetevents, a[0], a[1], a[2], a[3], a[4], &sp);
}

/* ---------- descriptors that name can files ---------- */
/* ST_RDONLY into the flag word of a statfs the kernel just filled (8.2), through the copies of 7.5.6 like every other write
 * into program memory: the kernel validated the buffer a moment ago, but another thread may have unmapped it since */
static long ro_flag(struct scratch *S, void *flags)
{
    long f; if (copy_exact(S->pid, &f, flags, sizeof f)) return -EFAULT;
    f |= ST_RDONLY;
    return copy_out(S->pid, flags, &f, sizeof f);
}
static int dfd_virtual(int fd, char *out) { return fd == AT_FDCWD ? cwd_virtual(out) : fd_virtual(fd, out); }   /* a descriptor argument that may be AT_FDCWD */
static long fd_can(struct scratch *S, int fd)
{
    long r = dfd_virtual(fd, S->v);
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

/* ---------- bind and connect (7.4.3, 13 item 31) ---------- */
/* a sockaddr_un's path is a path like any other, under the visibility rule. The kernel reads the family and the
 * path out of the structure, so the handler does the same and answers for a can-owned path what the kernel answers
 * on a read-only bind mount (oracle 17.7): bind is a create (unix_bind_bsd), the name looked up first, EEXIST read
 * as EADDRINUSE, then EROFS; connect looks the name up (unix_find_bsd), needs write permission on what it finds,
 * and finds no listener behind a file in the tree, ECONNREFUSED, since nothing can bind there. A host path, an
 * abstract name, an unnamed address or another family is re-issued as given; a bad length is the kernel's EINVAL. */
#define AF_UNIX 1
#ifndef W_OK
#define W_OK 2
#endif
static long do_sockaddr(struct scratch *S, long *a, int nr)
{
    long len = (int)a[2];                                    /* addrlen is an int: the kernel truncates, and a length past the word must not
                                                              * turn a can path into one re-issued as written */
    scpy(S->v, "-", PATH_MAX);
    if (len < 2 || len > 110 || !a[1]) return RE5(nr, a[0], a[1], a[2], 0, 0);
    long r = copy_exact(S->pid, S->extra, (const void *)a[1], (size_t)len); if (r) return r;
    unsigned short fam; xmemcpy(&fam, S->extra, 2);
    if (fam != AF_UNIX || len == 2 || S->extra[2] == 0) return RE5(nr, a[0], a[1], a[2], 0, 0);
    size_t n = (size_t)len - 2; if (n > 108) n = 108;         /* unix_mkname_bsd: the path ends at the length or at a NUL */
    xmemcpy(S->b1, S->extra + 2, n); S->b1[n] = 0;
    if (S->b1[0] != '/') { r = sys_faccessat(AT_FDCWD, ".", X_OK); if (r < 0) return r; }
    if ((r = canon(S, S->b1, AT_FDCWD, nr == NR_connect, S->v)) < 0) { scpy(S->v, S->b1, PATH_MAX); return r; }
    if (!is_can_owned(S->v)) {                                /* a host path: the kernel gets the resolved real path, as for every
                                                              * other syscall, since a can symlink may have led here (oracle 17.7) */
        to_real(S->v, S->real, S->tmp);
        size_t rl = xstrlen(S->real), gl = xstrlen(S->b1);
        size_t slash = gl > 1 && S->b1[gl - 1] == '/' && S->real[rl - 1] != '/';   /* a trailing slash is the kernel's to judge (filename_create) */
        if (rl + slash > 107) return -ENAMETOOLONG;              /* sun_path is 108 bytes: a real path past it cannot be named (13) */
        xmemcpy(S->extra + 2, S->real, rl); if (slash) S->extra[2 + rl] = '/'; S->extra[2 + rl + slash] = 0;
        return RE5(nr, a[0], S->extra, 2 + rl + slash + 1, 0, 0);
    }
    if (nr == NR_bind) { r = ro_create(S, S->v, 0); return r == -EEXIST ? -EADDRINUSE : r; }
    if (!exists_can(S, S->v, (struct kstat *)S->b2)) return absent_errno(S);
    r = sys_faccessat(AT_FDCWD, S->real, W_OK); if (r < 0) return r;
    return -ECONNREFUSED;
}

static long dispatch(struct scratch *S, int nr, long *a, void *uc, struct scratch **Sp)
{
    long r;
    switch (nr) {
    case NR_open:   return do_open(S, a, 0, -1, a[1], a[2], NR_openat);
    case NR_openat: return do_open(S, a, 1, 0, a[2], a[3], NR_openat);
    case NR_openat2: return do_openat2(S, a);
#ifndef CONT_TEST_OLD                                        /* build/opener-old: the previous version, which does not know them (17.4) */
    case NR_bind: case NR_connect: return do_sockaddr(S, a, nr);
#endif
    case NR_creat:  return do_open(S, a, 0, -1, O_CREAT | O_WRONLY | O_TRUNC, a[1], NR_openat);
    case NR_stat: case NR_lstat:
        if ((r = resolve(S, a, 0, -1, nr == NR_stat, 0)) < 0) return r;
        real_nofollow(S, nr == NR_lstat);
        return RE5(NR_newfstatat, AT_FDCWD, S->real, a[1], nr == NR_stat ? 0 : AT_SYMLINK_NOFOLLOW, 0);
    case NR_newfstatat:
        if ((r = resolve(S, a, 1, 0, !(a[3] & AT_SYMLINK_NOFOLLOW), (a[3] & AT_EMPTY_PATH) ? 2 : 0)) < 0) return r;
        if (r == 1) return RE5(nr, a[0], a[1], a[2], a[3], 0);
        real_nofollow(S, (a[3] & AT_SYMLINK_NOFOLLOW) != 0);
        return RE5(nr, AT_FDCWD, S->real, a[2], a[3] | AT_SYMLINK_NOFOLLOW, 0);
    case NR_statx:
        if ((r = resolve(S, a, 1, 0, !(a[2] & AT_SYMLINK_NOFOLLOW), (a[2] & AT_EMPTY_PATH) ? 2 : 0)) < 0) return r;
        if (r == 1) return RE5(nr, a[0], a[1], a[2], a[3], a[4]);
        real_nofollow(S, (a[2] & AT_SYMLINK_NOFOLLOW) != 0);
        return RE5(nr, AT_FDCWD, S->real, a[2] | AT_SYMLINK_NOFOLLOW, a[3], a[4]);
    case NR_access: case NR_faccessat: case NR_faccessat2: {
        int pi = nr == NR_access ? 0 : 1, di = nr == NR_access ? -1 : 0; long mode = a[pi + 1], fl = nr == NR_faccessat2 ? a[3] : 0;
        if ((r = resolve(S, a, pi, di, !(fl & AT_SYMLINK_NOFOLLOW), 0)) < 0) return r;
        to_real(S->v, S->real, S->tmp);
        r = nr == NR_faccessat2 ? RE5(nr, AT_FDCWD, S->real, mode, fl | AT_SYMLINK_NOFOLLOW, 0) : RE5(NR_faccessat, AT_FDCWD, S->real, mode, 0, 0);
        /* do_faccessat: the lookup's and the permission's own answers come first; then a write the permission allows on a
         * regular file, a directory or a symlink under a read-only mount is EROFS, and a special file never is */
        if (r < 0 || !(mode & W_OK) || !is_can_owned(S->v)) return r;
        struct kstat st; if (sys_lstat(S->real, &st) < 0) return r;
        int m = st.st_mode & S_IFMT;
        return m == S_IFREG || m == S_IFDIR || m == S_IFLNK ? -EROFS : r;
    }
    case NR_readlink:   return do_readlink(S, a, 0, -1, (char *)a[1], (int)a[2]);   /* bufsiz is an int: the kernel truncates, so must the copy's bound */
    case NR_readlinkat: return do_readlink(S, a, 1, 0, (char *)a[2], (int)a[3]);
    case NR_getcwd:
        r = RE5(NR_getcwd, S->tmp, PATH_MAX, 0, 0, 0);
        if (r <= 0) return r;
        if (starts_dir(S->tmp, C.root)) from_real(S->tmp);
        r = (long)xstrlen(S->tmp) + 1;
        if ((unsigned long)r > (unsigned long)a[1]) return -ERANGE;   /* size is unsigned: all ones is a large buffer, not a negative one */
        { long e = copy_out(S->pid, (void *)a[0], S->tmp, (size_t)r); if (e) return e; }
        return r;
    case NR_chdir:
        if ((r = resolve(S, a, 0, -1, 1, 0)) < 0) return r;
        to_real_exec(S->v, S->real);
        return RE5(NR_chdir, S->real, 0, 0, 0, 0);
    case NR_execve:   return do_execve(S, a, 0, -1, 0, (char **)a[1], (char **)a[2], Sp);
    case NR_execveat: return do_execve(S, a, 1, 0, a[4], (char **)a[2], (char **)a[3], Sp);
    case NR_truncate:
        if ((r = resolve(S, a, 0, -1, 1, 0)) < 0) return r;
        if (C.loader_mode && xstrcmp(S->v, C.program) == 0) return -ETXTBSY;
        if (is_can_owned(S->v)) {                            /* vfs_truncate: EISDIR and EINVAL for what cannot be truncated, then EROFS */
            struct kstat *st = (struct kstat *)S->b2; int ex = exists_can(S, S->v, st);
            if (!ex) return absent_errno(S);
            if ((st->st_mode & S_IFMT) == S_IFDIR) return -EISDIR;
            if (sys_lstat(S->real, st) == 0 && (st->st_mode & S_IFMT) != S_IFREG) return -EINVAL;
            to_real(S->v, S->real, S->tmp);                  /* vfs_truncate: the permission, EACCES, before the mount, EROFS */
            r = sys_faccessat(AT_FDCWD, S->real, W_OK); if (r < 0) return r;
            return -EROFS;
        }
        to_real_exec(S->v, S->real);
        return RE5(nr, S->real, a[1], 0, 0, 0);
    case NR_mkdir: case NR_mkdirat: {
        int pi = nr == NR_mkdir ? 0 : 1, di = nr == NR_mkdir ? -1 : 0;
        if ((r = resolve(S, a, pi, di, 0, 0)) < 0) return r;
        if ((r = ro_create(S, S->v, 1))) return r;
        return RE5(NR_mkdirat, AT_FDCWD, S->real, a[pi + 1], 0, 0);
    }
    case NR_mknod: case NR_mknodat: {
        int pi = nr == NR_mknod ? 0 : 1, di = nr == NR_mknod ? -1 : 0;
        if ((r = resolve(S, a, pi, di, 0, 0)) < 0) return r;
        if ((r = ro_create(S, S->v, 0))) return r;
        return RE5(NR_mknodat, AT_FDCWD, S->real, a[pi + 1], a[pi + 2], 0);
    }
    case NR_rmdir: case NR_unlink: case NR_unlinkat: {
        int pi = nr == NR_unlinkat ? 1 : 0, di = nr == NR_unlinkat ? 0 : -1;
        long fl = nr == NR_rmdir ? AT_REMOVEDIR : nr == NR_unlinkat ? a[2] : 0;
        if ((r = resolve(S, a, pi, di, 0, 0)) < 0) return r == -ENAMETOOLONG ? delete_overlong(S, di < 0 ? AT_FDCWD : (int)a[di]) : r;
        int sp = last_special(S->b1);                        /* do_rmdir, do_unlinkat: answered before any lookup */
        if (sp) return (fl & AT_REMOVEDIR) ? (sp == 1 ? -EINVAL : sp == 2 ? -ENOTEMPTY : -EBUSY) : -EISDIR;
        if ((r = ro_delete(S, S->v))) return r;
        return RE5(NR_unlinkat, AT_FDCWD, S->real, fl, 0, 0);
    }
    case NR_symlink: case NR_symlinkat: {
        int pi = nr == NR_symlink ? 1 : 2, di = nr == NR_symlink ? -1 : 1;
        if ((r = resolve(S, a, pi, di, 0, 0)) < 0) return r;
        if ((r = ro_create(S, S->v, 0))) return r;
        return RE5(NR_symlinkat, a[0], AT_FDCWD, S->real, 0, 0);
    }
    case NR_rename: case NR_renameat: case NR_renameat2: {
        int opi = nr == NR_rename ? 0 : 1, odi = nr == NR_rename ? -1 : 0, npi = nr == NR_rename ? 1 : 3, ndi = nr == NR_rename ? -1 : 2;
        long fl = nr == NR_renameat2 ? a[4] : 0; struct kstat st;
        if ((r = resolve(S, a, opi, odi, 0, 0)) < 0) return r;
        int osp = last_special(S->b1);
        scpy(S->v2, S->v, PATH_MAX);                         /* old */
        if ((r = resolve(S, a, npi, ndi, 0, 0)) < 0) return r;
        int nsp = last_special(S->b1);
        /* the kernel's order (do_renameat2, oracles 17.1 and 17.7): different mounts first, then a last component
         * that is "." or "..", then the write check, then the lookups */
        int oc = is_can_owned(S->v2), nc = is_can_owned(S->v);
        if (oc != nc) return -EXDEV;
        if (osp) return -EBUSY;
        if (nsp) return (fl & RENAME_NOREPLACE) ? -EEXIST : -EBUSY;
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
        if (r == 1) { if ((r = dfd_virtual((int)a[odi], S->v)) < 0) return r; }
        scpy(S->v2, S->v, PATH_MAX);                         /* old */
        if (!exists_can(S, S->v2, &st)) return absent_errno(S);   /* do_linkat: the old name is looked up before the new one is read at all: its own error, ENOTDIR for a slash on a file */
        if ((r = resolve(S, a, npi, ndi, 0, 0)) < 0) return r;
        /* then the new name, in either domain (EEXIST, the name's own error), then the read-only rule for a
         * can-owned new name, then EXDEV for a can-owned old one */
        scpy(S->cur, S->v, PATH_MAX);
        { size_t l = xstrlen(S->cur); if (l > 1 && S->cur[l - 1] == '/') S->cur[l - 1] = 0; }
        if (exists_can(S, S->cur, &st)) return -EEXIST;
        if ((r = ro_create(S, S->v, 0))) return r;
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
        long fl = nr == NR_utimensat ? (int)a[3] : 0;        /* an int: bits above the word are not flags */
        long ts[4] = { 0, 0, 0, 0 }; int badns = 0;
        if (nr == NR_utimensat) {                            /* the kernel's order (fs/utimes.c): the times read, two UTIME_OMITs a no-op, the flags,
                                                              * then the lookup or the descriptor, then vfs_utimes, where a nanosecond out of range is
                                                              * EINVAL before the mount's EROFS */
            if (a[2]) {
                if ((r = copy_exact(S->pid, ts, (const void *)a[2], sizeof ts))) return r;
                if (ts[1] == UTIME_OMIT && ts[3] == UTIME_OMIT) return 0;
                badns = !nsec_valid(ts[1]) || !nsec_valid(ts[3]);
            }
            if (fl & ~(AT_SYMLINK_NOFOLLOW | AT_EMPTY_PATH)) return -EINVAL;
            if (a[1] == 0) {                                 /* a NULL path names the descriptor, with no flag allowed; with AT_FDCWD it is getname's EFAULT */
                if ((int)a[0] == AT_FDCWD) return -EFAULT;   /* the descriptor is an int in the register: glibc's syscall() zero-extends it */
                if (fl) return -EINVAL;
                if (!fd_can(S, (int)a[0])) return RE5(nr, a[0], 0, a[2], a[3], 0);
                return badns ? -EINVAL : -EROFS;
            }
        } else if ((nr == NR_utimes || nr == NR_futimesat) && a[pi + 1]) {   /* do_futimesat: a microsecond out of range is EINVAL before the lookup */
            long tv[4]; if ((r = copy_exact(S->pid, tv, (const void *)a[pi + 1], sizeof tv))) return r;
            if (tv[1] < 0 || tv[1] >= 1000000 || tv[3] < 0 || tv[3] >= 1000000) return -EINVAL;
        }
        if ((r = resolve(S, a, pi, di, !(fl & AT_SYMLINK_NOFOLLOW), (fl & AT_EMPTY_PATH) != 0)) < 0) return r;
        if (r == 1) {                                        /* AT_EMPTY_PATH: the descriptor itself (5.9+) */
            if (!fd_can(S, (int)a[0])) return RE5(nr, a[0], a[1], a[2], a[3], 0);
            return badns ? -EINVAL : -EROFS;
        }
        if (is_can_owned(S->v)) {                            /* the name's own error, then the times, then the write */
            struct kstat st; if (!exists_can(S, S->v, &st)) return absent_errno(S);
            return badns ? -EINVAL : -EROFS;
        }
        to_real(S->v, S->real, S->tmp);
        if (nr == NR_utime) return RE5(NR_utime, S->real, a[1], 0, 0, 0);
        if (nr == NR_utimes) return RE5(NR_utimes, S->real, a[1], 0, 0, 0);
        if (nr == NR_futimesat) return RE5(NR_futimesat, AT_FDCWD, S->real, a[2], 0, 0);
        return RE5(NR_utimensat, AT_FDCWD, S->real, a[2], fl | AT_SYMLINK_NOFOLLOW, 0);
    }
    case NR_setxattrat: case NR_removexattrat:               /* (dfd, path, at_flags, name, [xattr_args, its size]) */
        if ((r = resolve(S, a, 1, 0, !(a[2] & AT_SYMLINK_NOFOLLOW), (a[2] & AT_EMPTY_PATH) ? 2 : 0)) < 0) return r;
        if (r == 1) return fd_can(S, (int)a[0]) ? -EROFS : RE6(nr, a[0], a[1], a[2], a[3], a[4], a[5]);
        if ((r = ro_attr(S, S->v))) return r;
        to_real(S->v, S->real, S->tmp);
        return RE6(nr, AT_FDCWD, S->real, a[2] | AT_SYMLINK_NOFOLLOW, a[3], a[4], a[5]);
    case NR_getxattrat: case NR_listxattrat:
        if ((r = resolve(S, a, 1, 0, !(a[2] & AT_SYMLINK_NOFOLLOW), (a[2] & AT_EMPTY_PATH) ? 2 : 0)) < 0) return r;
        if (r == 1) return RE6(nr, a[0], a[1], a[2], a[3], a[4], a[5]);
        to_real(S->v, S->real, S->tmp);
        return RE6(nr, AT_FDCWD, S->real, a[2] | AT_SYMLINK_NOFOLLOW, a[3], a[4], a[5]);
    case NR_file_getattr: case NR_file_setattr:              /* (dfd, path, attr, size, at_flags): the chattr ioctls as syscalls */
        if ((r = resolve(S, a, 1, 0, !(a[4] & AT_SYMLINK_NOFOLLOW), (a[4] & AT_EMPTY_PATH) ? 2 : 0)) < 0) return r;
        if (r == 1) return (nr == NR_file_setattr && fd_can(S, (int)a[0])) ? -EROFS : RE5(nr, a[0], a[1], a[2], a[3], a[4]);
        if (nr == NR_file_setattr && (r = ro_attr(S, S->v))) return r;
        to_real(S->v, S->real, S->tmp);
        return RE5(nr, AT_FDCWD, S->real, a[2], a[3], a[4] | AT_SYMLINK_NOFOLLOW);
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
        return r == 0 && is_can_owned(S->v) ? ro_flag(S, (char *)a[1] + STATFS_FLAGS_OFF) : r;
    case NR_fstatfs:
        r = RE5(NR_fstatfs, a[0], a[1], 0, 0, 0);
        return r == 0 && fd_can(S, (int)a[0]) ? ro_flag(S, (char *)a[1] + STATFS_FLAGS_OFF) : r;
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
        r = sys_fcntl((int)a[0], F_GETFL, 0); if (r < 0) return r;
        if (r & O_PATH) return -EBADF;                       /* an O_PATH descriptor cannot be used for these (open(2)) */
        if (fd_can(S, (int)a[0])) return -EROFS;
        return RE5(nr, a[0], a[1], a[2], a[3], a[4]);
    case NR_rt_sigaction:   return do_sigaction(S, a, uc);
    case NR_rt_sigprocmask: return do_sigprocmask(S, a, uc);
    case NR_rt_sigsuspend:  return do_sigsuspend(S, a);
    case NR_ppoll:          return do_ppoll(S, a);
    case NR_pselect6:       return do_pselect6(S, a);
    case NR_epoll_pwait: case NR_epoll_pwait2: return do_epoll_pwait(S, a, nr);
    case NR_io_pgetevents:  return do_io_pgetevents(S, a);
    default:
        return -ENOSYS;                                      /* 7.4.3: a trapped syscall the handler does not know */
    }
}

/* names for the log: one line per trapped syscall, "<name> <result> <virtual path>" */
static const char *sysname(int nr)
{
    switch (nr) {
    case NR_open: case NR_openat: case NR_creat: case NR_openat2: return "open";
#ifndef CONT_TEST_OLD
    case NR_bind: return "bind";
    case NR_connect: return "connect";
#endif
    case NR_stat: case NR_lstat: case NR_newfstatat: case NR_statx: return "stat";
    case NR_fchmod: case NR_fchown: case NR_file_getattr: case NR_file_setattr: return "attr";
    case NR_fsetxattr: case NR_fremovexattr: case NR_setxattrat: case NR_getxattrat: case NR_listxattrat: case NR_removexattrat: return "xattr";
    case NR_ioctl: return "ioctl";
    case NR_inotify_add_watch: case NR_fanotify_mark: return "watch";
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
    long a[6] = { g[REG_ARG0], g[REG_ARG1], g[REG_ARG2], g[REG_ARG3], g[REG_ARG4], g[REG_ARG5] };
    struct scratch *S = scratch_get(pid, tid, frame);
    if (S) { S->resolve = 0; S->v[0] = 0; }
    long r = S ? dispatch(S, nr, a, uc, &S) : -ENOMEM;
    if (C.logfd >= 0 && S) log_line(sysname(nr), r, S->v[0] ? S->v : 0);
    if (S) scratch_put(S);
    g[REG_RESULT] = r;
}

#if defined(__x86_64__)
__asm__(".text\n.globl sig_restorer\n.type sig_restorer,@function\nsig_restorer:\n mov $15, %eax\n syscall\n");
#elif defined(__aarch64__)
__asm__(".text\n.globl sig_restorer\n.type sig_restorer,%function\nsig_restorer:\n mov x8, #139\n svc #0\n");
#endif

void handler_install(void)
{
    struct { void *h; unsigned long flags; void *restorer; unsigned long mask; } sa =
        { (void *)on_sigsys, SA_SIGINFO | SA_ONSTACK | SA_RESTORER | SA_NODEFER, (void *)sig_restorer, 0 };
    if (sys_rt_sigaction(SIGSYS, &sa, 0, 8) < 0) die("cannot install the SIGSYS handler", 0, 0);
    unsigned long m = SIGSYS_BIT;
    sys_rt_sigprocmask(SIG_UNBLOCK, &m, 0, 8);
}
