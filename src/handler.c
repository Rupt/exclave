/* handler.c — the SIGSYS handler (DESIGN.md 7.4.3, 7.5, 8.2).
 *
 * Runs in the program's thread on every trapped syscall. It canonicalises the path in virtual space, decides host or
 * exclave, applies the read-only rule for the exclave, re-issues the syscall through the syscall page, and writes the
 * result into the frame. It uses at most 3 KB of the program's stack (7.5.4); everything larger lives in scratch
 * memory. It never blocks a signal, and it edits the program's signal mask only through the frame the kernel
 * restores. Its own syscalls go through the syscall page (sys.h), so a signal handler that interrupts one of them
 * cannot inherit a marker that would let its syscalls bypass translation.
 */
#include "common.h"

#define IN_DONT_FOLLOW 0x02000000
#define FAN_MARK_ADD 0x1
#define FAN_MARK_REMOVE 0x2
#define FAN_MARK_DONT_FOLLOW 0x4
#define FAN_MARK_FLUSH 0x80
#define STATFS_FLAGS_OFF offsetof(struct kstatfs, f_flags)
#define RENAME_NOREPLACE 1
#define RENAME_EXCHANGE 2
#define RENAME_WHITEOUT 4
#define AT_NO_AUTOMOUNT 0x800
#define STATX__RESERVED 0x80000000U
/* statx's mask bits and the offsets of the fields a directory's correction reads and writes (struct statx) */
#define STATX_TYPE 0x1U
#define STATX_NLINK 0x4U
#define STATX_SIZE 0x200U
#define STX_NLINK_OFF 16
#define STX_MODE_OFF 28
#define STX_SIZE_OFF 40
#define STX_DEV_MAJOR_OFF 136
#define STX_DEV_MINOR_OFF 140
#define STATX_SIZE_BYTES 256
/* statfs's f_type for the filesystems whose directory size counts entries */
#define ZFS_SUPER_MAGIC 0x2fc12fc1L
#define BTRFS_SUPER_MAGIC 0x9123683eL
#define TMPFS_MAGIC 0x01021994L
#define XATTR_CREATE 1
#define XATTR_REPLACE 2
#define XATTR_NAME_MAX 255
#define XATTR_SIZE_MAX 65536
#define IN_MASK_CREATE 0x10000000
#define IN_MASK_ADD 0x20000000
#define ALL_INOTIFY_BITS 0xf700efffU /* include/linux/inotify.h */
#define UTIME_OMIT ((1L << 30) - 2)
#define UTIME_NOW ((1L << 30) - 1)
/* fs/utimes.c */
static int nsec_valid(long ns) { return ns == UTIME_OMIT || ns == UTIME_NOW || (ns >= 0 && ns <= 999999999); }

static inline long *gregs(void *uc) { return (long *)((char *)uc + UC_GREGS_OFF); }
static inline unsigned long *frame_mask(void *uc) { return (unsigned long *)((char *)uc + UC_SIGMASK_OFF); }
#define RE5(nr, a, b, c, d, e) __sc6((nr), (long)(a), (long)(b), (long)(c), (long)(d), (long)(e), 0)
#define RE6(nr, a, b, c, d, e, f) __sc6((nr), (long)(a), (long)(b), (long)(c), (long)(d), (long)(e), (long)(f))

/* ---------- copying from the program's memory with EFAULT fidelity (7.5.6) ---------- */
/* process_vm_readv refused: copies go through a pipe (13 item 15) */
static int no_readv;
/* Whether this thread's PKRU, the program's once the handler has loaded it (program_keys), denies a key but 0 and is
 * not the kernel's initial one, which denies every key a program has not opened, so that it has set its keys itself:
 * process_vm_readv and process_vm_writev reach memory whatever its key, so a copy then goes through the pipe, whose
 * write() and read() the kernel checks against the PKRU as it checks the syscall's own copy (7.5.6). */
static int keys_restricted(void)
{
#if defined(__x86_64__)
    unsigned p = C.pkru_off ? rdpkru() & ~3U : 0;
    return p && p != (C.init_pkru & ~3U);
#else
    return 0;
#endif
}
/* Where process_vm_readv is refused, EPERM under a seccomp profile that gates it on a capability, as Docker's does
 * before kernel 4.8, the copy goes through a pipe: write() from program memory and read() into it fault exactly as the
 * syscall's own copy would, EFAULT or short at the boundary (13 item 15). The pipe lives for the copy alone, a page a
 * step. Returns the bytes copied, or pipe2's -errno. */
static long pipe_copy(void *dst, const void *src, size_t n)
{
    int fds[2];
    long done = 0, e = sys_pipe2(fds, O_CLOEXEC | O_NONBLOCK);
    /* no descriptor left: the syscall answers that, never a raw copy that could fault the handler */
    if (e < 0) return e;
    while (done < (long)n) {
        size_t chunk = n - (size_t)done;
        if (chunk > 4096) chunk = 4096;   /* a page always fits an empty pipe */
        long w = sys_write(fds[1], (const char *)src + done, chunk);
        long r = w > 0 ? sys_read(fds[0], (char *)dst + done, (size_t)w) : w;
        if (r <= 0) break;
        done += r;
        if (r < (long)chunk) break;
    }
    sys_close(fds[0]);
    sys_close(fds[1]);
    return done;
}
/* Copies n bytes of program memory at src into dst; returns the bytes copied, short at a fault, -EFAULT when none can
 * be, or pipe2's -errno. Every copy names the pid of the trap it serves, recorded in the trap's own chunk: a
 * process-wide value would be a vfork child's while a thread of the parent is in its handler, and name the child's new
 * image once it has exec'd (7.5.4). */
static long copy_in(pid_t pid, void *dst, const void *src, size_t n)
{
    unsigned long p = (unsigned long)src;
    if (!p) return -EFAULT;
    if (!no_readv && !keys_restricted()) {
        struct iovec l = {dst, n}, r[2];
        unsigned long rn = 1;
        unsigned long first = 4096 - (p & 4095);
        if (first > n) first = n;
        r[0].iov_base = (void *)p;
        r[0].iov_len = first;
        if (first < n) {
            r[1].iov_base = (void *)(p + first);
            r[1].iov_len = n - first;
            rn = 2;
        }
        long got = sys_process_vm_readv(pid, &l, 1, r, rn, 0);
        if (got != -ENOSYS && got != -EPERM) return got < 0 ? -EFAULT : got;
        no_readv = 1;
        log_msg("process_vm_readv refused; copies through a pipe", 0);
    }
    long g = pipe_copy(dst, src, n);
    return g < 0 ? g : g > 0 || n == 0 ? g : -EFAULT;
}
/* NUL-terminated string into dst[PATH_MAX]; returns its length or -EFAULT/-ENAMETOOLONG */
static long copy_str_in(pid_t pid, char *dst, const char *src)
{
    long got = copy_in(pid, dst, src, 256);
    if (got < 0) return got;
    for (long i = 0; i < got; i++)
        if (!dst[i]) return i;
    if (got < 256) return -EFAULT;
    long more = copy_in(pid, dst + 256, src + 256, PATH_MAX - 256);
    if (more < 0) return more;
    for (long i = 256; i < 256 + more; i++)
        if (!dst[i]) return i;
    return more == PATH_MAX - 256 ? -ENAMETOOLONG : -EFAULT;
}
static long copy_exact(pid_t pid, void *dst, const void *src, size_t n)
{
    long g = copy_in(pid, dst, src, n);
    return g == (long)n ? 0 : -EFAULT;
}
/* the mirror of copy_in: the only writes into program memory the kernel has not just validated */
static long copy_out(pid_t pid, void *dst, const void *src, size_t n)
{
    unsigned long p = (unsigned long)dst;
    if (!p) return -EFAULT;
    if (!no_readv && !keys_restricted()) {
        struct iovec l = {unconst(src), n}, r[2];
        unsigned long rn = 1;
        unsigned long first = 4096 - (p & 4095);
        if (first > n) first = n;
        r[0].iov_base = (void *)p;
        r[0].iov_len = first;
        if (first < n) {
            r[1].iov_base = (void *)(p + first);
            r[1].iov_len = n - first;
            rn = 2;
        }
        long got = sys_process_vm_writev(pid, &l, 1, r, rn, 0);
        if (got != -ENOSYS && got != -EPERM) return got == (long)n ? 0 : -EFAULT;
        no_readv = 1;
    }
    long g = pipe_copy(dst, src, n);
    return g == (long)n ? 0 : g < 0 ? g : -EFAULT;
}

/* ---------- arguments the kernel checks before the lookup (13 item 11) ---------- */
/* may_mknod (fs/namei.c): the file type mknod asks for */
static long may_mknod(unsigned short mode)
{
    switch (mode & S_IFMT) {
    case S_IFREG:
    case S_IFCHR:
    case S_IFBLK:
    case S_IFIFO:
    case S_IFSOCK:
    case 0: return 0;
    case S_IFDIR: return -EPERM;
    default: return -EINVAL;
    }
}
/* import_xattr_name (fs/xattr.c): the name, read before the path, ERANGE when empty or longer than XATTR_NAME_MAX */
static long xattr_name(struct scratch *S, const char *name)
{
    long got = copy_in(S->pid, S->tmp, name, XATTR_NAME_MAX + 1);
    if (got < 0) return got;
    for (long i = 0; i < got; i++)
        if (!S->tmp[i]) return i ? 0 : -ERANGE;
    return got < XATTR_NAME_MAX + 1 ? -EFAULT : -ERANGE;
}
/* setxattr_copy (fs/xattr.c): the flags, the name and the size, in that order, before the path */
static long setxattr_args(struct scratch *S, const char *name, size_t size, int flags)
{
    if (flags & ~(XATTR_CREATE | XATTR_REPLACE)) return -EINVAL;
    long r = xattr_name(S, name);
    if (r) return r;
    return size > XATTR_SIZE_MAX ? -E2BIG : 0;
}

/* ---------- path resolution ---------- */
/* The re-issue of a resolved path (7.4.3): the real path from the root, or, for a walk relative to a descriptor that
 * never touched the exclave, the path as given relative to that descriptor, which the kernel then resolves from the
 * directory itself, immune to a rename of the directory's ancestors, with no flag the handler adds. A path relative to
 * the working directory is re-issued as its real path: the working directory can change under the walk (13 item 14),
 * and a re-issue as given after such a change could write into the tree. */
static int as_given(const struct scratch *S) { return !S->touched_exclave && S->dfd != AT_FDCWD; }
#define RE_DFD(S) (as_given(S) ? (S)->dfd : AT_FDCWD)
#define RE_PATH(S) (as_given(S) ? (S)->given : (S)->real)
/* args[pi] relative to args[di] (or the cwd when di < 0) into S->v; 1 means "empty path with AT_EMPTY_PATH: fd-based".
 * follow is canon's rule for the last component: WALK_FOLLOW, WALK_PARENT, or 0 for a lookup that stops at a link.
 * allow_empty: 1 accepts the empty string, 2 also a NULL path, as getname_maybe_null does under AT_EMPTY_PATH for
 * newfstatat and statx (6.11+), the *xattrat calls and file_getattr and file_setattr; every other syscall answers
 * EFAULT for NULL, AT_EMPTY_PATH or not (oracle 17.7) */
static long resolve(struct scratch *S, long *a, int pi, int di, int follow, int allow_empty)
{
    S->follow_end = 0;
    S->touched_exclave = 0;
    /* the descriptor is recorded before the empty-path answers, so that a call on the descriptor's own file is
     * re-issued through it as given (7.4.3) and the kernel's rule for AT_EMPTY_PATH is its own: linkat's
     * CAP_DAC_READ_SEARCH check before 6.10 (oracle 17.7) */
    int dfd = di < 0 ? AT_FDCWD : (int)a[di];
    S->dfd = dfd;
    if (!a[pi] && allow_empty == 2) return 1;
    long r = copy_str_in(S->pid, S->given, (const char *)a[pi]);
    if (r < 0) return r;
    if (S->given[0] == 0) return allow_empty ? 1 : -ENOENT;
    /* a relative path starts with the kernel's search check on the directory it
     * starts from (link_path_walk): EACCES, ENOTDIR or EBADF before any lookup,
     * which the absolute re-issue would otherwise skip (oracle 17.7) */
    if (S->given[0] != '/') {
        r = sys_faccessat(dfd, ".", X_OK);
        if (r < 0) return r;
    }
    r = canon(S, S->given, dfd, follow, S->v);
    /* a walk from a host directory that failed at a host component: the handler walked from its own reading of
     * the directory's name, which a rename of an ancestor meanwhile makes stale where the kernel, walking from the
     * directory itself, sees nothing; the failed walk is the kernel's own to make too, so the path is spelt through
     * the descriptor's magic link and re-issued as given (7.4.3), the length errors excepted */
    if (r < 0 && r != -ENAMETOOLONG && as_given(S)) return through_magic(S, S->given, dfd, S->v);
    if (r < 0) scpy(S->v, S->given, PATH_MAX);                    /* the log names what was asked for, as given */
    return r;
}
/* Sets S->real to v's real path; 1 when v exists, with st's type set (and only its type when the cache answers), 0
 * when it does not. */
static int exists_exclave(struct scratch *S, const char *v, struct kstat *st)
{
    to_real_exec(v, S->real);
    if (is_exclave_path(v)) { /* 7.4.4: the answer is stable for an exclave path */
        int k = cache_classify(v, S->real, S->tmp);
        if (k == CK_NONE) return 0;
        if (k) {
            st->st_mode = k == CK_DIR ? S_IFDIR : k == CK_LINK ? S_IFLNK : S_IFREG;
            return 1;
        }
    }
    return sys_lstat(S->real, st) == 0;
}

/* the lstat error behind "absent", which the kernel reports before EROFS wherever it looks the name up first:
 * ENOTDIR for a trailing slash on a file, EILSEQ from a filesystem that refuses the name, ENOENT otherwise */
static long absent_errno(struct scratch *S)
{
    long r = sys_lstat(S->real, &S->st);
    return r < 0 && r != -ENOENT ? r : -ENOENT;
}
/* the kernel classifies a path's last component before it looks it up (fs/namei.c): "." and ".." are never
 * created, deleted or renamed, and neither is the root; each syscall has its own answer */
static int last_special(const char *p) /* 0: a name; 1: "."; 2: ".."; 3: the root */
{
    size_t n = xstrlen(p);
    while (n > 1 && p[n - 1] == '/') n--;
    if (n == 1 && p[0] == '/') return 3;
    size_t s = n;
    while (s > 0 && p[s - 1] != '/') s--;
    if (n - s == 1 && p[s] == '.') return 1;
    if (n - s == 2 && p[s] == '.' && p[s + 1] == '.') return 2;
    return 0;
}

/* 8.2: the kernel-matching answers for a read-only exclave, in the kernel's order (oracle 17.7). ro_create, ro_attr
 * and ro_delete each return 0 to re-issue on S->real, which they set, or -errno. A create (filename_create) looks the
 * name up first, so EEXIST for what exists and the name's own error come before EROFS, and a trailing slash on
 * something that is not a directory being made is ENOENT. */
static long ro_create(struct scratch *S, const char *v, int is_dir)
{
    if (!is_exclave_path(v)) {
        to_real_exec(v, S->real);
        return 0;
    }
    scpy(S->cur, v, PATH_MAX);
    size_t l = xstrlen(S->cur);
    int slash = l > 1 && S->cur[l - 1] == '/';
    /* the lookup is of the name; the slash only says "a directory" */
    if (slash) S->cur[l - 1] = 0;
    int ex = exists_exclave(S, S->cur, &S->st);
    if (ex) return -EEXIST;
    long e = absent_errno(S);
    if (e != -ENOENT) return e;
    return slash && !is_dir ? -ENOENT : -EROFS;
}
/* an attribute change: the file must exist, so its absence answers before EROFS */
static long ro_attr(struct scratch *S, const char *v)
{
    struct kstat st;
    int ex = exists_exclave(S, v, &st);
    if (!is_exclave_path(v)) return 0;
    return ex ? -EROFS : absent_errno(S);
}
/* an overlong last component of a delete: do_unlinkat and do_rmdir take the write lock on the parent
 * before they look the name up, so an exclave parent answers EROFS first, where an overlong earlier
 * component fails in the walk (oracle 17.7) */
static long delete_overlong(struct scratch *S, int dfd)
{
    char *p = S->given;
    size_t n = 0;
    while (n < PATH_MAX && p[n]) n++;
    if (n >= PATH_MAX) return -ENAMETOOLONG; /* getname's own answer: no NUL within PATH_MAX */
    while (n > 1 && p[n - 1] == '/') n--; /* a trailing slash names the same component */
    size_t s = n;
    while (s > 0 && p[s - 1] != '/') s--; /* p[s..n) is the last component */
    if (n - s <= NAME_MAX) return -ENAMETOOLONG; /* an earlier component was the overlong one */
    for (size_t i = 0, cl = 0; i < s; i++) {
        if (p[i] == '/') cl = 0;
        else if (++cl > NAME_MAX) return -ENAMETOOLONG;
    }
    /* the parent: what precedes the component, or the directory itself */
    char c = p[s];
    p[s] = 0;
    long r = canon(S, s ? p : ".", dfd, 1, S->v);
    p[s] = c;
    r = r < 0 ? -ENAMETOOLONG : is_exclave_path(S->v) ? -EROFS : -ENAMETOOLONG;
    scpy(S->v, S->given, PATH_MAX); /* the log names what was asked for */
    return r;
}
/* a delete: EROFS before the last component is looked up at all */
static long ro_delete(struct scratch *S, const char *v)
{
    to_real_exec(v, S->real);
    return is_exclave_path(v) ? -EROFS : 0;
}
/* The empty path or the NULL an AT_EMPTY_PATH call was given, for its re-issue: the kernel does not read the program's
 * memory again, which another thread could have changed since the handler read it. */
static long empty_as_given(long path) { return path ? (long)"" : 0; }
/* A no-follow flag for a re-issue on the resolved real path, which names the object the walk found; none when the walk
 * ended on a link the kernel is to follow: a magic link to an object with no path, which it reaches only through the
 * link, or an identity file's host link, followed on the host (canon, 8.4). */
static long nofollow(const struct scratch *S, long flag) { return S->follow_end ? 0 : flag; }
/* a no-follow flag the handler adds to a re-issue on the real path, which names what the walk found */
static long re_flag(const struct scratch *S, long flag) { return as_given(S) ? 0 : nofollow(S, flag); }
static int dfd_virtual(int fd, char *out);

/* ---------- open ---------- */
/* build_open_how and build_open_flags (fs/open.c): the flag word's own rules, before getname and any lookup. open and
 * openat keep the flags the kernel knows and let O_PATH drop every companion but its own, where openat2 has refused
 * the rest first (do_openat2); then O_DIRECTORY with O_CREAT is EINVAL (6.3), and O_TMPFILE wants O_DIRECTORY beside
 * it and write access. */
static long open_flags_check(long *flags, int nr)
{
    long f = *flags;
    if (nr != NR_openat2) {
        f &= (long)VALID_OPEN_FLAGS;
        if (f & O_PATH) f &= O_PATH_FLAGS;
    }
    if ((f & (O_DIRECTORY | O_CREAT)) == (O_DIRECTORY | O_CREAT)) return -EINVAL;
    if ((f & (O_TMPFILE & ~O_DIRECTORY)) && (!(f & O_DIRECTORY) || (f & O_ACCMODE) == O_RDONLY)) return -EINVAL;
    *flags = f;
    return 0;
}
/* open, creat, openat and openat2 of args[pi] relative to args[di], with the syscall's flags and mode: the read-only
 * answers, then the re-issue on the real path. Returns the descriptor or -errno. */
static long do_open(struct scratch *S, long *a, int pi, int di, long flags, long mode, int nr)
{
    long r = open_flags_check(&flags, nr);
    if (r < 0) return r;
    /* build_open_flags: O_CREAT|O_EXCL is O_NOFOLLOW too, and O_PATH keeps no O_CREAT; a create looks the last name
     * up in its parent (lookup_fast_for_open: a trailing slash is EISDIR before the lookup, so before any link there,
     * RESOLVE_NO_SYMLINKS or not) and then follows what it found */
    int creat = (flags & O_CREAT) && !(flags & O_PATH);
    int follow = (flags & O_NOFOLLOW) || (creat && (flags & O_EXCL)) ? 0 : WALK_FOLLOW;
    if (creat) follow |= WALK_PARENT;
    r = resolve(S, a, pi, di, follow, 0);
    /* a walk that never touched the exclave is the kernel's own to make, with every
     * resolve flag, on the host's own mounts (13 item 22); RESOLVE_CACHED dropped */
    if (nr == NR_openat2 && r <= 0 && r != -EFAULT && r != -ENAMETOOLONG && !S->touched_exclave) {
        S->how0[2] &= ~(unsigned long)RESOLVE_CACHED;
        return RE5(NR_openat2, a[0], S->given, S->how0, 24, 0); /* the path the handler read */
    }
    if (r < 0) return r;
    int acc = (int)(flags & O_ACCMODE);
    int wr = acc == O_WRONLY || acc == O_RDWR || (flags & O_TRUNC) || (flags & O_TMPFILE) == O_TMPFILE;
    if (flags & O_PATH) wr = 0;
    size_t vl = xstrlen(S->v);
    /* lookup_fast_for_open: O_CREAT with a trailing slash, before any lookup; a last name that is "." or ".." is the
     * directory itself (handle_dots), where do_open answers O_EXCL's EEXIST before EISDIR, as for any directory */
    if (creat && vl > 1 && S->v[vl - 1] == '/' && !last_special(S->given)) return -EISDIR;
    /* the kernel protects a running program; the launcher protects the one it loaded (13 items 29 and 40), a
     * regular file, which a directory wanted of it (O_DIRECTORY, O_TMPFILE) refuses with the lookup's ENOTDIR first,
     * from the rules below or from the re-issue. may_open checks the permission first, EACCES, with O_TRUNC
     * asking for write access under any access mode (build_open_flags); the ETXTBSY of do_dentry_open and
     * handle_truncate comes after it */
    if (wr && !(flags & O_DIRECTORY) && C.loader_mode && xstrcmp(S->v, C.program) == 0) {
        int want = (acc == O_RDONLY ? R_OK : acc == O_WRONLY ? W_OK : R_OK | W_OK) | ((flags & O_TRUNC) ? W_OK : 0);
        to_real(S->v, S->real, S->tmp);
        long pe = sys_faccessat(AT_FDCWD, S->real, want);
        return pe < 0 ? pe : -ETXTBSY;
    }
    int in = is_exclave_path(S->v);
    struct kstat st;
    int ex = 0, dir = 0;
    long ae = 0; /* the lookup's own error, which comes before the read-only answers */
    if (in) {
        ex = exists_exclave(S, S->v, &st);
        ae = ex ? 0 : absent_errno(S);
        dir = ex && (st.st_mode & S_IFMT) == S_IFDIR;
    }
    /* do_tmpfile: a directory looked up (path_lookupat, LOOKUP_DIRECTORY), then the mount wanted writable */
    if (in && (flags & O_TMPFILE) == O_TMPFILE) return !ex ? ae : dir ? -EROFS : -ENOTDIR;
    /* do_open, path_lookupat: O_DIRECTORY wants a directory, ENOTDIR, before may_open's answers, a symlink's ELOOP
     * among them, and before the write access a read-only mount refuses */
    if (in && (flags & O_DIRECTORY) && ex && !dir) return -ENOTDIR;
    /* an identity file that is a host symlink (8.4), the host's own: the lookup's ENOTDIR, then may_open's ELOOP */
    if ((flags & O_NOFOLLOW) && !(flags & O_PATH) && vis_readlink_identity(S->v, S->tmp) == 1)
        return flags & O_DIRECTORY ? -ENOTDIR : -ELOOP;
    if (in) {
        if (creat && (flags & O_EXCL)) return ex ? -EEXIST : ae != -ENOENT ? ae : -EROFS;
        if (creat && dir) return -EISDIR;
        if (wr) {
            if (!ex) return ae != -ENOENT ? ae : creat ? -EROFS : -ENOENT;
            if (dir) return -EISDIR;
            /* do_open, may_open, do_dentry_open: a special file is opened as the kernel opens it, since the
             * read-only mount does not protect it (ENXIO for a socket, a FIFO's own rules); on a regular file
             * O_TRUNC wants the mount writable before anything, EROFS, and otherwise the permission comes
             * first, EACCES, and the mount after it */
            struct kstat rs;
            to_real(S->v, S->real, S->tmp);
            if (sys_lstat(S->real, &rs) < 0 || (rs.st_mode & S_IFMT) == S_IFREG) {
                if (flags & O_TRUNC) return -EROFS;
                long pe = sys_faccessat(AT_FDCWD, S->real, acc == O_RDWR ? R_OK | W_OK : W_OK);
                return pe < 0 ? pe : -EROFS;
            }
        }
        if (creat && !ex) return ae != -ENOENT ? ae : -EROFS;
        flags &= ~O_CREAT; /* O_CREAT on an existing file, read-only: succeeds */
    }
    /* O_PATH|O_NOFOLLOW on an identity symlink opens the host's link itself */
    to_real(S->v, S->real, S->tmp);
    if (!follow && !as_given(S)) flags |= O_NOFOLLOW;
    /* re-issued as itself, so a kernel without it answers ENOSYS as it would natively */
    if (nr == NR_openat2) {
        unsigned long *how = S->how;
        how[0] = (unsigned long)flags;
        how[2] = 0;
        /* build_open_flags: a mode only with a create */
        how[1] = (flags & O_CREAT) || (flags & O_TMPFILE) == O_TMPFILE ? (unsigned long)mode : 0;
        return RE5(NR_openat2, RE_DFD(S), RE_PATH(S), how, 24, 0);
    }
    return RE5(NR_openat, RE_DFD(S), RE_PATH(S), flags, mode, 0);
}

/* openat2 (7.4.3): the kernel's checks on struct open_how first, in its order (build_open_flags), then the
 * same open as openat with the resolve flags honoured by the walk (canon.c) and dropped from the re-issue;
 * RESOLVE_CACHED refuses what no cached lookup can do, and is otherwise dropped, which openat2(2) permits,
 * since a resolved path is opened without it */
static long do_openat2(struct scratch *S, long *a)
{
    unsigned long how[3];
    long size = a[3], r;
    if (size < 24) return -EINVAL;
    /* an extended struct: the tail must be zero (copy_struct_from_user) */
    if (size > 24) {
        /* up to a page, the kernel's page (13 item 43), read a scratch buffer at a time */
        if ((unsigned long)size > C.pagesz) return -E2BIG;
        for (long off = 0; off < size; off += (long)sizeof S->extra) {
            long n = size - off < (long)sizeof S->extra ? size - off : (long)sizeof S->extra;
            if (copy_in(S->pid, S->extra, (const char *)a[2] + off, (size_t)n) != n) return -EFAULT;
            if (off == 0) xmemcpy(how, S->extra, 24);
            for (long i = off == 0 ? 24 : 0; i < n; i++)
                if (S->extra[i]) return -E2BIG;
        }
    } else if ((r = copy_exact(S->pid, how, (const void *)a[2], 24))) return r;
    unsigned long flags = how[0], mode = how[1], rf = how[2];
    if (flags & ~VALID_OPEN_FLAGS) return -EINVAL;
    if (rf & ~(unsigned long)RESOLVE_ALL) return -EINVAL;
    if ((rf & RESOLVE_BENEATH) && (rf & RESOLVE_IN_ROOT)) return -EINVAL; /* the scoping flags are exclusive */
    int creating = (flags & O_CREAT) || (flags & O_TMPFILE) == O_TMPFILE;
    if (creating ? (mode & ~07777UL) != 0 : mode != 0) return -EINVAL;
    if ((flags & (O_DIRECTORY | O_CREAT)) == (O_DIRECTORY | O_CREAT)) return -EINVAL;
    if (flags & (O_TMPFILE & ~O_DIRECTORY)) {
        if ((flags & O_TMPFILE) != O_TMPFILE) return -EINVAL;
        if ((flags & O_ACCMODE) == O_RDONLY) return -EINVAL;
    }
    if ((flags & O_PATH) && (flags & ~(unsigned long)O_PATH_FLAGS)) return -EINVAL;
    /* a create, a truncate or a temporary file under RESOLVE_CACHED: EAGAIN before any lookup (5.12) */
    if ((rf & RESOLVE_CACHED) && (flags & (O_TRUNC | O_CREAT | (O_TMPFILE & ~O_DIRECTORY)))) return -EAGAIN;
    /* as given, for a host-only walk; canon decides */
    S->how0[0] = flags;
    S->how0[1] = mode;
    S->how0[2] = rf;
    /* the scope: the descriptor's directory, a directory it must be */
    if (rf & (RESOLVE_IN_ROOT | RESOLVE_BENEATH)) {
        int dfd = (int)a[0];
        /* getname first: EFAULT, ENAMETOOLONG */
        if ((r = copy_str_in(S->pid, S->given, (const char *)a[1])) < 0) return r;
        if (S->given[0] == 0) return -ENOENT; /* an empty path, before the descriptor is looked at */
        if ((rf & RESOLVE_BENEATH) && S->given[0] == '/') return -EXDEV; /* nd_jump_root: an absolute path, likewise */
        if (dfd != AT_FDCWD) {
            struct kstat *st = &S->st;
            if ((r = SC2(NR_fstat, dfd, st)) < 0) return r;
            if ((st->st_mode & S_IFMT) != S_IFDIR && (rf & RESOLVE_IN_ROOT)) return -ENOTDIR;
        }
        r = dfd_virtual(dfd, S->v2);
        /* a scope whose file has no path, a removed directory, a memfd, an O_TMPFILE file, a pipe or a socket, is
         * one the handler cannot name and the walk cannot leave: the kernel walks from the descriptor itself
         * (path_init) and finds nothing the exclave owns there, since a removed directory is empty and the rest is
         * no directory at all, so the call is the kernel's own as given, like the unscoped walk through the
         * descriptor's magic link (7.4.3), with RESOLVE_CACHED dropped as for any host-only walk */
        if (r == -ENOENT || (r == 0 && S->v2[0] != '/')) {
            S->how0[2] &= ~(unsigned long)RESOLVE_CACHED;
            return RE5(NR_openat2, dfd, S->given, S->how0, 24, 0);
        }
        if (r < 0) return r;
    }
    S->resolve = (unsigned)rf;
    S->touched_exclave = 1;
    r = do_open(S, a, 1, 0, (long)flags, (long)mode, NR_openat2);
    S->resolve = 0;
    return r;
}

/* ---------- exec (7.4.5): scripts and host programs run inside the exclave's world ---------- */
static long exec_target(struct scratch *S, const char *v, const char *given, char **argv, char **envp, int depth,
                        int cloexec);

/* the first bytes of a file the exec must look at: the kernel needs no descriptor for its own exec, so a program at its
 * descriptor limit may still exec; the handler needs one and borrows it under the hard limit (7.4.5) */
static long open_header(const char *real) { return open_borrowed(real); }

/* A pointer vector of n entries: a scratch region when it fits, an anonymous mapping otherwise, set in *big; NULL
 * when the mapping fails. A mapping made by a vfork child stays in the parent, unused. */
static char **vector(void *region, size_t region_size, long n, void **big)
{
    *big = 0;
    if ((size_t)n * sizeof(char *) <= region_size) return (char **)region;
    long m = sys_mmap(0, ((size_t)n * sizeof(char *) + 0xfff) & ~(size_t)0xfff, PROT_READ | PROT_WRITE,
                      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (m < 0 && m > -4096) return 0;
    *big = (void *)m;
    return (char **)m;
}
static void vector_free(void *big, long n)
{
    if (big) SC2(NR_munmap, big, ((size_t)n * sizeof(char *) + 0xfff) & ~(size_t)0xfff);
}

#define VEC_MAX (1L << 20)
/* The program's argv or envp, read through copy_in as the paths are: a NULL vector is empty, a bad pointer is EFAULT,
 * one of more than VEC_MAX entries is E2BIG, and a vector that cannot be mapped is ENOMEM. Returns the count or
 * -errno; *out has count + extra + 1 slots, the entries first, then a NULL, and *big is the mapping to free, if any.
 * S->tmp is the probe buffer. */
static long vec_read(struct scratch *S, void *region, size_t region_size, char **user, long extra, char ***out,
                     void **big)
{
    long n = 0;
    if (user)
        for (;;) {
            long got = copy_in(S->pid, S->tmp, (const void *)(user + n), PATH_MAX);
            if (got < (long)sizeof(char *)) return -EFAULT;
            long k = got / (long)sizeof(char *), i;
            char **p = (char **)S->tmp;
            for (i = 0; i < k && p[i]; i++);
            n += i;
            if (i < k) break;
            if (n > VEC_MAX) return -E2BIG;
        }
    char **v = vector(region, region_size, n + extra + 1, big);
    if (!v) return -ENOMEM;
    if (n && copy_in(S->pid, (void *)v, (const void *)user, (size_t)n * sizeof(char *)) != n * (long)sizeof(char *)) {
        vector_free(*big, n + extra + 1);
        return -EFAULT;
    }
    v[n] = 0;
    *out = v;
    return n;
}

/* The execve the handler re-issues, preceded by a vfork child's deferred PTRACE_TRACEME (7.4.5): by now the handler has
 * answered what the kernel would refuse without exec'ing, so the request is made where the kernel's exec follows it at
 * once, and the post-exec SIGTRAP stops the new image for the tracer as it would natively. An exec the kernel still
 * refuses leaves the child traced, as the request made at its own time would have. A parent that died meanwhile, which
 * would have detached its tracee, has no request made for it: the child's new parent, a reaper, never asked. asked:
 * the request is to be made. */
static long exec_reissue(const char *path, char **argv, char **envp, int asked)
{
    if (asked) RE5(NR_ptrace, PTRACE_TRACEME, 0, 0, 0, 0);
    return RE5(NR_execve, path, argv, envp, 0, 0);
}

/* The exec of a wrapper, or of the launcher for a program on the loader path, with the identity the kernel would
 * give the program carried in the launcher's own variables (7.4.5, 7.6): EXCLAVE_EXEC names the loader-path
 * target, EXCLAVE_EXECFN the path the program is exec'd by as the kernel spells it, EXCLAVE_COMM the name the
 * kernel would set as comm, and EXCLAVE_TRACED a process its exec leaves newly traced. S->v2 and S->comm hold the
 * second and third from do_execve; an inherited copy of any of the four is dropped, and every launcher strips them
 * before a program runs. The strings are the kernel's to validate. Returns execve's -errno when it fails. */
static long exec_env(struct scratch *S, const char *path, char **argv, char **envp, const char *v, int loader)
{
    void *big;
    char **env;
    long envc = vec_read(S, S->extra, sizeof S->extra, envp, 4, &env, &big);
    if (envc < 0) return envc;
    /* the head of every variable, 16 bytes, room for EXCLAVE_EXECFN=, read in one process_vm_readv for up to 256 at a
     * time rather than one call each (16.4); a variable the batch could not read whole, near the end of a mapping, is
     * read on its own, and the batch resumes after it. tmp holds the heads, rest the iovecs: both free until the end */
    long n = 0;
    char head[16], *heads = S->tmp;
    struct iovec *riov = (struct iovec *)S->rest;
    for (long i = 0; i < envc;) {
        long k = envc - i, done = 0;
        if (k > 256) k = 256;
        if (!no_readv && !keys_restricted()) {
            for (long j = 0; j < k; j++) {
                riov[j].iov_base = env[i + j];
                riov[j].iov_len = sizeof head;
            }
            struct iovec l = {heads, (size_t)k * sizeof head};
            long got = sys_process_vm_readv(S->pid, &l, 1, riov, (unsigned long)k, 0);
            if (got > 0) done = got / (long)sizeof head;
        }
        if (!done) done = -1; /* one variable the slow way */
        for (long j = 0; j < (done < 0 ? 1 : done); j++, i++) {
            const char *h = heads + j * (long)sizeof head;
            long got = sizeof head;
            if (done < 0) {
                got = copy_in(S->pid, head, env[i], sizeof head);
                h = head;
            }
            if (got >= 13 &&
                (xmemcmp(h, "EXCLAVE_EXEC=", 13) == 0 || xmemcmp(h, "EXCLAVE_COMM=", 13) == 0 ||
                 (got >= 15 && (xmemcmp(h, "EXCLAVE_EXECFN=", 15) == 0 || xmemcmp(h, "EXCLAVE_TRACED=", 15) == 0))))
                continue;
            env[n++] = env[i];
        }
    }
    /* a name the child launcher would read cut short is refused, as a path too long to re-issue is (13 item 13) */
    if (xstrlen(S->v2) + 15 >= PATH_MAX || (loader && xstrlen(v) + 13 >= PATH_MAX)) {
        vector_free(big, envc + 5);
        return -ENAMETOOLONG;
    }
    /* after the program's own variables, so that the kernel lays the program's strings out contiguously after its
     * arguments, as a program that writes its title over them expects, with the launcher's at the end */
    scpy(S->cur, "EXCLAVE_EXECFN=", PATH_MAX);
    scat(S->cur, S->v2, PATH_MAX);
    scpy(S->rest, "EXCLAVE_COMM=", PATH_MAX);
    scat(S->rest, S->comm, PATH_MAX);
    env[n++] = S->cur;
    env[n++] = S->rest;
    if (loader) {
        scpy(S->tmp, "EXCLAVE_EXEC=", PATH_MAX); /* tmp's heads are read by now */
        scat(S->tmp, v, PATH_MAX);
        env[n++] = S->tmp;
    }
    /* a vfork child whose deferred PTRACE_TRACEME exec_reissue makes, or a debugger's shell that has passed it on: the
     * launcher execs itself once more, so that a debugger counting its start's execs meets a later one and reads the
     * launcher (7.6) */
    static char traced[] = "EXCLAVE_TRACED=1";
    pid_t tracer = scratch_deferred(S->pid, S->tid, 1);
    int asked = tracer && sys_getppid() == tracer;
    if (asked || C.traced_pid == S->pid) env[n++] = traced;
    env[n] = 0;
    log_line("exec", 0, v);
    long r = exec_reissue(path, argv, env, asked);
    vector_free(big, envc + 5); /* only reached when execve failed */
    return r;
}

/* a script that is not a wrapper (a host script, 7.4.5): the interpreter is resolved in the exclave's world,
 * the script is passed by its virtual path. Kernel convention: argv = interp [arg] script args... */
/* inlined into both callers: one frame per script level (7.5.4) */
static inline __attribute__((always_inline)) long exec_script(struct scratch *S, const char *given, char **argv,
                                                              char **envp, int depth)
{
    struct scratch *S2 = scratch_get(S->pid, S->tid, (unsigned long)__builtin_frame_address(0));
    if (!S2) return -ENOMEM;
    char *line = S2->extra, *vcopy = S2->given; /* the #! line and the script's path, in the vectors' chunk */
    void *big1, *big2;
    char **av, **nargv;
    long argc = vec_read(S, S->extra, sizeof S->extra, argv, 0, &av, &big1);
    if (argc < 0) {
        scratch_put(S2);
        return argc;
    }
    /* rest, cur, real, tmp and v of S2, contiguous, hold six PATH_MAXes */
    _Static_assert(offsetof(struct scratch, v) + PATH_MAX - offsetof(struct scratch, rest) == 6UL * PATH_MAX,
                   "rest through v are one region of six PATH_MAXes");
    nargv = vector(S2->rest, 6UL * PATH_MAX, argc + 4, &big2);
    if (!nargv) {
        vector_free(big1, argc + 1);
        scratch_put(S2);
        return -ENOMEM;
    }
    long fd = open_header(S->real);
    long n = fd < 0 ? fd : sys_read((int)fd, line, BINPRM_BUF_SIZE);
    if (fd >= 0) sys_close((int)fd);
    long r = -ENOEXEC;
    if (n < 0) r = n;
    else {
        /* the script's path as the caller spelt it, as the kernel passes it (7.4.5) */
        scpy(vcopy, given, PATH_MAX);
        long k = shebang_argv(line, n, vcopy, av, argc, nargv, argc + 4);
        if (k == -1) r = -ENOEXEC;
        else if (k == -2) r = -E2BIG;
        else if ((r = canon(S, nargv[0], AT_FDCWD, 1, S->v)) >= 0)
            r = exec_target(S, S->v, nargv[0], nargv, envp, depth + 1, 0);
    }
    vector_free(big2, argc + 4);
    vector_free(big1, argc + 1);
    scratch_put(S2); /* only reached when no exec happened */
    return r;
}

/* cloexec: the script came through a close-on-exec descriptor, which its interpreter could not open: the kernel refuses
 * such an exec with ENOENT before it runs anything (fs/exec.c, BINPRM_FLAGS_PATH_INACCESSIBLE) */
/* 7.4.2: while a program's own filter may be in force, a launcher whose filter has no judge rule, before version
 * 10, would re-issue every trapped call through the page unjudged, so it is not exec'd: EACCES, the kernel's answer
 * for an exec a security policy refuses (security_bprm_check), and a line in the log. real is a launcher file, whose
 * note says; one that cannot be read is refused too. S->tmp and S->extra are the probe's buffers. */
static long launcher_unjudged(struct scratch *S, const char *real, int version)
{
    if (!program_filters) return 0;
    if (version < 0) {
        int gen;
        if (elf_probe(real, S->tmp, &gen, &version, S->extra) < 0) version = 0;
    }
    if (version >= FILTER_JUDGE_SINCE) return 0;
    log_msg("a launcher before filter version 10 is not run under a program's own seccomp filter", real);
    return -EACCES;
}

static long exec_target(struct scratch *S, const char *v, const char *given, char **argv, char **envp, int depth,
                        int cloexec)
{
    /* binfmt_script: five interpreters may nest, the sixth is ELOOP (measured) */
    if (depth > 5) return -ELOOP;
    if (vis_in_data(v)) return -EACCES; /* 6.2: a data directory is never executed */
    to_real_exec(v, S->real);
    /* in the scratch, not the frame: six of these frames may nest (7.5.4) */
    struct kstat *st = &S->st;
    long e;
    /* ENOENT, ENOTDIR for a trailing slash, the name's own error */
    if ((e = sys_stat(S->real, st)) < 0) return e;
    if ((st->st_mode & S_IFMT) != S_IFREG) return -EACCES;
    /* the kernel's answer for this process, triads and search included */
    long ok = sys_faccessat(AT_FDCWD, S->real, X_OK);
    if (ok < 0) return ok;
    /* remembered by the walk (7.4.4) */
    int wrapper =
        (is_exclave_path(v) ? cache_classify(v, S->real, S->tmp) == CK_WRAPPER : is_wrapper_real(S->real, S->tmp)) &&
        payload_of(S->real, S->tmp);
    long fd = open_header(wrapper ? S->tmp : S->real);
    if (fd < 0) return fd;
    unsigned char h[4];
    long n = sys_read((int)fd, h, 4);
    sys_close((int)fd);
    int script = n >= 2 && h[0] == '#' && h[1] == '!',
        elf = n == 4 && h[0] == 0x7f && h[1] == 'E' && h[2] == 'L' && h[3] == 'F';
    if (script && cloexec) return -ENOENT;
    /* a comm left for the file finally run (7.6): this ELF's name; a wrapped script's interpreter is the child's */
    if (!S->comm[0] && elf) scpy(S->comm, base_name(v), sizeof S->comm);
    if (wrapper) {
        if (!script && !elf) return -ENOEXEC;
        if ((e = launcher_unjudged(S, S->real, -1))) return e;
        return exec_env(S, S->real, argv, envp, v, 0); /* the kernel runs the launcher under the program's name */
    }
    /* not a wrapper: a host program, or an unwrapped exclave file */
    if (script) return exec_script(S, given, argv, envp, depth);
    if (!elf) return -ENOEXEC;
    /* 7.4.5: a file carrying a launcher's note is another launcher: exec it as it is, with the launcher's variables */
    int another, version;
    int pr = elf_probe(S->real, S->tmp, &another, &version, S->extra);
    /* load_elf_binary's answer before its point of no return: ENOEXEC for a type, a machine or program headers it
     * cannot load, or an interpreter path without its NUL, EIO for one the file does not hold whole */
    if (pr < 0) return pr;
    if (another >= PAGE_GENERATION) {
        if ((e = launcher_unjudged(S, S->real, version))) return e;
        return exec_env(S, S->real, argv, envp, v, 0);
    }
    /* a launcher whose page this filter traps: the child refuses it by name */
    if (another) return exec_env(S, C.launcher, argv, envp, v, 1);
    /* the loader the header names, resolved as loader_run resolves it (7.3), checked as load_elf_binary checks it
     * before its point of no return: open_exec's answer first, the name's own error, EACCES for a directory, a special
     * file or one without execute permission, then its header, EIO for one the file does not hold whole and ELIBBAD
     * for one that is not this machine's ELF; one that passes but is not the exclave's own file, a host path or a data
     * directory, is left to the child launcher, which refuses it by name */
    if (pr == 1) {
        scpy(S->arg, S->tmp, PATH_MAX);
        if ((e = canon(S, S->arg, AT_FDCWD, 1, S->tmp)) < 0) return e;
        to_real(S->tmp, S->real, S->cur); /* through the wrapper redirect: ld.so is wrapped */
        if ((e = sys_stat(S->real, st)) < 0) return e;
        if ((st->st_mode & S_IFMT) != S_IFREG) return -EACCES;
        if ((ok = sys_faccessat(AT_FDCWD, S->real, X_OK)) < 0) return ok;
        if ((e = elf_interp_probe(S->real, S->extra)) < 0) return e;
    }
    return exec_env(S, C.launcher, argv, envp, v, 1);
}

/* a descriptor with no path (13 item 25): a memfd, or a file unlinked since it was opened. The kernel runs the file
 * behind the descriptor; the launcher runs it on the loader path named through /proc/self/fd, by a dup without
 * close-on-exec that the child launcher closes once the segments are mapped, and the child answers the link's text for
 * /proc/self/exe as the kernel does. A script goes to its interpreter as /dev/fd/N, the kernel's spelling, and a
 * close-on-exec script is ENOENT, since the interpreter could not open it (execveat(2)) */
static long exec_descriptor(struct scratch *S, int fd, char **argv, char **envp)
{
    /* buffers from the scratch (7.5.4): the number, the stat, the header */
    char *n = S->cur;
    ltoa_(fd, n);
    scpy(S->real, "/proc/self/fd/", PATH_MAX);
    scat(S->real, n, PATH_MAX);
    struct kstat *st = &S->st;
    long e;
    if ((e = sys_stat(S->real, st)) < 0) return e;
    if ((st->st_mode & S_IFMT) != S_IFREG) return -EACCES;
    long ok = sys_faccessat(AT_FDCWD, S->real, X_OK);
    if (ok < 0) return ok;
    /* comm is the file's own name (7.6), which the link spells with " (deleted)" */
    long l = sys_readlink(S->real, S->tmp, PATH_MAX - 1);
    if (l < 0) return l;
    S->tmp[l] = 0;
    if (l > 10 && xstrcmp(S->tmp + l - 10, " (deleted)") == 0) S->tmp[l - 10] = 0;
    scpy(S->comm, base_name(S->tmp), sizeof S->comm);
    long h = open_header(S->real);
    if (h < 0) return h;
    unsigned char *head = (unsigned char *)S->tmp;
    long k = sys_read((int)h, head, 4);
    sys_close((int)h);
    if (k >= 2 && head[0] == '#' && head[1] == '!') {
        long fl = sys_fcntl(fd, F_GETFD, 0);
        if (fl < 0) return fl;
        if (fl & FD_CLOEXEC) return -ENOENT;
        S->comm[0] = 0; /* a script's comm is its interpreter's, the file finally run (7.6) */
        /* S->real is read; /dev/fd/N, the kernel's spelling, is what the interpreter gets */
        scpy(S->v, S->v2, PATH_MAX);
        return exec_script(S, S->v, argv, envp, 0);
    }
    if (!(k == 4 && head[0] == 0x7f && head[1] == 'E' && head[2] == 'L' && head[3] == 'F')) return -ENOEXEC;
    /* inherited by the child launcher, which closes it after the mapping */
    long m = sys_fcntl(fd, F_DUPFD, 3);
    if (m < 0) return m;
    ltoa_(m, n);
    scpy(S->v, "/proc/self/fd/", PATH_MAX);
    scat(S->v, n, PATH_MAX);
    long r = exec_env(S, C.launcher, argv, envp, S->v, 1);
    sys_close((int)m); /* only reached when the exec failed */
    return r;
}

static long do_execve(struct scratch *S, long *a, int pi, int di, long flags, char **argv, char **envp)
{
    long r;
    /* execveat: a flag the kernel does not know is EINVAL before the name is read (oracle 17.7) */
    if (flags & ~(long)(AT_SYMLINK_NOFOLLOW | AT_EMPTY_PATH | AT_EXECVE_CHECK)) return -EINVAL;
    r = resolve(S, a, pi, di, !(flags & AT_SYMLINK_NOFOLLOW), (flags & AT_EMPTY_PATH) != 0);
    if (r < 0) return r;
    /* AT_EXECVE_CHECK (6.14) asks whether the file could be run and runs nothing: the kernel's own answer for the file
     * the walk found, re-issued with the flags as given, a wrapper answering as the launcher it is; a kernel before
     * 6.14 answers EINVAL for the flag (7.4.5) */
    if (flags & AT_EXECVE_CHECK) {
        if (r == 1) return RE5(NR_execveat, a[di], empty_as_given(a[pi]), (long)argv, (long)envp, flags);
        to_real(S->v, S->real, S->tmp);
        return RE5(NR_execveat, RE_DFD(S), RE_PATH(S), (long)argv, (long)envp, flags | re_flag(S, AT_SYMLINK_NOFOLLOW));
    }
    int dfd = di < 0 ? AT_FDCWD : (int)a[di], byfd = r == 1, cloexec = 0;
    /* the name the program is exec'd by, spelt as the kernel spells it (fs/exec.c, alloc_bprm): the path as given, or
     * through a descriptor /dev/fd/N and /dev/fd/N/rel; a script's $0, AT_EXECFN and comm come from it (7.6) */
    if (dfd != AT_FDCWD && (byfd || S->given[0] != '/')) {
        char *num = S->tmp;
        ltoa_(dfd, num);
        scpy(S->v2, "/dev/fd/", PATH_MAX);
        scat(S->v2, num, PATH_MAX);
        if (!byfd) {
            if (xstrlen(S->v2) + 1 + xstrlen(S->given) >= PATH_MAX) return -ENAMETOOLONG;
            scat(S->v2, "/", PATH_MAX);
            scat(S->v2, S->given, PATH_MAX);
        }
    } else scpy(S->v2, S->given, PATH_MAX);
    if (byfd) {
        /* a descriptor on a symlink itself (O_PATH|O_NOFOLLOW) cannot be run (fs/exec.c) */
        struct kstat st;
        /* AT_FDCWD with an empty path is the working directory, no descriptor */
        if (dfd != AT_FDCWD) {
            if (SC2(NR_fstat, dfd, &st) == 0) {
                unsigned m = st.st_mode & S_IFMT;
                /* a symlink descriptor (O_PATH|O_NOFOLLOW) cannot be run */
                if (m == S_IFLNK) return -ELOOP;
                /* do_open_execat: only a regular file is exec'd; a pipe or socket has no path to spell */
                if (m != S_IFREG) return -EACCES;
            }
            r = sys_fcntl(dfd, F_GETFD, 0);
            if (r < 0) return r;
            cloexec = (r & FD_CLOEXEC) != 0;
        }
        r = dfd_virtual(dfd, S->v);
        /* fd_virtual: the link ends " (deleted)": no path */
        if (r == -ENOENT) return exec_descriptor(S, dfd, argv, envp);
        if (r < 0) return r;
        /* through a bare descriptor, comm is the name of the file finally run (comm_from_dentry, fs/exec.c since
         * 6.12): an ELF's own, a script's interpreter's; left empty here and set where that file is found */
        S->comm[0] = 0;
    } else {
        if (flags & AT_SYMLINK_NOFOLLOW) { /* the kernel refuses to run a symlink itself, an identity link included */
            struct kstat st;
            to_real_exec(S->v, S->real);
            if (sys_lstat(S->real, &st) == 0 && (st.st_mode & S_IFMT) == S_IFLNK) return -ELOOP;
        }
        scpy(S->comm, base_name(S->v2), sizeof S->comm); /* kbasename of the name as spelt */
    }
    return exec_target(S, S->v, S->v2, argv, envp, 0, cloexec);
}

/* ---------- readlink: /proc links and identity files answer in virtual terms (8.4); any other link's text is
 * returned as stored, as the kernel returns it ---------- */
static long do_readlink(struct scratch *S, long *a, int pi, int di, char *buf, long bufsiz)
{
    if (bufsiz <= 0) return -EINVAL; /* do_readlinkat: before the path is read at all */
    long r = resolve(S, a, pi, di, 0, di >= 0);
    if (r < 0) return r;
    char *ans = 0;
    /* readlinkat(fd, ""): the kernel reads the descriptor's own link */
    if (r == 1) {
        r = RE5(NR_readlinkat, a[di], "", S->tmp, PATH_MAX - 1, 0);
        if (r < 0) return r;
        S->tmp[r] = 0;
        /* a descriptor on a /proc link reports a real path */
        if (fd_real_path((int)a[di], S->real2) >= 0 && xstrncmp(S->real2, "/proc/", 6) == 0) from_real(S->tmp);
        ans = S->tmp;
    }
    if ((C.loader_mode || xstrcmp(C.exe, C.program) != 0) && is_self_exe(S->v, S->pid)) ans = C.exe;
    if (!ans) {
        r = vis_readlink_identity(S->v, S->tmp);
        if (r < 0) return r;
        if (r == 1) ans = S->tmp;
    }
    if (!ans) {
        to_real_exec(S->v, S->real);
        /* 16.6 item 8: the walk remembered an exclave path's kind (7.4.4), so a directory or a file answers EINVAL and
         * a link its text without asking the kernel again; what is not remembered, absent above all, is asked */
        int k = is_exclave_path(S->v) ? cache_get(S->v, S->tmp) : 0;
        if (k == CK_DIR || k == CK_FILE || k == CK_WRAPPER) return -EINVAL;
        if (k != CK_LINK) {
            r = RE5(NR_readlinkat, RE_DFD(S), RE_PATH(S), S->tmp, PATH_MAX - 1, 0);
            if (r < 0) return r;
            S->tmp[r] = 0;
        }
        /* another process's exe that is the launcher names the program that process runs (7.6) */
        int o = other_exe(S, S->v, S->tmp);
        if (!o && xstrncmp(S->v, "/proc/", 6) == 0) from_real(S->tmp); /* real paths */
        ans = S->tmp;
        /* another process's exe link that names a wrapped script: that process runs the script's interpreter,
         * which is what the kernel would report natively; a tracer reads its tracee's link as the kernel gives it
         * (7.6) */
        if (o >= 0 && xstrncmp(S->v, "/proc/", 6) == 0 && xstrlen(S->v) > 4 &&
            xstrcmp(S->v + xstrlen(S->v) - 4, "/exe") == 0 && is_exclave_path(ans)) {
            scpy(S->v2, ans, PATH_MAX);
            to_real_exec(S->v2, S->real);
            if (is_wrapper_real(S->real, S->real2) && payload_of(S->real, S->real2)) {
                long fd = sys_open(S->real2, O_RDONLY | O_CLOEXEC, 0);
                char *line = S->extra; /* the #! line, as exec reads it */
                long n = fd < 0 ? -1 : sys_read((int)fd, line, BINPRM_BUF_SIZE);
                if (fd >= 0) sys_close((int)fd);
                char *nargv[4]; /* the interpreter as exec reads it */
                if (n > 0 && shebang_argv(line, n, S->real2, 0, 1, nargv, 4) > 0) {
                    scpy(S->arg, nargv[0], PATH_MAX);
                    if (canon(S, S->arg, AT_FDCWD, 1, S->v) == 0) {
                        scpy(S->tmp, S->v, PATH_MAX);
                        ans = S->tmp;
                    }
                }
            }
        }
    }
    long l = (long)xstrlen(ans);
    if (l > bufsiz) l = bufsiz;
    /* the program's buffer is never validated by the kernel here */
    if (l) {
        r = copy_out(S->pid, buf, ans, (size_t)l);
        if (r) return r;
    }
    return l;
}

/* ---------- signal masks (7.5.2): SIGSYS is never blocked, never handled by the program ---------- */
static long do_sigaction(struct scratch *S, long *a)
{
    int sig = (int)a[0];
    const void *act = (const void *)a[1];
    void *old = (void *)a[2];
    long size = a[3];
    if (size != 8) return RE5(NR_rt_sigaction, sig, act, old, size, 0);
    if (!act) return RE5(NR_rt_sigaction, sig, 0, old, size, 0);
    unsigned long k[4];
    long r = copy_exact(S->pid, k, act, sizeof k);
    if (r) return r;
    /* accepted, ignored (13 item 23), once act has been read as sys_rt_sigaction reads it; old reports the truth */
    if (sig == SIGSYS) return old ? RE5(NR_rt_sigaction, sig, 0, old, size, 0) : 0;
    k[3] &= ~SIGSYS_BIT;
    return RE5(NR_rt_sigaction, sig, k, old, size, 0);
}
static long do_sigprocmask(struct scratch *S, long *a, void *uc)
{
    int how = (int)a[0];
    const void *set = (const void *)a[1];
    void *old = (void *)a[2];
    long size = a[3];
    if (!set || size != 8) return RE5(NR_rt_sigprocmask, how, set, old, size, 0);
    unsigned long m;
    long r = copy_exact(S->pid, &m, set, 8);
    if (r) return r;
    if (how == SIG_BLOCK || how == SIG_SETMASK) m &= ~SIGSYS_BIT;
    unsigned long was;
    r = RE5(NR_rt_sigprocmask, how, &m, &was, size, 0);
    if (r) return r;
    unsigned long cur;
    if (sys_rt_sigprocmask(SIG_BLOCK, 0, &cur, 8) == 0) *frame_mask(uc) = cur;
    /* the old mask is written last, as sys_rt_sigprocmask writes it: a bad pointer is EFAULT with the mask changed */
    return old ? copy_out(S->pid, old, &was, 8) : 0;
}
static long do_sigsuspend(struct scratch *S, long *a)
{
    unsigned long m;
    long size = a[1];
    if (size != 8) return -EINVAL;
    long r = copy_exact(S->pid, &m, (const void *)a[0], 8);
    if (r) return r;
    m &= ~SIGSYS_BIT;
    return RE5(NR_rt_sigsuspend, &m, size, 0, 0, 0);
}
/* The timeout of a wait that carries a mask, read and checked ahead of the mask: ppoll, do_pselect and epoll_pwait2
 * call get_timespec64 and poll_select_set_timeout before set_user_sigmask, so a bad pointer is EFAULT and a bad
 * timespec EINVAL before the mask's own answers, and io_pgetevents reads its timeout before its mask pair and
 * never checks it. The re-issued syscall reads the program's timeout again. */
static long check_timeout(struct scratch *S, const void *tsp, int valid)
{
    if (!tsp) return 0;
    long ts[2];
    long r = copy_exact(S->pid, ts, tsp, sizeof ts);
    if (r) return r;
    return valid && (ts[0] < 0 || ts[1] < 0 || ts[1] >= 1000000000L) ? -EINVAL : 0;
}
static long do_ppoll(struct scratch *S, long *a)
{
    unsigned long m;
    long r = check_timeout(S, (const void *)a[2], 1);
    if (r) return r;
    if (a[4] != 8) return -EINVAL;
    r = copy_exact(S->pid, &m, (const void *)a[3], 8);
    if (r) return r;
    m &= ~SIGSYS_BIT;
    return RE5(NR_ppoll, a[0], a[1], a[2], &m, a[4]);
}
static long do_pselect6(struct scratch *S, long *a)
{
    struct {
        const unsigned long *ss;
        unsigned long len;
    } sp;
    unsigned long m;
    long r = copy_exact(S->pid, &sp, (const void *)a[5], sizeof sp);
    if (r) return r;
    if (!sp.ss) return RE6(NR_pselect6, a[0], a[1], a[2], a[3], a[4], a[5]);
    r = check_timeout(S, (const void *)a[4], 1);
    if (r) return r;
    if (sp.len != 8) return -EINVAL;
    r = copy_exact(S->pid, &m, sp.ss, 8);
    if (r) return r;
    m &= ~SIGSYS_BIT;
    sp.ss = &m;
    return RE6(NR_pselect6, a[0], a[1], a[2], a[3], a[4], &sp);
}
/* epoll_pwait and epoll_pwait2: mask in a[4], size in a[5] */
static long do_epoll_pwait(struct scratch *S, long *a, int nr)
{
    unsigned long m;
    long r = nr == NR_epoll_pwait2 ? check_timeout(S, (const void *)a[3], 1) : 0;
    if (r) return r;
    if (a[5] != 8) return -EINVAL;
    r = copy_exact(S->pid, &m, (const void *)a[4], 8);
    if (r) return r;
    m &= ~SIGSYS_BIT;
    return RE6(nr, a[0], a[1], a[2], a[3], &m, a[5]);
}
static long do_io_pgetevents(struct scratch *S, long *a)
{
    struct {
        const unsigned long *ss;
        unsigned long len;
    } sp;
    unsigned long m;
    long r = check_timeout(S, (const void *)a[4], 0);
    if (r) return r;
    r = copy_exact(S->pid, &sp, (const void *)a[5], sizeof sp);
    if (r) return r;
    if (!sp.ss) return RE6(NR_io_pgetevents, a[0], a[1], a[2], a[3], a[4], a[5]);
    if (sp.len != 8) return -EINVAL;
    r = copy_exact(S->pid, &m, sp.ss, 8);
    if (r) return r;
    m &= ~SIGSYS_BIT;
    sp.ss = &m;
    return RE6(NR_io_pgetevents, a[0], a[1], a[2], a[3], a[4], &sp);
}

/* ---------- descriptors that name exclave files ---------- */
/* ST_RDONLY into the flag word of a statfs the kernel just filled (8.2), through the copies of 7.5.6
 * like every other write into program memory: the kernel validated the buffer a moment ago, but
 * another thread may have unmapped it since */
static long ro_flag(struct scratch *S, void *flags)
{
    long f;
    if (copy_exact(S->pid, &f, flags, sizeof f)) return -EFAULT;
    f |= ST_RDONLY;
    return copy_out(S->pid, flags, &f, sizeof f);
}
/* a descriptor argument that may be AT_FDCWD */
static int dfd_virtual(int fd, char *out) { return fd == AT_FDCWD ? cwd_virtual(out) : fd_virtual(fd, out); }
static long fd_exclave(struct scratch *S, int fd)
{
    long r = dfd_virtual(fd, S->v);
    if (r < 0) return 0; /* pipes, sockets, deleted: the kernel decides */
    return S->v[0] == '/' && is_exclave_path(S->v);
}

/* ---------- bind and connect (7.4.3, 13 item 31) ---------- */
/* a sockaddr_un's path is a path like any other, under the visibility rule. The kernel reads the family and the
 * path out of the structure, so the handler does the same and answers for an exclave path what the kernel answers
 * on a read-only bind mount (oracle 17.7): bind is a create (unix_bind_bsd), the name looked up first, EEXIST read
 * as EADDRINUSE, then EROFS; connect looks the name up (unix_find_bsd), needs write permission on what it finds,
 * and finds no listener behind a file in the tree, ECONNREFUSED, since nothing can bind there. A host path, an
 * abstract name, an unnamed address or another family is re-issued as given; a bad length is the kernel's EINVAL. */
#ifndef EXCLAVE_TEST_OLD /* build/launcher-old does not trap bind or connect */
#define AF_UNIX 1
static long do_sockaddr(struct scratch *S, long *a, int nr)
{
    /* addrlen is an int: the kernel truncates, and a length past the word must not
     * turn an exclave path into one re-issued as written */
    long len = (int)a[2];
    scpy(S->v, "-", PATH_MAX);
    if (len < 2 || len > 110 || !a[1]) return RE5(nr, a[0], a[1], a[2], 0, 0);
    long r = copy_exact(S->pid, S->extra, (const void *)a[1], (size_t)len);
    if (r) return r;
    unsigned short fam;
    xmemcpy(&fam, S->extra, 2);
    /* re-issued from the handler's copy, as every address the handler reads is */
    if (fam != AF_UNIX || len == 2 || S->extra[2] == 0) return RE5(nr, a[0], S->extra, len, 0, 0);
    /* unix_mkname_bsd: the path ends at the length or at a NUL */
    size_t n = (size_t)len - 2;
    if (n > 108) n = 108;
    xmemcpy(S->given, S->extra + 2, n);
    S->given[n] = 0;
    if (S->given[0] != '/') {
        r = sys_faccessat(AT_FDCWD, ".", X_OK);
        if (r < 0) return r;
    }
    /* unix_bind_bsd creates the name (start_creating_path); connect looks it up (LOOKUP_FOLLOW) */
    if ((r = canon(S, S->given, AT_FDCWD, nr == NR_connect ? WALK_FOLLOW : WALK_PARENT, S->v)) < 0) {
        scpy(S->v, S->given, PATH_MAX);
        return r;
    }
    if (!is_exclave_path(S->v)) {
        /* a relative walk that stayed in the host's domain is the kernel's own, as given: from a working directory of
         * any depth, and getsockname answers the program's own name */
        if (!S->touched_exclave) return RE5(nr, a[0], S->extra, len, 0, 0);
        /* otherwise the kernel gets the resolved real path, as for every other syscall, since an exclave symlink or a
         * rewritten magic link may have led here (oracle 17.7) */
        to_real(S->v, S->real, S->tmp);
        size_t rl = xstrlen(S->real), gl = xstrlen(S->given);
        /* a trailing slash is the kernel's to judge (filename_create) */
        size_t slash = gl > 1 && S->given[gl - 1] == '/' && S->real[rl - 1] != '/';
        if (rl + slash <= 107) {
            xmemcpy(S->extra + 2, S->real, rl);
            if (slash) S->extra[2 + rl] = '/';
            S->extra[2 + rl + slash] = 0;
            return RE5(nr, a[0], S->extra, 2 + rl + slash + 1, 0, 0);
        }
        /* sun_path holds 107 bytes and a real path can be longer than the program's own: the name is
         * re-issued through a descriptor of its directory, /proc/self/fd/N/NAME, which the kernel
         * walks as it walks the path (13 item 31) */
        char *e = S->real + rl;
        while (e > S->real && e[-1] == '/') e--;
        char *b = e;
        while (b > S->real && b[-1] != '/') b--;
        size_t nl = (size_t)(e - b), dl = (size_t)(b - S->real);
        if (dl == 0 || nl == 0) return -ENAMETOOLONG;
        xmemcpy(S->tmp, S->real, dl);
        S->tmp[dl] = 0;
        long fd = sys_open(S->tmp, O_PATH | O_DIRECTORY | O_CLOEXEC, 0);
        if (fd < 0) return fd;
        char *p = (char *)S->extra + 2;
        scpy(p, "/proc/self/fd/", 108);
        ltoa_(fd, S->cur);
        scat(p, S->cur, 108);
        size_t pl = xstrlen(p);
        if (pl + 1 + nl + slash > 107) {
            sys_close((int)fd);
            return -ENAMETOOLONG;
        }
        p[pl] = '/';
        xmemcpy(p + pl + 1, b, nl);
        pl += 1 + nl;
        if (slash || *e) p[pl++] = '/';
        p[pl] = 0;
        r = RE5(nr, a[0], S->extra, 2 + pl + 1, 0, 0);
        sys_close((int)fd);
        return r;
    }
    if (nr == NR_bind) {
        r = ro_create(S, S->v, 0);
        return r == -EEXIST ? -EADDRINUSE : r;
    }
    if (!exists_exclave(S, S->v, &S->st)) return absent_errno(S);
    r = sys_faccessat(AT_FDCWD, S->real, W_OK);
    if (r < 0) return r;
    return -ECONNREFUSED;
}
#endif

/* Whether the directory the stat named holds .real/: for a path, the exclave's virtual S->v, by the cache under
 * S->v/.real, which is the exclave's and so never changes (7.4.4), the kernel asked on a miss and the answer kept;
 * for a descriptor, the kernel asked, and then whether the descriptor is the exclave's. A path the cache knows is no
 * directory is no such directory. */
static int holds_real(struct scratch *S, int dfd, const char *path)
{
    if (!path)
        return sys_fstatat(dfd, ".real", &S->st, AT_SYMLINK_NOFOLLOW) == 0 && (S->st.st_mode & S_IFMT) == S_IFDIR &&
               fd_exclave(S, dfd);
    int k = cache_get(S->v, S->rest);
    if (k && k != CK_DIR) return 0;
    if (xstrlen(S->v) + sizeof "/.real" > PATH_MAX || xstrlen(path) + sizeof "/.real" > PATH_MAX) return 0;
    scpy(S->tmp, S->v, PATH_MAX);
    scat(S->tmp, "/.real", PATH_MAX);
    if ((k = cache_get(S->tmp, S->rest))) return k == CK_DIR;
    scpy(S->real2, path, PATH_MAX);
    scat(S->real2, "/.real", PATH_MAX);
    long r = sys_fstatat(dfd, S->real2, &S->st, AT_SYMLINK_NOFOLLOW);
    if (r == 0 || r == -ENOENT || r == -ENOTDIR) {
        k = r == 0 && (S->st.st_mode & S_IFMT) == S_IFDIR ? CK_DIR : CK_NONE;
        cache_put(S->tmp, k, 0);
    }
    return k == CK_DIR;
}

/* A directory of the tree that holds .real/, as upstream's tree would stat it (8.3): a link fewer where links count
 * subdirectories, so not on a filesystem that gives every directory one, and on a filesystem whose directory size
 * counts entries, ZFS one an entry, btrfs twice its name and tmpfs 20 bytes, a size without .real's, where the
 * directory is on the tree's own filesystem. A stat has just written the program's buffer at at, statx's or struct
 * stat's, which is read back and written again only for such a directory; a field statx was not asked for is left
 * alone. The directory is path from dfd as the stat named it, its virtual path S->v, ours whether that is the
 * exclave's; or with path 0 the descriptor dfd itself. Anything that fails leaves the kernel's answer as it is. */
static void dir_upstream(struct scratch *S, int statx, long at, int dfd, const char *path, int ours)
{
    if (!ours || !holds_real(S, dfd, path)) return;
    void *buf = (void *)at;
    char *s = S->extra;
    size_t n = statx ? STATX_SIZE_BYTES : sizeof(struct kstat);
    if (copy_exact(S->pid, s, buf, n)) return;
    unsigned mask = statx ? *(unsigned *)s : STATX_TYPE | STATX_NLINK | STATX_SIZE;
    unsigned mode = statx ? *(unsigned short *)(s + STX_MODE_OFF) : ((struct kstat *)s)->st_mode;
    if (!(mask & STATX_TYPE) || (mode & S_IFMT) != S_IFDIR) return;
    /* the tree's filesystem's size of an entry, asked once */
    if (!C.dirent_known) {
        struct kstatfs fs;
        long t = SC2(NR_statfs, C.root, &fs) == 0 ? fs.f_type : 0;
        C.dirent_size = t == ZFS_SUPER_MAGIC ? 1 : t == BTRFS_SUPER_MAGIC ? 2 * 5 : t == TMPFS_MAGIC ? 20 : 0;
        C.dirent_known = 1;
    }
    unsigned long sd = C.root_dev, ma = ((sd >> 8) & 0xfff) | ((sd >> 32) & ~0xfffUL),
                  mi = (sd & 0xff) | ((sd >> 12) & ~0xffUL);
    int same_fs = statx ? *(unsigned *)(s + STX_DEV_MAJOR_OFF) == ma && *(unsigned *)(s + STX_DEV_MINOR_OFF) == mi
                        : ((struct kstat *)s)->st_dev == sd;
    long entry = same_fs ? C.dirent_size : 0;
    if (statx) {
        unsigned *nlink = (unsigned *)(s + STX_NLINK_OFF);
        unsigned long *size = (unsigned long *)(s + STX_SIZE_OFF);
        if ((mask & STATX_NLINK) && *nlink >= 3) --*nlink;
        if ((mask & STATX_SIZE) && entry && *size >= (unsigned long)entry) *size -= (unsigned long)entry;
    } else {
        struct kstat *st = (struct kstat *)s;
        if (st->st_nlink >= 3) st->st_nlink--;
        if (entry && st->st_size >= entry) st->st_size -= entry;
    }
    copy_out(S->pid, buf, s, n);
}

/* stat, lstat, newfstatat and statx: the flags the kernel checks first, then the re-issue of the resolved path */
static long do_stat(struct scratch *S, int nr, long *a)
{
    long r;
    switch (nr) {
    case NR_stat:
    case NR_lstat:
        if ((r = resolve(S, a, 0, -1, nr == NR_stat, 0)) < 0) return r;
        to_real(S->v, S->real, S->tmp);
        r = RE5(NR_newfstatat, AT_FDCWD, S->real, a[1], nr == NR_stat ? 0 : nofollow(S, AT_SYMLINK_NOFOLLOW), 0);
        if (r == 0) dir_upstream(S, 0, a[1], AT_FDCWD, S->real, is_exclave_path(S->v));
        return r;
    case NR_newfstatat:
        /* vfs_fstatat: the flags before the name */
        if ((unsigned)a[3] & ~(unsigned)(AT_SYMLINK_NOFOLLOW | AT_NO_AUTOMOUNT | AT_EMPTY_PATH | AT_STATX_SYNC_TYPE))
            return -EINVAL;
        if ((r = resolve(S, a, 1, 0, !(a[3] & AT_SYMLINK_NOFOLLOW), (a[3] & AT_EMPTY_PATH) ? 2 : 0)) < 0) return r;
        if (r == 1) {
            r = RE5(nr, a[0], empty_as_given(a[1]), a[2], a[3], 0);
            if (r == 0) dir_upstream(S, 0, a[2], (int)a[0], 0, -1);
            return r;
        }
        to_real(S->v, S->real, S->tmp);
        r = RE5(nr, RE_DFD(S), RE_PATH(S), a[2], a[3] | re_flag(S, AT_SYMLINK_NOFOLLOW), 0);
        if (r == 0) dir_upstream(S, 0, a[2], RE_DFD(S), RE_PATH(S), is_exclave_path(S->v));
        return r;
    case NR_statx: {
        /* statx: the mask, the two sync flags at once and any other flag, before the name */
        unsigned fl = (unsigned)a[2];
        if (((unsigned)a[3] & STATX__RESERVED) || (fl & AT_STATX_SYNC_TYPE) == AT_STATX_SYNC_TYPE ||
            (fl & ~(unsigned)(AT_SYMLINK_NOFOLLOW | AT_NO_AUTOMOUNT | AT_EMPTY_PATH | AT_STATX_SYNC_TYPE)))
            return -EINVAL;
        if ((r = resolve(S, a, 1, 0, !(fl & AT_SYMLINK_NOFOLLOW), (fl & AT_EMPTY_PATH) ? 2 : 0)) < 0) return r;
        if (r == 1) {
            r = RE5(nr, a[0], empty_as_given(a[1]), a[2], a[3], a[4]);
            if (r == 0) dir_upstream(S, 1, a[4], (int)a[0], 0, -1);
            return r;
        }
        to_real(S->v, S->real, S->tmp);
        r = RE5(nr, RE_DFD(S), RE_PATH(S), a[2] | re_flag(S, AT_SYMLINK_NOFOLLOW), a[3], a[4]);
        if (r == 0) dir_upstream(S, 1, a[4], RE_DFD(S), RE_PATH(S), is_exclave_path(S->v));
        return r;
    }
    default: __builtin_trap(); /* dispatch sends only the syscalls above */
    }
}

/* access, faccessat and faccessat2: the kernel's answers, then a write the permission allows on the exclave's file is
 * EROFS */
static long do_access(struct scratch *S, int nr, long *a)
{
    long r;
    int pi = nr == NR_access ? 0 : 1, di = nr == NR_access ? -1 : 0;
    long mode = a[pi + 1], fl = nr == NR_faccessat2 ? a[3] : 0;
    /* do_faccessat: the mode, then the flags */
    if ((unsigned)mode & ~7U) return -EINVAL;
    if ((unsigned)fl & ~(unsigned)(AT_EACCESS | AT_SYMLINK_NOFOLLOW | AT_EMPTY_PATH)) return -EINVAL;
    if ((r = resolve(S, a, pi, di, !(fl & AT_SYMLINK_NOFOLLOW), (fl & AT_EMPTY_PATH) != 0)) < 0) return r;
    int empty = r == 1; /* AT_EMPTY_PATH: the descriptor's own file */
    if (empty) r = RE5(nr, a[0], "", mode, fl, 0);
    else {
        to_real(S->v, S->real, S->tmp);
        r = nr == NR_faccessat2 ? RE5(nr, RE_DFD(S), RE_PATH(S), mode, fl | re_flag(S, AT_SYMLINK_NOFOLLOW), 0)
                                : RE5(NR_faccessat, RE_DFD(S), RE_PATH(S), mode, 0, 0);
    }
    /* do_faccessat: the lookup's and the permission's own answers come first; then a write the permission allows on
     * a regular file, a directory or a symlink under a read-only mount is EROFS, and a special file never is */
    if (r < 0 || !(mode & W_OK) || !(empty ? fd_exclave(S, (int)a[0]) : is_exclave_path(S->v))) return r;
    struct kstat st;
    if ((empty ? SC2(NR_fstat, a[0], &st) : sys_lstat(S->real, &st)) < 0) return r;
    unsigned m = st.st_mode & S_IFMT;
    return m == S_IFREG || m == S_IFDIR || m == S_IFLNK ? -EROFS : r;
}

/* getcwd: the working directory in virtual terms */
static long do_getcwd(struct scratch *S, long *a)
{
    long r;
    r = RE5(NR_getcwd, S->tmp, PATH_MAX, 0, 0, 0);
    if (r <= 0) return r;
    if (starts_dir(S->tmp, C.root)) from_real(S->tmp);
    r = (long)xstrlen(S->tmp) + 1;
    /* size is unsigned: all ones is a large buffer, not a negative one */
    if ((unsigned long)r > (unsigned long)a[1]) return -ERANGE;
    {
        long e = copy_out(S->pid, (void *)a[0], S->tmp, (size_t)r);
        if (e) return e;
    }
    return r;
}

/* truncate: the length, then vfs_truncate's answers for the exclave's file */
static long do_truncate(struct scratch *S, int nr, long *a)
{
    long r;
    if (a[1] < 0) return -EINVAL; /* do_sys_truncate: the length first */
    if ((r = resolve(S, a, 0, -1, 1, 0)) < 0) return r;
    /* the loaded program (13 item 29): vfs_truncate checks the permission, EACCES, before its ETXTBSY */
    if (C.loader_mode && xstrcmp(S->v, C.program) == 0) {
        to_real(S->v, S->real, S->tmp);
        r = sys_faccessat(AT_FDCWD, S->real, W_OK);
        return r < 0 ? r : -ETXTBSY;
    }
    /* vfs_truncate: EISDIR and EINVAL for what cannot be truncated, then EROFS */
    if (is_exclave_path(S->v)) {
        struct kstat *st = &S->st;
        int ex = exists_exclave(S, S->v, st);
        if (!ex) return absent_errno(S);
        if ((st->st_mode & S_IFMT) == S_IFDIR) return -EISDIR;
        if (sys_lstat(S->real, st) == 0 && (st->st_mode & S_IFMT) != S_IFREG) return -EINVAL;
        /* vfs_truncate: the permission, EACCES, before the mount, EROFS */
        to_real(S->v, S->real, S->tmp);
        r = sys_faccessat(AT_FDCWD, S->real, W_OK);
        if (r < 0) return r;
        return -EROFS;
    }
    to_real_exec(S->v, S->real);
    return RE5(nr, S->real, a[1], 0, 0, 0);
}

/* rmdir, unlink and unlinkat */
static long do_unlink(struct scratch *S, int nr, long *a)
{
    long r;
    int pi = nr == NR_unlinkat ? 1 : 0, di = nr == NR_unlinkat ? 0 : -1;
    long fl = nr == NR_rmdir ? AT_REMOVEDIR : nr == NR_unlinkat ? a[2] : 0;
    if ((unsigned)fl & ~(unsigned)AT_REMOVEDIR) return -EINVAL;
    if ((r = resolve(S, a, pi, di, WALK_PARENT, 0)) < 0)
        return r == -ENAMETOOLONG ? delete_overlong(S, di < 0 ? AT_FDCWD : (int)a[di]) : r;
    int sp = last_special(S->given); /* do_rmdir, do_unlinkat: answered before any lookup */
    if (sp) return (fl & AT_REMOVEDIR) ? (sp == 1 ? -EINVAL : sp == 2 ? -ENOTEMPTY : -EBUSY) : -EISDIR;
    if ((r = ro_delete(S, S->v))) return r;
    to_real_exec(S->v, S->real); /* an identity symlink: the host's link is what is deleted */
    return RE5(NR_unlinkat, RE_DFD(S), RE_PATH(S), fl, 0, 0);
}

/* The parent of a name whose last component is "." or ".." (sp 1 or 2), kept for a rename: the kernel resolves every
 * component before it (filename_parentat) and leaves the last one to do_renameat2, which compares the parent's mount
 * before it refuses the name. v gets the parent's virtual path, walked from the given without its last component,
 * the last of what remains followed as an intermediate component is; real gets the parent's real path with the
 * component after it, for the re-issue. */
static long parent_kept(struct scratch *S, const char *given, int dfd, int sp, char *v, char *real)
{
    scpy(real, given, PATH_MAX);
    size_t n = xstrlen(real);
    while (n > 1 && real[n - 1] == '/') n--;
    while (n > 0 && real[n - 1] != '/') n--; /* the "." or ".." itself */
    while (n > 1 && real[n - 1] == '/') n--;
    if (n == 0) scpy(real, ".", PATH_MAX); /* the directory the name is relative to */
    else real[n] = 0;
    long r = canon(S, real, dfd, WALK_FOLLOW, v);
    if (r < 0) return r;
    to_real_exec(v, real);
    if (xstrlen(real) + 3 >= PATH_MAX) return -ENAMETOOLONG;
    scat(real, sp == 1 ? "/." : "/..", PATH_MAX);
    return 0;
}

/* rename, renameat and renameat2, in do_renameat2's order */
static long do_rename(struct scratch *S, int nr, long *a)
{
    long r;
    int opi = nr == NR_rename ? 0 : 1, odi = nr == NR_rename ? -1 : 0, npi = nr == NR_rename ? 1 : 3,
        ndi = nr == NR_rename ? -1 : 2;
    unsigned fl = nr == NR_renameat2 ? (unsigned)a[4] : 0;
    /* do_renameat2: the flags first */
    if (fl & ~(unsigned)(RENAME_NOREPLACE | RENAME_EXCHANGE | RENAME_WHITEOUT)) return -EINVAL;
    if ((fl & (RENAME_NOREPLACE | RENAME_WHITEOUT)) && (fl & RENAME_EXCHANGE)) return -EINVAL;
    if ((r = resolve(S, a, opi, odi, WALK_PARENT, 0)) < 0) return r;
    int osp = last_special(S->given);
    scpy(S->v2, S->v, PATH_MAX); /* old */
    scpy(S->given2, S->given, PATH_MAX);
    int old_given = as_given(S), odfd = S->dfd;
    /* a last component that is "." or "..": the parent is what the kernel compares, and what it is given back; the
     * root is the tree's */
    if ((osp == 1 || osp == 2) && (r = parent_kept(S, S->given2, odfd, osp, S->v2, S->real2)) < 0) return r;
    if ((r = resolve(S, a, npi, ndi, WALK_PARENT, 0)) < 0) return r;
    int nsp = last_special(S->given);
    int new_given = as_given(S), ndfd = S->dfd;
    if ((nsp == 1 || nsp == 2) && (r = parent_kept(S, S->given, ndfd, nsp, S->v, S->real)) < 0) return r;
    /* the kernel's order (do_renameat2, oracles 17.1 and 17.7): different mounts first, the exclave's against the
     * host's, then, for two names the exclave owns, a last component that is "." or "..", then the write check; two
     * names the host owns are the kernel's own, the special last component kept, since the host's mounts may differ
     * among themselves, which the kernel sees before the name (oracle 17.7) */
    int oc = is_exclave_path(S->v2), nc = is_exclave_path(S->v);
    if (oc != nc) return -EXDEV;
    if (oc) {
        if (osp) return -EBUSY;
        if (nsp) return (fl & RENAME_NOREPLACE) ? -EEXIST : -EBUSY;
        return -EROFS;
    }
    /* neither name is followed: an identity symlink is the host's link on either side */
    if (!osp) to_real_exec(S->v2, S->real2);
    if (!nsp) to_real_exec(S->v, S->real);
    const char *old = old_given ? S->given2 : S->real2, *new = new_given ? S->given : S->real;
    int od = old_given ? odfd : AT_FDCWD, nd = new_given ? ndfd : AT_FDCWD;
    /* renameat2 is 3.15+ */
    if (nr != NR_renameat2 && fl == 0) return RE5(NR_renameat, od, old, nd, new, 0);
    return RE5(NR_renameat2, od, old, nd, new, fl);
}

/* link and linkat, in do_linkat's order */
static long do_link(struct scratch *S, int nr, long *a)
{
    long r;
    int opi = nr == NR_link ? 0 : 1, odi = nr == NR_link ? -1 : 0, npi = nr == NR_link ? 1 : 3,
        ndi = nr == NR_link ? -1 : 2;
    long fl = nr == NR_linkat ? a[4] : 0;
    if ((unsigned)fl & ~(unsigned)(AT_SYMLINK_FOLLOW | AT_EMPTY_PATH)) return -EINVAL; /* do_linkat: the flags first */
    struct kstat st;
    int pathless = 0;
    if ((r = resolve(S, a, opi, odi, (fl & AT_SYMLINK_FOLLOW) != 0, (fl & AT_EMPTY_PATH) != 0)) < 0) return r;
    if (r == 1) {
        r = dfd_virtual((int)a[odi], S->v);
        /* a descriptor whose file has no path, a pipe, a socket, an anonymous inode, an unlinked file or directory,
         * names nothing the exclave owns: the old name is the descriptor's own, which the kernel links or refuses
         * through the descriptor as given (EPERM for a directory, EXDEV across mounts, or the link itself since 6.10
         * allowed AT_EMPTY_PATH under the opener's credentials; oracle 17.7) */
        if (r == -ENOENT || (r == 0 && S->v[0] != '/')) pathless = 1;
        else if (r < 0) return r;
    }
    scpy(S->v2, S->v, PATH_MAX); /* old */
    scpy(S->given2, S->given, PATH_MAX);
    int old_given = as_given(S), odfd = S->dfd;
    /* an old name the walk leaves the kernel to follow, a magic link to a file with no path or an identity file's
     * host link, is followed, as the caller asked */
    long old_follow = S->follow_end ? AT_SYMLINK_FOLLOW : 0;
    /* do_linkat: the old name is looked up before the new one is read at all: its own error, ENOTDIR for a slash on
     * a file */
    if (!pathless && !exists_exclave(S, S->v2, &st)) return absent_errno(S);
    if ((r = resolve(S, a, npi, ndi, WALK_PARENT, 0)) < 0) return r;
    /* then the new name, in either domain (EEXIST, the name's own error), then the read-only rule for a
     * new name the exclave owns, then EXDEV for an old one it owns */
    scpy(S->cur, S->v, PATH_MAX);
    {
        size_t l = xstrlen(S->cur);
        if (l > 1 && S->cur[l - 1] == '/') S->cur[l - 1] = 0;
    }
    if (exists_exclave(S, S->cur, &st)) return -EEXIST;
    if ((r = ro_create(S, S->v, 0))) return r;
    if (!pathless && is_exclave_path(S->v2)) return -EXDEV;
    /* an old name that is an identity symlink is the host's link unless AT_SYMLINK_FOLLOW; a new name never follows */
    to_real_exec(S->v2, S->real2);
    to_real_exec(S->v, S->real);
    /* an old name as given keeps its own flags; a resolved one names what the walk found */
    if (old_given) return RE5(NR_linkat, odfd, S->given2, RE_DFD(S), RE_PATH(S), fl);
    return RE5(NR_linkat, AT_FDCWD, S->real2, RE_DFD(S), RE_PATH(S),
               (fl & ~AT_SYMLINK_FOLLOW & ~AT_EMPTY_PATH) | old_follow);
}

/* chmod, fchmodat and fchmodat2 */
static long do_chmod(struct scratch *S, int nr, long *a)
{
    long r;
    int pi = nr == NR_chmod ? 0 : 1, di = nr == NR_chmod ? -1 : 0;
    long fl = nr == NR_fchmodat2 ? a[3] : 0;
    if ((unsigned)fl & ~(unsigned)(AT_SYMLINK_NOFOLLOW | AT_EMPTY_PATH))
        return -EINVAL; /* do_fchmodat: the flags first */
    if ((r = resolve(S, a, pi, di, !(fl & AT_SYMLINK_NOFOLLOW), (fl & AT_EMPTY_PATH) != 0)) < 0) return r;
    /* AT_EMPTY_PATH: the descriptor's own file, read-only if it is the exclave's */
    if (r == 1) return fd_exclave(S, (int)a[0]) ? -EROFS : RE5(nr, a[0], "", a[2], fl, 0);
    if ((r = ro_attr(S, S->v))) return r;
    to_real(S->v, S->real, S->tmp);
    if (nr == NR_fchmodat2) return RE5(nr, RE_DFD(S), RE_PATH(S), a[2], fl | re_flag(S, AT_SYMLINK_NOFOLLOW), 0);
    return RE5(NR_fchmodat, RE_DFD(S), RE_PATH(S), a[pi + 1], 0, 0);
}

/* chown, lchown and fchownat */
static long do_chown(struct scratch *S, int nr, long *a)
{
    long r;
    int pi = nr == NR_fchownat ? 1 : 0, di = nr == NR_fchownat ? 0 : -1;
    long fl = nr == NR_fchownat ? a[4] : nr == NR_lchown ? AT_SYMLINK_NOFOLLOW : 0;
    if ((unsigned)fl & ~(unsigned)(AT_SYMLINK_NOFOLLOW | AT_EMPTY_PATH))
        return -EINVAL; /* do_fchownat: the flags first */
    if ((r = resolve(S, a, pi, di, !(fl & AT_SYMLINK_NOFOLLOW), (fl & AT_EMPTY_PATH) != 0)) < 0) return r;
    if (r == 1) return fd_exclave(S, (int)a[0]) ? -EROFS : RE5(nr, a[0], empty_as_given(a[1]), a[2], a[3], a[4]);
    if ((r = ro_attr(S, S->v))) return r;
    to_real(S->v, S->real, S->tmp);
    if (as_given(S)) return RE5(NR_fchownat, S->dfd, S->given, a[pi + 1], a[pi + 2], fl);
    return RE5(NR_fchownat, AT_FDCWD, S->real, a[pi + 1], a[pi + 2], nofollow(S, AT_SYMLINK_NOFOLLOW));
}

/* utime, utimes, futimesat and utimensat, in fs/utimes.c's order */
static long do_times(struct scratch *S, int nr, long *a)
{
    long r;
    int pi = nr == NR_utime || nr == NR_utimes ? 0 : 1, di = nr == NR_utime || nr == NR_utimes ? -1 : 0;
    long fl = nr == NR_utimensat ? (int)a[3] : 0; /* an int: bits above the word are not flags */
    long ts[4] = {0, 0, 0, 0};
    int badns = 0;
    /* the kernel's order (fs/utimes.c): the times read, two UTIME_OMITs a no-op, the flags,
     * then the lookup or the descriptor, then vfs_utimes, where a nanosecond out of range is
     * EINVAL before the mount's EROFS */
    if (nr == NR_utimensat) {
        if (a[2]) {
            if ((r = copy_exact(S->pid, ts, (const void *)a[2], sizeof ts))) return r;
            if (ts[1] == UTIME_OMIT && ts[3] == UTIME_OMIT) return 0;
            badns = !nsec_valid(ts[1]) || !nsec_valid(ts[3]);
        }
        if (fl & ~(AT_SYMLINK_NOFOLLOW | AT_EMPTY_PATH)) return -EINVAL;
        /* a NULL path names the descriptor, with no flag allowed; with AT_FDCWD it is getname's EFAULT */
        if (a[1] == 0) {
            /* the descriptor is an int in the register: glibc's syscall() zero-extends it */
            if ((int)a[0] == AT_FDCWD) return -EFAULT;
            if (fl) return -EINVAL;
            if (!fd_exclave(S, (int)a[0])) return RE5(nr, a[0], 0, a[2], a[3], 0);
            return badns ? -EINVAL : -EROFS;
        }
    } else if ((nr == NR_utimes || nr == NR_futimesat) && a[pi + 1]) {
        /* do_futimesat: a microsecond out of range is EINVAL before the lookup */
        long tv[4];
        if ((r = copy_exact(S->pid, tv, (const void *)a[pi + 1], sizeof tv))) return r;
        if (tv[1] < 0 || tv[1] >= 1000000 || tv[3] < 0 || tv[3] >= 1000000) return -EINVAL;
    }
    if ((r = resolve(S, a, pi, di, !(fl & AT_SYMLINK_NOFOLLOW), (fl & AT_EMPTY_PATH) != 0)) < 0) return r;
    if (r == 1) { /* AT_EMPTY_PATH: the descriptor itself (5.9+) */
        if (!fd_exclave(S, (int)a[0])) return RE5(nr, a[0], empty_as_given(a[1]), a[2], a[3], 0);
        return badns ? -EINVAL : -EROFS;
    }
    /* the name's own error, then the times, then the write */
    if (is_exclave_path(S->v)) {
        struct kstat st;
        if (!exists_exclave(S, S->v, &st)) return absent_errno(S);
        return badns ? -EINVAL : -EROFS;
    }
    to_real(S->v, S->real, S->tmp);
    if (nr == NR_utime) return RE5(NR_utime, S->real, a[1], 0, 0, 0);
    if (nr == NR_utimes) return RE5(NR_utimes, S->real, a[1], 0, 0, 0);
    if (nr == NR_futimesat) return RE5(NR_futimesat, RE_DFD(S), RE_PATH(S), a[2], 0, 0);
    return RE5(NR_utimensat, RE_DFD(S), RE_PATH(S), a[2], fl | re_flag(S, AT_SYMLINK_NOFOLLOW), 0);
}

/* the extended attributes by path and the chattr syscalls: the name and flags the kernel reads first, then the
 * read-only rule for a change */
static long do_xattr(struct scratch *S, int nr, long *a)
{
    long r;
    switch (nr) {
    case NR_setxattrat:
    case NR_removexattrat: /* (dfd, path, at_flags, name, [xattr_args, its size]) */
        if ((r = resolve(S, a, 1, 0, !(a[2] & AT_SYMLINK_NOFOLLOW), (a[2] & AT_EMPTY_PATH) ? 2 : 0)) < 0) return r;
        if (r == 1)
            return fd_exclave(S, (int)a[0]) ? -EROFS : RE6(nr, a[0], empty_as_given(a[1]), a[2], a[3], a[4], a[5]);
        if ((r = ro_attr(S, S->v))) return r;
        to_real(S->v, S->real, S->tmp);
        return RE6(nr, RE_DFD(S), RE_PATH(S), a[2] | re_flag(S, AT_SYMLINK_NOFOLLOW), a[3], a[4], a[5]);
    case NR_getxattrat:
    case NR_listxattrat:
        if ((r = resolve(S, a, 1, 0, !(a[2] & AT_SYMLINK_NOFOLLOW), (a[2] & AT_EMPTY_PATH) ? 2 : 0)) < 0) return r;
        if (r == 1) return RE6(nr, a[0], empty_as_given(a[1]), a[2], a[3], a[4], a[5]);
        to_real(S->v, S->real, S->tmp);
        return RE6(nr, RE_DFD(S), RE_PATH(S), a[2] | re_flag(S, AT_SYMLINK_NOFOLLOW), a[3], a[4], a[5]);
    /* (dfd, path, attr, size, at_flags): the chattr ioctls as syscalls */
    case NR_file_getattr:
    case NR_file_setattr:
        if ((r = resolve(S, a, 1, 0, !(a[4] & AT_SYMLINK_NOFOLLOW), (a[4] & AT_EMPTY_PATH) ? 2 : 0)) < 0) return r;
        if (r == 1)
            return (nr == NR_file_setattr && fd_exclave(S, (int)a[0]))
                       ? -EROFS
                       : RE5(nr, a[0], empty_as_given(a[1]), a[2], a[3], a[4]);
        if (nr == NR_file_setattr) {
            r = ro_attr(S, S->v);
            if (r) return r;
        }
        to_real(S->v, S->real, S->tmp);
        return RE5(nr, RE_DFD(S), RE_PATH(S), a[2], a[3], a[4] | re_flag(S, AT_SYMLINK_NOFOLLOW));
    case NR_setxattr:
    case NR_lsetxattr:
    case NR_removexattr:
    case NR_lremovexattr:
        /* path_setxattrat, path_removexattrat: the name, and for a set its flags and size, before the path */
        r = nr == NR_setxattr || nr == NR_lsetxattr ? setxattr_args(S, (const char *)a[1], (size_t)a[3], (int)a[4])
                                                    : xattr_name(S, (const char *)a[1]);
        if (r) return r;
        if ((r = resolve(S, a, 0, -1, nr == NR_setxattr || nr == NR_removexattr, 0)) < 0) return r;
        if ((r = ro_attr(S, S->v))) return r;
        to_real(S->v, S->real, S->tmp);
        return RE5(nr, S->real, a[1], a[2], a[3], a[4]);
    case NR_getxattr:
    case NR_lgetxattr:
    case NR_listxattr:
    case NR_llistxattr:
        /* path_getxattrat: the name before the path */
        r = nr == NR_getxattr || nr == NR_lgetxattr ? xattr_name(S, (const char *)a[1]) : 0;
        if (r) return r;
        if ((r = resolve(S, a, 0, -1, nr == NR_getxattr || nr == NR_listxattr, 0)) < 0) return r;
        to_real(S->v, S->real, S->tmp);
        return RE5(nr, S->real, a[1], a[2], a[3], 0);
    default: __builtin_trap(); /* dispatch sends only the syscalls above */
    }
}

/* inotify_add_watch and fanotify_mark: the watched path */
static long do_watch(struct scratch *S, int nr, long *a)
{
    long r;
    switch (nr) {
    case NR_inotify_add_watch: {
        /* the mask, then the descriptor, which must be an inotify instance, then the path */
        unsigned mask = (unsigned)a[2];
        if (!(mask & ALL_INOTIFY_BITS) || ((mask & IN_MASK_ADD) && (mask & IN_MASK_CREATE))) return -EINVAL;
        if (fd_real_path((int)a[0], S->tmp) < 0) return -EBADF;
        if (xstrcmp(S->tmp, "anon_inode:inotify") != 0) return -EINVAL;
        if ((r = resolve(S, a, 1, -1, !(mask & IN_DONT_FOLLOW), 0)) < 0) return r;
        to_real(S->v, S->real, S->tmp);
        return RE5(nr, a[0], S->real, a[2] | nofollow(S, IN_DONT_FOLLOW), 0, 0);
    }
    case NR_fanotify_mark: {
        /* do_fanotify_mark: the mask's upper half, the command and its mask, then the descriptor, which must be a
         * fanotify instance, before the path; a flush names none. The flag bits and mark types each kernel knows are
         * its own to refuse, after the handler's lookup (13 item 41) */
        unsigned cmd = (unsigned)a[1] & (FAN_MARK_ADD | FAN_MARK_REMOVE | FAN_MARK_FLUSH);
        if ((unsigned long)a[2] >> 32) return -EINVAL;
        if (cmd != FAN_MARK_ADD && cmd != FAN_MARK_REMOVE && cmd != FAN_MARK_FLUSH) return -EINVAL;
        if (cmd != FAN_MARK_FLUSH && !(unsigned)a[2]) return -EINVAL;
        if (fd_real_path((int)a[0], S->tmp) < 0) return -EBADF;
        if (xstrcmp(S->tmp, "anon_inode:[fanotify]") != 0) return -EINVAL;
        if (a[4] == 0 || cmd == FAN_MARK_FLUSH) return RE5(nr, a[0], a[1], a[2], a[3], a[4]);
        if ((r = resolve(S, a, 4, 3, !(a[1] & FAN_MARK_DONT_FOLLOW), 0)) < 0) return r;
        to_real(S->v, S->real, S->tmp);
        return RE5(nr, a[0], a[1] | re_flag(S, FAN_MARK_DONT_FOLLOW), a[2], RE_DFD(S), RE_PATH(S));
    }
    default: __builtin_trap(); /* dispatch sends only the syscalls above */
    }
}

/* the changes made through a descriptor, which are EROFS on the exclave's file */
static long do_fd_change(struct scratch *S, int nr, long *a)
{
    long r;
    /* fsetxattr, fremovexattr: the name, flags and size before the descriptor */
    r = nr == NR_fsetxattr      ? setxattr_args(S, (const char *)a[1], (size_t)a[3], (int)a[4])
        : nr == NR_fremovexattr ? xattr_name(S, (const char *)a[1])
                                : 0;
    if (r) return r;
    r = sys_fcntl((int)a[0], F_GETFL, 0);
    if (r < 0) return r;
    /* an O_PATH descriptor cannot be used for these (open(2)) */
    if (r & O_PATH) return -EBADF;
    if (!fd_exclave(S, (int)a[0])) return RE5(nr, a[0], a[1], a[2], a[3], a[4]);
    /* the exclave's file: the chattr ioctls read their argument before the mount's EROFS (ioctl_setflags,
         * ioctl_fssetxattr) */
    if (nr == NR_ioctl) {
        r = copy_exact(S->pid, S->tmp, (const void *)a[2], (unsigned long)a[1] == FS_IOC_SETFLAGS ? sizeof(int) : 28);
        if (r) return r;
    }
    return -EROFS;
}

/* Whether the directory's next record is the tree's .real, read alone into the scratch and so passed; another record
 * read is put back, the directory where it was. A listing's EINVAL, a buffer too small for the next record, and its
 * EFAULT, a buffer the kernel cannot write the next record to, may be .real's alone, which upstream's tree does not
 * have. ours is the cache of whether the directory is the tree's. The kernel takes one call at a time on a descriptor
 * and this is three: another thread listing the same descriptor between the read and the lseek back sees that record
 * again, on these refusals alone (8.3). */
static int next_is_real(struct scratch *S, int nr, int fd, int *ours, unsigned long name_at)
{
    /* .real's record: the name, its NUL and getdents' trailing d_type, in 8-byte units */
    unsigned long size = (name_at + 6 + (nr != NR_getdents64) + 7) & ~7UL;
    long pos = SC3(NR_lseek, fd, 0, SEEK_CUR);
    if (pos < 0) return 0;
    long n = SC3(nr, fd, S->extra, size);
    if (n <= 0) return 0;
    if (xstrcmp(S->extra + name_at, ".real") == 0) {
        if (*ours < 0) *ours = fd_real_path(fd, S->tmp) >= 0 && starts_dir(S->tmp, C.root);
        if (*ours) return 1;
    }
    SC3(NR_lseek, fd, pos, SEEK_SET);
    return 0;
}

/* getdents64 and getdents: the directory's entries as the kernel lists them, but for a .real/ in a directory of the
 * tree, which upstream's tree does not have (8.3, 6.1). The kernel writes its batch into the program's buffer, so
 * every error and every short or faulting write is its own, but for one .real alone causes (next_is_real); the count
 * is an unsigned int, as it reads it, and at most the scratch's size, which a listing may return fewer than asked
 * for. The batch is read back and, only when it holds the tree's .real, written again without it, to the bytes the
 * kernel writes; whether the directory is the tree's is asked only of a batch that holds one. A batch of nothing but
 * .real is followed by the next, so that only the directory's end is an empty answer, and the room .real took in a
 * batch is filled. Both records hold d_reclen at 16; the name is at 19, or at 18 in getdents' older record, which
 * ends in d_type, where getdents64's ends in the padding after the name's NUL. A copy that fails on memory the
 * kernel has just written, which only another thread's unmapping or a pipe the fallback cannot make can cause,
 * answers the kernel's count. */
static long do_getdents(struct scratch *S, int nr, long *a)
{
    unsigned int count = (unsigned int)a[2];
    if (count > sizeof S->extra) count = sizeof S->extra;
    int fd = (int)a[0], ours = -1;
    unsigned long name_at = nr == NR_getdents64 ? 19 : 18;
    for (;;) {
        long n = SC3(nr, fd, a[1], count), kept = 0, end = 0, real_seen = 0;
        if ((n == -EINVAL || n == -EFAULT) && next_is_real(S, nr, fd, &ours, name_at)) continue;
        if (n <= 0) return n;
        if (copy_in(S->pid, S->extra, (const void *)a[1], (size_t)n) != n) return n;
        for (long o = 0; o + 18 <= n;) {
            unsigned short len = *(unsigned short *)(S->extra + o + 16);
            if (len < name_at + 1 || o + len > n) return n; /* not the kernel's records any more: left as they are */
            const char *name = S->extra + o + name_at;
            /* the name, read within its record: the program's memory, which another thread may have changed since the
             * kernel wrote it, so a record without its NUL is left as the kernel's answer */
            long nlen = 0;
            while (nlen < (long)(len - name_at) && name[nlen]) nlen++;
            if (nlen == (long)(len - name_at)) return n;
            int real = nlen == 5 && xmemcmp(name, ".real", 5) == 0;
            if (real && ours < 0) ours = fd_real_path(fd, S->tmp) >= 0 && starts_dir(S->tmp, C.root);
            if (real && ours) {
                real_seen = 1;
            } else {
                /* the bytes the kernel wrote of the record, measured before it moves */
                long written = nr == NR_getdents64 ? (long)name_at + nlen + 1 : len;
                if (kept != o) xmemcpy(S->extra + kept, S->extra + o, len); /* forward over a gap: safe */
                end = kept + written;
                kept += len;
            }
            o += len;
        }
        if (!real_seen) return n;
        if (kept == 0) continue; /* nothing but .real: the next batch */
        if (copy_out(S->pid, (void *)a[1], S->extra, (size_t)end)) return n;
        /* the room .real took, filled as the kernel fills a batch; a directory holds one .real, and an error after a
         * record is the records' count */
        long more = SC3(nr, fd, a[1] + kept, count - (unsigned long)kept);
        return more > 0 ? kept + more : kept;
    }
}

#ifndef EXCLAVE_TEST_OLD
/* PTRACE_TRACEME, the one ptrace request the filter traps (7.4.2). A vfork child's is deferred to its exec (7.4.5):
 * made at once, it would have the child traced when its execve traps, and the kernel stops a traced task for its
 * tracer at the SIGSYS, before this handler runs, while the tracer, its parent, waits in vfork for that very exec.
 * Nothing but an exec or an exit can follow the request in a vfork child, natively too, so deferring it changes no
 * program that runs natively; a second request is the kernel's EPERM for a task already traced. In any other process
 * the request is made at once, since a fork child may stop for its tracer before it execs (13 item 54). */
static long do_ptrace(struct scratch *S, long *a)
{
    pid_t ppid = (pid_t)sys_getppid();
    if (a[0] != PTRACE_TRACEME || !vfork_child(S->pid, ppid)) return RE5(NR_ptrace, a[0], a[1], a[2], a[3], 0);
    if (scratch_deferred(S->pid, S->tid, 0)) return -EPERM;
    scratch_keep(S, ppid);
    return 0;
}
#endif

#ifndef EXCLAVE_TEST_OLD /* build/launcher-old, version 3, refuses the install in its filter */
/* A program's own filter (7.4.2): the kernel's answers for what it refuses, in its order (seccomp_set_mode_filter,
 * seccomp_prepare_filter, bpf_prog_create_from_user), ENOSYS for what the launcher refuses, and otherwise the filter
 * filter_wrap makes of it, installed through the page with the flags and in the form given. The body and the built
 * filter live in a transient mapping, not the scratch, which holds neither. The flag is set before the install, so
 * that a thread the install reaches by TSYNC is judged from its next trap on; an install that fails leaves it set,
 * which costs a judge call that answers MARK_NONE. A vfork child's install sets it in the parent too: stricter. */
#define SECCOMP_FLAGS_HONOURED                                                                                         \
    (SECCOMP_FILTER_FLAG_TSYNC | SECCOMP_FILTER_FLAG_LOG | SECCOMP_FILTER_FLAG_SPEC_ALLOW |                            \
     SECCOMP_FILTER_FLAG_TSYNC_ESRCH)
static __attribute__((noinline)) long do_seccomp(struct scratch *S, int nr, long *a)
{
    unsigned long flags = 0;
    const void *uargs;
    if (nr == NR_prctl) {
        if ((int)a[0] != PR_SET_SECCOMP) return -ENOSYS; /* the kernel's int; another is a newer filter's trap */
        if (a[1] == SECCOMP_MODE_STRICT) return -ENOSYS;
        if (a[1] != SECCOMP_MODE_FILTER) return -EINVAL;
        uargs = (const void *)a[2];
    } else {
        unsigned op = (unsigned)a[0]; /* the kernel's unsigned int */
        /* the flags an unsigned int, as the kernel takes them */
        if (op == SECCOMP_SET_MODE_STRICT) return (unsigned)a[1] || a[2] ? -EINVAL : -ENOSYS;
        if (op == SECCOMP_GET_ACTION_AVAIL || op == SECCOMP_GET_NOTIF_SIZES)
            return RE5(NR_seccomp, op, a[1], a[2], 0, 0);
        if (op != SECCOMP_SET_MODE_FILTER) return -EINVAL;
        flags = (unsigned)a[1];
        uargs = (const void *)a[2];
        /* the kernel's answer for the flags, which it checks before it reads the program: EFAULT for none */
        long r = RE5(NR_seccomp, SECCOMP_SET_MODE_FILTER, a[1], 0, 0, 0);
        if (r != -EFAULT) return r;
        if (flags & ~(unsigned long)SECCOMP_FLAGS_HONOURED) return -ENOSYS; /* a listener, or a flag newer than this */
    }
    struct {
        unsigned short len;
        const struct sock_filter *filter;
    } fp;
    if (copy_exact(S->pid, &fp, uargs, sizeof fp)) return -EFAULT;
    if (fp.len == 0 || fp.len > BPF_MAXINSNS || !fp.filter) return -EINVAL;
    size_t room = 2UL * BPF_MAXINSNS * sizeof(struct sock_filter);
    long m = sys_mmap(0, room, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (m < 0 && m > -4096) return -ENOMEM;
    struct sock_filter *body = (struct sock_filter *)m, *out = body + BPF_MAXINSNS;
    long r = copy_exact(S->pid, body, fp.filter, fp.len * sizeof *body);
    if (r == 0) r = filter_wrap(body, fp.len, out);
    /* LOG before 4.14 is an action the kernel kills on, which the judge would not: refused where the kernel lacks it */
    for (long i = 0; r > 0 && i < fp.len; i++)
        if (body[i].code == 0x06 && (body[i].k & SECCOMP_RET_ACTION_FULL) == SECCOMP_RET_LOG) {
            unsigned action = SECCOMP_RET_LOG;
            if (RE5(NR_seccomp, SECCOMP_GET_ACTION_AVAIL, 0, &action, 0, 0)) r = -ENOSYS;
            break;
        }
    if (r > 0) {
        fp.len = (unsigned short)r;
        fp.filter = out;
        program_filters = 1;
        r = nr == NR_prctl ? RE5(NR_prctl, PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &fp, a[3], a[4])
                           : RE5(NR_seccomp, SECCOMP_SET_MODE_FILTER, flags, &fp, 0, 0);
    }
    SC2(NR_munmap, m, room);
    return r;
}
#endif

static long dispatch(struct scratch *S, int nr, long *a, void *uc)
{
    long r;
    switch (nr) {
    case NR_open: return do_open(S, a, 0, -1, a[1], a[2], NR_openat);
    case NR_openat: return do_open(S, a, 1, 0, a[2], a[3], NR_openat);
    case NR_openat2:
        return do_openat2(S, a);
/* build/launcher-old, filter version 3, traps neither (17.4) */
#ifndef EXCLAVE_TEST_OLD
    case NR_bind:
    case NR_connect: return do_sockaddr(S, a, nr);
#endif
    case NR_creat: return do_open(S, a, 0, -1, O_CREAT | O_WRONLY | O_TRUNC, a[1], NR_openat);
    case NR_stat:
    case NR_lstat:
    case NR_newfstatat:
    case NR_statx: return do_stat(S, nr, a);
    case NR_access:
    case NR_faccessat:
    case NR_faccessat2: return do_access(S, nr, a);
    /* bufsiz is an int: the kernel truncates, so must the copy's bound */
    case NR_readlink: return do_readlink(S, a, 0, -1, (char *)a[1], (int)a[2]);
    case NR_readlinkat: return do_readlink(S, a, 1, 0, (char *)a[2], (int)a[3]);
    case NR_getcwd: return do_getcwd(S, a);
    case NR_chdir:
        if ((r = resolve(S, a, 0, -1, 1, 0)) < 0) return r;
        to_real_exec(S->v, S->real);
        return RE5(NR_chdir, S->real, 0, 0, 0, 0);
    case NR_execve: return do_execve(S, a, 0, -1, 0, (char **)a[1], (char **)a[2]);
    case NR_execveat: return do_execve(S, a, 1, 0, a[4], (char **)a[2], (char **)a[3]);
    case NR_truncate: return do_truncate(S, nr, a);
    case NR_mkdir:
    case NR_mkdirat: {
        int pi = nr == NR_mkdir ? 0 : 1, di = nr == NR_mkdir ? -1 : 0;
        if ((r = resolve(S, a, pi, di, WALK_PARENT, 0)) < 0) return r;
        if ((r = ro_create(S, S->v, 1))) return r;
        return RE5(NR_mkdirat, RE_DFD(S), RE_PATH(S), a[pi + 1], 0, 0);
    }
    case NR_mknod:
    case NR_mknodat: {
        int pi = nr == NR_mknod ? 0 : 1, di = nr == NR_mknod ? -1 : 0;
        if ((r = may_mknod((unsigned short)a[pi + 1]))) return r;
        if ((r = resolve(S, a, pi, di, WALK_PARENT, 0)) < 0) return r;
        if ((r = ro_create(S, S->v, 0))) return r;
        return RE5(NR_mknodat, RE_DFD(S), RE_PATH(S), a[pi + 1], a[pi + 2], 0);
    }
    case NR_rmdir:
    case NR_unlink:
    case NR_unlinkat: return do_unlink(S, nr, a);
    case NR_symlink:
    case NR_symlinkat: {
        int pi = nr == NR_symlink ? 1 : 2, di = nr == NR_symlink ? -1 : 1;
        /* do_symlinkat: the target is read before the new name */
        if ((r = copy_str_in(S->pid, S->extra, (const char *)a[0])) < 0) return r;
        if (S->extra[0] == 0) return -ENOENT;
        if ((r = resolve(S, a, pi, di, WALK_PARENT, 0)) < 0) return r;
        if ((r = ro_create(S, S->v, 0))) return r;
        return RE5(NR_symlinkat, S->extra, RE_DFD(S), RE_PATH(S), 0, 0);
    }
    case NR_rename:
    case NR_renameat:
    case NR_renameat2: return do_rename(S, nr, a);
    case NR_link:
    case NR_linkat: return do_link(S, nr, a);
    case NR_chmod:
    case NR_fchmodat:
    case NR_fchmodat2: return do_chmod(S, nr, a);
    case NR_chown:
    case NR_lchown:
    case NR_fchownat: return do_chown(S, nr, a);
    case NR_utime:
    case NR_utimes:
    case NR_futimesat:
    case NR_utimensat: return do_times(S, nr, a);
    case NR_setxattrat:
    case NR_removexattrat:
    case NR_getxattrat:
    case NR_listxattrat:
    case NR_file_getattr:
    case NR_file_setattr:
    case NR_setxattr:
    case NR_lsetxattr:
    case NR_removexattr:
    case NR_lremovexattr:
    case NR_getxattr:
    case NR_lgetxattr:
    case NR_listxattr:
    case NR_llistxattr: return do_xattr(S, nr, a);
    case NR_statfs:
        if ((r = resolve(S, a, 0, -1, 1, 0)) < 0) return r;
        to_real(S->v, S->real, S->tmp);
        r = RE5(NR_statfs, S->real, a[1], 0, 0, 0);
        return r == 0 && is_exclave_path(S->v) ? ro_flag(S, (char *)a[1] + STATFS_FLAGS_OFF) : r;
    case NR_fstatfs:
        r = RE5(NR_fstatfs, a[0], a[1], 0, 0, 0);
        return r == 0 && fd_exclave(S, (int)a[0]) ? ro_flag(S, (char *)a[1] + STATFS_FLAGS_OFF) : r;
    case NR_getdents64:
    case NR_getdents: return do_getdents(S, nr, a);
    case NR_fstat:
        /* the kernel's answer, as for a stat of the descriptor's own file */
        if ((r = RE5(NR_fstat, a[0], a[1], 0, 0, 0)) == 0) dir_upstream(S, 0, a[1], (int)a[0], 0, -1);
        return r;
    case NR_inotify_add_watch:
    case NR_fanotify_mark: return do_watch(S, nr, a);
    case NR_fchmod:
    case NR_fchown:
    case NR_fsetxattr:
    case NR_fremovexattr:
    case NR_ioctl: return do_fd_change(S, nr, a);
    case NR_rt_sigaction: return do_sigaction(S, a);
    case NR_rt_sigprocmask: return do_sigprocmask(S, a, uc);
    case NR_rt_sigsuspend: return do_sigsuspend(S, a);
    case NR_ppoll: return do_ppoll(S, a);
    case NR_pselect6: return do_pselect6(S, a);
    case NR_epoll_pwait:
    case NR_epoll_pwait2: return do_epoll_pwait(S, a, nr);
    case NR_io_pgetevents:
        return do_io_pgetevents(S, a);
/* build/launcher-old, filter version 3, does not trap it (17.4) */
#ifndef EXCLAVE_TEST_OLD
    case NR_ptrace: return do_ptrace(S, a);
#endif
#ifndef EXCLAVE_TEST_OLD
    case NR_seccomp:
    case NR_prctl: return do_seccomp(S, nr, a);
#endif
    default: return -ENOSYS; /* 7.4.3: a trapped syscall the handler does not know */
    }
}

/* names for the log: one line per trapped syscall, "<name> <result> <virtual path>" */
static const char *sysname(int nr)
{
    switch (nr) {
    case NR_open:
    case NR_openat:
    case NR_creat:
    case NR_openat2: return "open";
#ifndef EXCLAVE_TEST_OLD
    case NR_bind: return "bind";
    case NR_connect: return "connect";
#endif
    case NR_stat:
    case NR_lstat:
    case NR_newfstatat:
    case NR_fstat:
    case NR_statx: return "stat";
    case NR_fchmod:
    case NR_fchown:
    case NR_file_getattr:
    case NR_file_setattr: return "attr";
    case NR_fsetxattr:
    case NR_fremovexattr:
    case NR_setxattrat:
    case NR_getxattrat:
    case NR_listxattrat:
    case NR_removexattrat: return "xattr";
    case NR_ioctl: return "ioctl";
    case NR_inotify_add_watch:
    case NR_fanotify_mark: return "watch";
    case NR_access:
    case NR_faccessat:
    case NR_faccessat2: return "access";
    case NR_readlink:
    case NR_readlinkat: return "readlink";
    case NR_execve:
    case NR_execveat: return "exec";
    case NR_chdir: return "chdir";
    case NR_getcwd: return "getcwd";
    case NR_mkdir:
    case NR_mkdirat: return "mkdir";
    case NR_mknod:
    case NR_mknodat: return "mknod";
    case NR_unlink:
    case NR_unlinkat:
    case NR_rmdir: return "unlink";
    case NR_rename:
    case NR_renameat:
    case NR_renameat2: return "rename";
    case NR_link:
    case NR_linkat: return "link";
    case NR_symlink:
    case NR_symlinkat: return "symlink";
    case NR_chmod:
    case NR_fchmodat:
    case NR_fchmodat2:
    case NR_chown:
    case NR_lchown:
    case NR_fchownat:
    case NR_utime:
    case NR_utimes:
    case NR_futimesat:
    case NR_utimensat:
    case NR_truncate: return "attr";
    case NR_setxattr:
    case NR_lsetxattr:
    case NR_getxattr:
    case NR_lgetxattr:
    case NR_listxattr:
    case NR_llistxattr:
    case NR_removexattr:
    case NR_lremovexattr: return "xattr";
    case NR_statfs:
    case NR_fstatfs: return "statfs";
    case NR_getdents64:
    case NR_getdents: return "listing";
    case NR_rt_sigaction:
    case NR_rt_sigprocmask:
    case NR_rt_sigsuspend:
    case NR_ppoll:
    case NR_pselect6:
    case NR_epoll_pwait:
    case NR_epoll_pwait2:
    case NR_io_pgetevents: return "signal";
    default: return "trap";
    }
}

/* The program's PKRU, loaded from the frame the kernel saved: a handler starts with the kernel's own, which denies
 * keys a program may have allowed itself, and a syscall the handler issues into the program's memory is checked
 * against the thread's, so that it answers as the program's own would (7.5.6). Key 0, the launcher's memory, stays
 * open to the handler; the return through the frame restores the program's PKRU as it was. */
static void program_keys(void *uc)
{
#if defined(__x86_64__)
    if (!C.pkru_off) return;
    const char *fp = *(char *const *)((char *)uc + UC_FPREGS_OFF);
    if (!fp || *(const unsigned *)(fp + 464) != FP_XSTATE_MAGIC1) return;
    if (!(*(const unsigned long *)(fp + 472) >> XFEATURE_PKRU & 1)) return;
    /* a component the header does not mark is in its initial state, which for PKRU is every key open */
    unsigned pkru = *(const unsigned long *)(fp + 512) >> XFEATURE_PKRU & 1 ? *(const unsigned *)(fp + C.pkru_off) : 0;
    wrpkru(pkru & ~3U);
#else
    (void)uc;
#endif
}

volatile int program_filters;

/* The program's own filters' answer for a trapped call (7.4.2): the call re-issued unchanged from the judge slot, which
 * the launcher's filter answers MARK_NONE and a program filter's prologue leaves to its body, so that the kernel takes
 * the answer of highest precedence as it did for the original, and among ERRNO answers the newest filter's, which a
 * program's are: MARK_NONE where none refuses the call, else the errno, or 0, of the refusal, returned without
 * translating. A KILL would have killed the original before the handler ran, unless an install by TSYNC came between,
 * which the kernel then applies. No call, and no cost, in a process where no program installed a filter. */
static long judge(int nr, const long *a)
{
#ifndef EXCLAVE_TEST_OLD
    if (!program_filters) return -MARK_NONE;
    long r = __sc6_judge(nr, a[0], a[1], a[2], a[3], a[4], a[5]);
    /* the launcher's filter answers every call from the slot that it traps; a foreign outer filter's TRAP, which no
     * launcher filter answers, would end here, or in the nesting limit should the call trap again: loud either way */
    if (r > 0) die("the judge call ran", 0, nr);
    return r;
#else
    (void)nr;
    (void)a;
    return -MARK_NONE;
#endif
}

static void on_sigsys(int sig, void *info, void *uc)
{
    (void)sig; /* SIGSYS: the handler is installed for nothing else */
    long *g = gregs(uc);
    if (*(int *)((char *)info + SI_CODE_OFF) != SYS_SECCOMP) {
        /* a real SIGSYS (kill -SYS): the program's default disposition applies, so re-raise it under SIG_DFL */
        unsigned long dfl[4] = {0, 0, 0, 0};
        sys_rt_sigaction(SIGSYS, dfl, 0, 8);
        sys_tgkill((pid_t)sys_getpid(), (pid_t)sys_gettid(), SIGSYS);
        return;
    }
    program_keys(uc);
    int nr = *(int *)((char *)info + SI_SYSCALL_OFF);
    unsigned long ip = *(unsigned long *)((char *)info + SI_CALL_ADDR_OFF);
    pid_t pid = (pid_t)sys_getpid(), tid = (pid_t)sys_gettid();
    unsigned long frame = (unsigned long)__builtin_frame_address(0);
    int depth = nest_enter(pid, tid, frame);
    if (depth > 1 && ip >= C.text_lo && ip < C.text_hi) die("the launcher trapped its own syscall", 0, nr);
    if (depth > 64) die("signal handlers nested too deep (or left behind by longjmp on another stack)", 0, 0);
    long a[6] = {g[REG_ARG0], g[REG_ARG1], g[REG_ARG2], g[REG_ARG3], g[REG_ARG4], g[REG_ARG5]};
    struct scratch *S = scratch_get(pid, tid, frame);
    if (S) {
        S->resolve = 0;
        S->v[0] = 0;
    }
    long r = judge(nr, a);
    if (r == -MARK_NONE) r = S ? dispatch(S, nr, a, uc) : -ENOMEM;
    if (C.logfd >= 0 && S) log_line(sysname(nr), r, S->v[0] ? S->v : 0);
    if (S) scratch_put(S);
    g[REG_RESULT] = r;
}

void handler_install(void)
{
#if defined(__x86_64__)
    /* OSPKE, cpuid leaf 7's ecx bit 4: the kernel gives protection keys, and PKRU is component 9 of XSAVE */
    if (cpuid(0, 0).a >= 0xd && cpuid(7, 0).c >> 4 & 1) {
        C.pkru_off = cpuid(0xd, XFEATURE_PKRU).b;
        C.init_pkru = rdpkru(); /* the launcher has set none: the kernel's initial PKRU */
    }
#endif
    /* the restorer is the page's (sys.h), so that a program's own filter lets the return from every trap through */
    struct {
        void *h;
        unsigned long flags;
        void *restorer;
        unsigned long mask;
    } sa = {(void *)on_sigsys, SA_SIGINFO | SA_ONSTACK | SA_RESTORER | SA_NODEFER, (void *)SC_RESTORER, 0};
    if (sys_rt_sigaction(SIGSYS, &sa, 0, 8) < 0) die("cannot install the SIGSYS handler", 0, 0);
    unsigned long m = SIGSYS_BIT;
    sys_rt_sigprocmask(SIG_UNBLOCK, &m, 0, 8);
}
