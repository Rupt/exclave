/* sys.h — freestanding Linux syscall layer for the cont launcher.
 *
 * The launcher is built with -nostdlib -ffreestanding: it links against
 * nothing at all, so it can be dropped into any bundle and run on any
 * Linux of the same architecture regardless of what libc the host has.
 * Everything it needs from the OS is a raw syscall defined here.
 */
#pragma once
#include <stddef.h>
#include <stdint.h>

typedef long ssize_t;
typedef int pid_t;
typedef unsigned int uid_t;
typedef unsigned int gid_t;
typedef unsigned int mode_t;

/* ---------- architecture: syscall instruction + numbers ---------- */
#if defined(__x86_64__)
static inline long __sc6(long n, long a, long b, long c, long d, long e, long f)
{
    long ret;
    register long r10 __asm__("r10") = d;
    register long r8  __asm__("r8")  = e;
    register long r9  __asm__("r9")  = f;
    __asm__ volatile ("syscall"
                      : "=a"(ret)
                      : "a"(n), "D"(a), "S"(b), "d"(c), "r"(r10), "r"(r8), "r"(r9)
                      : "rcx", "r11", "memory");
    return ret;
}
enum {
    NR_read = 0, NR_write = 1, NR_close = 3, NR_fstat = 5, NR_lseek = 8,
    NR_mmap = 9, NR_munmap = 11, NR_ioctl = 16, NR_pread64 = 17,
    NR_getpid = 39, NR_clone = 56, NR_execve = 59, NR_wait4 = 61,
    NR_kill = 62, NR_fchdir = 81, NR_chdir = 80, NR_getcwd = 79,
    NR_getuid = 102, NR_getgid = 104, NR_statfs = 137, NR_pivot_root = 155,
    NR_prctl = 157, NR_mount = 165, NR_umount2 = 166, NR_getdents64 = 217,
    NR_exit_group = 231, NR_openat = 257, NR_mkdirat = 258, NR_newfstatat = 262,
    NR_unlinkat = 263, NR_symlinkat = 266, NR_readlinkat = 267,
    NR_faccessat = 269, NR_unshare = 272, NR_dup3 = 292,
    NR_mount_setattr = 442, NR_rt_sigaction = 13, NR_rt_sigprocmask = 14,
    NR_ptrace = 101, NR_fork = 57,
};
#define ARCH_NAME "x86_64"
#elif defined(__aarch64__)
static inline long __sc6(long n, long a, long b, long c, long d, long e, long f)
{
    register long x8 __asm__("x8") = n;
    register long x0 __asm__("x0") = a;
    register long x1 __asm__("x1") = b;
    register long x2 __asm__("x2") = c;
    register long x3 __asm__("x3") = d;
    register long x4 __asm__("x4") = e;
    register long x5 __asm__("x5") = f;
    __asm__ volatile ("svc #0"
                      : "+r"(x0)
                      : "r"(x8), "r"(x1), "r"(x2), "r"(x3), "r"(x4), "r"(x5)
                      : "memory");
    return x0;
}
enum {
    NR_read = 63, NR_write = 64, NR_close = 57, NR_fstat = 80, NR_lseek = 62,
    NR_mmap = 222, NR_munmap = 215, NR_ioctl = 29, NR_pread64 = 67,
    NR_getpid = 172, NR_clone = 220, NR_execve = 221, NR_wait4 = 260,
    NR_kill = 129, NR_fchdir = 50, NR_chdir = 49, NR_getcwd = 17,
    NR_getuid = 174, NR_getgid = 176, NR_statfs = 43, NR_pivot_root = 41,
    NR_prctl = 167, NR_mount = 40, NR_umount2 = 39, NR_getdents64 = 61,
    NR_exit_group = 94, NR_openat = 56, NR_mkdirat = 34, NR_newfstatat = 79,
    NR_unlinkat = 35, NR_symlinkat = 36, NR_readlinkat = 78,
    NR_faccessat = 48, NR_unshare = 97, NR_dup3 = 24,
    NR_mount_setattr = 442, NR_rt_sigaction = 134, NR_rt_sigprocmask = 135,
    NR_ptrace = 117, NR_fork = -1,
};
#define ARCH_NAME "aarch64"
#else
#error "unsupported architecture (add syscall numbers to sys.h)"
#endif

#define MAGIC 0xC0DEC0DE5CA1AB1EUL
#define SC0(n)                 __sc6(n, 0, 0, 0, 0, 0, MAGIC)
#define SC1(n, a)              __sc6(n, (long)(a), 0, 0, 0, 0, MAGIC)
#define SC2(n, a, b)           __sc6(n, (long)(a), (long)(b), 0, 0, 0, MAGIC)
#define SC3(n, a, b, c)        __sc6(n, (long)(a), (long)(b), (long)(c), 0, 0, MAGIC)
#define SC4(n, a, b, c, d)     __sc6(n, (long)(a), (long)(b), (long)(c), (long)(d), 0, MAGIC)
#define SC5(n, a, b, c, d, e)  __sc6(n, (long)(a), (long)(b), (long)(c), (long)(d), (long)(e), MAGIC)
#define SC6(n, a, b, c, d, e, f) __sc6(n, (long)(a), (long)(b), (long)(c), (long)(d), (long)(e), (long)(f))

/* ---------- constants (stable Linux ABI) ---------- */
#define AT_FDCWD            (-100)
#define AT_SYMLINK_NOFOLLOW 0x100
#define AT_REMOVEDIR        0x200
#define AT_EMPTY_PATH       0x1000
#define AT_RECURSIVE        0x8000

#define O_RDONLY    00
#define O_WRONLY    01
#define O_RDWR      02
#define O_CREAT     0100
#define O_EXCL      0200
#define O_TRUNC     01000
#define O_DIRECTORY 0200000
#define O_NOFOLLOW  0400000
#define O_CLOEXEC   02000000
#define O_PATH      010000000

#define EPERM   1
#define ENOENT  2
#define EINTR   4
#define EACCES  13
#define EEXIST  17
#define ENOTDIR 20
#define EINVAL  22
#define EROFS   30
#define ENOSYS  38
#define ENAMETOOLONG 36

#define S_IFMT   0170000
#define S_IFDIR  0040000
#define S_IFREG  0100000
#define S_IFLNK  0120000

#define MS_RDONLY      1
#define MS_NOSUID      2
#define MS_NODEV       4
#define MS_NOEXEC      8
#define MS_SYNCHRONOUS 16
#define MS_REMOUNT     32
#define MS_MANDLOCK    64
#define MS_NOATIME     1024
#define MS_NODIRATIME  2048
#define MS_BIND        4096
#define MS_REC         16384
#define MS_SILENT      32768
#define MS_PRIVATE     (1<<18)
#define MS_SLAVE       (1<<19)
#define MS_RELATIME    (1<<21)
#define MNT_DETACH     2

/* statfs f_flags bits (ST_*) share values with MS_* for the ones we care about */
#define ST_RDONLY  1
#define ST_NOSUID  2
#define ST_NODEV   4
#define ST_NOEXEC  8
#define ST_SYNCHRONOUS 16
#define ST_MANDLOCK 64
#define ST_NOATIME 1024
#define ST_NODIRATIME 2048
#define ST_RELATIME 4096

#define MOUNT_ATTR_RDONLY 0x1
#define MOUNT_ATTR_NOSUID 0x2
#define MOUNT_ATTR_NODEV  0x4
#define MOUNT_ATTR_NOEXEC 0x8

#define CLONE_NEWNS   0x00020000
#define CLONE_NEWUSER 0x10000000
#define SIGCHLD 17
#define SIGKILL 9

#define PR_SET_NO_NEW_PRIVS 38
#define PR_SET_PDEATHSIG 1

#define AT_NULL   0
#define AT_EXECFN 31

#define X_OK 1
#define W_OK 2
#define R_OK 4

/* ---------- structs ---------- */
struct kstat {              /* struct stat, x86_64 & aarch64 kernel layout */
#if defined(__x86_64__)
    unsigned long st_dev; unsigned long st_ino; unsigned long st_nlink;
    unsigned int st_mode; unsigned int st_uid; unsigned int st_gid; unsigned int __pad0;
    unsigned long st_rdev; long st_size; long st_blksize; long st_blocks;
    unsigned long st_atime, st_atime_nsec, st_mtime, st_mtime_nsec, st_ctime, st_ctime_nsec;
    long __unused[3];
#else
    unsigned long st_dev; unsigned long st_ino; unsigned int st_mode; unsigned int st_nlink;
    unsigned int st_uid; unsigned int st_gid; unsigned long st_rdev; unsigned long __pad1;
    long st_size; int st_blksize; int __pad2; long st_blocks;
    long st_atime; unsigned long st_atime_nsec; long st_mtime; unsigned long st_mtime_nsec;
    long st_ctime; unsigned long st_ctime_nsec; unsigned int __unused4, __unused5;
#endif
};

struct kstatfs {
    long f_type, f_bsize, f_blocks, f_bfree, f_bavail, f_files, f_ffree;
    int f_fsid[2];
    long f_namelen, f_frsize, f_flags, f_spare[4];
};

struct mount_attr {
    uint64_t attr_set, attr_clr, propagation, userns_fd;
};

struct linux_dirent64 {
    uint64_t d_ino; int64_t d_off; unsigned short d_reclen; unsigned char d_type; char d_name[];
};
#define DT_DIR 4
#define DT_REG 8
#define DT_LNK 10

/* ---------- thin wrappers ---------- */
static inline long sys_read(int fd, void *b, size_t n)          { return SC3(NR_read, fd, b, n); }
static inline long sys_write(int fd, const void *b, size_t n)   { return SC3(NR_write, fd, b, n); }
static inline long sys_close(int fd)                             { return SC1(NR_close, fd); }
static inline long sys_openat(int dfd, const char *p, int fl, int mode) { return SC4(NR_openat, dfd, p, fl, mode); }
static inline long sys_open(const char *p, int fl, int mode)     { return sys_openat(AT_FDCWD, p, fl, mode); }
static inline long sys_fstatat(int dfd, const char *p, struct kstat *st, int fl) { return SC4(NR_newfstatat, dfd, p, st, fl); }
static inline long sys_lstat(const char *p, struct kstat *st)    { return sys_fstatat(AT_FDCWD, p, st, AT_SYMLINK_NOFOLLOW); }
static inline long sys_stat(const char *p, struct kstat *st)     { return sys_fstatat(AT_FDCWD, p, st, 0); }
static inline long sys_mkdirat(int dfd, const char *p, int mode) { return SC3(NR_mkdirat, dfd, p, mode); }
static inline long sys_mkdir(const char *p, int mode)            { return sys_mkdirat(AT_FDCWD, p, mode); }
static inline long sys_symlinkat(const char *t, int dfd, const char *p) { return SC3(NR_symlinkat, t, dfd, p); }
static inline long sys_symlink(const char *t, const char *p)     { return sys_symlinkat(t, AT_FDCWD, p); }
static inline long sys_readlinkat(int dfd, const char *p, char *b, size_t n) { return SC4(NR_readlinkat, dfd, p, b, n); }
static inline long sys_readlink(const char *p, char *b, size_t n) { return sys_readlinkat(AT_FDCWD, p, b, n); }
static inline long sys_faccessat(int dfd, const char *p, int m)  { return SC3(NR_faccessat, dfd, p, m); }
static inline long sys_access(const char *p, int m)              { return sys_faccessat(AT_FDCWD, p, m); }
static inline long sys_chdir(const char *p)                      { return SC1(NR_chdir, p); }
static inline long sys_fchdir(int fd)                            { return SC1(NR_fchdir, fd); }
static inline long sys_getcwd(char *b, size_t n)                 { return SC2(NR_getcwd, b, n); }
static inline long sys_mount(const char *s, const char *t, const char *fs, unsigned long fl, const void *d) { return SC5(NR_mount, s, t, fs, fl, d); }
static inline long sys_umount2(const char *t, int fl)            { return SC2(NR_umount2, t, fl); }
static inline long sys_pivot_root(const char *n, const char *o)  { return SC2(NR_pivot_root, n, o); }
static inline long sys_unshare(int fl)                           { return SC1(NR_unshare, fl); }
static inline long sys_execve(const char *p, char *const *a, char *const *e) { return SC3(NR_execve, p, a, e); }
static inline __attribute__((noreturn)) void sys_exit(int c)     { for (;;) SC1(NR_exit_group, c); }
static inline long sys_getuid(void)                              { return SC0(NR_getuid); }
static inline long sys_getgid(void)                              { return SC0(NR_getgid); }
static inline long sys_getpid(void)                              { return SC0(NR_getpid); }
static inline long sys_getdents64(int fd, void *b, size_t n)     { return SC3(NR_getdents64, fd, b, n); }
static inline long sys_statfs(const char *p, struct kstatfs *s)  { return SC2(NR_statfs, p, s); }
static inline long sys_mount_setattr(int dfd, const char *p, unsigned fl, struct mount_attr *a, size_t sz) { return SC5(NR_mount_setattr, dfd, p, fl, a, sz); }
static inline long sys_wait4(pid_t p, int *st, int opt, void *ru) { return SC4(NR_wait4, p, st, opt, ru); }
static inline long sys_prctl(int op, unsigned long a, unsigned long b, unsigned long c, unsigned long d) { return SC5(NR_prctl, op, a, b, c, d); }
static inline long sys_kill(pid_t p, int s)                      { return SC2(NR_kill, p, s); }
static inline long sys_dup3(int a, int b, int fl)                { return SC3(NR_dup3, a, b, fl); }
static inline long sys_mmap(void *a, size_t n, int prot, int fl, int fd, long off) { return SC6(NR_mmap, a, n, prot, fl, fd, off); }
static inline long sys_pread(int fd, void *b, size_t n, long off) { return SC4(NR_pread64, fd, b, n, off); }
static inline long sys_lseek(int fd, long off, int wh)           { return SC3(NR_lseek, fd, off, wh); }
static inline long sys_unlinkat(int dfd, const char *p, int fl)  { return SC3(NR_unlinkat, dfd, p, fl); }

/* fork(): x86_64 has a real fork; aarch64 only has clone. */
static inline long sys_fork(void)
{
#if defined(__x86_64__)
    return SC0(NR_fork);
#else
    return SC5(NR_clone, SIGCHLD, 0, 0, 0, 0);
#endif
}

/* ---------- tiny libc subset ---------- */
static inline size_t xstrlen(const char *s) { size_t n = 0; while (s[n]) n++; return n; }
static inline int xstrcmp(const char *a, const char *b) { while (*a && *a == *b) a++, b++; return (unsigned char)*a - (unsigned char)*b; }
static inline int xstrncmp(const char *a, const char *b, size_t n) { while (n && *a && *a == *b) a++, b++, n--; return n ? (unsigned char)*a - (unsigned char)*b : 0; }
static inline int xstarts(const char *s, const char *pfx) { return xstrncmp(s, pfx, xstrlen(pfx)) == 0; }
static inline char *xstrchr(const char *s, int c) { for (; *s; s++) if (*s == c) return (char *)s; return c == 0 ? (char *)s : 0; }
static inline char *xstrrchr(const char *s, int c) { const char *r = 0; for (; *s; s++) if (*s == c) r = s; return (char *)r; }
static inline void *xmemcpy(void *d, const void *s, size_t n) { char *dd = d; const char *ss = s; while (n--) *dd++ = *ss++; return d; }
static inline void *xmemset(void *d, int c, size_t n) { char *dd = d; while (n--) *dd++ = (char)c; return d; }
static inline int xmemcmp(const void *a, const void *b, size_t n) { const unsigned char *x = a, *y = b; for (; n; n--, x++, y++) if (*x != *y) return *x - *y; return 0; }

/* gcc may emit calls to these even in freestanding mode */
void *memcpy(void *d, const void *s, size_t n);
void *memset(void *d, int c, size_t n);
void *memmove(void *d, const void *s, size_t n);
int memcmp(const void *a, const void *b, size_t n);
size_t strlen(const char *s);

/* ---------- output helpers ---------- */
static inline void outs(int fd, const char *s) { size_t n = xstrlen(s); while (n) { long r = sys_write(fd, s, n); if (r <= 0) return; s += r; n -= (size_t)r; } }
static inline void outn(int fd, long v)
{
    char b[24]; int i = 23; b[i] = 0;
    unsigned long u = v < 0 ? (unsigned long)(-v) : (unsigned long)v;
    do { b[--i] = (char)('0' + u % 10); u /= 10; } while (u);
    if (v < 0) b[--i] = '-';
    outs(fd, b + i);
}

static inline const char *strerr(long e)
{
    switch (e < 0 ? -e : e) {
    case EPERM:  return "Operation not permitted";
    case ENOENT: return "No such file or directory";
    case EACCES: return "Permission denied";
    case EEXIST: return "File exists";
    case ENOTDIR: return "Not a directory";
    case EINVAL: return "Invalid argument";
    case EROFS:  return "Read-only file system";
    case ENOSYS: return "Function not implemented";
    case ENAMETOOLONG: return "File name too long";
    case 12:     return "Cannot allocate memory";
    case 16:     return "Device or resource busy";
    case 21:     return "Is a directory";
    case 24:     return "Too many open files";
    case 40:     return "Too many levels of symbolic links";
    default:     return "error";
    }
}
