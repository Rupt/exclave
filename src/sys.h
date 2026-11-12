/* sys.h — freestanding Linux syscall layer for the launcher.
 *
 * The launcher is built with -nostdlib -ffreestanding: it links against
 * nothing at all, so it can be dropped into any exclave and run on any
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
/* The syscall page (DESIGN.md 7.4.2): one page at a fixed address holding the syscall instruction and a return.
 * Every syscall the launcher makes goes through it, and the filter allows a syscall by that instruction address alone.
 * The address is the same in every process, so one filter serves the whole tree. The page is mapped by page_init()
 * before anything else runs; only the bootstrap and the filter probe (7.4.2) use a raw instruction, and the signal
 * restorer lies in the page. It lies high in the low 2 GB, above program images, which every linker starts low and
 * grows upward (Go's on aarch64 from 0x10000, 13 item 24), and below 0x7fff8000, where ASan's shadow begins on
 * x86-64; 64K-aligned for kernels with 64K pages. Filters before version 6 allow a page at 0x3f0000 instead, so
 * neither launcher runs under the other's filter (FILTER_PAGE_SINCE). */
#define SC_PAGE 0x7fe00000UL
/* The page's layout (7.4.2): at 0 the launcher's syscall and a return; at 16 the judge slot, the same two
 * instructions, from which the handler re-issues a trapped call for the kernel to judge by the program's own filters,
 * and which every filter from version 10 answers rather than allows; at 32 the signal restorer, rt_sigreturn, jumped
 * to and never called, since the kernel reads the frame from the stack; at 48 the handler-call slot, 32 bytes, from
 * which a trampoline calls a program's handler with its return address at the restorer's own two instructions, whose
 * rt_sigreturn the filter answers with an error from that one address, SC_HCALL_RET, before a jump back into the
 * trampoline (7.5.7); at 80 the re-issue slot, 32 bytes, through which the handler makes the program's call: it makes
 * none when the trap's record says a program's handler redirected the program, and stores the answer in the record
 * (7.5.7). A call's instruction pointer, the address after its syscall instruction, lies in its slot on both
 * architectures. The filter names SC_HCALL_RET, so the handler-call slot's layout is fixed for the page generation. */
#define SC_JUDGE (SC_PAGE + 16)
#define SC_RESTORER (SC_PAGE + 32)
#define SC_HCALL (SC_PAGE + 48)
#define SC_HCALL_RET (SC_PAGE + 60)
#define SC_REISSUE (SC_PAGE + 80)
/* A syscall the architecture lacks gets a sentinel below zero, unique so that the handler's switch compiles, and
 * the filter skips it (a legacy form the kernel of the other architecture has: open, stat, fork, ...). */
#define ABSENT(k) (-1000 - (k))
#ifdef __ANALYZER__
/* Under gcc's analyser (scripts/check) a syscall is an opaque call: the analyser cannot see what the kernel writes
 * through the pointers an asm statement passes, and would otherwise read every stat buffer as uninitialised. */
long __sc6(long n, long a, long b, long c, long d, long e, long f);
long __sc6_raw(long n, long a, long b, long c, long d, long e, long f);
long __sc6_judge(long n, long a, long b, long c, long d, long e, long f);
long __sc6_reissue(long n, long a, long b, long c, long d, long e, long f);
#endif
#if defined(__x86_64__)
#ifndef __ANALYZER__
static inline long __sc6(long n, long a, long b, long c, long d, long e, long f)
{
    long ret;
    register long r10 __asm__("r10") = d;
    register long r8 __asm__("r8") = e;
    register long r9 __asm__("r9") = f;
    __asm__ volatile("call *%[pg]"
                     : "=a"(ret)
                     : "a"(n), "D"(a), "S"(b), "d"(c), "r"(r10), "r"(r8), "r"(r9), [pg] "r"(SC_PAGE)
                     : "rcx", "r11", "memory");
    return ret;
}
static inline long __sc6_raw(long n, long a, long b, long c, long d, long e, long f)
{
    long ret;
    register long r10 __asm__("r10") = d;
    register long r8 __asm__("r8") = e;
    register long r9 __asm__("r9") = f;
    __asm__ volatile("syscall"
                     : "=a"(ret)
                     : "a"(n), "D"(a), "S"(b), "d"(c), "r"(r10), "r"(r8), "r"(r9)
                     : "rcx", "r11", "memory");
    return ret;
}
/* the same call from the judge slot (7.4.2) */
static inline long __sc6_judge(long n, long a, long b, long c, long d, long e, long f)
{
    long ret;
    register long r10 __asm__("r10") = d;
    register long r8 __asm__("r8") = e;
    register long r9 __asm__("r9") = f;
    __asm__ volatile("call *%[pg]"
                     : "=a"(ret)
                     : "a"(n), "D"(a), "S"(b), "d"(c), "r"(r10), "r"(r8), "r"(r9), [pg] "r"(SC_JUDGE)
                     : "rcx", "r11", "memory");
    return ret;
}
/* the program's call, from the re-issue slot, which reads the trap's record through r15 (7.5.7) */
static inline long __sc6_reissue(long n, long a, long b, long c, long d, long e, long f)
{
    long ret;
    register long r10 __asm__("r10") = d;
    register long r8 __asm__("r8") = e;
    register long r9 __asm__("r9") = f;
    __asm__ volatile("call *%[pg]"
                     : "=a"(ret)
                     : "a"(n), "D"(a), "S"(b), "d"(c), "r"(r10), "r"(r8), "r"(r9), [pg] "r"(SC_REISSUE)
                     : "rcx", "r11", "memory");
    return ret;
}
#endif
/* the syscall numbers, laid out as a table, which test/syscalls.py checks against the kernel's, every one, this
 * architecture's and the other's */
/* clang-format off */
enum {
    NR_read = 0, NR_write = 1, NR_close = 3, NR_fstat = 5,
    NR_mmap = 9, NR_munmap = 11, NR_ioctl = 16, NR_pread64 = 17,
    NR_getpid = 39, NR_execve = 59,
    NR_kill = 62, NR_chdir = 80, NR_getcwd = 79, NR_madvise = 28,
    NR_statfs = 137, NR_pivot_root = 155,
    NR_prctl = 157, NR_mount = 165, NR_umount2 = 166, NR_getdents64 = 217, NR_getdents = 78, NR_lseek = 8,
    NR_exit_group = 231, NR_openat = 257, NR_mkdirat = 258, NR_newfstatat = 262,
    NR_unlinkat = 263, NR_symlinkat = 266, NR_readlinkat = 267,
    NR_faccessat = 269,
    NR_mount_setattr = 442, NR_rt_sigaction = 13, NR_rt_sigprocmask = 14, NR_rt_sigreturn = 15,
    NR_uname = 63, NR_tgkill = 234, NR_gettid = 186, NR_process_vm_readv = 310, NR_fchmod = 91,
    NR_fchown = 93, NR_fsetxattr = 190, NR_fremovexattr = 199,
    NR_rt_sigsuspend = 130, NR_ppoll = 271, NR_pselect6 = 270, NR_epoll_pwait = 281,
    NR_epoll_pwait2 = 441, NR_io_pgetevents = 333,
    NR_io_uring_setup = 425, NR_seccomp = 317, NR_fstatfs = 138,
    NR_clone3 = 435, NR_mprotect = 10, NR_fcntl = 72,
    NR_open = 2, NR_stat = 4, NR_lstat = 6, NR_access = 21, NR_truncate = 76, NR_rename = 82,
    NR_mkdir = 83, NR_rmdir = 84, NR_creat = 85, NR_link = 86, NR_unlink = 87, NR_symlink = 88,
    NR_readlink = 89, NR_chmod = 90, NR_chown = 92, NR_lchown = 94, NR_utime = 132, NR_mknod = 133,
    NR_uselib = 134, NR_chroot = 161, NR_acct = 163, NR_setxattr = 188, NR_lsetxattr = 189,
    NR_getxattr = 191, NR_lgetxattr = 192, NR_listxattr = 194, NR_llistxattr = 195,
    NR_removexattr = 197, NR_lremovexattr = 198, NR_utimes = 235, NR_inotify_add_watch = 254,
    NR_mknodat = 259, NR_fchownat = 260, NR_futimesat = 261, NR_renameat = 264, NR_linkat = 265,
    NR_fchmodat = 268, NR_utimensat = 280, NR_name_to_handle_at = 303, NR_renameat2 = 316,
    NR_execveat = 322, NR_statx = 332, NR_openat2 = 437, NR_faccessat2 = 439, NR_fchmodat2 = 452,
    NR_fanotify_mark = 301, NR_writev = 20, NR_process_vm_writev = 311,
    NR_setxattrat = 463, NR_getxattrat = 464, NR_listxattrat = 465, NR_removexattrat = 466, NR_open_tree_attr = 467,
    NR_file_getattr = 468, NR_file_setattr = 469, NR_bind = 49, NR_connect = 42,
    NR_pipe2 = 293, NR_prlimit64 = 302, NR_ptrace = 101, NR_getppid = 110, NR_kcmp = 312,
    NR_brk = 12, NR_getrandom = 318,
    NR_open_tree = 428, NR_move_mount = 429, NR_fsopen = 430, NR_fsconfig = 431, NR_fsmount = 432, NR_fspick = 433,
};
/* clang-format on */
#define ARCH_NAME "x86_64"
#define ARCH_ISA_DEFAULT "x86-64"
#define TASK_SIZE 0x7ffffffff000UL /* the kernel's bound on a segment (load_elf_binary) */
/* where the kernel lays a new image out (7.3), from the end of the stack it gave: the stack's end without
 * randomization (STACK_TOP), the base of a program that names a loader (ELF_ET_DYN_BASE, two thirds of the address
 * space) and the width of the random offset added to it (arch_mmap_rnd, 28 bits of pages by default) */
#define STACK_TOP(end) 0x7ffffffff000UL
#define ET_DYN_BASE(end) 0x555555554000UL
#define MMAP_RND_SPAN (1UL << 40)
#define EM_NATIVE 62
#define AUDIT_ARCH_NATIVE 0xC000003EU
#define R_NATIVE_RELATIVE 8                 /* R_X86_64_RELATIVE */
#define O_DIRECTORY 0200000
#define O_NOFOLLOW 0400000
#elif defined(__aarch64__)
/* svc #0 with the number in x8 and the arguments in x0 to x5; the result in x0. Through the page: a branch with
 * link to the page, whose svc executes with the program counter inside it, which is what the filter checks. */
#ifndef __ANALYZER__
static inline long __sc6(long n, long a, long b, long c, long d, long e, long f)
{
    register long x8 __asm__("x8") = n;
    register long x0 __asm__("x0") = a;
    register long x1 __asm__("x1") = b;
    register long x2 __asm__("x2") = c;
    register long x3 __asm__("x3") = d;
    register long x4 __asm__("x4") = e;
    register long x5 __asm__("x5") = f;
    register long x9 __asm__("x9") = (long)SC_PAGE;
    __asm__ volatile("blr x9"
                     : "+r"(x0)
                     : "r"(x8), "r"(x1), "r"(x2), "r"(x3), "r"(x4), "r"(x5), "r"(x9)
                     : "x30", "memory");
    return x0;
}
static inline long __sc6_raw(long n, long a, long b, long c, long d, long e, long f)
{
    register long x8 __asm__("x8") = n;
    register long x0 __asm__("x0") = a;
    register long x1 __asm__("x1") = b;
    register long x2 __asm__("x2") = c;
    register long x3 __asm__("x3") = d;
    register long x4 __asm__("x4") = e;
    register long x5 __asm__("x5") = f;
    __asm__ volatile("svc #0" : "+r"(x0) : "r"(x8), "r"(x1), "r"(x2), "r"(x3), "r"(x4), "r"(x5) : "memory");
    return x0;
}
/* the same call from the judge slot (7.4.2) */
static inline long __sc6_judge(long n, long a, long b, long c, long d, long e, long f)
{
    register long x8 __asm__("x8") = n;
    register long x0 __asm__("x0") = a;
    register long x1 __asm__("x1") = b;
    register long x2 __asm__("x2") = c;
    register long x3 __asm__("x3") = d;
    register long x4 __asm__("x4") = e;
    register long x5 __asm__("x5") = f;
    register long x9 __asm__("x9") = (long)SC_JUDGE;
    __asm__ volatile("blr x9"
                     : "+r"(x0)
                     : "r"(x8), "r"(x1), "r"(x2), "r"(x3), "r"(x4), "r"(x5), "r"(x9)
                     : "x30", "memory");
    return x0;
}
/* the program's call, from the re-issue slot, which reads the trap's record through x27 and uses x16 (7.5.7) */
static inline long __sc6_reissue(long n, long a, long b, long c, long d, long e, long f)
{
    register long x8 __asm__("x8") = n;
    register long x0 __asm__("x0") = a;
    register long x1 __asm__("x1") = b;
    register long x2 __asm__("x2") = c;
    register long x3 __asm__("x3") = d;
    register long x4 __asm__("x4") = e;
    register long x5 __asm__("x5") = f;
    register long x9 __asm__("x9") = (long)SC_REISSUE;
    __asm__ volatile("blr x9"
                     : "+r"(x0)
                     : "r"(x8), "r"(x1), "r"(x2), "r"(x3), "r"(x4), "r"(x5), "r"(x9)
                     : "x16", "x30", "memory");
    return x0;
}
#endif
/* clang-format off */
enum {   /* asm-generic/unistd.h: the *at forms only; the legacy forms are absent */
    NR_read = 63, NR_write = 64, NR_close = 57, NR_fstat = 80,
    NR_mmap = 222, NR_munmap = 215, NR_ioctl = 29, NR_pread64 = 67,
    NR_getpid = 172, NR_execve = 221,
    NR_kill = 129, NR_chdir = 49, NR_getcwd = 17, NR_madvise = 233,
    NR_statfs = 43, NR_pivot_root = 41,
    NR_prctl = 167, NR_mount = 40, NR_umount2 = 39, NR_getdents64 = 61, NR_getdents = ABSENT(24), NR_lseek = 62,
    NR_exit_group = 94, NR_openat = 56, NR_mkdirat = 34, NR_newfstatat = 79,
    NR_unlinkat = 35, NR_symlinkat = 36, NR_readlinkat = 78,
    NR_faccessat = 48,
    NR_mount_setattr = 442, NR_rt_sigaction = 134, NR_rt_sigprocmask = 135, NR_rt_sigreturn = 139,
    NR_uname = 160, NR_tgkill = 131, NR_gettid = 178, NR_process_vm_readv = 270, NR_fchmod = 52,
    NR_fchown = 55, NR_fsetxattr = 7, NR_fremovexattr = 16,
    NR_rt_sigsuspend = 133, NR_ppoll = 73, NR_pselect6 = 72, NR_epoll_pwait = 22,
    NR_epoll_pwait2 = 441, NR_io_pgetevents = 292,
    NR_io_uring_setup = 425, NR_seccomp = 277, NR_fstatfs = 44,
    NR_clone3 = 435, NR_mprotect = 226, NR_fcntl = 25,
    NR_open = ABSENT(4), NR_stat = ABSENT(5), NR_lstat = ABSENT(6), NR_access = ABSENT(7), NR_truncate = 45, NR_rename = ABSENT(8),
    NR_mkdir = ABSENT(9), NR_rmdir = ABSENT(10), NR_creat = ABSENT(11), NR_link = ABSENT(12), NR_unlink = ABSENT(13), NR_symlink = ABSENT(14),
    NR_readlink = ABSENT(15), NR_chmod = ABSENT(16), NR_chown = ABSENT(17), NR_lchown = ABSENT(18), NR_utime = ABSENT(19), NR_mknod = ABSENT(20),
    NR_uselib = ABSENT(21), NR_chroot = 51, NR_acct = 89, NR_setxattr = 5, NR_lsetxattr = 6,
    NR_getxattr = 8, NR_lgetxattr = 9, NR_listxattr = 11, NR_llistxattr = 12,
    NR_removexattr = 14, NR_lremovexattr = 15, NR_utimes = ABSENT(22), NR_inotify_add_watch = 27,
    NR_mknodat = 33, NR_fchownat = 54, NR_futimesat = ABSENT(23), NR_renameat = 38, NR_linkat = 37,
    NR_fchmodat = 53, NR_utimensat = 88, NR_name_to_handle_at = 264, NR_renameat2 = 276,
    NR_execveat = 281, NR_statx = 291, NR_openat2 = 437, NR_faccessat2 = 439, NR_fchmodat2 = 452,
    NR_fanotify_mark = 263, NR_writev = 66, NR_process_vm_writev = 271,
    NR_setxattrat = 463, NR_getxattrat = 464, NR_listxattrat = 465, NR_removexattrat = 466, NR_open_tree_attr = 467,
    NR_file_getattr = 468, NR_file_setattr = 469, NR_bind = 200, NR_connect = 203,
    NR_pipe2 = 59, NR_prlimit64 = 261, NR_ptrace = 117, NR_getppid = 173, NR_kcmp = 272,
    NR_brk = 214, NR_getrandom = 278,
    NR_open_tree = 428, NR_move_mount = 429, NR_fsopen = 430, NR_fsconfig = 431, NR_fsmount = 432, NR_fspick = 433,
};
/* clang-format on */
#define ARCH_NAME "aarch64"
#define ARCH_ISA_DEFAULT "aarch64"
#define TASK_SIZE (1UL << 52) /* the widest arm64 address space; a tighter kernel refuses the mapping itself */
/* where the kernel lays a new image out (7.3), as on x86-64. The address space is the kernel's choice, 39 to 48 bits
 * (DEFAULT_MAP_WINDOW_64), and the stack ends at its top, less a random distance under half of it: the power of two
 * the stack's end rounds up to. The random offset is 18 bits of 4 KB pages by default, 1 GB at every page size */
#define STACK_TOP(end) (1UL << (64 - __builtin_clzl((end) - 1)))
#define ET_DYN_BASE(end) (2 * STACK_TOP(end) / 3)
#define MMAP_RND_SPAN (1UL << 30)
#define EM_NATIVE 183
#define AUDIT_ARCH_NATIVE 0xC00000B7U
#define R_NATIVE_RELATIVE 1027              /* R_AARCH64_RELATIVE */
#define O_DIRECTORY 040000
#define O_NOFOLLOW 0100000
#else
#error "the launcher is built for x86-64 or aarch64"
#endif

/* MAGIC marks the filter probe (uname with MAGIC as its argument, 7.4.2); nothing else. */
#define MAGIC 0xC0DEC0DE5CA1AB1EUL
/* The static analyser cannot see what a syscall's assembly writes through its arguments, and would report every
 * buffer a syscall fills as uninitialised: to it, a syscall is a call to a function it cannot see. */
#ifdef __clang_analyzer__
long __sc6_opaque(long n, long a, long b, long c, long d, long e, long f);
#define __sc6 __sc6_opaque
long __sc6_judge_opaque(long n, long a, long b, long c, long d, long e, long f);
#define __sc6_judge __sc6_judge_opaque
#endif
#define SC0(n) __sc6(n, 0, 0, 0, 0, 0, 0)
#define SC1(n, a) __sc6(n, (long)(a), 0, 0, 0, 0, 0)
#define SC2(n, a, b) __sc6(n, (long)(a), (long)(b), 0, 0, 0, 0)
#define SC3(n, a, b, c) __sc6(n, (long)(a), (long)(b), (long)(c), 0, 0, 0)
#define SC4(n, a, b, c, d) __sc6(n, (long)(a), (long)(b), (long)(c), (long)(d), 0, 0)
#define SC5(n, a, b, c, d, e) __sc6(n, (long)(a), (long)(b), (long)(c), (long)(d), (long)(e), 0)
#define SC6(n, a, b, c, d, e, f) __sc6(n, (long)(a), (long)(b), (long)(c), (long)(d), (long)(e), (long)(f))

/* ---------- constants (stable Linux ABI) ---------- */
#define AT_FDCWD (-100)
#define AT_SYMLINK_NOFOLLOW 0x100
#define AT_REMOVEDIR 0x200
#define AT_EMPTY_PATH 0x1000
#define AT_EXECVE_CHECK 0x10000

#define O_RDONLY 00
#define O_WRONLY 01
#define O_RDWR 02
#define O_CREAT 0100
#define O_EXCL 0200
#define O_TRUNC 01000
#define O_CLOEXEC 02000000
#define O_PATH 010000000

#define EPERM 1
#define ENOENT 2
#define ESRCH 3
#define EINTR 4
#define EIO 5
#define E2BIG 7
#define ENOEXEC 8
#define EBADF 9
#define EAGAIN 11
#define ENOMEM 12
#define EACCES 13
#define EFAULT 14
#define EBUSY 16
#define EEXIST 17
#define EXDEV 18
#define ENOTDIR 20
#define EISDIR 21
#define EINVAL 22
#define ENFILE 23
#define EMFILE 24
#define ETXTBSY 26
#define EROFS 30
#define ERANGE 34
#define ENAMETOOLONG 36
#define ENOSYS 38
#define ENOTEMPTY 39
#define ELOOP 40
#define ELIBBAD 80
#define EADDRINUSE 98
#define ECONNREFUSED 111

#define S_IFMT 0170000
#define S_IFDIR 0040000
#define S_IFREG 0100000
#define S_IFLNK 0120000
#define S_IFIFO 0010000
#define S_IFCHR 0020000
#define S_IFBLK 0060000
#define S_IFSOCK 0140000

#define F_DUPFD 0
#define F_GETFD 1
#define F_GETFL 3
#define SEEK_SET 0
#define SEEK_CUR 1
#define F_DUPFD_CLOEXEC 1030
#define FD_CLOEXEC 1

#define GRND_NONBLOCK 1

#define X_OK 1
#define W_OK 2
#define R_OK 4

/* ---------- open / at flags ---------- */
#define O_ACCMODE 03
#define O_APPEND 02000
#define O_NONBLOCK 04000
#define O_TMPFILE (020000000 | O_DIRECTORY)
/* every O_ flag the kernel accepts, the same bits on x86-64 and aarch64 (fs/open.c) */
#define VALID_OPEN_FLAGS 0x7fffc3UL
#define O_PATH_FLAGS (O_PATH | O_CLOEXEC | O_NOFOLLOW | O_DIRECTORY)
/* openat2's resolve flags (7.4.3) */
#define RESOLVE_NO_XDEV 0x01
#define RESOLVE_NO_MAGICLINKS 0x02
#define RESOLVE_NO_SYMLINKS 0x04
#define RESOLVE_BENEATH 0x08
#define RESOLVE_IN_ROOT 0x10
#define RESOLVE_CACHED 0x20
#define RESOLVE_ALL 0x3f
#define AT_EACCESS 0x200
#define AT_SYMLINK_FOLLOW 0x400
#define AT_STATX_SYNC_TYPE 0x6000

/* ---------- signals ---------- */
#define SIGKILL 9
#define SIGSEGV 11
#define SIGSTOP 19
#define SIGSYS 31
#define SIGSYS_BIT (1UL << (SIGSYS - 1))
#define SA_SIGINFO 4
#define SA_ONSTACK 0x08000000
#define SA_RESTORER 0x04000000
#define SA_NODEFER 0x40000000
#define SIG_BLOCK 0
#define SIG_UNBLOCK 1
#define SIG_SETMASK 2
#define SYS_SECCOMP 1

/* ---------- seccomp ---------- */
#define PR_SET_SECCOMP 22
#define PR_SET_NO_NEW_PRIVS 38
#define PR_SET_MM 35
#define PR_SET_MM_MAP 14
#define RLIMIT_NOFILE 7
#define PR_SET_NAME 15
#define SECCOMP_MODE_FILTER 2
#define SECCOMP_SET_MODE_FILTER 1
#define SECCOMP_GET_ACTION_AVAIL 2
#define SECCOMP_SET_MODE_STRICT 0
#define SECCOMP_MODE_STRICT 1
#define SECCOMP_GET_NOTIF_SIZES 3
#define SECCOMP_FILTER_FLAG_TSYNC 1
#define SECCOMP_FILTER_FLAG_LOG 2
#define SECCOMP_FILTER_FLAG_SPEC_ALLOW 4    /* 4.17 */
#define SECCOMP_FILTER_FLAG_TSYNC_ESRCH 16
#define SECCOMP_RET_KILL_THREAD 0U
#define SECCOMP_RET_LOG 0x7ffc0000U
#define SECCOMP_RET_ACTION_FULL 0xffff0000U
#define BPF_MAXINSNS 4096
/* 7.4.2: the judge's answers, errnos a program's filter is not let give (one of 4095 or below, which the kernel
 * returns unclamped): MARK_NONE, the launcher filter's to a call from the judge slot, and MARK_PRESENT, a program
 * filter's prologue's to the probe from it */
#define MARK_NONE 4094
#define MARK_PRESENT 4093
/* the filter's answer to an rt_sigreturn from the handler-call slot, so that a program's handler returns into the
 * trampoline (7.5.7) */
#define MARK_HANDLER_RETURN 4092
#define SECCOMP_RET_KILL_PROCESS 0x80000000U
#define SECCOMP_RET_TRAP 0x00030000U
#define SECCOMP_RET_ERRNO 0x00050000U
#define SECCOMP_RET_ALLOW 0x7fff0000U
#define X32_SYSCALL_BIT 0x40000000U

/* ---------- mmap ---------- */
#define PROT_NONE 0
#define PROT_READ 1
#define PROT_WRITE 2
#define PROT_EXEC 4
#define MAP_PRIVATE 2
#define MAP_FIXED 0x10
#define MAP_ANONYMOUS 0x20
#define MAP_NORESERVE 0x4000
#define MADV_WIPEONFORK 18 /* 4.14+: the range reads as zero in a fork child; a vfork child shares it */
#define MAP_FIXED_NOREPLACE 0x100000

/* the ptrace request the filter traps (7.4.2): a vfork child's is deferred to its exec (7.4.5) */
#define PTRACE_TRACEME 0
#define KCMP_VM 1

/* ---------- ioctl requests the filter traps (chattr) ---------- */
#define FS_IOC_SETFLAGS 0x40086602UL
#define FS_IOC_FSSETXATTR 0x401c5820UL /* _IOW('X', 32, struct fsxattr) */

/* ---------- statfs flag ---------- */
#define ST_RDONLY 1 /* statfs's f_flags bit for a read-only mount */

/* ---------- auxv ---------- */
#define AT_NULL 0
#define AT_EXECFN 31
#define AT_PHDR 3
#define AT_PHENT 4
#define AT_PHNUM 5
#define AT_PAGESZ 6
#define AT_BASE 7
#define AT_ENTRY 9
#define AT_HWCAP 16

/* ---------- the signal frame (rt_sigframe), by architecture ----------
 * x86-64: uc_mcontext.gregs at +40 from the ucontext, uc_sigmask at +296; verified against a real frame. The names
 * index the argument registers of the syscall convention and the result register.
 * aarch64: the ucontext is uc_flags, uc_link, uc_stack (24), uc_sigmask (8) at +40, 120 unused bytes, then
 * struct sigcontext at +176: fault_address, regs[31] from +184, sp, pc, pstate. The arguments are x0 to x5, the
 * number x8, the result x0, which is also the first argument: the handler copies the arguments before it writes. */
#if defined(__x86_64__)
#define UC_GREGS_OFF 40
#define UC_SIGMASK_OFF 296
/* the XSAVE area the kernel saved, which uc_mcontext.fpregs at +224 points to: the software bytes at +464 begin with
 * FP_XSTATE_MAGIC1 and hold the frame's features at +472, and the XSAVE header at +512 those in use; a component is at
 * the offset cpuid leaf 0xd gives it, in the standard format a signal frame always uses */
#define UC_FPREGS_OFF 224
#define FP_XSTATE_MAGIC1 0x46505853U
#define XFEATURE_PKRU 9
enum {
    REG_R8 = 0,
    REG_R9,
    REG_R10,
    REG_R11,
    REG_R12,
    REG_R13,
    REG_R14,
    REG_R15,
    REG_RDI,
    REG_RSI,
    REG_RBP,
    REG_RBX,
    REG_RDX,
    REG_RAX,
    REG_RCX,
    REG_RSP,
    REG_RIP
};
#define REG_ARG0 REG_RDI
#define REG_ARG1 REG_RSI
#define REG_ARG2 REG_RDX
#define REG_ARG3 REG_R10
#define REG_ARG4 REG_R8
#define REG_ARG5 REG_R9
#define REG_RESULT REG_RAX
#elif defined(__aarch64__)
#define UC_GREGS_OFF 184
#define UC_SIGMASK_OFF 40
#define REG_ARG0 0
#define REG_ARG1 1
#define REG_ARG2 2
#define REG_ARG3 3
#define REG_ARG4 4
#define REG_ARG5 5
#define REG_RESULT 0
#endif
/* siginfo: si_signo@0 si_errno@4 si_code@8; SIGSYS: _call_addr@16 _syscall@24 _arch@28 */
#define SI_CODE_OFF 8
#define SI_CALL_ADDR_OFF 16
#define SI_SYSCALL_OFF 24

/* ---------- what the handler reads of its calls' flags and structs ---------- */
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

/* ---------- structs ---------- */
struct kstat {              /* struct stat, x86_64 & aarch64 kernel layout */
#if defined(__x86_64__)
    unsigned long st_dev;
    unsigned long st_ino;
    unsigned long st_nlink;
    unsigned int st_mode;
    unsigned int st_uid;
    unsigned int st_gid;
    unsigned int __pad0;
    unsigned long st_rdev;
    long st_size;
    long st_blksize;
    long st_blocks;
    unsigned long st_atime, st_atime_nsec, st_mtime, st_mtime_nsec, st_ctime, st_ctime_nsec;
    long __unused[3];
#else
    unsigned long st_dev;
    unsigned long st_ino;
    unsigned int st_mode;
    unsigned int st_nlink;
    unsigned int st_uid;
    unsigned int st_gid;
    unsigned long st_rdev;
    unsigned long __pad1;
    long st_size;
    int st_blksize;
    int __pad2;
    long st_blocks;
    long st_atime;
    unsigned long st_atime_nsec;
    long st_mtime;
    unsigned long st_mtime_nsec;
    long st_ctime;
    unsigned long st_ctime_nsec;
    unsigned int __unused4, __unused5;
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
    uint64_t d_ino;
    int64_t d_off;
    unsigned short d_reclen;
    unsigned char d_type;
    char d_name[];
};
#define DT_UNKNOWN 0
#define DT_DIR 4
#define DT_REG 8
#define DT_LNK 10

/* ---------- thin wrappers ---------- */
static inline long sys_read(int fd, void *b, size_t n) { return SC3(NR_read, fd, b, n); }
static inline long sys_write(int fd, const void *b, size_t n) { return SC3(NR_write, fd, b, n); }
static inline long sys_close(int fd) { return SC1(NR_close, fd); }
static inline long sys_pipe2(int *fds, int flags) { return SC2(NR_pipe2, fds, flags); }
static inline long sys_openat(int dfd, const char *p, int fl, int mode) { return SC4(NR_openat, dfd, p, fl, mode); }
static inline long sys_open(const char *p, int fl, int mode) { return sys_openat(AT_FDCWD, p, fl, mode); }
static inline long sys_fstatat(int dfd, const char *p, struct kstat *st, int fl)
{ return SC4(NR_newfstatat, dfd, p, st, fl); }
static inline long sys_lstat(const char *p, struct kstat *st)
{ return sys_fstatat(AT_FDCWD, p, st, AT_SYMLINK_NOFOLLOW); }
static inline long sys_stat(const char *p, struct kstat *st) { return sys_fstatat(AT_FDCWD, p, st, 0); }
static inline long sys_readlinkat(int dfd, const char *p, char *b, size_t n)
{ return SC4(NR_readlinkat, dfd, p, b, n); }
static inline long sys_readlink(const char *p, char *b, size_t n) { return sys_readlinkat(AT_FDCWD, p, b, n); }
static inline long sys_faccessat(int dfd, const char *p, int m) { return SC3(NR_faccessat, dfd, p, m); }
static inline long sys_getcwd(char *b, size_t n) { return SC2(NR_getcwd, b, n); }
static inline long sys_execve(const char *p, char *const *a, char *const *e) { return SC3(NR_execve, p, a, e); }
static inline __attribute__((noreturn)) void sys_exit(int c)
{
    for (;;) SC1(NR_exit_group, c);
}
static inline long sys_getpid(void) { return SC0(NR_getpid); }
static inline long sys_getppid(void) { return SC0(NR_getppid); }
static inline long sys_getdents64(int fd, void *b, size_t n) { return SC3(NR_getdents64, fd, b, n); }
static inline long sys_prctl(int op, unsigned long a, unsigned long b, unsigned long c, unsigned long d)
{ return SC5(NR_prctl, op, a, b, c, d); }
static inline long sys_kill(pid_t p, int s) { return SC2(NR_kill, p, s); }
static inline long sys_mmap(void *a, size_t n, int prot, int fl, int fd, long off)
{ return SC6(NR_mmap, a, n, prot, fl, fd, off); }
static inline long sys_madvise(void *a, size_t n, int advice) { return SC3(NR_madvise, a, n, advice); }
static inline long sys_pread(int fd, void *b, size_t n, long off) { return SC4(NR_pread64, fd, b, n, off); }

static inline long sys_gettid(void) { return SC0(NR_gettid); }
static inline long sys_tgkill(pid_t tg, pid_t t, int s) { return SC3(NR_tgkill, tg, t, s); }
static inline long sys_fcntl(int fd, int cmd, long arg) { return SC3(NR_fcntl, fd, cmd, arg); }
static inline long sys_mprotect(void *a, size_t n, int prot) { return SC3(NR_mprotect, a, n, prot); }
static inline long sys_rt_sigprocmask(int how, const void *set, void *old, size_t n)
{ return SC4(NR_rt_sigprocmask, how, set, old, n); }
static inline long sys_rt_sigaction(int sig, const void *act, void *old, size_t n)
{ return SC4(NR_rt_sigaction, sig, act, old, n); }
struct iovec {
    void *iov_base;
    size_t iov_len;
};
static inline long sys_process_vm_readv(pid_t pid, const struct iovec *l, unsigned long ln, const struct iovec *r,
                                        unsigned long rn, unsigned long fl)
{ return SC6(NR_process_vm_readv, pid, l, ln, r, rn, fl); }
static inline long sys_process_vm_writev(pid_t pid, const struct iovec *l, unsigned long ln, const struct iovec *r,
                                         unsigned long rn, unsigned long fl)
{ return SC6(NR_process_vm_writev, pid, l, ln, r, rn, fl); }

/* ---------- tiny libc subset ---------- */
/* a pointer into a const argument handed back writable, as strchr does, or into a struct iovec for writing out */
static inline void *unconst(const void *p) { return (void *)(uintptr_t)p; }
static inline size_t xstrlen(const char *s)
{
    size_t n = 0;
    while (s[n]) n++;
    return n;
}
static inline int xstrcmp(const char *a, const char *b)
{
    while (*a && *a == *b) a++, b++;
    return (unsigned char)*a - (unsigned char)*b;
}
static inline int xstrncmp(const char *a, const char *b, size_t n)
{
    while (n && *a && *a == *b) a++, b++, n--;
    return n ? (unsigned char)*a - (unsigned char)*b : 0;
}
static inline int xstarts(const char *s, const char *pfx) { return xstrncmp(s, pfx, xstrlen(pfx)) == 0; }
static inline char *xstrchr(const char *s, int c)
{
    for (; *s; s++)
        if (*s == c) return unconst(s);
    return c == 0 ? unconst(s) : 0;
}
static inline char *xstrrchr(const char *s, int c)
{
    const char *r = 0;
    for (; *s; s++)
        if (*s == c) r = s;
    return unconst(r);
}
static inline char *xstrstr(const char *h, const char *n)
{
    size_t l = xstrlen(n);
    for (; *h; h++)
        if (xstrncmp(h, n, l) == 0) return unconst(h);
    return 0;
}
static inline void *xmemcpy(void *d, const void *s, size_t n)
{
    char *dd = d;
    const char *ss = s;
    while (n--) *dd++ = *ss++;
    return d;
}
static inline void *xmemset(void *d, int c, size_t n)
{
    char *dd = d;
    while (n--) *dd++ = (char)c;
    return d;
}
static inline int xmemcmp(const void *a, const void *b, size_t n)
{
    const unsigned char *x = a, *y = b;
    for (; n; n--, x++, y++)
        if (*x != *y) return *x - *y;
    return 0;
}

/* gcc may emit calls to these even in freestanding mode */
void *memcpy(void *d, const void *s, size_t n);
void *memset(void *d, int c, size_t n);
void *memmove(void *d, const void *s, size_t n);
int memcmp(const void *a, const void *b, size_t n);
size_t strlen(const char *s);

/* ---------- output helpers ---------- */
static inline void outs(int fd, const char *s)
{
    size_t n = xstrlen(s);
    while (n) {
        long r = sys_write(fd, s, n);
        if (r <= 0) return;
        s += r;
        n -= (size_t)r;
    }
}

#if defined(__x86_64__)
/* ---------- x86-64: cpuid and the protection-key register ---------- */
struct cpuid {
    unsigned a, b, c, d;
};
static inline struct cpuid cpuid(unsigned leaf, unsigned sub)
{
    struct cpuid r;
    __asm__ volatile("cpuid" : "=a"(r.a), "=b"(r.b), "=c"(r.c), "=d"(r.d) : "a"(leaf), "c"(sub));
    return r;
}
/* PKRU, two bits a key, access and write disabled, which the kernel checks a thread's access to memory against, its
 * own copies included; rdpkru and wrpkru spelt as bytes, for assemblers without them */
static inline unsigned rdpkru(void)
{
    unsigned v;
    __asm__ volatile(".byte 0x0f,0x01,0xee" : "=a"(v) : "c"(0) : "rdx");
    return v;
}
static inline void wrpkru(unsigned v)
{ __asm__ volatile(".byte 0x0f,0x01,0xef" : : "a"(v), "c"(0), "d"(0) : "memory"); }
#endif
