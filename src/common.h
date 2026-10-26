/* common.h — shared definitions for the launcher.
 *
 * The launcher is freestanding: no libc, raw syscalls only (sys.h). Every
 * module includes this header. Section numbers in comments refer to
 * docs/PROPOSAL.md.
 */
#pragma once
#include "sys.h"

#define LAUNCHER_VERSION "0.1"
#ifndef FILTER_VERSION
#define FILTER_VERSION 6                 /* 7.4.2: versioned reuse; bumped whenever the trap set grows or the page moves (2: the *xattrat and file_*attr syscalls; 3: openat2; 4: bind and connect; 5: FS_IOC_FSSETXATTR's right number; 6: the syscall page moved) */
#endif
#define FILTER_PAGE_SINCE 6              /* an inherited filter older than this allows another page's syscalls and traps this launcher's */
#define PAGE_GENERATION 2                /* the word of the launcher's notes (launcher.c): 1 in launchers whose page was at 0x3f0000 */
#define PATH_MAX 4096
#define NAME_MAX 255

/* ---------- errno ---------- */
#define EBADF   9
#define ECHILD  10
#define EAGAIN  11
#define ENOMEM  12
#define EFAULT  14
#define EBUSY   16
#define EXDEV   18
#define EISDIR  21
#define ENFILE  23
#define EMFILE  24
#define ENOTTY  25
#define ENOSPC  28
#define ESPIPE  29
#define ERANGE  34
#define ELOOP   40
#define ENOEXEC 8
#define E2BIG   7
#define ESRCH   3
#define EIO     5
#define ENOTEMPTY 39
#define EOPNOTSUPP 95

/* ---------- open / at flags ---------- */
#define O_ACCMODE  03
#define O_NOCTTY   0400
#define O_APPEND   02000
#define O_NONBLOCK 04000
#define O_TMPFILE  (020000000 | O_DIRECTORY)
#define VALID_OPEN_FLAGS 0x7fffc3UL         /* every O_ flag the kernel accepts, the same bits on x86-64 and aarch64 (fs/open.c) */
#define O_PATH_FLAGS (O_PATH | O_CLOEXEC | O_NOFOLLOW | O_DIRECTORY)
/* openat2's resolve flags (7.4.3) */
#define RESOLVE_NO_XDEV       0x01
#define RESOLVE_NO_MAGICLINKS 0x02
#define RESOLVE_NO_SYMLINKS   0x04
#define RESOLVE_BENEATH       0x08
#define RESOLVE_IN_ROOT       0x10
#define RESOLVE_CACHED        0x20
#define RESOLVE_ALL           0x3f
#define AT_EACCESS 0x200
#define AT_SYMLINK_FOLLOW 0x400
#define AT_STATX_SYNC_TYPE 0x6000

/* ---------- signals ---------- */
#define SIGHUP 1
#define SIGINT 2
#define SIGQUIT 3
#define SIGILL 4
#define SIGABRT 6
#define SIGBUS 7
#define SIGFPE 8
#define SIGSEGV 11
#define SIGTERM 15
#define SIGSTOP 19
#define SIGSYS 31
#define SA_SIGINFO   4
#define SA_ONSTACK   0x08000000
#define SA_RESTORER  0x04000000
#define SA_NODEFER   0x40000000
#define SIG_BLOCK 0
#define SIG_UNBLOCK 1
#define SIG_SETMASK 2
#define SYS_SECCOMP 1

/* ---------- seccomp ---------- */
#define PR_SET_SECCOMP 22
#define RLIMIT_NOFILE 7
#define PR_SET_NAME 15
#define SECCOMP_MODE_FILTER 2
#define SECCOMP_SET_MODE_FILTER 1
#define SECCOMP_GET_ACTION_AVAIL 2
#define SECCOMP_FILTER_FLAG_SPEC_ALLOW 4    /* 4.17 */
#define SECCOMP_RET_KILL_PROCESS 0x80000000u
#define SECCOMP_RET_KILL_THREAD  0x00000000u
#define SECCOMP_RET_TRAP  0x00030000u
#define SECCOMP_RET_ERRNO 0x00050000u
#define SECCOMP_RET_ALLOW 0x7fff0000u
#define AUDIT_ARCH_X86_64 0xC000003Eu
#define AUDIT_ARCH_AARCH64 0xC00000B7u
#define X32_SYSCALL_BIT 0x40000000u

/* ---------- mmap ---------- */
#define PROT_READ 1
#define PROT_WRITE 2
#define PROT_EXEC 4
#define MAP_PRIVATE 2
#define MAP_FIXED 0x10
#define MAP_ANONYMOUS 0x20
#define MAP_FIXED_NOREPLACE 0x100000
#define MAP_STACK 0x20000

/* ---------- ioctl requests the filter traps (chattr) ---------- */
#define FS_IOC_SETFLAGS   0x40086602UL
#define FS_IOC_FSSETXATTR 0x401c5820UL                  /* _IOW('X', 32, struct fsxattr); versions 1 to 4 had 'X' 28 */

/* ---------- statfs flag ---------- */
#define ST_RDONLY_BIT 1

/* ---------- auxv ---------- */
#define AT_PHDR 3
#define AT_PHENT 4
#define AT_PHNUM 5
#define AT_PAGESZ 6
#define AT_BASE 7
#define AT_ENTRY 9
#define AT_RANDOM 25
#define AT_HWCAP 16
#define AT_HWCAP2 26
#define AT_MINSIGSTKSZ 51

/* ---------- the signal frame (rt_sigframe), by architecture ----------
 * x86-64: uc_mcontext.gregs at +40 from the ucontext, uc_sigmask at +296; verified against a real frame by both
 * first-round reviews. The names index the argument registers of the syscall convention and the result register.
 * aarch64: the ucontext is uc_flags, uc_link, uc_stack (24), uc_sigmask (8) at +40, 120 unused bytes, then
 * struct sigcontext at +176: fault_address, regs[31] from +184, sp, pc, pstate. The arguments are x0 to x5, the
 * number x8, the result x0, which is also the first argument: the handler copies the arguments before it writes. */
#if defined(__x86_64__)
#define UC_GREGS_OFF 40
#define UC_SIGMASK_OFF 296
enum { REG_R8 = 0, REG_R9, REG_R10, REG_R11, REG_R12, REG_R13, REG_R14, REG_R15, REG_RDI, REG_RSI,
       REG_RBP, REG_RBX, REG_RDX, REG_RAX, REG_RCX, REG_RSP, REG_RIP };
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
#define REG_SP 31
#define REG_PC 32
#endif
/* siginfo: si_signo@0 si_errno@4 si_code@8; SIGSYS: _call_addr@16 _syscall@24 _arch@28 */
#define SI_CODE_OFF 8
#define SI_CALL_ADDR_OFF 16
#define SI_SYSCALL_OFF 24
#define SI_ARCH_OFF 28

/* ---------- the can's run-time state (7.2), filled at startup ---------- */
struct hostmap { const char *v; const char *r; int is_file; };   /* virtual path -> host real path */

struct exclave {
    char dir[PATH_MAX];            /* directory holding .exclave/ */
    char root[PATH_MAX];           /* dir/tree */
    long rootlen;
    char launcher[PATH_MAX];         /* dir/.exclave/launcher */
    unsigned long launcher_dev, launcher_ino; long launcher_size;
    char program[PATH_MAX];        /* virtual path of the program this process runs */
    char exe[PATH_MAX];            /* what /proc/self/exe answers: the program, or a wrapped script's interpreter (F3-22) */
    char execfn[PATH_MAX];         /* the path the program was exec'd by, as the kernel spells it: AT_EXECFN, a script's $0 (7.6) */
    char comm[NAME_MAX + 1];       /* the name the kernel would set as comm: the exec'd path's last component, a descriptor's file (7.6) */
    int loader_mode;               /* 1: re-exec'd with EXCLAVE_EXEC; program is not a wrapper */
    int descfd;                    /* loader mode for a descriptor with no path (13 item 25): the dup to close once the segments are mapped, else -1 */
    int exe_fixed;                 /* exe holds the descriptor's link text, the kernel's identity for such a program; run() leaves it */
    int boundary;                  /* 1: no filter of ours inherited: this process is the can boundary (7.2) */
    /* the manifest (6.2) and what the tree says (8.1); the limits are stated in 8.1 and enforced by cannery wrap */
    char cpu[32];
    const char *own[512]; int nown;   /* the manifest's claims (at most 256), then every non-empty top-level entry of the tree (at most 256) */
    struct hostmap host[128]; int nhost;   /* the manifest's host records (at most 32), then the identity files (8.4) */
    const char *data[32]; int ndata;  /* data prefixes: never executed, never a loader (6.2) */
    /* cwd rule (8.1.4) */
    char cwdclaim[PATH_MAX]; long cwdclaim_len;   /* subtree claimed for the host; empty if none */
    unsigned long rlim[2]; int borrowed;   /* RLIMIT_NOFILE as the program had it, raised for the launcher's own opens (7.4.5) */
    /* diagnostics */
    int logfd;
    unsigned long text_lo, text_hi;   /* the launcher's own text range, for the nesting rule (7.5.3) */
    unsigned long root_dev, root_ino; /* the tree's root directory, so that any spelling of it is recognised (F3-13) */
    unsigned long pagesz;              /* the kernel's page size, AT_PAGESZ: 4 KB, or 16 KB or 64 KB on some aarch64 kernels (7.3) */
};
extern struct exclave C;

/* ---------- string helpers (str.c) ---------- */
char *scpy(char *d, const char *s, size_t n);
char *scat(char *d, const char *s, size_t n);
const char *base_name(const char *p);
void ltoa_(long v, char *b);            /* decimal, buffer >= 24 */
void xtoa_(unsigned long v, char *b);   /* lowercase hex, buffer >= 20 */
int starts_dir(const char *s, const char *pfx);  /* s == pfx or s starts with pfx + "/" ; "/" matches all */
void *arena_alloc(size_t n);            /* bump allocator for the manifest's strings, the tables, the environment; never freed */
const char *arena_str(const char *s, size_t n);
long shebang_argv(char *line, const char *script, char **argv, long argc, char **nargv, long cap);

/* ---------- logging (log.c) ---------- */
void log_open(char **envp);
void log_line(const char *what, long result, const char *path);
void log_msg(const char *a, const char *b);
__attribute__((noreturn)) void die(const char *what, const char *detail, long err);
__attribute__((noreturn)) void die_status(int status, const char *what, const char *detail, long err);   /* 126 where a shell says so: found but not executable */

/* ---------- manifest (manifest.c) ---------- */
int manifest_parse(const char *buf, size_t len, struct exclave *c, char *err, size_t errn);

/* ---------- scratch (scratch.c) ---------- */
struct scratch {
    char b1[PATH_MAX], b2[PATH_MAX];
    char rest[2 * PATH_MAX];       /* the walk's remaining path: a directory and a relative path, or a link's text and the rest, each under PATH_MAX */
    char cur[PATH_MAX], real[PATH_MAX], tmp[PATH_MAX], v[PATH_MAX];
    char v2[PATH_MAX];             /* the first path of a two-path syscall, the directory a scoped openat2 walk may not leave, or the
                                    * name an exec'd program is exec'd by as the kernel spells it (7.4.5); canon never writes it */
    char comm[NAME_MAX + 1];       /* the comm the kernel would set for an exec'd program (7.6) */
    char extra[8192];              /* argv and envp vectors, ELF headers, an extended open_how, a sockaddr */
    pid_t pid, tid;                /* the owner, looked up once per trap */
    unsigned resolve;              /* openat2's resolve flags for the walk (7.4.3); 0 for every other syscall */
    int touched_exclave;               /* set by canon: the walk started at, passed through or ended in the can's domain, or rewrote a magic link */
    unsigned long how0[3];         /* openat2's struct open_how as given, for a walk that never touched the can (7.4.3) */
};
struct scratch *scratch_get(pid_t pid, pid_t tid, unsigned long frame);
void scratch_put(struct scratch *s);
int  nest_enter(pid_t pid, pid_t tid, unsigned long frame); /* returns depth, 1 for outermost; releases frames left by longjmp */

/* ---------- visibility (vis.c) ---------- */
void vis_init(void);
int  vis_is_host(const char *v, const char **real);   /* 1 if host-owned; *real = host path */
char *to_real(const char *v, char *out, char *tmp);   /* v -> real, with wrapper redirect; tmp PATH_MAX */
char *to_real_exec(const char *v, char *out);         /* v -> real, no wrapper redirect */
void from_real(char *r);                              /* in place, no buffer */
int  is_exclave_path(const char *v);
int  vis_leads_to_host_file(const char *v);   /* v is a proper ancestor of a host-resolved file */
int  vis_walk_facts(const char *v, int *identity, int *leads, const char **real);   /* the three in one pass: 1 if the host's */
int  vis_plain_host_chain(const char *p, unsigned from);   /* every prefix from that long the host's plainly: the one-step check may stand in */
int  is_wrapper_real(const char *real, char *tmp);   /* tmp PATH_MAX */
int  payload_of(const char *real, char *out);         /* out = real's payload path, dir/.real/base; 1 if it fits; no wrapper check */
int  vis_readlink_identity(const char *v, char *out); /* 1 if v is an identity file that is a host symlink, out = its text; -EINVAL if not a symlink; 0 otherwise */
int  vis_is_identity_file(const char *v);              /* 1 if v is exactly a host identity file */
int  vis_in_data(const char *v);                       /* 1 if v lies under a data prefix (6.2) */

/* ---------- the canonicalisation cache (cache.c, 7.4.4) ---------- */
enum { CK_NONE = 1, CK_DIR, CK_LINK, CK_FILE, CK_WRAPPER };
int  cache_get(const char *v, char *link_out);        /* 0 on a miss; link_out PATH_MAX gets a symlink's text */
void cache_put(const char *v, int kind, const char *link);
int  cache_classify(const char *v, const char *real, char *tmp);   /* one lstat on a miss, two more for a regular file's wrapper check; 0 only if a readlink raced */

/* ---------- canonicalisation (canon.c) ---------- */
int canon(struct scratch *S, const char *path, int dfd, int follow_last, char *out);  /* 0 or -errno */
int fd_virtual(int fd, char *out);
int cwd_virtual(char *out);
int is_self_exe(const char *p, pid_t pid);   /* /proc/self/exe in any spelling, for this process */

/* ---------- loader (loader.c) ---------- */
__attribute__((noreturn)) void loader_run(const char *vpath, const char *real, long argc, char **argv, char **envp, unsigned long *auxv);
int elf_probe(const char *real, char *interp, int *is_launcher, void *buf);   /* 1 has interp, 0 none, <0 error; buf >= 7680 bytes; is_launcher: the note's page generation, 0 for no launcher */

/* ---------- filter (filter.c) ---------- */
int  filter_probe(void);      /* 0: no filter of ours inherited; otherwise the newest inherited filter's version (7.4.2) */
void filter_install(void);
extern const int path_syscalls[]; extern const int n_path_syscalls;

/* ---------- handler (handler.c) ---------- */
void handler_install(void);
void sig_restorer(void);

/* ---------- ISA (isa.c) ---------- */
int isa_supported(const char *isa, unsigned long *auxv);   /* 1 yes, 0 no, -1 unknown string; auxv for AT_HWCAP on aarch64 */
