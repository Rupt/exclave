/* common.h — shared definitions for the opener.
 *
 * The opener is freestanding: no libc, raw syscalls only (sys.h). Every
 * module includes this header. Section numbers in comments refer to
 * docs/PROPOSAL.md.
 */
#pragma once
#include "sys.h"

#define OPENER_VERSION "0.1"
#define FILTER_VERSION 1                 /* 7.4.2: versioned reuse */
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
#define O_TMPFILE  020200000
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
#define PR_SET_NAME 15
#define SECCOMP_MODE_FILTER 2
#define SECCOMP_SET_MODE_FILTER 1
#define SECCOMP_GET_ACTION_AVAIL 2
#define SECCOMP_RET_KILL_PROCESS 0x80000000u
#define SECCOMP_RET_KILL_THREAD  0x00000000u
#define SECCOMP_RET_TRAP  0x00030000u
#define SECCOMP_RET_ERRNO 0x00050000u
#define SECCOMP_RET_ALLOW 0x7fff0000u
#define AUDIT_ARCH_X86_64 0xC000003Eu
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
#define FS_IOC_FSSETXATTR 0x401c581cUL

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
#define AT_HWCAP2 26
#define AT_MINSIGSTKSZ 51

/* ---------- x86-64 signal frame (rt_sigframe) ----------
 * uc_mcontext.gregs at +40 from the ucontext, uc_sigmask at +296; verified
 * against a real frame by both first-round reviews. */
#define UC_GREGS_OFF 40
#define UC_SIGMASK_OFF 296
enum { REG_R8 = 0, REG_R9, REG_R10, REG_R11, REG_R12, REG_R13, REG_R14, REG_R15, REG_RDI, REG_RSI,
       REG_RBP, REG_RBX, REG_RDX, REG_RAX, REG_RCX, REG_RSP, REG_RIP };
/* siginfo: si_signo@0 si_errno@4 si_code@8; SIGSYS: _call_addr@16 _syscall@24 _arch@28 */
#define SI_CODE_OFF 8
#define SI_CALL_ADDR_OFF 16
#define SI_SYSCALL_OFF 24
#define SI_ARCH_OFF 28

/* ---------- the can's run-time state (7.2), filled at startup ---------- */
struct hostmap { const char *v; const char *r; int is_file; };   /* virtual path -> host real path */

struct can {
    char dir[PATH_MAX];            /* directory holding .can/ */
    char root[PATH_MAX];           /* dir/root */
    long rootlen;
    char opener[PATH_MAX];         /* dir/.can/opener */
    unsigned long opener_dev, opener_ino; long opener_size;
    char program[PATH_MAX];        /* virtual path of the program this process runs */
    char exe[PATH_MAX];            /* what /proc/self/exe answers: the program, or a wrapped script's interpreter (F3-22) */
    int loader_mode;               /* 1: re-exec'd with CAN_EXEC; program is not a wrapper */
    int boundary;                  /* 1: this process installed the filter (can boundary) */
    /* index (6.3) */
    char arch[32], isa[32], libc_name[32], libc_ver[32];
    char interp[PATH_MAX];         /* virtual path of the one loader */
    const char *own[128]; int nown;
    struct hostmap host[64]; int nhost;
    const char *data[32]; int ndata;
    const char *envset[64]; int nenv;   /* "NAME=value" */
    /* cwd rule (8.1.4) */
    char cwdclaim[PATH_MAX]; long cwdclaim_len;   /* subtree claimed for the host; empty if none */
    /* diagnostics */
    int logfd;
    unsigned long text_lo, text_hi;   /* the opener's own text range, for the nesting rule (7.5.3) */
    unsigned long root_dev, root_ino; /* the tree's root directory, so that any spelling of it is recognised (F3-13) */
};
extern struct can C;

/* ---------- string helpers (str.c) ---------- */
char *scpy(char *d, const char *s, size_t n);
char *scat(char *d, const char *s, size_t n);
const char *base_name(const char *p);
void ltoa_(long v, char *b);            /* decimal, buffer >= 24 */
void xtoa_(unsigned long v, char *b);   /* lowercase hex, buffer >= 20 */
int starts_dir(const char *s, const char *pfx);  /* s == pfx or s starts with pfx + "/" ; "/" matches all */
void *arena_alloc(size_t n);            /* bump allocator for index strings; never freed */
const char *arena_str(const char *s, size_t n);
long shebang_argv(char *line, const char *script, char **argv, long argc, char **nargv, long cap);

/* ---------- logging (log.c) ---------- */
void log_open(char **envp);
void log_line(const char *what, long result, const char *path);
void log_msg(const char *a, const char *b);
__attribute__((noreturn)) void die(const char *what, const char *detail, long err);

/* ---------- index (index.c) ---------- */
int index_parse(const char *buf, size_t len, struct can *c, char *err, size_t errn);

/* ---------- scratch (scratch.c) ---------- */
struct scratch {
    char b1[PATH_MAX], b2[PATH_MAX], rest[PATH_MAX], cur[PATH_MAX], real[PATH_MAX], tmp[PATH_MAX], v[PATH_MAX];
    char v2[PATH_MAX];             /* the first path of a two-path syscall; canon never touches it */
    char extra[8192];              /* argv vectors, masks, headers */
    pid_t pid, tid;                /* the owner, looked up once per trap */
};
struct scratch *scratch_get(pid_t pid, pid_t tid, unsigned long frame);
void scratch_put(struct scratch *s);
void scratch_release_all_mine(void);   /* before execve */
int  nest_enter(pid_t pid, pid_t tid, unsigned long frame); /* returns depth, 1 for outermost; releases frames left by longjmp */
void nest_leave(void);

/* ---------- visibility (vis.c) ---------- */
void vis_init(char **envp);
int  vis_is_host(const char *v, const char **real);   /* 1 if host-owned; *real = host path */
char *to_real(const char *v, char *out, char *tmp);   /* v -> real, with wrapper redirect; tmp PATH_MAX */
char *to_real_exec(const char *v, char *out);         /* v -> real, no wrapper redirect */
void from_real(char *r);                              /* in place, no buffer */
int  is_can_owned(const char *v);
int  vis_leads_to_host_file(const char *v);   /* v is a proper ancestor of a host-resolved file */
int  is_wrapper_real(const char *real, char *tmp);   /* tmp PATH_MAX */
int  payload_of(const char *real, char *out);         /* 1 if real is a wrapper; out = payload */
int  vis_readlink_identity(const char *v, char *out); /* 1 if v is an identity file; out = host link text */
int  vis_is_identity_file(const char *v);              /* 1 if v is exactly a host identity file */

/* ---------- the canonicalisation cache (cache.c, 7.4.4) ---------- */
enum { CK_NONE = 1, CK_DIR, CK_LINK, CK_FILE, CK_WRAPPER };
int  cache_get(const char *v, char *link_out);        /* 0 on a miss; link_out PATH_MAX gets a symlink's text */
void cache_put(const char *v, int kind, const char *link);
int  cache_classify(const char *v, const char *real, char *tmp);   /* one lstat on a miss; 0 only if the lstat raced */

/* ---------- canonicalisation (canon.c) ---------- */
int canon(struct scratch *S, const char *path, int dfd, int follow_last, char *out);  /* 0 or -errno */
int fd_virtual(int fd, char *out);
int cwd_virtual(char *out);
int is_self_exe(const char *p, pid_t pid);   /* /proc/self/exe in any spelling, for this process */

/* ---------- loader (loader.c) ---------- */
__attribute__((noreturn)) void loader_run(const char *vpath, const char *real, long argc, char **argv, char **envp, unsigned long *auxv);
int elf_probe(const char *real, char *interp, int *is_opener, void *buf);   /* 1 has interp, 0 none, <0 error; buf >= 4096 bytes */

/* ---------- filter (filter.c) ---------- */
int  filter_probe(void);      /* 1 if an equal-or-newer filter is inherited */
void filter_install(void);
extern const int path_syscalls[]; extern const int n_path_syscalls;

/* ---------- handler (handler.c) ---------- */
void handler_install(void);
void sig_restorer(void);

/* ---------- ISA (isa.c) ---------- */
int isa_supported(const char *isa);   /* 1 yes, 0 no, -1 unknown string */
