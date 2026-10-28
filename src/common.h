/* common.h — shared definitions for the launcher.
 *
 * The launcher is freestanding: no libc, raw syscalls only (sys.h). Every
 * module includes this header. Section numbers in comments refer to
 * docs/DESIGN.md.
 */
#pragma once
#include "sys.h"

#ifndef FILTER_VERSION
/* 7.4.2: versioned reuse; the version moves whenever the trap set grows or the syscall page moves. build/launcher-old
 * is these sources at version 3, without bind and connect, which version 4 added (EXCLAVE_TEST_OLD). */
#define FILTER_VERSION 6
#endif
/* an inherited filter older than this allows another page's syscalls and traps this launcher's */
#define FILTER_PAGE_SINCE 6
/* the word of the launcher's notes (launcher.c); 1 marks a launcher whose page is at 0x3f0000 */
#define PAGE_GENERATION 2
#define PATH_MAX 4096
#define BINPRM_BUF_SIZE 256 /* the bytes of a file the kernel reads for its #! line (fs/binfmt_script.c) */
#define NAME_MAX 255
/* the launcher's tables (8.1.1): the manifest's records, the tree's top-level entries and the identity files (8.1.5);
 * exclave wrap refuses an exclave beyond them, with the same numbers */
#define MAX_OWN_RECORDS 256
#define MAX_HOST_RECORDS 32
#define MAX_DATA_RECORDS 32
#define MAX_TOP_LEVEL 256
#define N_IDENTITY 8

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
#define RLIMIT_NOFILE 7
#define PR_SET_NAME 15
#define SECCOMP_MODE_FILTER 2
#define SECCOMP_SET_MODE_FILTER 1
#define SECCOMP_GET_ACTION_AVAIL 2
#define SECCOMP_FILTER_FLAG_SPEC_ALLOW 4    /* 4.17 */
#define SECCOMP_RET_KILL_PROCESS 0x80000000U
#define SECCOMP_RET_TRAP 0x00030000U
#define SECCOMP_RET_ERRNO 0x00050000U
#define SECCOMP_RET_ALLOW 0x7fff0000U
#define X32_SYSCALL_BIT 0x40000000U

/* ---------- mmap ---------- */
#define PROT_READ 1
#define PROT_WRITE 2
#define PROT_EXEC 4
#define MAP_PRIVATE 2
#define MAP_FIXED 0x10
#define MAP_ANONYMOUS 0x20
#define MAP_FIXED_NOREPLACE 0x100000

/* ---------- ioctl requests the filter traps (chattr) ---------- */
#define FS_IOC_SETFLAGS 0x40086602UL
#define FS_IOC_FSSETXATTR 0x401c5820UL /* _IOW('X', 32, struct fsxattr) */

/* ---------- statfs flag ---------- */

/* ---------- auxv ---------- */
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

/* ---------- the exclave's run-time state (7.2), filled at startup ---------- */
/* a host record or an identity file: virtual path -> host real path */
struct hostmap {
    const char *v;
    const char *r;
    int is_file;
};

struct exclave {
    char dir[PATH_MAX]; /* directory holding .exclave/ */
    char root[PATH_MAX]; /* dir/tree */
    long rootlen;
    char launcher[PATH_MAX]; /* dir/.exclave/launcher */
    unsigned long launcher_dev, launcher_ino;
    long launcher_size;
    char program[PATH_MAX]; /* virtual path of the program this process runs */
    char exe[PATH_MAX]; /* what /proc/self/exe answers: the program, or a wrapped script's interpreter */
    /* the path the program was exec'd by, as the kernel spells it: AT_EXECFN, a script's $0 (7.6) */
    char execfn[PATH_MAX];
    /* the name the kernel would set as comm: the exec'd path's last component, a descriptor's file (7.6) */
    char comm[NAME_MAX + 1];
    int loader_mode; /* 1: re-exec'd with EXCLAVE_EXEC; program is not a wrapper */
    /* loader mode for a descriptor with no path (13 item 25): the dup to close once the segments are mapped, else -1 */
    int descfd;
    /* exe holds the descriptor's link text, the kernel's identity for such a program; run() leaves it */
    int exe_fixed;
    int boundary; /* 1: no filter of ours inherited: this process is at the border (7.2) */
    /* the manifest (6.2) and what the tree says (8.1); the limits are stated in 8.1 and enforced by exclave wrap */
    char cpu[32];
    /* the manifest's own records (at most 256), then every non-empty top-level entry of the tree (at most 256) */
    const char *own[MAX_OWN_RECORDS + MAX_TOP_LEVEL];
    int nown;
    struct hostmap host[MAX_HOST_RECORDS + N_IDENTITY];
    int nhost; /* the manifest's host records (at most 32), then the identity files (8.4) */
    const char *data[MAX_DATA_RECORDS];
    int ndata; /* data directories: never executed, never a loader (6.2) */
    /* cwd rule (8.1.4) */
    char cwdclaim[PATH_MAX];
    long cwdclaim_len; /* subtree given to the host; empty if none */
    /* RLIMIT_NOFILE as the program had it, raised for the launcher's own opens (7.4.5) */
    unsigned long rlim[2];
    int borrowed;
    /* diagnostics */
    int logfd;
    unsigned long text_lo, text_hi; /* the launcher's own text range, for the nesting rule (7.5.3) */
    unsigned long root_dev, root_ino; /* the tree's root directory, so that any spelling of it is recognised */
    /* the kernel's page size, AT_PAGESZ: 4 KB, or 16 KB or 64 KB on some aarch64 kernels (7.3) */
    unsigned long pagesz;
};
extern struct exclave C;

/* ---------- string helpers (str.c) ---------- */
char *scpy(char *d, const char *s, size_t n);
char *scat(char *d, const char *s, size_t n);
const char *base_name(const char *p);
void ltoa_(long v, char *b); /* decimal, buffer >= 24 */
long fd_real_path(int fd, char *out);
int starts_dir(const char *s, const char *pfx); /* s == pfx or s starts with pfx + "/" ; "/" matches all */
/* bump allocator for the manifest's strings, the tables, the environment; never freed */
void *arena_alloc(size_t n);
char *arena_str(const char *s, size_t n);
long shebang_argv(char *line, long n, char *script, char **argv, long argc, char **nargv, long cap);

/* ---------- logging (log.c) ---------- */
void log_open(char **envp);
void log_line(const char *what, long result, const char *path);
void log_msg(const char *a, const char *b);
__attribute__((noreturn)) void die(const char *what, const char *detail, long err);
/* 126 where a shell says so: found but not executable */
__attribute__((noreturn)) void die_status(int status, const char *what, const char *detail, long err);

/* ---------- manifest (manifest.c) ---------- */
int manifest_parse(const char *buf, size_t len, struct exclave *c, char *err, size_t errn);

/* ---------- scratch (scratch.c) ---------- */
/* Each buffer has one role, named here, so that no site reads a buffer another has reused (7.5.4). */
struct scratch {
    /* canon's working buffers: the walk's remaining path (a directory and a relative path, or a link's text and the
     * rest, each under PATH_MAX), the directory so far, its real path and a link's text; real and v are what canon
     * leaves for the re-issue. rest, cur and tmp are dead once canon returns, so a caller may use them until it calls
     * canon again (exec_env builds its variables there) */
    char rest[2 * PATH_MAX];
    char cur[PATH_MAX], real[PATH_MAX], tmp[PATH_MAX], v[PATH_MAX];
    char comp[PATH_MAX]; /* canon's own: the component in hand, or a descriptor's number for a magic link */
    char given[PATH_MAX]; /* the path as the program gave it (resolve), read by the checks the kernel makes on it */
    /* the first path of a two-path syscall, the directory a scoped openat2 walk may not leave, or the
     * name an exec'd program is exec'd by as the kernel spells it (7.4.5); canon never writes it */
    char v2[PATH_MAX];
    char real2[PATH_MAX]; /* a second real path: of v2 for the re-issue, of a wrapper's payload, of a descriptor */
    /* a path copied out of canon's output buffer to be canon's next input: a loader's or an interpreter's name, the
     * entry's target */
    char arg[PATH_MAX];
    struct kstat st; /* the stat the kernel's order asks for, in the scratch rather than the frame (7.5.4) */
    unsigned long how[3]; /* the open_how an openat2 is re-issued with */
    char comm[NAME_MAX + 1]; /* the comm the kernel would set for an exec'd program (7.6) */
    char extra[8192]; /* argv and envp vectors, ELF headers, a #! line, an extended open_how, a sockaddr */
    pid_t pid, tid; /* the owner, looked up once per trap */
    unsigned resolve; /* openat2's resolve flags for the walk (7.4.3); 0 for every other syscall */
    /* set by canon: the walk started at, passed through or ended in the exclave's domain, or rewrote a magic link */
    int touched_exclave;
    int magic_end; /* the walk ended on a magic link to an object with no path, which a re-issue must follow */
    /* openat2's struct open_how as given, for a walk that never touched the exclave (7.4.3) */
    unsigned long how0[3];
};
struct scratch *scratch_get(pid_t pid, pid_t tid, unsigned long frame);
void scratch_put(struct scratch *s);
/* returns depth, 1 for outermost; releases frames left by longjmp */
int nest_enter(pid_t pid, pid_t tid, unsigned long frame);

/* ---------- visibility (vis.c) ---------- */
void vis_init(void);
int vis_is_host(const char *v, const char **real); /* 1 if host-owned; *real = host path */
char *to_real(const char *v, char *out, char *tmp); /* v -> real, with wrapper redirect; tmp PATH_MAX */
char *to_real_exec(const char *v, char *out); /* v -> real, no wrapper redirect */
void from_real(char *r); /* in place, no buffer */
int is_exclave_path(const char *v);
/* the three in one pass: 1 if the host's */
int vis_walk_facts(const char *v, int *identity, int *leads, const char **real);
/* every prefix from that long the host's plainly: the one-step check may stand in */
int vis_plain_host_chain(const char *p, unsigned from);
int is_wrapper_real(const char *real, char *tmp); /* tmp PATH_MAX */
/* payload = the wrapper's original's path, dir/.real/base; 1 if it fits; no wrapper check */
int payload_of(const char *wrapper, char *payload);
/* 1 if v is an identity file that is a host symlink, out = its text; -EINVAL if not a symlink; 0 otherwise */
int vis_readlink_identity(const char *v, char *out);
int vis_is_identity_file(const char *v); /* 1 if v is exactly a host identity file */
int vis_in_data(const char *v); /* 1 if v lies under a data directory (6.2) */

/* ---------- the canonicalisation cache (cache.c, 7.4.4) ---------- */
enum { CK_NONE = 1, CK_DIR, CK_LINK, CK_FILE, CK_WRAPPER };
int cache_get(const char *v, char *link_out); /* 0 on a miss; link_out PATH_MAX gets a symlink's text */
void cache_put(const char *v, int kind, const char *link);
/* one lstat on a miss, two more for a regular file's wrapper check; 0 only if a readlink raced */
int cache_classify(const char *v, const char *real, char *tmp);

/* ---------- canonicalisation (canon.c) ---------- */
int canon(struct scratch *S, const char *path, int dfd, int follow_last, char *out); /* 0 or -errno */
int fd_virtual(int fd, char *out);
int cwd_virtual(char *out);
int is_self_exe(const char *p, pid_t pid); /* /proc/self/exe in any spelling, for this process */

/* ---------- loader (loader.c) ---------- */
__attribute__((noreturn)) void loader_run(const char *vpath, const char *real, long argc, char **argv, char **envp,
                                          const unsigned long *auxv);
/* 1 has interp, 0 none, <0 error; buf >= 7680 bytes; is_launcher: the note's page generation, 0 for no launcher */
int elf_probe(const char *real, char *interp, int *is_launcher, void *buf);

/* ---------- filter (filter.c) ---------- */
/* 0: no filter of ours inherited; otherwise the newest inherited filter's version (7.4.2) */
int filter_probe(void);
void filter_install(void);
extern const int path_syscalls[];
extern const int n_path_syscalls;

/* ---------- handler (handler.c) ---------- */
void handler_install(void);
void sig_restorer(void);

/* ---------- CPU level (isa.c) ---------- */
/* 1 yes, 0 no, -1 unknown string; auxv for AT_HWCAP on aarch64 */
int isa_supported(const char *isa, const unsigned long *auxv);
#if !defined(__aarch64__)
/* the x86-64 decision, testable on the host */
int isa_x86_level_ok(int level, unsigned c1, unsigned b7, unsigned cx, unsigned long xcr0);
#endif
