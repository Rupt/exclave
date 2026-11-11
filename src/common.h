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
#define FILTER_VERSION 11
#endif
/* filters from this version answer a call from the syscall page's judge slot rather than allow it (7.4.2), so that a
 * program's own filter can be honoured: a launcher whose note names an older one is not exec'd while one exists */
#define FILTER_JUDGE_SINCE 10
/* an inherited filter older than this allows another page's syscalls and traps this launcher's */
#define FILTER_PAGE_SINCE 6
/* the word of the launcher's notes (launcher.c); 1 marks a launcher whose page is at 0x3f0000 */
#define PAGE_GENERATION 2
/* the EXCLAVE_LOG format's version, the number in every launcher line (6.2): one digit, as log_msg writes it */
#define LOG_VERSION "2"
#define PATH_MAX 4096
#define BINPRM_BUF_SIZE 256 /* the bytes of a file the kernel reads for its #! line (fs/binfmt_script.c) */
#define NAME_MAX 255
/* the launcher's tables (8.1.1): the manifest's records, the tree's top-level entries and the identity files (8.1.5);
 * exclave wrap refuses an exclave beyond them, with the same numbers */
#define MAX_OWN_RECORDS 256
#define MAX_HOST_RECORDS 32
#define MAX_DATA_RECORDS 32
#define MAX_TOP_LEVEL 256
/* the top-level directories of the tree whose reading waits for the first path that reaches one (8.1.1); a tree
 * with more has the rest read at startup */
#define MAX_UNREAD_TOP 32
#define N_IDENTITY 11
/* the identity directories (8.1.5, 8.4): the two trust directories and SSSD's state */
#define N_IDENTITY_DIRS 3
/* a manifest record's most fields, and the most bytes a field holds, a string's decoded (6.2) */
#define MANIFEST_FIELDS 8
#define MANIFEST_FIELD_MAX (PATH_MAX - 1)

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

/* ---------- the exclave's run-time state (7.2), filled at startup ---------- */
/* a host record or an identity file: virtual path -> host real path */
struct hostmap {
    const char *v;
    const char *r;
    int is_file;
    /* an identity directory (8.1.5, 8.4): the directories on the way to it are directories, as an identity file's are,
     * and the links at and below it are followed on the host */
    int is_identity_dir;
    /* an identity directory whose host name is a link, 1 + the index of the directory it resolves to, which is one
     * too at its own name; 0 otherwise */
    int is_link;
};

struct exclave {
    /* the paths are strings of the arena, each as long as it is, so that a start touches one page for them and not one
     * for each (16.4) */
    const char *dir; /* directory holding .exclave/ */
    const char *root; /* dir/tree */
    long rootlen;
    const char *launcher; /* dir/.exclave/launcher */
    unsigned long launcher_dev, launcher_ino;
    long launcher_size;
    const char *program; /* virtual path of the program this process runs */
    const char *exe; /* what /proc/self/exe answers: the program, or a wrapped script's interpreter */
    /* the path the program was exec'd by, as the kernel spells it: AT_EXECFN, a script's $0 (7.6); the program's to
     * write, as the kernel's is */
    char *execfn;
    /* the name the kernel would set as comm: the exec'd path's last component, or empty for the name of the file
     * finally run, after an exec through a bare descriptor (7.6) */
    char comm[NAME_MAX + 1];
    int loader_mode; /* 1: re-exec'd with EXCLAVE_EXEC; program is not a wrapper */
    /* loader mode for a descriptor with no path (13 item 25): the dup to close once the segments are mapped, else -1 */
    int descfd;
    /* exe holds the descriptor's link text, the kernel's identity for such a program; run() leaves it */
    int exe_fixed;
    int boundary; /* 1: no filter of ours inherited: this process is at the border (7.2) */
    /* a process newly traced whose launcher left the second exec to its next one, a debugger's shell (7.6): its pid */
    long traced_pid;
    /* the manifest (6.2) and what the tree says (8.1); the limits are stated in 8.1 and enforced by exclave wrap. The
     * counts of the tables, which come last */
    char cpu[32];
    int nown, nhost;
    int ndata; /* data directories: never executed, never a loader (6.2) */
    /* cwd rule (8.1.4) */
    const char *cwdclaim;
    long cwdclaim_len; /* subtree given to the host; 0 and no string if none */
    /* EXCLAVE_CWD with this exclave's mark and the run's working directory, as given to the host or none, for the
     * launchers this one execs (7.4.5, vis.c) */
    char *cwdvar;
    /* RLIMIT_NOFILE as the program had it, raised for the launcher's own opens (7.4.5) */
    unsigned long rlim[2];
    int borrowed;
    /* the kernel's argument strings, where the exec laid them: the first one's start and the environment's, each 0
     * where there is none (7.3) */
    unsigned long arg_start, arg_end;
    /* diagnostics */
    int logfd;
    unsigned long text_lo, text_hi; /* the launcher's own text range, for the nesting rule (7.5.3) */
    unsigned long root_dev, root_ino; /* the tree's root directory, so that any spelling of it is recognised */
    /* the kernel's page size, AT_PAGESZ: 4 KB, or 16 KB or 64 KB on some aarch64 kernels (7.3) */
    unsigned long pagesz;
    /* x86-64: PKRU's offset in a signal frame's XSAVE area, or 0 where the kernel gives no protection keys (7.5.6) */
    unsigned pkru_off;
    unsigned init_pkru; /* x86-64: the PKRU a process starts with */
    /* the size of a directory entry on the tree's filesystem, where a directory's size counts them, or 0 (8.3) */
    long dirent_size;
    int dirent_known;
    /* the tables last, each filled from its start: the fields above and the entries an exclave has then fit one page,
     * the one the state begins (log.c), and a start touches no other for them (16.4) */
    /* the manifest's host records (at most 32), then the identity files (8.4) and the identity directories, each with
     * the directory a host link at its name resolves to */
    struct hostmap host[MAX_HOST_RECORDS + N_IDENTITY + 2 * N_IDENTITY_DIRS];
    const char *data[MAX_DATA_RECORDS];
    /* the manifest's own records (at most 256), then the top-level entries of the tree the start found the exclave's
     * (at most 256): every one but a directory, and a directory it read (vis.c) */
    const char *own[MAX_OWN_RECORDS + MAX_TOP_LEVEL];
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
/* the paths of struct exclave: its directory, its tree, its launcher, the program as it arrived and as the entry
 * resolved it, the exe answer, the name it was exec'd by and the working directory given to the host, which has its
 * variable's name and the exclave's mark before it, the 64 bytes more */
#define EXCLAVE_PATHS 8
/* the arena's whole capacity, which str.c's comment counts */
#define ARENA_SIZE                                                                                                     \
    ((2 + MAX_OWN_RECORDS + MAX_HOST_RECORDS + MAX_DATA_RECORDS + MANIFEST_FIELDS) * (MANIFEST_FIELD_MAX + 17) +       \
     MAX_TOP_LEVEL * (NAME_MAX + 18) + MAX_UNREAD_TOP * (PATH_MAX + 16) +                                              \
     (N_IDENTITY_DIRS + N_IDENTITY + MAX_OWN_RECORDS) * (PATH_MAX + 16) + 4 * 64 + 3 * (PATH_MAX + 32) +               \
     6 * (BINPRM_BUF_SIZE + 17 + 2 * (PATH_MAX + 16)) + EXCLAVE_PATHS * (PATH_MAX + 16) + 64)
/* the reserve (str.c): the cache's strings, its full table of CACHE_SLOTS 16-byte slots, the arena's rest */
#define RESERVE_STEP 65536UL
#define CACHE_STRINGS (1024UL * 1024)
#define CACHE_SLOTS 16384
#define RESERVE_STRINGS_AT 0UL
#define RESERVE_TABLE_AT CACHE_STRINGS
#define RESERVE_ARENA_AT (RESERVE_TABLE_AT + CACHE_SLOTS * 16UL)
#define RESERVE_SIZE (RESERVE_ARENA_AT + ((ARENA_SIZE + RESERVE_STEP - 1) & ~(RESERVE_STEP - 1)))
char *reserve_base(long *err); /* the reserve, mapped without access at the first call; 0 and *err where not */
long reserve_open(char *at, size_t n); /* opened for reading and writing; 0, or the negative errno */
char *start_map(size_t chunk); /* the lock page, the first chunk and the reserve as one mapping; the lock page, or 0 */
_Static_assert(CACHE_STRINGS % RESERVE_STEP == 0, "the strings' size a multiple of the step");
_Static_assert(RESERVE_TABLE_AT % RESERVE_STEP == 0 && RESERVE_TABLE_AT >= RESERVE_STRINGS_AT + CACHE_STRINGS,
               "the table's part after the strings', at a step");
_Static_assert(RESERVE_ARENA_AT % RESERVE_STEP == 0 && RESERVE_ARENA_AT >= RESERVE_TABLE_AT + CACHE_SLOTS * 16UL,
               "the arena's part after the table's, at a step");
_Static_assert(RESERVE_SIZE >= RESERVE_ARENA_AT + ARENA_SIZE, "the arena's part holds the whole arena");
long shebang_argv(char *line, long n, char *script, char **argv, long argc, char **nargv, long cap);

/* ---------- logging (log.c) ---------- */
void log_open(char **envp);
void log_line(const char *what, long result, const char *path);
void log_msg(const char *a, const char *b);
__attribute__((noreturn)) void die(const char *what, const char *detail, long err);
/* the message, then death by sig with its default disposition: what the kernel does to an image it cannot load once
 * past its point of no return (SIGSEGV from bprm_execve, fs/exec.c) */
__attribute__((noreturn)) void die_signal(int sig, const char *what, const char *detail, long err);
/* 126 where a shell says so: found but not executable */
__attribute__((noreturn)) void die_status(int status, const char *what, const char *detail, long err);

/* ---------- manifest (manifest.c) ---------- */
int manifest_parse(const char *buf, size_t len, struct exclave *c, char *err, size_t errn);

/* ---------- scratch (scratch.c) ---------- */
/* Each buffer has one role, named here, so that no site reads a buffer another has reused (7.5.4).
 *
 * The start holds one chunk from its first path to the jump (launcher.c) and keeps every buffer of its own there, so
 * that the pages it touches are the ones the program's first trapped call would, and the image carries none (16.4).
 * Between its walks, which have the buffers in the roles below, it uses them one step at a time: v is the launcher's
 * own path until the program is named, then the directories the rule's resolution has found (tree_real_of); cur and
 * tmp are the search for the exclave and then the name a message needs, a link's text or a wrapper's original; rest
 * is the manifest, then the listing of the tree's top level, then the head of each file loaded; comp is a file's
 * notes; real is the working directory; given is the loader's name as the program spells it, across the walk that
 * resolves it; extra is the program headers. */
struct scratch {
    /* canon's working buffers: the walk's remaining path (a directory and a relative path, or a link's text and the
     * rest, each under PATH_MAX), the directory so far, its real path and a link's text; real and v are what canon
     * leaves for the re-issue. rest, cur and tmp are dead once canon returns, so a caller may use them until it calls
     * canon again (exec_env builds its variables there) */
    char rest[2 * PATH_MAX];
    char cur[PATH_MAX], real[PATH_MAX], tmp[PATH_MAX], v[PATH_MAX];
    char comp[PATH_MAX]; /* canon's own: the component in hand, or a descriptor's number for a magic link */
    char given[PATH_MAX]; /* the path as the program gave it (resolve), read by the checks the kernel makes on it */
    char given2[PATH_MAX]; /* the first path of a two-path syscall as given, for its re-issue as given */
    int dfd; /* the descriptor the path was given relative to, AT_FDCWD for the working directory (resolve) */
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
    char extra[8192]; /* argv and envp vectors, ELF headers, a #! line, an extended open_how, a sockaddr, a listing */
    pid_t pid, tid; /* the owner, looked up once per trap */
    unsigned resolve; /* openat2's resolve flags for the walk (7.4.3); 0 for every other syscall */
    /* set by canon: the walk started at, passed through or ended in the exclave's domain, or rewrote a magic link */
    int touched_exclave;
    /* the walk ended on a link the re-issue must follow: 1 for a magic link to an object with no path, 2 for an
     * identity file's host link or a link at or below an identity directory, followed on the host (8.4) */
    int follow_end;
    /* openat2's struct open_how as given, for a walk that never touched the exclave (7.4.3) */
    unsigned long how0[3];
};
struct scratch *scratch_get(pid_t pid, pid_t tid, unsigned long frame);
size_t scratch_chunk_bytes(void); /* the size of a chunk's mapping, before its rounding to pages */
void scratch_spare(void *mem); /* memory the start mapped for the first chunk (start_map) */
void scratch_put(struct scratch *s);
/* returns depth, 1 for outermost; releases frames left by longjmp */
int nest_enter(pid_t pid, pid_t tid, unsigned long frame);
/* a vfork child's PTRACE_TRACEME, deferred to its exec (7.4.5): kept marks s as holding it, past the handler's return;
 * deferred answers the tracer the caller's names, 0 for none, and with take releases it */
void scratch_keep(struct scratch *s, pid_t tracer);
pid_t scratch_deferred(pid_t pid, pid_t tid, int take);

/* ---------- visibility (vis.c) ---------- */
/* S: the start's chunk, whose buffers the tables are built in (launcher.c) */
void vis_init(struct scratch *S, const char *cwd);
void cache_init(pid_t pid, void *page); /* pid: the process's own; page: the lock's, mapped already, or 0 */
/* 1 when the caller, pid, shares the memory of its parent, ppid: a vfork child (7.5.4) */
int vfork_child(pid_t pid, pid_t ppid);
int vis_is_host(const char *v, const char **real); /* 1 if host-owned; *real = host path */
char *to_real(const char *v, char *out, char *tmp); /* v -> real, with wrapper redirect; tmp PATH_MAX */
char *to_real_exec(const char *v, char *out); /* v -> real, no wrapper redirect */
char *vis_exclave_real(const char *v, char *out); /* an exclave path v -> its real path in the tree */
int from_real(char *r); /* in place, no buffer; -ENAMETOOLONG where the virtual name would not fit */
/* the directory the kernel named at startup for an identity directory whose host name is a link, or 0 */
const char *vis_identity_link_reached(const char *v);
int is_exclave_path(const char *v);
/* the same for a walk, which can fail: 1 the exclave's, 0 the host's, or the negative errno of the read of a top-level
 * directory of the tree that v reaches first (8.1.1) */
int vis_owned(const char *v);
/* the walk's questions in one pass: 1 if the host's, or the negative errno vis_owned answers; *idd as vis.c says */
int vis_walk_facts(const char *v, int *identity, int *leads, int *idd, const char **real);
/* every prefix from that long the host's plainly: the one-step check may stand in */
int vis_plain_host_chain(const char *p, unsigned from);
int is_wrapper_real(const char *real, char *tmp); /* tmp PATH_MAX */
/* the same for a file real whose lstat is st */
int is_wrapper_st(const char *real, const struct kstat *st, char *tmp);
/* payload = the wrapper's original's path, dir/.real/base; 1 if it fits; no wrapper check */
int payload_of(const char *wrapper, char *payload);
/* 1 if v is an identity file that is a host symlink, out = its text; -EINVAL if not a symlink; 0 otherwise */
int vis_readlink_identity(const char *v, char *out);
int vis_is_identity_file(const char *v); /* 1 if v is exactly a host identity file */
/* 1 if v is exactly an identity directory the host has as a directory, 2 if its host name is a link, else 0 */
int vis_identity_dir_kind(const char *v);
int vis_in_data(const char *v); /* 1 if v lies under a data directory (6.2) */

/* ---------- the canonicalisation cache (cache.c, 7.4.4) ---------- */
enum { CK_NONE = 1, CK_DIR, CK_LINK, CK_FILE, CK_WRAPPER };
int cache_get(const char *v, char *link_out); /* 0 on a miss; link_out PATH_MAX gets a symlink's text */
void cache_put(const char *v, int kind, const char *link);
/* one lstat on a miss, two more for a regular file's wrapper check; 0 only if a readlink raced */
int cache_classify(const char *v, const char *real, char *tmp);

/* ---------- canonicalisation (canon.c) ---------- */
/* canon's rule for the last component, after the kernel's lookup flags (fs/namei.c). WALK_FOLLOW follows a final
 * symlink (LOOKUP_FOLLOW); without it the walk stops at the link itself, unless a trailing slash asks for a directory,
 * which the kernel follows (lookup_last). WALK_PARENT is a call that looks the last name up in its parent
 * (filename_parentat: a create, a delete, a rename, link's new name, open with O_CREAT): the walk stops before the
 * last component when a trailing slash ends it, whatever it is, and the caller judges the slash, as the kernel does
 * after the parent's walk (EISDIR for O_CREAT before any lookup, EEXIST or ENOENT for a create, ENOTDIR for a delete);
 * without a trailing slash WALK_FOLLOW decides, since O_CREAT follows what the lookup found (open_last_lookups) */
#define WALK_FOLLOW 1
#define WALK_PARENT 2
int canon(struct scratch *S, const char *path, int dfd, int follow_last, char *out); /* 0 or -errno */
int through_magic(struct scratch *S, const char *path, int dfd, char *out);
int fd_virtual(int fd, char *out);
int cwd_virtual(char *out);
int is_self_exe(const char *p, pid_t pid); /* /proc/self/exe in any spelling, for this process */
/* another process's exe link v whose text is the launcher: text becomes the program it runs (PATH_MAX); 1 if so */
int other_exe(const struct scratch *S, const char *v, char *text);
/* the TracerPid field of a /proc/<pid>/status head of n bytes, 0 for none (7.6) */
long status_tracer(const char *buf, long n);
/* the TracerPid of the status file at path, 0 for none or one unreadable (7.6) */
long tracer_of(const char *path);

/* ---------- loader (loader.c) ---------- */
/* the buffer the program's real path is resolved into, PATH_MAX, which loader_run loads and gdb's script reads (7.6) */
char *loader_real(void);
/* reads the first bytes of fd, the file the startup loads, for loader_run, into S->rest: returns their count, *bytes
 * the bytes, which last until the next walk */
long loader_head(struct scratch *S, int fd, const char **bytes);
/* fd: the file at loader_real(), open, its head read by loader_head; S: the start's chunk, released before the jump */
__attribute__((noreturn)) void loader_run(struct scratch *S, const char *vpath, int fd, long argc, char **argv,
                                          char **envp, const unsigned long *auxv);
/* path, relative to dfd, opened with flags and O_CLOEXEC, the soft descriptor limit raised to the hard one for the open
 * when the program is at it (7.4.5): the descriptor or -errno */
long open_borrowed(int dfd, const char *path, int flags);
/* 1 has interp, 0 none, <0 -errno as load_elf_binary answers before its point of no return; buf >= 7680 bytes;
 * is_launcher: the note's page generation, 0 for no launcher, filter_version its filter version, 0 for none */
int elf_probe(const char *real, char *interp, int *is_launcher, int *filter_version, void *buf);
/* the kernel's checks of a program's interpreter once opened (load_elf_binary, before begin_new_exec): 0 or -errno,
 * EIO for a header the file does not hold whole, ELIBBAD for one that is not this machine's ELF; buf >= 208 bytes */
int elf_interp_probe(const char *real, void *buf);

/* ---------- filter (filter.c) ---------- */
struct sock_filter {
    uint16_t code;
    uint8_t jt, jf;
    uint32_t k;
};
/* 0: no filter of ours inherited; otherwise the newest inherited filter's version (7.4.2) */
int filter_probe(void);
void filter_install(void);
/* a program's own filter, body of n instructions, made into the one the handler installs for it (7.4.2): the
 * prologue, the body with each return of an action other than ALLOW sent through the page's exemption, and the
 * epilogue, in out, which holds BPF_MAXINSNS; returns its length, or -EINVAL where the kernel refuses the body,
 * -ENOSYS where the launcher does */
long filter_wrap(const struct sock_filter *body, long n, struct sock_filter *out);
/* 1 once a program's filter may exist in this process: set before an install, and by the start under one (7.4.2) */
extern volatile int program_filters;
extern const int path_syscalls[];
extern const int n_path_syscalls;

/* ---------- handler (handler.c) ---------- */
void handler_install(void);
/* The trap's record (7.5.7), made by the handler's entry stub on its stack before anything else, its address in a
 * register reserved for it throughout the launcher's code (r15, x27): what a trampoline reads of a trap it
 * interrupts. The offsets are the re-issue slot's and the entry stub's (launcher.c, handler.c). */
struct trap {
    unsigned long magic; /* TRAP_MAGIC */
    void *uc; /* the trap's frame */
    long answer; /* the call's answer, ANSWER_NONE until there is one */
    long redirected; /* a program's handler redirected the program */
};
/* spelt once and without a suffix: the entry stub's assembly takes the same token through ASM_STR (handler.c) */
#define TRAP_MAGIC 0x7472617065786331
#define ASM_STR_(x) #x
#define ASM_STR(x) ASM_STR_(x)
#define ANSWER_NONE (-0x7fffffffffffffffL - 1)
void exclave_on_sigsys(int sig, void *info, void *uc, struct trap *rec);
/* the entry stub and its labels (handler.c): before the record exists, its tail's test and write, its last return */
extern char exclave_sigsys_entry[], exclave_sigsys_set[], exclave_sigsys_tail[], exclave_sigsys_done[],
    exclave_sigsys_ret[];

/* ---------- trampolines (tramp.c, 7.5.7) ---------- */
#define TRAMP_SLOTS 256UL
#if defined(__x86_64__)
#define TRAMP_STUB 16UL /* a stub's bytes */
#define TRAMP_PRESENTED 1040 /* the presented frame: the pretcode slot, then room for glibc's ucontext_t whole */
#else
#define TRAMP_STUB 8UL
#define TRAMP_PRESENTED 4688 /* the kernel's rt_sigframe: siginfo, then the ucontext with 4096 bytes of records */
#endif
#define TRAMP_BLOCK 112 /* the trampoline's own block above the presented frame */
struct tramp_slot {
    void *h; /* the program's handler; 0 until published */
    unsigned long mask; /* its sa_mask as the kernel stores it, without SIGKILL and SIGSTOP */
    unsigned long restorer; /* the restorer installed with the stub, by which a delivery is told from a call */
    unsigned long forced; /* the launcher set SA_RESTORER and the restorer, the program having given none */
};
extern struct tramp_slot exclave_slots[TRAMP_SLOTS];
extern char exclave_stubs[];
/* the stub for the program's handler h, its mask and the restorer installed with it: an address to install, or h itself
 * when no slot is left */
unsigned long tramp_stub_for(unsigned long h, unsigned long mask, unsigned long restorer, unsigned long forced);
/* the slot a handler address names, or -1 when it is no stub's */
long tramp_slot_of(unsigned long h);

/* ---------- CPU level (isa.c) ---------- */
/* 1 yes, 0 no, -1 unknown string; auxv for AT_HWCAP on aarch64 */
int isa_supported(const char *isa, const unsigned long *auxv);
#if !defined(__aarch64__)
/* the x86-64 decision, testable on the host */
int isa_x86_level_ok(int level, unsigned c1, unsigned b7, unsigned cx, unsigned long xcr0);
#endif
