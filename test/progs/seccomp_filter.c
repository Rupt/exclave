/* seccomp_filter.c — a program's own seccomp filter, as the kernel applies it (DESIGN.md 7.4.2, 13 item 5): ERRNO
 * filters on path calls the launcher translates, at exclave and host paths; two filters, where among ERRNO answers the
 * newer one's wins and any ERRNO outranks an ALLOW whatever the filters' order; a LOG filter; an sshd-shaped allow-list
 * whose default kills, with the launcher's own calls, its restorer included, absent from the list; TSYNC and a thread
 * without it; fork; an exec, whose new image is judged by the inherited filter; a vfork child's filter; PR_GET_SECCOMP;
 * and the installs the kernel refuses or the launcher refuses visibly. Every case that installs a filter runs in a
 * child of its own. usage: seccomp_filter HOSTDIR. Prints one line per case, "<case>: <answer>", an answer "ok" or an
 * errno's name, and a child's end as its wait status. Exit 0 always. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <pthread.h>
#include <signal.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef SECCOMP_GET_NOTIF_SIZES
#define SECCOMP_GET_NOTIF_SIZES 3
#endif
#ifndef SECCOMP_FILTER_FLAG_NEW_LISTENER
#define SECCOMP_FILTER_FLAG_NEW_LISTENER (1UL << 3)
#endif
#ifndef SECCOMP_RET_KILL_PROCESS
#define SECCOMP_RET_KILL_PROCESS 0x80000000U
#endif
#ifndef SECCOMP_RET_LOG
#define SECCOMP_RET_LOG 0x7ffc0000U
#endif

static const char *hostdir;
static const char exfile[] = "/usr/share/exclave-test-marker";
static char hostfile[4096], hostsub[4096], hostzero[4096];

/* errno's name, spelt as glibc's strerrorname_np spells it, which musl lacks */
static const char *ename(int e)
{
    static char num[24];
    static const struct {
        int e;
        const char *n;
    } t[] = {{EPERM, "EPERM"},   {ENOENT, "ENOENT"}, {ESRCH, "ESRCH"},   {EIO, "EIO"},       {ENOMEM, "ENOMEM"},
             {EACCES, "EACCES"}, {EFAULT, "EFAULT"}, {EEXIST, "EEXIST"}, {EXDEV, "EXDEV"},   {EINVAL, "EINVAL"},
             {EROFS, "EROFS"},   {EMLINK, "EMLINK"}, {EDOM, "EDOM"},     {ERANGE, "ERANGE"}, {ENOSYS, "ENOSYS"}};
    for (unsigned i = 0; i < sizeof t / sizeof t[0]; i++)
        if (t[i].e == e) return t[i].n;
    snprintf(num, sizeof num, "errno %d", e);
    return num;
}
static const char *res(long r) { return r < 0 ? ename(errno) : "ok"; }
static void line(const char *c, const char *a)
{
    /* write, not stdio: an allow-list below has no fstat for stdio's first look at the descriptor */
    char b[512];
    int n = snprintf(b, sizeof b, "%s: %s\n", c, a);
    if (write(1, b, (size_t)n) < 0) _exit(2);
}

static long sys_open(const char *p) { return syscall(SYS_openat, AT_FDCWD, p, O_RDONLY); }
static long open_close(const char *p)
{
    long fd = sys_open(p);
    if (fd >= 0) close((int)fd);
    return fd;
}
static long sys_stat(const char *p)
{
    struct stat st;
    return syscall(SYS_newfstatat, AT_FDCWD, p, &st, 0);
}
static long sys_readlink(const char *p)
{
    char b[64];
    return syscall(SYS_readlinkat, AT_FDCWD, p, b, sizeof b);
}
static long sys_mkdir(const char *p) { return syscall(SYS_mkdirat, AT_FDCWD, p, 0700); }

static long install(struct sock_filter *f, unsigned short n, unsigned long flags)
{
    struct sock_fprog p = {n, f};
    long r = syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER, flags, &p);
    /* a kernel before 3.17 has no seccomp(2): the prctl form, which takes no flags */
    if (r < 0 && errno == ENOSYS && !flags) r = prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &p, 0, 0);
    return r;
}
#define LD_NR BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr))
/* "nr answers action, everything else is allowed" */
static long install_nr(int nr, unsigned action, unsigned long flags)
{
    struct sock_filter f[] = {LD_NR, BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, (unsigned)nr, 0, 1),
                              BPF_STMT(BPF_RET | BPF_K, action), BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW)};
    return install(f, 4, flags);
}

static const char *status(int st)
{
    static char b[64];
    if (WIFEXITED(st)) snprintf(b, sizeof b, "exited %d", WEXITSTATUS(st));
    else snprintf(b, sizeof b, "signal %s", WTERMSIG(st) == SIGSYS ? "SYS" : WTERMSIG(st) == SIGKILL ? "KILL" : "?");
    return b;
}
/* a case in a child of its own, so that its filters stay there; its end reported */
static void in_child(const char *name, void (*fn)(void))
{
    pid_t p = fork();
    if (p == 0) {
        fn();
        _exit(0);
    }
    int st;
    waitpid(p, &st, 0);
    char c[128];
    snprintf(c, sizeof c, "%s end", name);
    line(c, status(st));
}

static void errno_filters(void)
{
    long r = install_nr(SYS_openat, SECCOMP_RET_ERRNO | EDOM, 0);
    line("errno install openat", res(r));
    r = install_nr(SYS_newfstatat, SECCOMP_RET_ERRNO | ERANGE, 0);
    line("errno install newfstatat", res(r));
    r = install_nr(SYS_readlinkat, SECCOMP_RET_ERRNO | EXDEV, 0);
    line("errno install readlinkat", res(r));
    line("errno openat exclave", res(open_close(exfile)));
    line("errno openat host", res(open_close(hostfile)));
    line("errno newfstatat exclave", res(sys_stat(exfile)));
    line("errno newfstatat host", res(sys_stat(hostfile)));
    line("errno readlinkat exclave", res(sys_readlink("/usr/bin/cc")));
    line("errno readlinkat host", res(sys_readlink(hostfile)));
    line("errno faccessat exclave", res(syscall(SYS_faccessat, AT_FDCWD, exfile, R_OK)));
    line("errno getppid", syscall(SYS_getppid) > 0 ? "ok" : "fails");
}

static void two_errno(void)
{
    install_nr(SYS_openat, SECCOMP_RET_ERRNO | EPERM, 0);
    install_nr(SYS_openat, SECCOMP_RET_ERRNO | EACCES, 0);
    line("two errno newer wins exclave", res(open_close(exfile)));
    line("two errno newer wins host", res(open_close(hostfile)));
}
static void errno_then_allow(void)
{
    struct sock_filter allow[] = {BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW)};
    install_nr(SYS_openat, SECCOMP_RET_ERRNO | EPERM, 0);
    line("errno then allow install", res(install(allow, 1, 0)));
    line("errno then allow exclave", res(open_close(exfile)));
    line("errno then allow host", res(open_close(hostfile)));
}
static void allow_then_errno(void)
{
    struct sock_filter allow[] = {BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW)};
    install(allow, 1, 0);
    install_nr(SYS_openat, SECCOMP_RET_ERRNO | EIO, 0);
    line("allow then errno exclave", res(open_close(exfile)));
}
static void log_filter(void)
{
    line("log install", res(install_nr(SYS_openat, SECCOMP_RET_LOG, 0)));
    line("log openat exclave", res(open_close(exfile)));
    line("log openat host", res(open_close(hostfile)));
}

/* an sshd-shaped sandbox: an allow-list, ERRNO for one call, KILL_PROCESS for everything else; nothing the launcher
 * issues for itself (getpid, gettid, process_vm_readv, rt_sigreturn) is listed */
static void allow_list(int last)
{
    struct sock_filter f[] = {
        LD_NR,
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_openat, 7, 0),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_newfstatat, 6, 0),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_close, 5, 0),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_write, 4, 0),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_exit_group, 3, 0),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_readlinkat, 1, 0),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EACCES),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    };
    long r = install(f, sizeof f / sizeof f[0], 0);
    line(last ? "allow-list getppid install" : "allow-list install", res(r));
    if (last == 0) {
        line("allow-list openat exclave", res(open_close(exfile)));
        line("allow-list openat host", res(open_close(hostfile)));
        line("allow-list newfstatat exclave", res(sys_stat(exfile)));
        line("allow-list readlinkat exclave", res(sys_readlink("/usr/bin/cc")));
    }
    if (last == 0) sys_mkdir(hostsub); /* a translated call the list kills */
    else syscall(SYS_getppid); /* an untranslated one */
    line("allow-list after the forbidden call", "survived");
}
static void allow_list_mkdir(void) { allow_list(0); }
static void allow_list_getppid(void) { allow_list(1); }

static int go[2];
static long thread_r;
static int thread_e;
static void *thread_main(void *a)
{
    (void)a;
    char c;
    if (read(go[0], &c, 1) != 1) return 0;
    thread_r = open_close(exfile);
    thread_e = errno;
    return 0;
}
static void threads(unsigned long flags)
{
    pthread_t t;
    if (pipe(go) || pthread_create(&t, 0, thread_main, 0)) _exit(3);
    long r = install_nr(SYS_openat, SECCOMP_RET_ERRNO | EDOM, flags);
    line(flags ? "tsync install" : "one thread install", r < 0 ? ename(errno) : r ? "a thread's id" : "ok");
    if (write(go[1], "x", 1) != 1) _exit(3);
    pthread_join(t, 0);
    errno = thread_e;
    line(flags ? "tsync other thread openat" : "one thread other thread openat", res(thread_r));
    line(flags ? "tsync own openat" : "one thread own openat", res(open_close(exfile)));
}
static void tsync(void) { threads(SECCOMP_FILTER_FLAG_TSYNC); }
static void one_thread(void) { threads(0); }

static void forked(void)
{
    install_nr(SYS_openat, SECCOMP_RET_ERRNO | EDOM, 0);
    pid_t p = fork();
    if (p == 0) {
        line("fork child openat", res(open_close(exfile)));
        _exit(0);
    }
    waitpid(p, 0, 0);
}

static void vforked(void)
{
    volatile long r = 0;
    pid_t p = vfork();
    if (p == 0) {
        r = install_nr(SYS_openat, SECCOMP_RET_ERRNO | EDOM, 0);
        _exit(0);
    }
    waitpid(p, 0, 0);
    line("vfork child install", r ? "fails" : "ok");
    line("vfork parent openat", res(open_close(exfile)));
}

static void exec_self(void)
{
    install_nr(SYS_mkdirat, SECCOMP_RET_ERRNO | EMLINK, 0);
    static char name[] = "seccomp_filter", mode[] = "after-exec";
    char dir[4096];
    snprintf(dir, sizeof dir, "%s", hostdir);
    char *av[] = {name, mode, dir, 0};
    execv("/proc/self/exe", av);
    line("exec", ename(errno));
}
static void after_exec(void)
{
    line("exec mkdirat host", res(sys_mkdir(hostsub)));
    line("exec mkdirat exclave", res(sys_mkdir("/usr/share/exclave-filter-dir")));
    line("exec openat exclave", res(open_close(exfile)));
    line("exec PR_GET_SECCOMP", prctl(PR_GET_SECCOMP) == 2 ? "2" : "not 2");
}

/* the installs refused: by the kernel, the same in both worlds, or by the launcher, which answers ENOSYS (13 item 5) */
static long rc_;
static void strict_seccomp(void)
{
    rc_ = syscall(SYS_seccomp, SECCOMP_SET_MODE_STRICT, 0, 0);
    line("strict seccomp", res(rc_));
    syscall(SYS_exit, 0); /* strict mode allows exit, not exit_group */
}
static void strict_prctl(void)
{
    rc_ = prctl(PR_SET_SECCOMP, SECCOMP_MODE_STRICT, 0, 0, 0);
    line("strict prctl", res(rc_));
    syscall(SYS_exit, 0);
}
static void ret_a(void)
{
    struct sock_filter f[] = {BPF_STMT(BPF_LD | BPF_IMM, SECCOMP_RET_ALLOW), BPF_STMT(BPF_RET | BPF_A, 0)};
    line("ret a", res(install(f, 2, 0)));
}
static void trap_action(void) { line("trap action", res(install_nr(SYS_getppid, SECCOMP_RET_TRAP, 0))); }
static void trace_action(void) { line("trace action", res(install_nr(SYS_getppid, SECCOMP_RET_TRACE, 0))); }
static void listener(void)
{
    struct sock_filter f[] = {BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW)};
    long r = install(f, 1, SECCOMP_FILTER_FLAG_NEW_LISTENER);
    line("new listener", r >= 0 ? "a descriptor" : ename(errno));
}
static void reads_ip(void)
{
    struct sock_filter f[] = {BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, instruction_pointer)),
                              BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW)};
    line("reads the instruction pointer", res(install(f, 2, 0)));
}
static void reads_ip_high(void)
{
    struct sock_filter f[] = {
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, instruction_pointer) + 4),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW)};
    line("reads the instruction pointer's high word", res(install(f, 2, 0)));
}
static struct sock_filter big[4096];
static void long_filter(unsigned short n)
{
    for (unsigned i = 0; i + 1 < n; i++) big[i] = (struct sock_filter)BPF_STMT(BPF_LD | BPF_W | BPF_ABS, 0);
    big[n - 1] = (struct sock_filter)BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW);
    char c[64];
    snprintf(c, sizeof c, "%u instructions", n);
    line(c, res(install(big, n, 0)));
}
static void long_2100(void) { long_filter(2100); }
static void long_4090(void) { long_filter(4090); }
static void long_4096(void) { long_filter(4096); }
static void errno_4094(void) { line("errno 4094", res(install_nr(SYS_getppid, SECCOMP_RET_ERRNO | 4094, 0))); }
static void errno_4095(void)
{
    line("errno 65535 install", res(install_nr(SYS_mkdirat, SECCOMP_RET_ERRNO | 0xffff, 0)));
    line("errno 65535 mkdirat exclave", res(sys_mkdir("/usr/share/exclave-filter-dir")));
}
static void errno_zero(void)
{
    line("errno 0 install", res(install_nr(SYS_mkdirat, SECCOMP_RET_ERRNO | 0, 0)));
    long r = sys_mkdir(hostzero);
    line("errno 0 mkdirat host", r < 0 ? ename(errno) : "0");
    line("errno 0 made the directory", sys_stat(hostzero) == 0 ? "yes" : "no");
}

static void refusals(void)
{
    struct sock_filter allow[] = {BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW)};
    struct sock_filter far[] = {BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0, 3, 0),
                                BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW)};
    struct sock_filter falls[] = {LD_NR};
    struct sock_fprog p0 = {0, allow}, pbig = {4097, big};
    line("unknown flag", res(syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER, 1UL << 30, &(struct sock_fprog){1, allow})));
    line("tsync probe with no program",
         res(syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER, SECCOMP_FILTER_FLAG_TSYNC, 0)));
    line("strict with a flag", res(syscall(SYS_seccomp, SECCOMP_SET_MODE_STRICT, 1, 0)));
    line("empty program", res(syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER, 0, &p0)));
    line("4097 instructions", res(syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER, 0, &pbig)));
    line("a jump past the end", res(install(far, 2, 0)));
    line("no return at the end", res(install(falls, 1, 0)));
    line("program at NULL", res(syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER, 0, &(struct sock_fprog){1, 0})));
    line("program at an unmapped address",
         res(syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER, 0, &(struct sock_fprog){1, (struct sock_filter *)8})));
    line("header at an unmapped address", res(syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER, 0, (void *)8)));
    line("unknown operation", res(syscall(SYS_seccomp, 7, 0, 0)));
    line("prctl unknown mode", res(prctl(PR_SET_SECCOMP, 5, 0, 0, 0)));
    unsigned act = SECCOMP_RET_TRAP;
    line("action available", res(syscall(SYS_seccomp, SECCOMP_GET_ACTION_AVAIL, 0, &act)));
    unsigned short sizes[3];
    line("notification sizes", res(syscall(SYS_seccomp, SECCOMP_GET_NOTIF_SIZES, 0, sizes)));
}

static void prctl_filter(void)
{
    struct sock_filter f[] = {LD_NR, BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_openat, 0, 1),
                              BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EDOM),
                              BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW)};
    struct sock_fprog p = {4, f};
    line("prctl install", res(prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &p, 0, 0)));
    line("prctl openat exclave", res(open_close(exfile)));
    line("prctl PR_GET_SECCOMP", prctl(PR_GET_SECCOMP) == 2 ? "2" : "not 2");
}

int main(int argc, char **argv)
{
    if (argc < 2) return 2;
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) return 2;
    if (argc == 3 && !strcmp(argv[1], "after-exec")) {
        hostdir = argv[2];
        snprintf(hostsub, sizeof hostsub, "%s/sub-exec", hostdir);
        after_exec();
        return 0;
    }
    hostdir = argv[1];
    snprintf(hostfile, sizeof hostfile, "%s/file", hostdir);
    int fd = open(hostfile, O_CREAT | O_WRONLY, 0600);
    if (fd < 0) return 2;
    close(fd);
    snprintf(hostsub, sizeof hostsub, "%s/sub", hostdir);
    snprintf(hostzero, sizeof hostzero, "%s/zero", hostdir);
    setvbuf(stdout, 0, _IONBF, 0);
    line("PR_GET_SECCOMP before", prctl(PR_GET_SECCOMP) == 0 ? "0" : "2");
    in_child("errno", errno_filters);
    in_child("two errno", two_errno);
    in_child("errno then allow", errno_then_allow);
    in_child("allow then errno", allow_then_errno);
    in_child("log", log_filter);
    in_child("allow-list mkdirat", allow_list_mkdir);
    in_child("allow-list getppid", allow_list_getppid);
    in_child("tsync", tsync);
    in_child("one thread", one_thread);
    in_child("fork", forked);
    in_child("vfork", vforked);
    in_child("exec", exec_self);
    in_child("prctl", prctl_filter);
    in_child("strict seccomp", strict_seccomp);
    in_child("strict prctl", strict_prctl);
    in_child("ret a", ret_a);
    in_child("trap action", trap_action);
    in_child("trace action", trace_action);
    in_child("new listener", listener);
    in_child("reads ip", reads_ip);
    in_child("reads ip high", reads_ip_high);
    in_child("2100", long_2100);
    in_child("4090", long_4090);
    in_child("4096", long_4096);
    in_child("errno 4094", errno_4094);
    in_child("errno 65535", errno_4095);
    in_child("errno 0", errno_zero);
    in_child("refusals", refusals);
    return 0;
}
