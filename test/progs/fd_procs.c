/* fd_procs.c — descriptors and processes around trapped calls (DESIGN.md 7.4.3, 7.4.5, 7.5.4, 17 item 4): the
 * descriptors a program starts with and the number a trapped open returns, with holes, under a soft limit at the
 * table's edge and after close_range; another process's /proc/<pid>/fd, cwd and task links; a directory changed by a
 * clone(CLONE_VM) child without CLONE_FS, by a thread, and by posix_spawn's chdir action; a descriptor of the tree
 * passed by SCM_RIGHTS and taken by pidfd_getfd; and wait statuses of children that exec'd. usage: fd_procs HOSTDIR;
 * "fd_procs --child LABEL" is the program it re-executes. Prints one line per case, "<case>: <answer>", the same in
 * every world, so the kernel under bwrap is the oracle. Exit 0 always. */
#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <spawn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef CLOSE_RANGE_UNSHARE
#define CLOSE_RANGE_UNSHARE 2
#endif
#ifndef CLOSE_RANGE_CLOEXEC
#define CLOSE_RANGE_CLOEXEC 4
#endif

extern char **environ;
static char self[PATH_MAX];
static const char *marker = "/usr/share/exclave-test-marker";

/* errno's name, for the errors the cases meet; strerrorname_np is glibc's alone */
static const char *en(int e)
{
    switch (e) {
    case ENOENT: return "ENOENT";
    case EMFILE: return "EMFILE";
    case EROFS: return "EROFS";
    case EBADF: return "EBADF";
    case EACCES: return "EACCES";
    case ENOSYS: return "ENOSYS";
    case EPERM: return "EPERM";
    case EINVAL: return "EINVAL";
    case ENOTDIR: return "ENOTDIR";
    default: return "another error";
    }
}

static const char *err(long r) { return r < 0 ? en(errno) : "ok"; }

/* the open descriptors, as "0,1,2", without EXCLAVE_LOG's, which the launcher holds while it logs (6.2) */
static const char *fds(void)
{
    const char *log = getenv("EXCLAVE_LOG");
    struct stat ls, fs;
    int has_log = log && stat(log, &ls) == 0;
    static char s[512];
    int n[256], k = 0;
    DIR *d = opendir("/proc/self/fd");
    int dfd = dirfd(d);
    struct dirent *e;
    while ((e = readdir(d)) && k < 256)
        if (e->d_name[0] != '.' && atoi(e->d_name) != dfd &&
            !(has_log && fstat(atoi(e->d_name), &fs) == 0 && fs.st_ino == ls.st_ino && fs.st_dev == ls.st_dev))
            n[k++] = atoi(e->d_name);
    closedir(d);
    for (int i = 0; i < k; i++)
        for (int j = i + 1; j < k; j++)
            if (n[j] < n[i]) {
                int t = n[i];
                n[i] = n[j], n[j] = t;
            }
    s[0] = 0;
    for (int i = 0; i < k; i++) snprintf(s + strlen(s), sizeof s - strlen(s), "%s%d", i ? "," : "", n[i]);
    return s;
}

static void numbers(void)
{
    printf("start fds: %s\n", fds());
    for (int i = 0; i < 3; i++) printf("start F_GETFD %d: %d\n", i, fcntl(i, F_GETFD));
    int a = open(marker, O_RDONLY);
    printf("first open: %d\n", a);
    int b = open(marker, O_RDONLY), c = open(marker, O_RDONLY);
    close(b);
    int d = open(marker, O_RDONLY);
    printf("open fills a hole: %s\n", d == b ? "yes" : "no");
    close(a), close(c), close(d);
    int x = fcntl(0, F_DUPFD_CLOEXEC, 0);
    printf("F_DUPFD_CLOEXEC 0 lowest: %d cloexec %d\n", x, fcntl(x, F_GETFD));
    close(x);
    /* a soft limit at the table's edge: one number left, then none */
    pid_t p = fork();
    if (p == 0) {
        if (chdir("/")) _exit(1);
        int top = open(marker, O_RDONLY);
        struct rlimit rl;
        getrlimit(RLIMIT_NOFILE, &rl);
        rl.rlim_cur = (rlim_t)top + 1;
        close(top);
        setrlimit(RLIMIT_NOFILE, &rl);
        int r = open(marker, O_RDONLY);
        printf("limit edge open: %s\n", r == top ? "the last number" : r < 0 ? en(errno) : "past it");
        r = open(marker, O_RDONLY);
        printf("limit edge second open: %s\n", r < 0 ? en(errno) : "opened");
        struct stat st;
        printf("limit edge stat: %s\n", err(stat(marker, &st)));
        printf("limit edge relative stat: %s\n", err(fstatat(AT_FDCWD, "usr/share/exclave-test-marker", &st, 0)));
        DIR *dd = opendir("/usr/share");
        printf("limit edge opendir: %s\n", dd ? "opened" : en(errno));
        getrlimit(RLIMIT_NOFILE, &rl);
        printf("limit edge soft limit kept: %s\n", rl.rlim_cur == (rlim_t)top + 1 ? "yes" : "no");
        /* a hard limit lowered too, below the numbers held */
        rl.rlim_max = rl.rlim_cur = 3;
        setrlimit(RLIMIT_NOFILE, &rl);
        printf("hard 3 stat: %s\n", err(stat(marker, &st)));
        printf("hard 3 open: %s\n", err(open(marker, O_RDONLY)));
        fflush(stdout);
        _exit(0);
    }
    waitpid(p, 0, 0);
    p = fork();
    if (p == 0) {
        long r = syscall(SYS_close_range, 3, ~0U, 0);
        printf("close_range all: %s fds %s\n", err(r), fds());
        struct stat st;
        printf("close_range then stat: %s\n", err(stat(marker, &st)));
        printf("close_range then open: %d\n", open(marker, O_RDONLY));
        r = syscall(SYS_close_range, 3, ~0U, CLOSE_RANGE_UNSHARE);
        printf("close_range unshare 3..: %s\n", err(r));
        printf("close_range unshare then stat: %s\n", err(stat(marker, &st)));
        printf("close_range unshare then open: %d\n", open(marker, O_RDONLY));
        fflush(stdout);
        _exit(0);
    }
    waitpid(p, 0, 0);
    p = fork();
    if (p == 0) {
        long r = syscall(SYS_close_range, 0, ~0U, CLOSE_RANGE_CLOEXEC);
        printf("close_range cloexec: %s F_GETFD 1 %d\n", err(r), fcntl(1, F_GETFD));
        int o = open(marker, O_RDONLY);
        printf("close_range cloexec then open: %d cloexec %d\n", o, fcntl(o, F_GETFD));
        fflush(stdout);
        _exit(0);
    }
    waitpid(p, 0, 0);
    /* dup2 onto every low number, then a trapped open */
    p = fork();
    if (p == 0) {
        int src = open("/dev/null", O_RDONLY);
        for (int i = 3; i < 24; i++) dup2(src, i);
        close(10);
        int o = open(marker, O_RDONLY);
        printf("dup2 3..23 hole at 10 open: %d\n", o);
        o = open(marker, O_RDONLY);
        printf("dup2 3..23 next open: %d\n", o);
        fflush(stdout);
        _exit(0);
    }
    waitpid(p, 0, 0);
}

/* readlink of a link, the tree's prefix shown as it is */
static void link_of(const char *label, const char *path)
{
    char b[PATH_MAX];
    ssize_t n = readlink(path, b, sizeof b - 1);
    if (n < 0) {
        printf("%s: %s\n", label, en(errno));
        return;
    }
    b[n] = 0;
    printf("%s: %s\n", label, b);
}

static void other_links(void)
{
    int ready[2], go[2];
    if (pipe(ready) || pipe(go)) return;
    pid_t p = fork();
    if (p == 0) {
        int fd = open(marker, O_RDONLY);
        if (dup2(fd, 40) < 0 || chdir("/usr/share") < 0) _exit(1);
        char c = 1;
        if (write(ready[1], &c, 1) != 1 || read(go[0], &c, 1) != 1) _exit(1);
        _exit(0);
    }
    char c, path[64];
    if (read(ready[0], &c, 1) != 1) return;
    snprintf(path, sizeof path, "/proc/%d/fd/40", p);
    link_of("child fd link", path);
    struct stat a, b;
    printf("child fd stat: %s\n",
           stat(path, &a) == 0 && stat(marker, &b) == 0 && a.st_ino == b.st_ino ? "the file" : "not it");
    snprintf(path, sizeof path, "/proc/%d/cwd", p);
    link_of("child cwd link", path);
    snprintf(path, sizeof path, "/proc/%d/task/%d/fd/40", p, p);
    link_of("child task fd link", path);
    snprintf(path, sizeof path, "/proc/%d/root", p);
    link_of("child root link", path);
    if (write(go[1], &c, 1) != 1) return;
    waitpid(p, 0, 0);
    int fd = open(marker, O_RDONLY);
    snprintf(path, sizeof path, "/proc/self/task/%ld/fd/%d", (long)gettid(), fd);
    link_of("own task fd link", path);
    snprintf(path, sizeof path, "/proc/thread-self/fd/%d", fd);
    link_of("thread-self fd link", path);
    snprintf(path, sizeof path, "/dev/fd/%d", fd);
    link_of("dev fd link", path);
    snprintf(path, sizeof path, "/proc/%d/fd/%d", getpid(), fd);
    link_of("own pid fd link", path);
    int pfd = open("/proc/self/fd", O_RDONLY | O_DIRECTORY);
    char name[16];
    snprintf(name, sizeof name, "%d", fd);
    char b2[PATH_MAX];
    ssize_t n = readlinkat(pfd, name, b2, sizeof b2 - 1);
    b2[n < 0 ? 0 : n] = 0;
    printf("readlinkat proc fd dir: %s\n", n < 0 ? en(errno) : b2);
    close(pfd);
    close(fd);
}

static char stk[65536] __attribute__((aligned(16)));
static int vm_child(void *arg)
{
    (void)arg;
    return chdir("/usr/share") ? 1 : 0;
}

static void *thread_chdir(void *arg)
{
    (void)arg;
    if (chdir("/usr")) return (void *)1;
    return 0;
}

static void cwds(const char *hostdir)
{
    char b[PATH_MAX];
    struct stat st;
    if (chdir("/")) return;
    pid_t p = clone(vm_child, stk + sizeof stk, CLONE_VM | SIGCHLD, 0);
    int s;
    waitpid(p, &s, 0);
    printf("CLONE_VM child chdir: status %d\n", WEXITSTATUS(s));
    printf("CLONE_VM parent cwd: %s\n", getcwd(b, sizeof b) ? b : en(errno));
    printf("CLONE_VM parent relative stat: %s\n", err(stat("usr/share/exclave-test-marker", &st)));
    p = clone(vm_child, stk + sizeof stk, CLONE_VM | CLONE_FS | SIGCHLD, 0);
    waitpid(p, &s, 0);
    printf("CLONE_FS parent cwd: %s\n", getcwd(b, sizeof b) ? b : en(errno));
    printf("CLONE_FS parent relative stat: %s\n", err(stat("exclave-test-marker", &st)));
    if (chdir("/")) return;
    pthread_t t;
    pthread_create(&t, 0, thread_chdir, 0);
    pthread_join(t, 0);
    printf("thread chdir cwd: %s\n", getcwd(b, sizeof b) ? b : en(errno));
    printf("thread chdir relative stat: %s\n", err(stat("share/exclave-test-marker", &st)));
    if (chdir(hostdir)) return;
    /* posix_spawn with a chdir action into the tree and an open action of a tree file */
    posix_spawn_file_actions_t fa;
    posix_spawn_file_actions_init(&fa);
    posix_spawn_file_actions_addchdir_np(&fa, "/usr/share");
    posix_spawn_file_actions_addopen(&fa, 5, "exclave-test-marker", O_RDONLY, 0);
    /* the tree's shell, which every view holds; this program may lie where the child cannot see it (13 item 63) */
    char *av[] = {"sh", "-c", "echo \"spawned cwd: $(pwd)\"; echo \"spawned fd 5: $(readlink /proc/self/fd/5)\"", 0};
    int r = posix_spawn(&p, "/bin/sh", &fa, 0, av, environ);
    printf("spawn chdir+open: %s\n", r ? en(r) : "ok");
    if (!r) waitpid(p, &s, 0);
    posix_spawn_file_actions_destroy(&fa);
    printf("spawn parent cwd is hostdir: %s\n", getcwd(b, sizeof b) && strcmp(b, hostdir) == 0 ? "yes" : b);
    int hf = open("x", O_CREAT | O_WRONLY, 0644);
    printf("spawn parent relative create: %s\n", hf < 0 ? en(errno) : "ok");
    if (hf >= 0) close(hf), unlink("x");
    /* an action that fails: the child never runs */
    posix_spawn_file_actions_init(&fa);
    posix_spawn_file_actions_addopen(&fa, 5, "/usr/share/nonexistent", O_RDONLY, 0);
    r = posix_spawn(&p, "/bin/sh", &fa, 0, av, environ);
    printf("spawn failing open action: %s\n", r ? en(r) : "ran");
    if (!r) waitpid(p, &s, 0);
    posix_spawn_file_actions_destroy(&fa);
    posix_spawn_file_actions_init(&fa);
    posix_spawn_file_actions_addopen(&fa, 5, "/usr/share/exclave-test-marker", O_WRONLY, 0);
    r = posix_spawn(&p, "/bin/sh", &fa, 0, av, environ);
    printf("spawn write-open action: %s\n", r ? en(r) : "ran");
    if (!r) waitpid(p, &s, 0);
    posix_spawn_file_actions_destroy(&fa);
    if (chdir("/")) return;
}

static void passing(void)
{
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv)) return;
    pid_t p = fork();
    if (p == 0) {
        close(sv[0]);
        char c;
        char ctl[CMSG_SPACE(sizeof(int))];
        struct iovec io = {&c, 1};
        struct msghdr m = {.msg_iov = &io, .msg_iovlen = 1, .msg_control = ctl, .msg_controllen = sizeof ctl};
        if (recvmsg(sv[1], &m, 0) != 1) _exit(1);
        struct cmsghdr *got = CMSG_FIRSTHDR(&m);
        if (!got) _exit(1);
        int fd;
        memcpy(&fd, CMSG_DATA(got), sizeof fd);
        char path[64];
        snprintf(path, sizeof path, "/proc/self/fd/%d", fd);
        link_of("SCM_RIGHTS received link", path);
        int dfd = openat(fd, "exclave-test-marker", O_RDONLY);
        printf("SCM_RIGHTS openat from it: %s\n", dfd < 0 ? en(errno) : "ok");
        fflush(stdout);
        _exit(0);
    }
    close(sv[1]);
    int dir = open("/usr/share", O_RDONLY | O_DIRECTORY);
    char c = 1;
    char ctl[CMSG_SPACE(sizeof(int))] = {0};
    struct iovec io = {&c, 1};
    struct msghdr m = {.msg_iov = &io, .msg_iovlen = 1, .msg_control = ctl, .msg_controllen = sizeof ctl};
    struct cmsghdr *h = CMSG_FIRSTHDR(&m);
    h->cmsg_level = SOL_SOCKET, h->cmsg_type = SCM_RIGHTS, h->cmsg_len = CMSG_LEN(sizeof(int));
    memcpy(CMSG_DATA(h), &dir, sizeof dir);
    if (sendmsg(sv[0], &m, 0) != 1) return;
    waitpid(p, 0, 0);
    close(sv[0]);
    /* pidfd_getfd of a child's descriptor on the tree */
    int ready[2], go[2];
    if (pipe(ready) || pipe(go)) return;
    p = fork();
    if (p == 0) {
        int fd = open(marker, O_RDONLY);
        if (dup2(fd, 41) < 0) _exit(1);
        if (write(ready[1], &c, 1) != 1 || read(go[0], &c, 1) != 1) _exit(1);
        _exit(0);
    }
    if (read(ready[0], &c, 1) != 1) return;
    int pidfd = (int)syscall(SYS_pidfd_open, p, 0);
    int got = pidfd < 0 ? -1 : (int)syscall(SYS_pidfd_getfd, pidfd, 41, 0);
    if (got < 0) {
        printf("pidfd_getfd link: %s\n", en(errno));
        printf("pidfd_getfd cloexec: none\n");
    } else {
        char path[64];
        snprintf(path, sizeof path, "/proc/self/fd/%d", got);
        link_of("pidfd_getfd link", path);
        printf("pidfd_getfd cloexec: %d\n", fcntl(got, F_GETFD));
        close(got);
    }
    if (write(go[1], &c, 1) != 1) return;
    printf("pidfd_send_signal 0: %s\n", err(syscall(SYS_pidfd_send_signal, pidfd, 0, 0, 0)));
    waitpid(p, 0, 0);
    close(pidfd);
}

static void statuses(const char *hostdir)
{
    struct {
        const char *label;
        char *path;
    } t[] = {{"wrapper false", "/usr/bin/false"}, {"wrapper true", "/usr/bin/true"}};
    for (unsigned i = 0; i < sizeof t / sizeof *t; i++) {
        pid_t p = fork();
        if (p == 0) {
            char *av[] = {t[i].path, 0};
            execv(t[i].path, av);
            _exit(99);
        }
        int s;
        siginfo_t si;
        waitid(P_PID, (id_t)p, &si, WEXITED);
        (void)s;
        printf("%s: code %d status %d\n", t[i].label, si.si_code, si.si_status);
    }
    /* a host script whose interpreter the exclave lacks, and one with no execute permission */
    char path[PATH_MAX];
    snprintf(path, sizeof path, "%s/noint", hostdir);
    FILE *f = fopen(path, "w");
    if (!f) return;
    fputs("#!/nonexistent/interp\n", f);
    fclose(f);
    chmod(path, 0755);
    pid_t p = fork();
    if (p == 0) {
        char *av[] = {path, 0};
        execv(path, av);
        _exit(errno == ENOENT ? 42 : 43);
    }
    int s;
    waitpid(p, &s, 0);
    printf("missing interpreter: exit %d\n", WIFEXITED(s) ? WEXITSTATUS(s) : -WTERMSIG(s));
    /* the child killed by a signal after exec'ing a wrapper */
    p = fork();
    if (p == 0) {
        char *av[] = {"sleep", "5", 0};
        execv("/usr/bin/sleep", av);
        _exit(99);
    }
    usleep(200000);
    kill(p, SIGTERM);
    waitpid(p, &s, 0);
    printf("wrapper killed: %s %d\n", WIFSIGNALED(s) ? "signal" : "exit",
           WIFSIGNALED(s) ? WTERMSIG(s) : WEXITSTATUS(s));
    /* a process group and a session of a child that exec'd */
    p = fork();
    if (p == 0) {
        setsid();
        char *av[] = {"sleep", "5", 0};
        execv("/usr/bin/sleep", av);
        _exit(99);
    }
    usleep(200000);
    printf("child session is its pid: %s\n", getsid(p) == p ? "yes" : "no");
    printf("child pgid is its pid: %s\n", getpgid(p) == p ? "yes" : "no");
    kill(-p, SIGKILL);
    waitpid(p, &s, 0);
    printf("group killed: %s %d\n", WIFSIGNALED(s) ? "signal" : "exit", WIFSIGNALED(s) ? WTERMSIG(s) : WEXITSTATUS(s));
}

/* a program exec'd with some of 0, 1 and 2 closed: what it holds and where its first open lands; it answers on 7 */
static void closed_std(void)
{
    static const struct {
        const char *label;
        int mask;
    } t[] = {{"closed 0", 1}, {"closed 0 2", 5}, {"closed 0 1 2", 7}};
    for (unsigned i = 0; i < sizeof t / sizeof *t; i++) {
        fflush(stdout);
        pid_t p = fork();
        if (p == 0) {
            if (dup2(1, 7) < 0) _exit(1);
            for (int k = 0; k < 3; k++)
                if (t[i].mask & 1 << k) close(k);
            char lab[32];
            snprintf(lab, sizeof lab, "%s", t[i].label);
            char *av[] = {self, "--child", lab, 0};
            execve(self, av, environ);
            _exit(127);
        }
        int s;
        waitpid(p, &s, 0);
        if (!WIFEXITED(s) || WEXITSTATUS(s)) dprintf(1, "%s: status %#x\n", t[i].label, s);
    }
}

int main(int argc, char **argv)
{
    ssize_t n = readlink("/proc/self/exe", self, sizeof self - 1);
    if (n < 0) return 0;
    self[n] = 0;
    setvbuf(stdout, 0, _IOLBF, 0);
    if (argc >= 3 && strcmp(argv[1], "--child") == 0) {
        if (strncmp(argv[2], "closed", 6) == 0) {
            int o = open(marker, O_RDONLY);
            dprintf(7, "%s 0 1 2 open: %d %d %d\n", argv[2], fcntl(0, F_GETFD) >= 0, fcntl(1, F_GETFD) >= 0,
                    fcntl(2, F_GETFD) >= 0);
            dprintf(7, "%s first open: %d\n", argv[2], o);
            return 0;
        }
        return 0;
    }
    if (argc < 2) return 0;
    static char start[PATH_MAX];
    if (!getcwd(start, sizeof start)) return 0;
    numbers();
    other_links();
    cwds(argv[1]);
    passing();
    statuses(argv[1]);
    /* from the directory it started in, whose view holds this program (13 item 63) */
    if (chdir(start)) return 0;
    closed_std();
    return 0;
}
