/* adversarial.c — what a hostile program or a fuzzer would try (PROPOSAL.md 17.4): arguments with their upper 32 bits
 * set where the kernel takes an int, which the probe cannot try since it passes longs; the opener's own variables set
 * before an exec; a working directory deleted under the program; an exec with no descriptor left; mounts and roots
 * from inside; SIGSYS ignored, handled or fed to a signalfd; magic links under /proc/1; interpreter loops and chains;
 * an empty executable, a loader that is a directory. usage: adversarial HOSTDIR, or "adversarial HOSTDIR --child".
 * Prints one line per case, "<case>: <answer>", the same in every world where the kernel is the oracle, so the
 * exerciser shows what differs; the named regression asserts the kernel's answers, and for the cases the opener
 * decides for itself (its variables stripped, mounts refused) the opener's. Exit 0 always. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <sched.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/resource.h>
#include <sys/signalfd.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

extern char **environ;
#define HI (1UL << 32)                                        /* a bit the kernel never sees in an int argument */

static const char *en(long r)
{
    static char b[32];
    if (r >= 0) return "ok";
    int e = errno;
    switch (e) {
    case ENOENT: return "ENOENT"; case EACCES: return "EACCES"; case EROFS: return "EROFS"; case EINVAL: return "EINVAL";
    case EFAULT: return "EFAULT"; case ENOTDIR: return "ENOTDIR"; case ERANGE: return "ERANGE"; case EPERM: return "EPERM";
    case ENOSYS: return "ENOSYS"; case ELOOP: return "ELOOP"; case ENOEXEC: return "ENOEXEC"; case EMFILE: return "EMFILE";
    case ECONNREFUSED: return "ECONNREFUSED"; case EADDRINUSE: return "EADDRINUSE"; case EBADF: return "EBADF"; case EEXIST: return "EEXIST";
    default: snprintf(b, sizeof b, "errno=%d", e); return b;
    }
}
#define P(name, expr) do { errno = 0; long r_ = (long)(expr); printf("%s: %s\n", name, en(r_)); } while (0)

/* the child's exec answer: the errno through a close-on-exec pipe when the exec returned, else "ran" with the program's
 * exit status and the first line it wrote to stderr; with nofds the child first closes everything above the pipe and
 * lowers RLIMIT_NOFILE to what is open, so that no descriptor can be opened */
struct ex { const char *path; char *const *argv; int nofds; };   /* nofds 1: the soft limit lowered to what is open; 2: the hard one too */
static const char *exec_answer(struct ex *x)
{
    static char b[200];
    int p[2], e[2]; pipe2(p, O_CLOEXEC); pipe(e);
    fflush(stdout);
    pid_t c = fork();
    if (c == 0) {
        dup2(e[1], 2); close(e[0]); close(e[1]);
        if (x->nofds) {
            dup2(p[1], 3); close(p[1]); fcntl(3, F_SETFD, FD_CLOEXEC);
            for (int fd = 4; fd < 1024; fd++) close(fd);
            struct rlimit rl; getrlimit(RLIMIT_NOFILE, &rl); rl.rlim_cur = 4; if (x->nofds == 2) rl.rlim_max = 4;
            setrlimit(RLIMIT_NOFILE, &rl);                     /* 0, 1, 2 and the pipe: nothing left to open with */
        }
        execve(x->path, x->argv, environ);
        int err = errno; write(x->nofds ? 3 : p[1], &err, sizeof err); _exit(1);
    }
    close(p[1]); close(e[1]);
    int err = 0; ssize_t n = read(p[0], &err, sizeof err); close(p[0]);
    char se[160] = ""; ssize_t m = read(e[0], se, sizeof se - 1); close(e[0]); if (m > 0) { se[m] = 0; se[strcspn(se, "\n")] = 0; }
    int st = -1; waitpid(c, &st, 0);
    if (n == (ssize_t)sizeof err) { errno = err; return en(-1); }
    if (x->nofds) snprintf(b, sizeof b, "ran");             /* what happens after the exec is the loader's under that limit: not the point */
    else snprintf(b, sizeof b, "ran, exit %d%s%.60s", WIFEXITED(st) ? WEXITSTATUS(st) : -1, se[0] ? ": " : "", se);
    return b;
}

static void copy_self(const char *to)
{
    int i = open("/proc/self/exe", O_RDONLY), o = open(to, O_WRONLY | O_CREAT | O_TRUNC, 0755);
    if (i < 0 || o < 0) { perror("copy self"); exit(2); }
    char b[65536]; ssize_t n;
    while ((n = read(i, b, sizeof b)) > 0) write(o, b, (size_t)n);
    close(i); close(o);
}
/* the copy's PT_INTERP string replaced by a directory, in place */
static int interp_to_dir(const char *path, const char *dir)
{
    int fd = open(path, O_RDWR); if (fd < 0) return -1;
    unsigned char eh[64]; if (pread(fd, eh, 64, 0) != 64) { close(fd); return -1; }
    uint64_t phoff; uint16_t phentsize, phnum;
    memcpy(&phoff, eh + 32, 8); memcpy(&phentsize, eh + 54, 2); memcpy(&phnum, eh + 56, 2);
    for (unsigned i = 0; i < phnum; i++) {
        unsigned char ph[56]; if (pread(fd, ph, 56, (off_t)(phoff + i * phentsize)) != 56) break;
        uint32_t type; uint64_t off, filesz; memcpy(&type, ph, 4); memcpy(&off, ph + 8, 8); memcpy(&filesz, ph + 32, 8);
        if (type == 3 && filesz > strlen(dir) + 1) {
            char *z = calloc(1, filesz); memcpy(z, dir, strlen(dir)); pwrite(fd, z, filesz, (off_t)off); free(z); close(fd); return 0;
        }
    }
    close(fd); return -1;
}
static void script(const char *path, const char *text) { FILE *f = fopen(path, "w"); fputs(text, f); fclose(f); chmod(path, 0755); }
static volatile int program_handler_ran;
static void on_sys(int s) { (void)s; program_handler_ran = 1; }

int main(int argc, char **argv)
{
    if (argc >= 3 && strcmp(argv[2], "--child") == 0) {
        printf("child sees CAN_EXEC=%s CAN_EXECFN=%s CAN_COMM=%s\n", getenv("CAN_EXEC") ? "set" : "unset", getenv("CAN_EXECFN") ? "set" : "unset", getenv("CAN_COMM") ? "set" : "unset");
        return 0;
    }
    if (argc < 2) { fprintf(stderr, "usage: adversarial HOSTDIR\n"); return 2; }
    const char *hd = argv[1], *sh = getenv("SH") ? getenv("SH") : "/usr/bin/sh";
    char p[4096], q[4096], buf[64];
    snprintf(p, sizeof p, "%s/f", hd); { int c = open(p, O_WRONLY | O_CREAT, 0644); write(c, "f\n", 2); close(c); }
    snprintf(q, sizeof q, "%s/hl", hd); symlink("f", q);      /* a host symlink of four bytes of text */
    int hfd = open(hd, O_RDONLY | O_DIRECTORY);
    struct stat st;
    struct timespec ts[2] = { { 1000, 0 }, { 2000, 0 } };

    /* 1. an int argument with its upper 32 bits set: the kernel truncates, so must the handler */
    memset(buf, 'X', sizeof buf);
    long r = syscall(SYS_readlink, q, buf, HI | 1);           /* a one-byte link text, a one-byte buffer with bits above the word */
    printf("readlink size 1 with upper bits: %s%s\n", r < 0 ? en(r) : r == 1 ? "1 byte" : "other count", buf[1] == 'X' ? ", buffer intact" : ", BUFFER OVERRUN");
    memset(buf, 'X', sizeof buf);
    r = syscall(SYS_readlink, q, buf, 0xffffffffUL);          /* -1 as an int */
    printf("readlink size -1 as int: %s%s\n", en(r), buf[0] == 'X' ? ", buffer intact" : ", BUFFER OVERRUN");
    memset(buf, 'X', sizeof buf);
    r = syscall(SYS_readlink, q, buf, HI);                     /* 0 as an int */
    printf("readlink size 0 as int: %s%s\n", en(r), buf[0] == 'X' ? ", buffer intact" : ", BUFFER OVERRUN");
    r = syscall(SYS_readlinkat, HI | (unsigned)AT_FDCWD, q, buf, 8);
    printf("readlinkat AT_FDCWD with upper bits: %s\n", r < 0 ? en(r) : "ok");
    P("openat dfd with upper bits", syscall(SYS_openat, HI | (unsigned)hfd, "f", O_RDONLY));
    P("utimensat host, flags upper bits only", syscall(SYS_utimensat, AT_FDCWD, p, ts, HI));
    P("utimensat can, flags upper bits only", syscall(SYS_utimensat, AT_FDCWD, "/usr/share/cont-test-marker", ts, HI));
    P("faccessat2 can, flags upper bits only", syscall(SYS_faccessat2, AT_FDCWD, "/usr/share/cont-test-marker", R_OK, HI));
    P("newfstatat can, flags upper bits only", syscall(SYS_newfstatat, AT_FDCWD, "/usr/share/cont-test-marker", &st, HI));
    P("getcwd size all ones", syscall(SYS_getcwd, buf, ~0UL));
    P("getcwd size 4 with upper bits", syscall(SYS_getcwd, buf, HI | 4));
    snprintf(q, sizeof q, "%s/a", hd); { int c = open(q, O_WRONLY | O_CREAT, 0644); close(c); }
    snprintf(p, sizeof p, "%s/b", hd);
    P("renameat2 flags upper bits only", syscall(SYS_renameat2, AT_FDCWD, q, AT_FDCWD, p, HI));
    P("unlinkat flags upper bits only", syscall(SYS_unlinkat, AT_FDCWD, p, HI));
    {
        struct sockaddr_un a = { AF_UNIX, "/usr/share/cont-adv.sock" };
        int s = socket(AF_UNIX, SOCK_STREAM, 0);
        socklen_t l = (socklen_t)(2 + strlen(a.sun_path) + 1);
        P("bind can path, addrlen upper bits", syscall(SYS_bind, s, &a, HI | l));
        strcpy(a.sun_path, "/usr/share/cont-test.sock"); l = (socklen_t)(2 + strlen(a.sun_path) + 1);
        P("connect can socket, addrlen upper bits", syscall(SYS_connect, s, &a, HI | l));
        close(s);
    }
    P("openat2 size with upper bits", syscall(SYS_openat2, AT_FDCWD, "/usr/share", (unsigned long long[]){ O_RDONLY | O_DIRECTORY, 0, 0 }, HI | 24));

    /* 2. the opener's own variables set by a program: never seen by the next program, never obeyed */
    setenv("CAN_EXEC", "/nonexistent/evil", 1); setenv("CAN_EXECFN", "/evil", 1); setenv("CAN_COMM", "evil", 1);
    snprintf(p, sizeof p, "%s/self", hd); copy_self(p);
    { char *const av[] = { (char *)p, (char *)hd, "--child", 0 }; struct ex x = { p, av, 0 }; printf("exec of a host ELF with CAN_* set: %s\n", exec_answer(&x)); }
    { char *const av[] = { "sh", "-c", "read c < /proc/self/comm; echo \"wrapper with CAN_* set: comm=$c CAN_EXEC=${CAN_EXEC:-unset} CAN_EXECFN=${CAN_EXECFN:-unset} CAN_COMM=${CAN_COMM:-unset}\"", 0 };
      struct ex x = { sh, av, 0 }; const char *ans = exec_answer(&x); if (strncmp(ans, "ran, exit 0", 11)) printf("wrapper with CAN_* set: %s\n", ans); }
    unsetenv("CAN_EXEC"); unsetenv("CAN_EXECFN"); unsetenv("CAN_COMM");

    /* 3. the working directory deleted under the program */
    snprintf(p, sizeof p, "%s/gone", hd); mkdir(p, 0755);
    if (chdir(p) == 0) {
        rmdir(p);
        P("deleted cwd: getcwd", syscall(SYS_getcwd, buf, sizeof buf));
        P("deleted cwd: stat .", stat(".", &st));
        P("deleted cwd: open .", open(".", O_RDONLY | O_DIRECTORY));
        P("deleted cwd: stat ../f", stat("../f", &st));
        P("deleted cwd: mkdir x", mkdir("x", 0755));
        P("deleted cwd: open x O_CREAT", open("x", O_WRONLY | O_CREAT, 0644));
        chdir(hd);
    }

    /* 4. an exec with no descriptor left: the kernel needs none */
    {
        struct { const char *name; const char *path; } cases[] = { { "no fd left: exec can true", 0 }, { "no fd left: exec host ELF", 0 }, { "no fd left: exec host script", 0 } };
        char tp[4096], sp[4096], ep[4096];
        snprintf(tp, sizeof tp, "%s", sh); char *s = strrchr(tp, '/'); strcpy(s + 1, "true");   /* the can's true beside its sh */
        snprintf(sp, sizeof sp, "%s/s.sh", hd); script(sp, "#!/bin/sh\nexit 0\n");
        snprintf(ep, sizeof ep, "%s/self", hd);
        cases[0].path = tp; cases[1].path = ep; cases[2].path = sp;
        char *const av_true[] = { "true", 0 }; char *const av_self[] = { ep, (char *)hd, "--child", 0 }; char *const av_sh[] = { "s.sh", 0 };
        char *const *avs[] = { av_true, av_self, av_sh };
        for (int i = 0; i < 3; i++) { struct ex x = { cases[i].path, avs[i], 1 }; printf("%s: %s\n", cases[i].name, exec_answer(&x)); }
        { struct ex x = { tp, av_true, 2 }; printf("no fd left, hard limit too: exec can true: %s\n", exec_answer(&x)); }
    }

    /* 5. mounts and roots from inside */
    {
        fflush(stdout);
        pid_t c = fork();
        if (c == 0) {
            int u = unshare(CLONE_NEWUSER | CLONE_NEWNS);
            snprintf(q, sizeof q, "%s/mnt", hd); mkdir(q, 0755);
            printf("unshare user+mount: %s\n", u ? en(u) : "ok");
            P("mount tmpfs inside", mount("none", q, "tmpfs", 0, ""));
            P("chroot inside", chroot(hd));
            P("open_tree", syscall(428, AT_FDCWD, hd, 0));
            P("mount_setattr", syscall(SYS_mount_setattr, AT_FDCWD, hd, 0, 0, 0));
            fflush(stdout); _exit(0);
        }
        waitpid(c, 0, 0);
    }

    /* 6. SIGSYS ignored, handled or fed to a signalfd: the handler still answers every trap */
    signal(SIGSYS, SIG_IGN);
    P("stat with SIGSYS ignored", stat("/usr/share/cont-test-marker", &st));
    { struct sigaction sa = { .sa_handler = on_sys }; sigaction(SIGSYS, &sa, 0); }
    P("stat with a SIGSYS handler installed", stat("/usr/share/cont-test-marker", &st));
    printf("program's SIGSYS handler ran: %s\n", program_handler_ran ? "yes" : "no");
    { sigset_t m; sigemptyset(&m); sigaddset(&m, SIGSYS); sigprocmask(SIG_BLOCK, &m, 0); int sfd = signalfd(-1, &m, SFD_NONBLOCK);
      P("stat with SIGSYS blocked and on a signalfd", stat("/usr/share/cont-test-marker", &st));
      struct signalfd_siginfo si; long n = sfd >= 0 ? read(sfd, &si, sizeof si) : -1;
      printf("signalfd delivered a SIGSYS: %s\n", n > 0 ? "yes" : "no"); if (sfd >= 0) close(sfd); sigprocmask(SIG_UNBLOCK, &m, 0); }

    /* 7. magic links under another process's /proc entry, which this user may not follow */
    P("stat /proc/1/root/etc", stat("/proc/1/root/etc", &st));
    P("stat /proc/1/root", stat("/proc/1/root", &st));
    P("lstat /proc/1/root", lstat("/proc/1/root", &st));
    P("open /proc/1/cwd", open("/proc/1/cwd", O_RDONLY | O_DIRECTORY));
    P("readlink /proc/1/exe", readlink("/proc/1/exe", buf, sizeof buf));

    /* 8. interpreters: a loop, a chain, an empty line, a missing one; an empty file; a loader that is a directory */
    snprintf(p, sizeof p, "%s/loop.sh", hd); snprintf(q, sizeof q, "#!%s\n", p); script(p, q);
    { char *const av[] = { "loop.sh", 0 }; struct ex x = { p, av, 0 }; printf("exec of a script that is its own interpreter: %s\n", exec_answer(&x)); }
    for (int n = 3; n <= 6; n++) {
        for (int i = n; i >= 1; i--) {
            snprintf(p, sizeof p, "%s/c%d_%d.sh", hd, n, i);
            if (i == n) snprintf(q, sizeof q, "#!%s\nexit 0\n", sh); else snprintf(q, sizeof q, "#!%s/c%d_%d.sh\n", hd, n, i + 1);
            script(p, q);
        }
        snprintf(p, sizeof p, "%s/c%d_1.sh", hd, n);
        char *const av[] = { "c", 0 }; struct ex x = { p, av, 0 };
        printf("exec of a chain of %d scripts: %s\n", n, exec_answer(&x));
    }
    snprintf(p, sizeof p, "%s/bare.sh", hd); script(p, "#!   \n");
    { char *const av[] = { "bare.sh", 0 }; struct ex x = { p, av, 0 }; printf("exec of a script with an empty #! line: %s\n", exec_answer(&x)); }
    snprintf(p, sizeof p, "%s/empty", hd); script(p, "");
    { char *const av[] = { "empty", 0 }; struct ex x = { p, av, 0 }; printf("exec of an empty executable: %s\n", exec_answer(&x)); }
    snprintf(p, sizeof p, "%s/dirinterp", hd); copy_self(p);
    if (interp_to_dir(p, "/usr/bin") == 0) { char *const av[] = { "dirinterp", 0 }; struct ex x = { p, av, 0 }; printf("exec of an ELF whose loader is a directory: %s\n", exec_answer(&x)); }
    else printf("exec of an ELF whose loader is a directory: static (no PT_INTERP)\n");
    close(hfd);
    return 0;
}
