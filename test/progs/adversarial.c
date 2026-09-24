/* adversarial.c — what a hostile program or a fuzzer would try (PROPOSAL.md 17.4): arguments with their upper 32 bits
 * set where the kernel takes an int, with the program's buffer checked past the count; the opener's own variables set
 * before an exec; a working directory deleted under the program; an exec with no descriptor left; mounts and roots
 * from inside; SIGSYS ignored, handled or fed to a signalfd; magic links under /proc/1; interpreter loops and chains;
 * an empty executable, a loader that is a directory. A second batch (sections 9 to 15): an exec with 0, 1 and 2 closed;
 * a pipe, a socket or /dev/null handed to fexecve; a hard link across the boundary, symlink chains at the kernel's
 * limit and one past it, odd spellings of the self magic links; the read-only rule from mknod, ftruncate and a shared
 * writable mapping; CLONE_FS, CLONE_FILES, not dumpable, PER_LINUX32, a vfork child and a handler on an alternate
 * stack; io_uring and clone3 refused; a saturated cache, a huge environment, bad pointers; execute-only files and
 * interpreters spelt oddly. usage: adversarial HOSTDIR, or "adversarial HOSTDIR --child".
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
#include <sys/mman.h>
#include <sys/sysmacros.h>
#include <sys/prctl.h>
#include <sys/personality.h>
#include <sys/wait.h>
#include <unistd.h>

extern char **environ;
#define HI (1UL << 32)                                        /* a bit the kernel never sees in an int argument */
/* the newest syscall numbers this test names, for a can whose headers predate them (the number is stable per arch) */
#if defined(__x86_64__)
#ifndef SYS_io_uring_setup
#define SYS_io_uring_setup 425
#endif
#ifndef SYS_clone3
#define SYS_clone3 435
#endif
#endif

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
struct ex { const char *path; char *const *argv; int nofds; void (*prep)(void); char *const *envp; };   /* nofds 1: the soft limit lowered to what
                                                                 * is open; 2: the hard one too; 3: 0, 1 and 2 closed; prep: run in the child first */
static const char *exec_answer(struct ex *x)
{
    static char b[200];
    int p[2], e[2]; pipe2(p, O_CLOEXEC); pipe(e);
    fflush(stdout);
    pid_t c = fork();
    if (c == 0) {
        dup2(e[1], 2); close(e[0]); close(e[1]);
        if (x->prep) x->prep();
        if (x->nofds == 3) { close(0); close(1); close(2); }
        if (x->nofds == 1 || x->nofds == 2) {
            dup2(p[1], 3); close(p[1]); fcntl(3, F_SETFD, FD_CLOEXEC);
            for (int fd = 4; fd < 1024; fd++) close(fd);
            struct rlimit rl; getrlimit(RLIMIT_NOFILE, &rl); rl.rlim_cur = 4; if (x->nofds == 2) rl.rlim_max = 4;
            setrlimit(RLIMIT_NOFILE, &rl);                     /* 0, 1, 2 and the pipe: nothing left to open with */
        }
        execve(x->path, x->argv, x->envp ? x->envp : environ);
        int err = errno; write(x->nofds == 1 || x->nofds == 2 ? 3 : p[1], &err, sizeof err); _exit(1);
    }
    close(p[1]); close(e[1]);
    int err = 0; ssize_t n = read(p[0], &err, sizeof err); close(p[0]);
    char se[160] = ""; ssize_t m = read(e[0], se, sizeof se - 1); close(e[0]); if (m > 0) { se[m] = 0; se[strcspn(se, "\n")] = 0; }
    int st = -1; waitpid(c, &st, 0);
    if (n == (ssize_t)sizeof err) { errno = err; return en(-1); }
    if (x->nofds == 1 || x->nofds == 2) snprintf(b, sizeof b, "ran");   /* what happens after the exec is the loader's under that limit: not the point */
    else if (WIFSIGNALED(st)) snprintf(b, sizeof b, "ran, killed by signal %d", WTERMSIG(st));
    else snprintf(b, sizeof b, "ran, exit %d%s%.60s", WIFEXITED(st) ? WEXITSTATUS(st) : -1, se[0] ? ": " : "", se);
    return b;
}
static void prep_linux32(void) { personality(PER_LINUX32); }
static volatile int program_handler_ran;
static char prep_dir[4096];
static void prep_chdir(void) { if (chdir(prep_dir) != 0) _exit(97); }
static void on_usr1(int s) { struct stat st; (void)s; if (stat("/usr/share/cont-test-marker", &st) == 0) program_handler_ran = 2; }

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

    /* 9. an exec with the standard descriptors closed, and traps with them closed: the opener owns none of 0, 1, 2 */
    {
        char tp[4096]; snprintf(tp, sizeof tp, "%s", sh); *strrchr(tp, '/') = 0; strcat(tp, "/true");
        char *const av[] = { "true", 0 };
        { struct ex x = { tp, av, 3, 0, 0 }; printf("exec with 0, 1 and 2 closed: %s\n", exec_answer(&x)); }
        { int keep = dup(1); close(0); close(1); close(2); int r0 = stat("/usr/share/cont-test-marker", &st); int r1 = open("/usr/share/cont-test-marker", O_RDONLY);
          int r2 = readlink("/proc/self/exe", buf, sizeof buf); dup2(keep, 1); close(keep); if (r1 >= 0) close(r1);
          printf("traps with 0, 1 and 2 closed: stat %s, open %s, readlink %s\n", r0 ? "failed" : "ok", r1 < 0 ? "failed" : "ok", r2 < 0 ? "failed" : "ok"); }
        /* 10. descriptors that name no file, given to exec; a device; /proc/self/exe by its own magic link */
        { int pp[2]; pipe(pp); char *const av2[] = { "x", 0 }; snprintf(q, sizeof q, "/proc/self/fd/%d", pp[0]);
          fflush(stdout); pid_t c = fork(); if (c == 0) { syscall(SYS_execveat, pp[0], "", av2, environ, AT_EMPTY_PATH); _exit(errno & 0x7f); }
          int st2; waitpid(c, &st2, 0); errno = WEXITSTATUS(st2); printf("fexecve of a pipe: %s\n", en(-1)); close(pp[0]); close(pp[1]); }
        { int sk = socket(AF_UNIX, SOCK_STREAM, 0); char *const av2[] = { "x", 0 };
          fflush(stdout); pid_t c = fork(); if (c == 0) { syscall(SYS_execveat, sk, "", av2, environ, AT_EMPTY_PATH); _exit(errno & 0x7f); }
          int st2; waitpid(c, &st2, 0); errno = WEXITSTATUS(st2); printf("fexecve of a socket: %s\n", en(-1)); close(sk); }
        { int dn = open("/dev/null", O_RDONLY); char *const av2[] = { "x", 0 };
          fflush(stdout); pid_t c = fork(); if (c == 0) { syscall(SYS_execveat, dn, "", av2, environ, AT_EMPTY_PATH); _exit(errno & 0x7f); }
          int st2; waitpid(c, &st2, 0); errno = WEXITSTATUS(st2); printf("fexecve of /dev/null: %s\n", en(-1)); close(dn); }
    }
    /* 11. links: a hard link across the can boundary is EXDEV, a symlink chain at the kernel's limit and one over it, the self magic links */
    {
        int cf = open("/usr/share/cont-test-marker", O_RDONLY);
        snprintf(q, sizeof q, "/proc/self/fd/%d", cf); snprintf(p, sizeof p, "%s/hostname", hd);
        P("linkat a can file by /proc/self/fd to a host name", linkat(AT_FDCWD, q, AT_FDCWD, p, AT_SYMLINK_FOLLOW));
        P("linkat a can file by empty path to a host name", linkat(cf, "", AT_FDCWD, p, AT_EMPTY_PATH));
        close(cf);
        for (int i = 41; i >= 1; i--) { snprintf(p, sizeof p, "%s/l%d", hd, i); if (i == 41) symlink("f", p); else { snprintf(q, sizeof q, "l%d", i + 1); symlink(q, p); } }
        snprintf(p, sizeof p, "%s/l2", hd); P("a chain of 40 symlinks", stat(p, &st));
        snprintf(p, sizeof p, "%s/l1", hd); P("a chain of 41 symlinks", stat(p, &st));
        char self[4096]; long m = readlink("/proc/self/exe", self, sizeof self - 1); self[m > 0 ? m : 0] = 0;
        snprintf(q, sizeof q, "/proc/self/task/%ld/exe", (long)syscall(SYS_gettid)); long n = readlink(q, buf, sizeof buf - 1); buf[n > 0 ? n : 0] = 0;
        printf("readlink /proc/self/task/tid/exe: %s\n", n > 0 && strcmp(buf, self) == 0 ? "the program" : "other");
        P("stat /proc/self/root/usr/share/cont-test-marker", stat("/proc/self/root/usr/share/cont-test-marker", &st));
        char slashes[4200]; memset(slashes, '/', 4000); strcpy(slashes + 4000, "usr/share/cont-test-marker");
        P("a path of 4000 slashes then a can file", stat(slashes, &st));
    }
    /* 12. the read-only rule from other angles: a device node, a read-only descriptor asked to write, a shared writable mapping, O_PATH with a write mode */
    P("mknod a char device in the can", mknod("/usr/share/cont-adv-dev", S_IFCHR | 0600, makedev(1, 3)));
    { int cf = open("/usr/share/cont-test-marker", O_RDONLY);
      P("ftruncate a read-only can descriptor", ftruncate(cf, 0));
      void *mm = mmap(0, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, cf, 0); printf("mmap PROT_WRITE MAP_SHARED of a read-only can descriptor: %s\n", mm == MAP_FAILED ? en(-1) : "mapped");
      if (mm != MAP_FAILED) munmap(mm, 4096);
      struct timespec mix[2] = { { 0, UTIME_NOW }, { 0, UTIME_OMIT } };
      P("utimensat can descriptor NULL path, NOW and OMIT", syscall(SYS_utimensat, cf, NULL, mix, 0));
      close(cf); }
    P("open a can file O_PATH with O_WRONLY", open("/usr/share/cont-test-marker", O_PATH | O_WRONLY));
    P("truncate /dev/null", truncate("/dev/null", 0));
    /* 13. the process's own shape changed: CLONE_FS, CLONE_FILES, not dumpable, PER_LINUX32, a vfork child that traps, an alternate stack */
    { fflush(stdout); pid_t c = fork(); if (c == 0) { int u = unshare(CLONE_FS); int r0 = chdir("/usr/share"); long g = syscall(SYS_getcwd, buf, sizeof buf);
        printf("unshare CLONE_FS then chdir into the can: %s, %s, getcwd %s\n", u ? "unshare failed" : "ok", r0 ? "chdir failed" : "ok", g > 0 ? buf : "failed"); fflush(stdout); _exit(0); } waitpid(c, 0, 0); }
    { fflush(stdout); pid_t c = fork(); if (c == 0) { int u = unshare(CLONE_FILES); int r0 = stat("/usr/share/cont-test-marker", &st); int r1 = open("/usr/share/cont-test-marker", O_RDONLY);
        printf("unshare CLONE_FILES then trap: %s, stat %s, open %s\n", u ? "unshare failed" : "ok", r0 ? "failed" : "ok", r1 < 0 ? "failed" : "ok"); fflush(stdout); _exit(0); } waitpid(c, 0, 0); }
    { fflush(stdout); pid_t c = fork(); if (c == 0) { prctl(PR_SET_DUMPABLE, 0); int r0 = stat("/usr/share/cont-test-marker", &st); long n = readlink("/proc/self/exe", buf, sizeof buf - 1);
        printf("not dumpable: stat %s, readlink exe %s\n", r0 ? "failed" : "ok", n > 0 ? "ok" : en(-1)); fflush(stdout); _exit(0); } waitpid(c, 0, 0); }
    { char tp[4096]; snprintf(tp, sizeof tp, "%s", sh); *strrchr(tp, '/') = 0; strcat(tp, "/true"); char *const av[] = { "true", 0 };
      struct ex x = { tp, av, 0, prep_linux32, 0 }; printf("PER_LINUX32 then exec of a wrapper: %s\n", exec_answer(&x)); }
    { fflush(stdout); pid_t c = vfork(); if (c == 0) { int r0 = stat("/usr/share/cont-test-marker", &st); _exit(r0 ? 1 : 0); }
      int st2; waitpid(c, &st2, 0); int r1 = stat("/usr/share/cont-test-marker", &st); printf("a vfork child that traps and exits: child %s, parent after %s\n", WEXITSTATUS(st2) ? "failed" : "ok", r1 ? "failed" : "ok"); }
    { static char altstack[16384]; stack_t ss = { altstack, 0, sizeof altstack }; sigaltstack(&ss, 0);
      struct sigaction sa = { .sa_handler = on_usr1, .sa_flags = SA_ONSTACK }; sigaction(SIGUSR1, &sa, 0); raise(SIGUSR1);
      printf("a trap from a handler on a 16 KB alternate stack: %s\n", program_handler_ran == 2 ? "ok" : "no"); }
    /* 14. the refusals of 7.4.2 by name, a descriptor on a renamed directory, the cache saturated, a huge environment, bad vectors */
    { unsigned char params[128]; memset(params, 0, sizeof params);   /* 0 entries: EINVAL and no ring created; the filter answers ENOSYS either way */
      P("io_uring_setup", syscall(SYS_io_uring_setup, 0, params)); }
    { unsigned long ca[16]; memset(ca, 0, sizeof ca); ca[0] = ~0UL;   /* an invalid flags word: EINVAL and never a child; the filter answers ENOSYS */
      P("clone3", syscall(SYS_clone3, ca, sizeof ca)); }
    { snprintf(p, sizeof p, "%s/d1", hd); mkdir(p, 0755); int dfd = open(p, O_RDONLY | O_DIRECTORY); snprintf(q, sizeof q, "%s/d1/f", hd); close(open(q, O_WRONLY | O_CREAT, 0644));
      snprintf(q, sizeof q, "%s/d2", hd); rename(p, q); P("openat on a descriptor of a directory renamed meanwhile", openat(dfd, "f", O_RDONLY)); close(dfd); }
    { int bad = 0; for (int i = 0; i < 20000; i++) { snprintf(q, sizeof q, "/usr/share/cont-absent-%d", i); if (stat(q, &st) == 0 || errno != ENOENT) bad++; }
      int r0 = stat("/usr/share/cont-test-marker", &st); int r1 = stat("/usr/share/cont-absent-x", &st);
      printf("20000 absent can paths then a present and an absent one: %d wrong, present %s, absent %s\n", bad, r0 ? "failed" : "ok", r1 == 0 || errno != ENOENT ? "wrong" : "ENOENT"); }
    { char tp[4096]; snprintf(tp, sizeof tp, "%s", sh); *strrchr(tp, '/') = 0; strcat(tp, "/true"); char *const av[] = { "true", 0 };
      static char *big[50002]; static char strs[50000][12]; for (int i = 0; i < 50000; i++) { snprintf(strs[i], 12, "V%d=%d", i, i); big[i] = strs[i]; } big[50000] = 0;
      struct ex x = { tp, av, 0, 0, big }; printf("exec of a wrapper with 50000 environment entries: %s\n", exec_answer(&x)); }
    { char tp[4096]; snprintf(tp, sizeof tp, "%s", sh); *strrchr(tp, '/') = 0; strcat(tp, "/true"); char *const av[] = { "true", (char *)0x10, 0 };
      struct ex x = { tp, av, 0, 0, 0 }; printf("exec with a bad pointer among argv: %s\n", exec_answer(&x)); }
    { char *pg = mmap(0, 8192, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0); mprotect(pg + 4096, 4096, PROT_NONE);
      snprintf(q, sizeof q, "%s/hl_long", hd); symlink("0123456789abcdef0123456789abcdef", q);
      P("readlink whose write crosses into an unmapped page", readlink(q, pg + 4090, 32)); munmap(pg, 8192); }
    /* 15. execute-only files the loader cannot read (limitation), the stated limitation 12, and interpreters spelt oddly */
    snprintf(p, sizeof p, "%s/unreadable", hd); copy_self(p); chmod(p, 0111);
    { char *const av[] = { "u", (char *)hd, "--child", 0 }; struct ex x = { p, av, 0, 0, 0 }; printf("exec of an ELF with mode 0111: %s\n", exec_answer(&x)); }
    snprintf(p, sizeof p, "%s/unreadable.sh", hd); script(p, "#!/bin/sh\nexit 0\n"); chmod(p, 0111);
    { char *const av[] = { "u.sh", 0 }; struct ex x = { p, av, 0, 0, 0 }; printf("exec of a script with mode 0111: %s\n", exec_answer(&x)); }
    snprintf(p, sizeof p, "%s/interp.sh", hd); snprintf(q, sizeof q, "#!%s\nexit 0\n", sh); script(p, q);
    snprintf(p, sizeof p, "%s/rel.sh", hd); script(p, "#!./interp.sh\n");
    { char *const av[] = { "rel.sh", 0 }; strcpy(prep_dir, hd); struct ex x = { p, av, 0, prep_chdir, 0 };   /* the interpreter is relative to the cwd the child sets */
      printf("exec of a script whose interpreter is relative: %s\n", exec_answer(&x)); }
    snprintf(p, sizeof p, "%s/twoopts.sh", hd); snprintf(q, sizeof q, "#!%s -e -x\nexit 0\n", sh); script(p, q);
    { char *const av[] = { "t.sh", 0 }; struct ex x = { p, av, 0, 0, 0 }; const char *a = exec_answer(&x);   /* the kernel passes "-e -x" as one argument; the shell rejects it (the exit code varies) */
      printf("exec of a script whose #! has two options: %s\n", strstr(a, "ran, exit 0") ? "ran (the argument was split)" : "one argument, the shell rejected it"); }
    { char *const av[] = { "sh", "-c", "exit 0", 0 }; static char *none[] = { 0 };      /* the opener sets and strips its own variables even from an empty environment */
      struct ex x = { sh, av, 0, 0, none }; printf("exec of a wrapper with an empty environment: %s\n", exec_answer(&x)); }
    close(hfd);
    return 0;
}
