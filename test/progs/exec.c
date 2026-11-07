/* exec.c — exec fidelity: /proc/self/exe, own ELF header, fexecve of a wrapper and of an original, execvp past a
 * non-executable PATH hit, a program with its own seccomp filter, the persona an exec keeps. Mode in argv[1]. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/personality.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <unistd.h>
extern char **environ;

int main(int argc, char **argv)
{
    /* run with an empty or a NULL argv (vectors): what the kernel made of it */
    if (argc <= 1) {
        printf("argc %d argv0 '%s'\n", argc, argc ? argv[0] : "(null)");
        return 0;
    }
    const char *mode = argv[1];
    if (!strcmp(mode, "child")) {
        printf("child ok argv0=%s\n", argv[0]);
        return 0;
    }
    if (!strcmp(mode, "self")) {
        execl("/proc/self/exe", argv[0], "child", (char *)0);
        perror("execl /proc/self/exe");
        return 1;
    }
    if (!strcmp(mode, "header")) {
        char exe[4096];
        ssize_t n = readlink("/proc/self/exe", exe, sizeof exe - 1);
        if (n < 0) {
            perror("readlink");
            return 1;
        }
        exe[n] = 0;
        if (argc > 2 && strcmp(exe, argv[2])) {
            printf("FAIL exe=%s wanted %s\n", exe, argv[2]);
            return 1;
        }
        int fd = open("/proc/self/exe", O_RDONLY);
        unsigned char h[4];
        struct stat a, b;
        if (fd < 0 || read(fd, h, 4) != 4 || memcmp(h, "\177ELF", 4) || fstat(fd, &a) || stat(exe, &b) ||
            a.st_size != b.st_size) {
            printf("FAIL own header\n");
            return 1;
        }
        printf("header ok %s\n", exe);
        return 0;
    }
    /* fexecve_payload PATH ARGV...: an original's descriptor, which the handler maps back to its wrapper */
    if (!strcmp(mode, "fexecve_payload") && argc > 3) {
        int fd = open(argv[2], O_RDONLY);
        if (fd < 0) {
            perror(argv[2]);
            return 1;
        }
        fexecve(fd, argv + 3, environ);
        perror("fexecve");
        return 1;
    }
    if (!strncmp(mode, "fexecve", 7)) {
        const char *p = getenv("EXCLAVE_TEST_TRUE") ? getenv("EXCLAVE_TEST_TRUE") : "/usr/bin/true";
        int fd = open(p, !strcmp(mode, "fexecve_opath") ? O_PATH : O_RDONLY);
        if (fd < 0) {
            perror(p);
            return 1;
        }
        char *av[] = {"true", 0};
        fexecve(fd, av, environ);
        perror("fexecve");
        return 1;
    }
    if (!strcmp(mode, "execvp")) {
        char *av[] = {"true", 0};
        execvp("true", av);
        perror("execvp");
        return 1;
    }
    if (!strcmp(mode, "seccomp")) {
        struct sock_filter f[] = {BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW)};
        struct sock_fprog p = {1, f};
        /* 7.4.2: a program's own sandbox is installed, in either form, the queries are answered, and the filter is
         * inherited by the exec that follows, which runs under it */
        if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) {
            perror("no_new_privs");
            return 1;
        }
        errno = 0;
        /* a kernel before 3.17 has no seccomp(2): the prctl form below then stands alone */
        long r = syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER, 0, &p);
        int no_syscall = r != 0 && errno == ENOSYS;
        if (r != 0 && !no_syscall) {
            printf("FAIL seccomp install: errno=%d\n", errno);
            return 1;
        }
        errno = 0;
        if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &p) != 0) {
            printf("FAIL prctl seccomp: errno=%d\n", errno);
            return 1;
        }
        unsigned act = SECCOMP_RET_TRAP;
        /* 4.14's query, which a kernel without seccomp(2) cannot be asked */
        if (!no_syscall && syscall(SYS_seccomp, SECCOMP_GET_ACTION_AVAIL, 0, &act) != 0 && errno != EINVAL) {
            printf("FAIL seccomp availability query\n");
            return 1;
        }
        struct stat st;
        if (stat("/usr/share/exclave-test-marker", &st)) {
            printf("FAIL stat under the filter\n");
            return 1;
        }
        execl(getenv("EXCLAVE_TEST_TRUE") ? getenv("EXCLAVE_TEST_TRUE") : "/usr/bin/true", "true", (char *)0);
        perror("execl");
        return 1;
    }
    /* the persona an exec keeps (begin_new_exec clears only PER_CLEAR_ON_SETID, and that for setid), and where the
     * program's own code landed, the same in every run without randomisation */
    if (!strcmp(mode, "persona")) {
        struct utsname u;
        uname(&u);
        printf("personality %#x machine %s main %p\n", personality(0xffffffff), u.machine, (void *)main);
        return 0;
    }
    if (!strcmp(mode, "personality") && argc > 3) { /* personality FLAGS PROGRAM ARGS... */
        personality(strtoul(argv[2], 0, 0));
        execv(argv[3], argv + 3);
        perror("execv");
        return 1;
    }
    if (!strcmp(mode, "script")) {
        execl(argv[2], argv[2], "arg1", (char *)0);
        perror("execl script");
        return 1;
    }
    if (!strcmp(mode, "showenv")) {
        printf("A=%s B=%s EXCLAVE_COMMX=%s\n", getenv("A") ? getenv("A") : "-", getenv("B") ? getenv("B") : "-",
               getenv("EXCLAVE_COMMX") ? getenv("EXCLAVE_COMMX") : "-");
        return 0;
    }
    /* a variable in the last bytes before an unmapped page, between others: the handler
     * reads every variable's head in one batch, and one it cannot read whole falls back
     * to its own read without losing the rest (DESIGN.md 16.6 item 6) */
    if (!strcmp(mode, "envedge")) {
        char *pg = mmap(0, 8192, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (pg == MAP_FAILED) {
            perror("mmap");
            return 1;
        }
        munmap(pg + 4096, 4096);
        char *edge = pg + 4096 - 4;
        memcpy(edge, "A=1", 4);
        char *ev[] = {"B=2", edge, "EXCLAVE_COMMX=keep", "EXCLAVE_EXEC=/bogus", 0}, *av[] = {argv[2], "showenv", 0};
        execve(argv[2], av, ev);
        perror("execve");
        return 1;
    }
    /* NULL and bad vectors behave as the kernel makes them: the errno, and a line "TARGET CASE: OUTPUT" with the first
     * line the program wrote */
    if (!strcmp(mode, "vectors")) {
        int fails = 0;
        for (int t = 2; t < argc; t++) {
            struct {
                const char *name;
                char **av;
                char **ev;
                int want;
            } cases[] = {{"null/null", 0, 0, 0},
                         {"null/env", 0, environ, 0},
                         {"argv/null", (char *[]){"x", "child", 0}, 0, 0},
                         {"bad argv", (char **)1, environ, EFAULT},
                         {"bad envp", (char *[]){"x", "child", 0}, (char **)1, EFAULT}};
            for (unsigned i = 0; i < sizeof cases / sizeof cases[0]; i++) {
                int o[2];
                if (pipe(o)) {
                    perror("pipe");
                    return 1;
                }
                fflush(stdout);
                pid_t p = fork();
                if (p == 0) {
                    dup2(o[1], 1);
                    close(o[0]);
                    close(o[1]);
                    execve(argv[t], cases[i].av, cases[i].ev);
                    _exit(errno == EFAULT ? 77 : 78);
                }
                close(o[1]);
                char out[512];
                ssize_t n = 0, m;
                while (n < (ssize_t)sizeof out - 1 && (m = read(o[0], out + n, sizeof out - 1 - (size_t)n)) > 0) n += m;
                close(o[0]);
                out[n] = 0;
                out[strcspn(out, "\n")] = 0;
                printf("%s %s: %s\n", argv[t], cases[i].name, out);
                int st;
                waitpid(p, &st, 0);
                int got = WIFSIGNALED(st)         ? -WTERMSIG(st)
                          : WEXITSTATUS(st) == 77 ? EFAULT
                          : WEXITSTATUS(st) == 78 ? -1
                                                  : 0;
                if (got != cases[i].want) {
                    fails++;
                    printf("FAIL %s %s: got %d wanted %d\n", argv[t], cases[i].name, got, cases[i].want);
                }
            }
        }
        printf("vectors: %d failures\n", fails);
        return fails ? 1 : 0;
    }
    if (!strcmp(mode, "nofollow")) { /* execveat of a symlink itself is ELOOP */
        errno = 0;
        syscall(SYS_execveat, AT_FDCWD, getenv("EXCLAVE_TEST_SH") ? getenv("EXCLAVE_TEST_SH") : "/usr/bin/sh",
                (char *[]){"sh", "-c", "echo RAN", 0}, environ, AT_SYMLINK_NOFOLLOW);
        printf("%d\n", errno);
        return errno == ELOOP ? 0 : 1;
    }
    /* close everything, open a file, trap: the log must not land in it */
    if (!strcmp(mode, "closefds")) {
        for (int fd = 3; fd < 1024; fd++) close(fd);
        int fd = open(argv[2], O_WRONLY | O_CREAT | O_TRUNC, 0644);
        if (write(fd, "line one\n", 9) != 9) {
            perror(argv[2]);
            return 1;
        }
        struct stat st;
        stat("/usr/share", &st);
        stat(getenv("EXCLAVE_TEST_SH") ? getenv("EXCLAVE_TEST_SH") : "/usr/bin/sh", &st);
        if (write(fd, "line two\n", 9) != 9) {
            perror(argv[2]);
            return 1;
        }
        close(fd);
        printf("closefds done fd=%d\n", fd);
        return 0;
    }
    /* the kernel's permission triads, not "anyone may execute" */
    if (!strcmp(mode, "perm")) {
        int fails = 0;
        for (int i = 2; i < argc; i++) {
            errno = 0;
            execl(argv[i], argv[i], (char *)0);
            if (errno != EACCES) {
                fails++;
                printf("FAIL exec %s: errno %d\n", argv[i], errno);
            }
        }
        printf("perm: %d failures\n", fails);
        return fails ? 1 : 0;
    }
    fprintf(stderr, "unknown mode\n");
    return 2;
}
