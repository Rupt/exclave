/* exec.c — exec fidelity: /proc/self/exe, own ELF header, fexecve of a wrapper and of a payload, execvp past a
 * non-executable PATH hit, a program with its own seccomp filter, personality. Mode in argv[1]. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/personality.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>
extern char **environ;

int main(int argc, char **argv)
{
    const char *mode = argc > 1 ? argv[1] : "";
    if (!strcmp(mode, "child")) { printf("child ok argv0=%s\n", argv[0]); return 0; }
    if (!strcmp(mode, "self")) { execl("/proc/self/exe", argv[0], "child", (char *)0); perror("execl /proc/self/exe"); return 1; }
    if (!strcmp(mode, "header")) {
        char exe[4096]; ssize_t n = readlink("/proc/self/exe", exe, sizeof exe - 1); if (n < 0) { perror("readlink"); return 1; } exe[n] = 0;
        if (argc > 2 && strcmp(exe, argv[2])) { printf("FAIL exe=%s wanted %s\n", exe, argv[2]); return 1; }
        int fd = open("/proc/self/exe", O_RDONLY); unsigned char h[4]; struct stat a, b;
        if (fd < 0 || read(fd, h, 4) != 4 || memcmp(h, "\177ELF", 4) || fstat(fd, &a) || stat(exe, &b) || a.st_size != b.st_size) { printf("FAIL own header\n"); return 1; }
        printf("header ok %s\n", exe); return 0;
    }
    if (!strncmp(mode, "fexecve", 7)) {
        const char *p = !strcmp(mode, "fexecve_payload") ? "/usr/bin/.real/true" : "/usr/bin/true";
        int fd = open(p, !strcmp(mode, "fexecve_opath") ? O_PATH : O_RDONLY); if (fd < 0) { perror(p); return 1; }
        char *av[] = { "true", 0 }; fexecve(fd, av, environ); perror("fexecve"); return 1;
    }
    if (!strcmp(mode, "execvp")) { char *av[] = { "true", 0 }; execvp("true", av); perror("execvp"); return 1; }
    if (!strcmp(mode, "seccomp")) {
        struct sock_filter f[] = { BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW) }; struct sock_fprog p = { 1, f };
        /* 7.4.2: a program's own sandbox is refused with ENOSYS; the availability query is answered */
        if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) { perror("no_new_privs"); return 1; }
        errno = 0; if (syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER, 0, &p) != -1 || errno != ENOSYS) { printf("FAIL seccomp install: errno=%d\n", errno); return 1; }
        errno = 0; if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &p) != -1 || errno != ENOSYS) { printf("FAIL prctl seccomp: errno=%d\n", errno); return 1; }
        unsigned act = SECCOMP_RET_TRAP; if (syscall(SYS_seccomp, SECCOMP_GET_ACTION_AVAIL, 0, &act) != 0) { printf("FAIL seccomp availability query\n"); return 1; }
        struct stat st; if (stat("/usr/share/cont-test-marker", &st)) { printf("FAIL stat after refused filter\n"); return 1; }
        execl("/usr/bin/true", "true", (char *)0); perror("execl"); return 1;
    }
    if (!strcmp(mode, "personality")) { personality(ADDR_NO_RANDOMIZE); execl("/proc/self/exe", argv[0], "child", (char *)0); perror("execl"); return 1; }
    if (!strcmp(mode, "script")) { execl(argv[2], argv[2], "arg1", (char *)0); perror("execl script"); return 1; }
    fprintf(stderr, "unknown mode\n"); return 2;
}
