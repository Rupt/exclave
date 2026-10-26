/* fexec.c — exec of a descriptor that has no path (DESIGN.md 13 item 25, 17.4): a memfd holding an ELF, an unlinked
 * file, a script in a memfd, with and without close-on-exec. usage: fexec HOSTDIR, or "fexec child" as the program it
 * re-executes. Prints one line per case, "<case>: ret=<r> errno=<e> status=<s> out=<first line>", the same in every
 * world, so the kernel under bwrap is the oracle. Exit 0 always. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

static void run_case(const char *name, int fd, const char *path, int flags, char *const argv[])
{
    int pipefd[2]; if (pipe(pipefd)) { perror("pipe"); return; }
    fflush(stdout);
    pid_t pid = fork();
    if (pid == 0) {
        dup2(pipefd[1], 1); close(pipefd[0]); close(pipefd[1]);
        int dn = open("/dev/null", O_RDONLY); if (dn >= 0) { dup2(dn, 0); close(dn); }
        errno = 0;
        long r = syscall(SYS_execveat, fd, path, argv, environ, flags);
        printf("execveat failed: ret=%ld errno=%d\n", r, errno);
        _exit(100 + (errno & 0xff));
    }
    close(pipefd[1]);
    char out[512] = ""; ssize_t n = read(pipefd[0], out, sizeof out - 1); if (n > 0) out[n] = 0; close(pipefd[0]);
    char *nl = strchr(out, '\n'); if (nl) *nl = 0;
    int st = -1; waitpid(pid, &st, 0);
    if (WIFEXITED(st) && WEXITSTATUS(st) >= 100)
        printf("%s: ret=-1 errno=%d\n", name, WEXITSTATUS(st) - 100);
    else
        printf("%s: ret=0 errno=0 status=%d out=%s\n", name, WIFEXITED(st) ? WEXITSTATUS(st) : -1, out);
}
static int memfd_with(const char *name, const void *data, size_t n, unsigned flags)
{
    int fd = (int)syscall(SYS_memfd_create, name, flags);
    if (fd < 0) return -1;
    if (write(fd, data, n) != (ssize_t)n) { close(fd); return -1; }
    return fd;
}
static char *slurp(const char *path, size_t *n)
{
    int fd = open(path, O_RDONLY); if (fd < 0) return 0;
    size_t cap = 1 << 20, len = 0; char *b = malloc(cap);
    for (;;) { ssize_t r = read(fd, b + len, cap - len); if (r <= 0) break; len += (size_t)r; if (len == cap) { cap *= 2; b = realloc(b, cap); } }
    close(fd); *n = len; return b;
}

int main(int argc, char **argv)
{
    if (argc >= 2 && strcmp(argv[1], "child") == 0) {
        char exe[4096]; ssize_t n = readlink("/proc/self/exe", exe, sizeof exe - 1); exe[n > 0 ? n : 0] = 0;
        char *base = strrchr(exe, '/');
        printf("child ran, exe %s, argv0 %s\n", n > 0 ? (base ? base + 1 : exe) : "(unreadable)", argv[0]);
        return 7;
    }
    if (argc < 2) { fprintf(stderr, "usage: fexec HOSTDIR | fexec child\n"); return 2; }
    const char *host = argv[1];
    size_t n; char *elf = slurp("/proc/self/exe", &n);
    if (!elf) { printf("cannot read /proc/self/exe: errno=%d\n", errno); return 0; }
    char *const child[] = { "fexec", "child", 0 };
    char *const child_named[] = { "memfd-program", "child", 0 };
    { int fd = memfd_with("prog", elf, n, 0); run_case("memfd elf", fd, "", AT_EMPTY_PATH, child); close(fd); }
    { int fd = memfd_with("prog", elf, n, 1 /* MFD_CLOEXEC */); run_case("memfd elf cloexec", fd, "", AT_EMPTY_PATH, child_named); close(fd); }
    { char p[4096]; snprintf(p, sizeof p, "%s/unlinked-prog", host);
      int w = open(p, O_WRONLY | O_CREAT | O_TRUNC, 0755); if (w >= 0) { write(w, elf, n); close(w); }
      int fd = open(p, O_RDONLY); unlink(p); run_case("unlinked elf", fd, "", AT_EMPTY_PATH, child); close(fd); }
    static const char script[] = "#!/bin/sh\necho script ran, argv0 $0\n";
    { int fd = memfd_with("script", script, sizeof script - 1, 0); run_case("memfd script", fd, "", AT_EMPTY_PATH, child); close(fd); }
    { int fd = memfd_with("script", script, sizeof script - 1, 1); run_case("memfd script cloexec", fd, "", AT_EMPTY_PATH, child); close(fd); }
    { char p[4096]; snprintf(p, sizeof p, "%s/unlinked-script", host);
      int w = open(p, O_WRONLY | O_CREAT | O_TRUNC, 0755); if (w >= 0) { write(w, script, sizeof script - 1); close(w); }
      int fd = open(p, O_RDONLY); unlink(p); run_case("unlinked script", fd, "", AT_EMPTY_PATH, child); close(fd); }
    { char p[4096]; snprintf(p, sizeof p, "%s/linked-prog", host);
      int w = open(p, O_WRONLY | O_CREAT | O_TRUNC, 0755); if (w >= 0) { write(w, elf, n); close(w); }
      int fd = open(p, O_RDONLY); run_case("fd with a path (control)", fd, "", AT_EMPTY_PATH, child); close(fd); unlink(p); }
    free(elf);
    return 0;
}
