/* exe_link.c — another process's /proc/<pid>/exe (DESIGN.md 7.6, 13 item 10): a forked child reads, stats and runs its
 * parent's exe link, by the parent's pid and through a descriptor on the parent's /proc/self opened before the fork.
 * Natively the link names the program the parent runs; the launcher once named itself, and running the link ran the
 * launcher without a program. usage: exe_link, or "exe_link --ran LABEL" as what the exec runs. Prints one line per
 * case, "<case>: <answer>", the same in every world, so the kernel under bwrap is the oracle. Exit 0 always. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

/* the exec in a child of the child, its one line of output read back, or "<tag>: errno=N" when the exec fails */
static void run_link(const char *tag, int dfd, const char *path, const char *self)
{
    int p[2];
    if (pipe(p)) {
        printf("%s: pipe errno=%d\n", tag, errno);
        return;
    }
    pid_t c = fork();
    if (c == 0) {
        dup2(p[1], 1);
        close(p[0]);
        close(p[1]);
        char a0[] = "exe_link", a1[] = "--ran", t[64];
        snprintf(t, sizeof t, "%s", tag);
        char *av[] = {a0, a1, t, 0};
        syscall(SYS_execveat, dfd, path, av, environ, 0);
        printf("%s: errno=%d\n", tag, errno);
        fflush(stdout);
        _exit(0);
    }
    close(p[1]);
    char buf[512];
    long n = 0, r;
    while ((r = read(p[0], buf + n, sizeof buf - 1 - (size_t)n)) > 0) n += r;
    buf[n > 0 ? n : 0] = 0;
    close(p[0]);
    waitpid(c, 0, 0);
    fputs(buf, stdout);
    (void)self;
}

int main(int argc, char **argv)
{
    if (argc == 3 && strcmp(argv[1], "--ran") == 0) {
        printf("%s: ran\n", argv[2]);
        return 0;
    }
    setvbuf(stdout, 0, _IOLBF, 0);
    char self[4096];
    long n = readlink("/proc/self/exe", self, sizeof self - 1);
    if (n < 0) {
        printf("self exe: errno=%d\n", errno);
        return 0;
    }
    self[n] = 0;
    struct stat own;
    stat("/proc/self/exe", &own);
    int procself = open("/proc/self", O_PATH | O_DIRECTORY);
    pid_t parent = getpid();
    fflush(stdout);
    pid_t c = fork();
    if (c == 0) {
        char link[64], text[4096];
        snprintf(link, sizeof link, "/proc/%d/exe", (int)parent);
        n = readlink(link, text, sizeof text - 1);
        if (n < 0) printf("readlink parent exe: errno=%d\n", errno);
        else {
            text[n] = 0;
            printf("readlink parent exe: %s\n", strcmp(text, self) == 0 ? "the program" : text);
        }
        n = readlinkat(procself, "exe", text, sizeof text - 1);
        if (n < 0) printf("readlinkat procself exe: errno=%d\n", errno);
        else {
            text[n] = 0;
            printf("readlinkat procself exe: %s\n", strcmp(text, self) == 0 ? "the program" : text);
        }
        struct stat st;
        if (stat(link, &st)) printf("stat parent exe: errno=%d\n", errno);
        else
            printf("stat parent exe: %s\n",
                   st.st_ino == own.st_ino && st.st_dev == own.st_dev ? "the program" : "another file");
        int fd = open(link, O_RDONLY);
        if (fd < 0) printf("open parent exe: errno=%d\n", errno);
        else {
            if (fstat(fd, &st)) printf("open parent exe: fstat errno=%d\n", errno);
            else
                printf("open parent exe: %s\n",
                       st.st_ino == own.st_ino && st.st_dev == own.st_dev ? "the program" : "another file");
            close(fd);
        }
        run_link("exec parent exe", AT_FDCWD, link, self);
        run_link("exec procself exe", procself, "exe", self);
        _exit(0);
    }
    waitpid(c, 0, 0);
    return 0;
}
