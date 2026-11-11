/* mem_edge.c — what a call is given at the very end of a mapping (DESIGN.md 7.5.6, 13 item 15): a path, an attribute's
 * name, a vector of arguments or of variables and a variable whose last byte is the mapping's last, and a buffer that
 * ends there. The kernel reads a string up to its NUL and a vector up to its NULL and no further, so each call answers
 * as it would anywhere else, and a string or a vector that is not ended before its mapping is, is EFAULT. One line per
 * case. usage: mem_edge HOSTDIR (HOSTDIR: a writable host directory; run by a path with a slash) */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/xattr.h>
#include <unistd.h>

static size_t page;

/* the end of a mapping of one page, with a page after it that cannot be read */
static char *edge(void)
{
    char *m = mmap(0, 2 * page, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (m == MAP_FAILED || mprotect(m + page, page, PROT_NONE)) {
        perror("mmap");
        exit(2);
    }
    return m + page;
}
/* s in the last bytes of a mapping, its NUL the last of them */
static char *at_edge(const char *s)
{
    size_t n = strlen(s) + 1;
    return memcpy(edge() - n, s, n);
}
/* the n pointers of v in the last words of a mapping */
static char **vec_at_edge(char *const *v, size_t n) { return memcpy(edge() - n * sizeof *v, v, n * sizeof *v); }

static const char *answer(long r) { return r < 0 ? strerror(errno) : "ok"; }

/* exec this program as "show LABEL", which prints the case's line, or print execve's refusal */
static void run(const char *label, const char *self, char **av, char **ev)
{
    fflush(stdout);
    pid_t p = fork();
    if (p == 0) {
        execve(self, av, ev);
        printf("%s: %s\n", label, strerror(errno));
        fflush(stdout);
        _exit(1);
    }
    waitpid(p, 0, 0);
}

int main(int argc, char **argv)
{
    if (argc > 2 && !strcmp(argv[1], "show")) {
        const char *a = getenv("A"), *b = getenv("B");
        printf("%s: ran with %d arguments, A=%s B=%s\n", argv[2], argc, a ? a : "-", b ? b : "-");
        return 0;
    }
    if (argc != 2) {
        fprintf(stderr, "usage: mem_edge HOSTDIR\n");
        return 2;
    }
    page = (size_t)sysconf(_SC_PAGESIZE);
    struct stat st;
    char f[2048], l[2048], buf[64];
    snprintf(f, sizeof f, "%s/f", argv[1]);
    snprintf(l, sizeof l, "%s/l", argv[1]);
    close(open(f, O_WRONLY | O_CREAT, 0600));
    unlink(l);
    if (symlink("target", l)) perror("symlink");

    /* a path: its window is the handler's, 256 bytes and then the rest of PATH_MAX */
    char *p = at_edge(f);
    printf("stat, a path that ends where its mapping does: %s\n", answer(stat(p, &st)));
    int fd = open(p, O_RDONLY);
    printf("open, the same path: %s\n", answer(fd));
    if (fd >= 0) close(fd);
    /* 300 bytes: the directory, then ./ as often as it takes, then the name */
    char longp[512];
    size_t n = strlen(argv[1]);
    memcpy(longp, argv[1], n);
    while (n < 298) {
        longp[n++] = '/';
        longp[n++] = '.';
    }
    memcpy(longp + n, "/f", 3);
    printf("stat, a path of 300 bytes that ends there: %s\n", answer(stat(at_edge(longp), &st)));
    char *off = edge() - 96;
    memset(off, '/', 96);
    printf("stat, a path that runs off its mapping: %s\n", answer(stat(off, &st)));

    /* an attribute's name: read before the path, 256 bytes of it */
    long r = getxattr(f, at_edge("user.edge"), buf, sizeof buf);
    printf("getxattr, a name that ends there: %s\n", answer(r));

    /* a buffer the handler writes: the link's text and no more */
    char *b6 = edge() - 6;
    printf("readlink, a buffer of the text's length that ends there: %ld\n", (long)readlink(l, b6, 6));
    printf("readlink, a size that runs off the mapping: %ld\n", (long)readlink(l, b6, 64));
    printf("readlink, a path and a buffer that end there: %ld\n", (long)readlink(at_edge(l), edge() - 6, 6));

    /* exec: the vectors are read to their NULL, each variable's head for the launcher's own names */
    char *self = argv[0];
    char *ev[] = {"A=1", "B=2", 0};
    {
        char *av[] = {self, "show", "exec, an argument vector that ends there", 0};
        run(av[2], self, vec_at_edge(av, 4), ev);
    }
    {
        char *av[] = {self, "show", "exec, an environment vector that ends there", 0};
        run(av[2], self, av, vec_at_edge(ev, 3));
    }
    {
        char *av[] = {self, "show", "exec, a variable that ends there", 0}, *ev2[] = {at_edge("A=1"), "B=2", 0};
        run(av[2], self, av, ev2);
    }
    {
        char *av[] = {self, "show", "exec, a path and an argument that end there", 0};
        av[2] = at_edge(av[2]);
        run(av[2], at_edge(self), av, ev);
    }
    {
        char *av[] = {self, "show", "exec, an argument vector that runs off its mapping"};
        run(av[2], self, vec_at_edge(av, 3), ev);
    }
    {
        char *av[] = {self, "show", "exec, an environment vector that runs off its mapping", 0};
        run(av[2], self, av, vec_at_edge(ev, 2));
    }
    unlink(f);
    unlink(l);
    return 0;
}
