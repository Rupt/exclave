/* listing.c — a directory's listing through getdents64 and getdents (DESIGN.md 8.3): the same names at every buffer
 * size, .real never among them, a count read as the unsigned int the kernel reads, a buffer that runs into a
 * read-only page answered with the records the kernel can write, and a record's d_off that the listing resumes from.
 * usage: listing DIR; prints the names of the first listing, one per line, sorted, then one line per case. Exit 0. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>

enum { MAXN = 8192 };
static char *names[MAXN], *first[MAXN];
static long offs[MAXN];
static int count_names;
static unsigned long longest; /* the longest record of the last listing */

static int cmp(const void *x, const void *y) { return strcmp(*(char *const *)x, *(char *const *)y); }

/* every name of dir through nr at buffer size size, into names and offs; the count, or -errno */
static int list(const char *dir, long nr, unsigned long size)
{
    static char buf[65536];
    int fd = open(dir, O_RDONLY | O_DIRECTORY), n = 0;
    if (fd < 0) return -errno;
    longest = 0;
    for (;;) {
        long got = syscall(nr, fd, buf, size);
        if (got < 0) {
            n = -errno;
            break;
        }
        if (got == 0) break;
        for (long o = 0; o < got;) {
            unsigned short len = *(unsigned short *)(buf + o + 16);
            if (len > longest) longest = len;
            const char *name = buf + o + (nr == SYS_getdents64 ? 19 : 18);
            if (n < MAXN) {
                names[n] = strdup(name);
                offs[n] = *(long *)(buf + o + 8); /* d_off, at 8 in both records */
                n++;
            }
            o += len;
        }
    }
    close(fd);
    return n;
}

static void mode(const char *dir, const char *label, long nr, unsigned long size)
{
    const char *at = size == 4096 ? "4096" : size == 32768 ? "32768" : "the longest record";
    if (!size) { /* the longest record's size: a batch of one record, or a few short ones */
        if (list(dir, nr, 4096) < 0) return;
        size = longest;
    }
    int n = list(dir, nr, size), real = 0, same;
    if (n < 0) {
        printf("%s %s: errno %d\n", label, at, -n);
        return;
    }
    for (int i = 0; i < n; i++) real |= strcmp(names[i], ".real") == 0;
    qsort(names, (size_t)n, sizeof *names, cmp);
    same = n == count_names;
    for (int i = 0; same && i < n; i++) same = strcmp(names[i], first[i]) == 0;
    printf("%s %s: %s, %s\n", label, at, same ? "the same names" : "other names", real ? ".real listed" : "no .real");
}

int main(int argc, char **argv)
{
    if (argc != 2) return 2;
    const char *dir = argv[1];
    int n = list(dir, SYS_getdents64, 4096);
    if (n < 0) {
        printf("listing: errno %d\n", -n);
        return 0;
    }
    qsort(names, (size_t)n, sizeof *names, cmp);
    for (int i = 0; i < n; i++) {
        first[i] = names[i];
        printf("%s\n", names[i]);
    }
    count_names = n;
    unsigned long sizes[] = {0, 4096, 32768}; /* 0: the longest record's size */
    for (unsigned i = 0; i < sizeof sizes / sizeof *sizes; i++) mode(dir, "getdents64", SYS_getdents64, sizes[i]);
#ifdef SYS_getdents
    for (unsigned i = 0; i < sizeof sizes / sizeof *sizes; i++) mode(dir, "getdents", SYS_getdents, sizes[i]);
#endif

    /* a count whose upper bits are set: the kernel reads its low 32 bits */
    static char buf[65536];
    int fd = open(dir, O_RDONLY | O_DIRECTORY);
    long got = syscall(SYS_getdents64, fd, buf, (1UL << 32) | 32);
    printf("count with upper bits: %s\n", got > 0 && got <= 32 ? "read as 32" : "read otherwise");
    close(fd);

    /* a buffer whose last 100 bytes before a read-only page are writable */
    long page = sysconf(_SC_PAGESIZE);
    char *m = mmap(0, 2 * (size_t)page, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    mprotect(m + page, (size_t)page, PROT_READ);
    fd = open(dir, O_RDONLY | O_DIRECTORY);
    errno = 0;
    got = syscall(SYS_getdents64, fd, m + page - 100, 4096);
    printf("into a buffer that meets a read-only page: %s %d\n",
           got > 0   ? "some records"
           : got < 0 ? "errno"
                     : "none",
           got < 0 ? errno : 0);
    errno = 0;
    got = syscall(SYS_getdents64, fd, m + page, 4096);
    printf("into a read-only buffer, after those: %ld %d\n", got, got < 0 ? errno : 0);
    close(fd);
    fd = open(dir, O_RDONLY | O_DIRECTORY);
    errno = 0;
    got = syscall(SYS_getdents64, fd, m + page, 4096);
    printf("into a read-only buffer, first: %ld %d\n", got, got < 0 ? errno : 0);
    close(fd);

    /* resuming from a record's d_off: the names after it, as the whole listing has them */
    list(dir, SYS_getdents64, 4096);
    n = list(dir, SYS_getdents64, longest);
    if (n > 4) {
        int k = n / 2, rest = 0, ok = 1;
        char *after[MAXN];
        for (int i = k + 1; i < n; i++) after[rest++] = names[i];
        fd = open(dir, O_RDONLY | O_DIRECTORY);
        lseek(fd, offs[k], SEEK_SET);
        int m2 = 0;
        for (;;) {
            got = syscall(SYS_getdents64, fd, buf, 4096);
            if (got <= 0) break;
            for (long o = 0; o < got; o += *(unsigned short *)(buf + o + 16))
                ok &= m2 < rest && strcmp(buf + o + 19, after[m2++]) == 0;
        }
        ok &= m2 == rest;
        close(fd);
        printf("resumed from a d_off: %s\n", ok ? "the names after it" : "other names");
    }
    return 0;
}
