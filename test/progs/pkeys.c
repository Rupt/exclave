/* pkeys.c — syscalls into a buffer under a memory protection key (DESIGN.md 7.5.6): the kernel checks a program's
 * memory against the thread's PKRU, so a buffer the program may write is written and one whose key it denied writes is
 * EFAULT. usage: pkeys PATH DIR LINK; prints "<case>: <return> <errno>" per case, or "no protection keys" where the
 * machine or kernel has none. Exit 0. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

#if defined(__x86_64__)
static void set_rights(int key, unsigned rights) /* rights: 0 all, 2 no writes; the key's two bits of PKRU */
{
    unsigned pkru;
    __asm__ volatile(".byte 0x0f,0x01,0xee" : "=a"(pkru) : "c"(0) : "rdx"); /* rdpkru */
    pkru = (pkru & ~(3U << (2 * key))) | rights << (2 * key);
    __asm__ volatile(".byte 0x0f,0x01,0xef" : : "a"(pkru), "c"(0), "d"(0)); /* wrpkru */
}
#else
static void set_rights(int key, unsigned rights) { (void)key, (void)rights; }
#endif

static void report(const char *what, long r) { printf("%s: %ld %d\n", what, r, r < 0 ? errno : 0); }

static void cases(const char *label, char *buf, const char *path, const char *dir, const char *link)
{
    char name[96];
    snprintf(name, sizeof name, "stat %s", label);
    errno = 0;
    report(name, syscall(SYS_newfstatat, AT_FDCWD, path, buf, 0) < 0 ? -1 : 0);
    snprintf(name, sizeof name, "getdents64 %s", label);
    int fd = open(dir, O_RDONLY | O_DIRECTORY);
    errno = 0;
    long got = syscall(SYS_getdents64, fd, buf, 4096);
    report(name, got < 0 ? -1 : got > 0);
    close(fd);
    snprintf(name, sizeof name, "readlink %s", label);
    errno = 0;
    got = readlink(link, buf, 256);
    report(name, got < 0 ? -1 : got > 0);
    snprintf(name, sizeof name, "getcwd %s", label);
    errno = 0;
    report(name, syscall(SYS_getcwd, buf, 4096) < 0 ? -1 : 1);
}

int main(int argc, char **argv)
{
    if (argc != 4) return 2;
#if defined(__x86_64__)
    long key = syscall(SYS_pkey_alloc, 0, 0);
#else
    long key = -1;
#endif
    if (key < 0) {
        printf("no protection keys\n");
        return 0;
    }
    long page = sysconf(_SC_PAGESIZE);
    char *buf = mmap(0, (size_t)page, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (syscall(SYS_pkey_mprotect, buf, page, PROT_READ | PROT_WRITE, key) < 0) {
        printf("no protection keys\n");
        return 0;
    }
    set_rights((int)key, 0);
    buf[0] = 1; /* the program writes its keyed buffer */
    cases("into a keyed buffer", buf, argv[1], argv[2], argv[3]);
    set_rights((int)key, 2);
    cases("into a keyed buffer the program may not write", buf, argv[1], argv[2], argv[3]);
    return 0;
}
