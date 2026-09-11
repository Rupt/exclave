/* openat2_xdev.c — openat2's resolve flags on walks that never touch the can (PROPOSAL.md 13 item 22, 17.4): RESOLVE_NO_XDEV
 * across the host's own mount boundaries, and the other flags on host-only walks. usage: openat2_xdev HOSTDIR. Prints one
 * line per case, "<case>: ret=<r> errno=<e>", the same in every world, so the kernel under bwrap is the oracle. Exit 0
 * always, 3 when the kernel has no openat2. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

#define RESOLVE_NO_XDEV 0x01
#define RESOLVE_NO_MAGICLINKS 0x02
#define RESOLVE_NO_SYMLINKS 0x04
#define RESOLVE_BENEATH 0x08
#define RESOLVE_IN_ROOT 0x10
struct how { unsigned long long flags, mode, resolve; };

static long o2(int dfd, const char *path, unsigned long flags, unsigned long resolve)
{
    struct how h = { flags, 0, resolve };
    long r = syscall(SYS_openat2, dfd, path, &h, sizeof h);
    if (r >= 0) { close((int)r); return 0; }
    return r;
}
static void show(const char *name, long r) { printf("%s: ret=%ld errno=%d\n", name, r < 0 ? -1L : 0L, r < 0 ? errno : 0); }

int main(int argc, char **argv)
{
    if (argc < 2) { fprintf(stderr, "usage: openat2_xdev HOSTDIR\n"); return 2; }
    const char *host = argv[1];
    char p[4096];
    errno = 0;
    if (o2(AT_FDCWD, "/", O_RDONLY | O_DIRECTORY, 0) < 0 && errno == ENOSYS) { printf("no openat2 on this kernel\n"); return 3; }
    if (chdir(host) != 0) { perror("chdir"); return 2; }
    snprintf(p, sizeof p, "%s/file", host); { int fd = open(p, O_WRONLY | O_CREAT, 0644); if (fd >= 0) close(fd); }
    snprintf(p, sizeof p, "%s/lnk", host); unlink(p); symlink("file", p);
    snprintf(p, sizeof p, "%s/sub", host); mkdir(p, 0755);
    int dev = open("/dev", O_PATH | O_DIRECTORY), proc = open("/proc", O_PATH | O_DIRECTORY), hd = open(host, O_PATH | O_DIRECTORY);
    /* no_xdev across the host's own mounts: from the working directory, from /, and from a descriptor on the mount */
    show("no_xdev cwd to /dev/null", o2(AT_FDCWD, "/dev/null", O_RDONLY, RESOLVE_NO_XDEV));
    show("no_xdev cwd to /dev/shm", o2(AT_FDCWD, "/dev/shm", O_RDONLY | O_DIRECTORY, RESOLVE_NO_XDEV));
    show("no_xdev cwd to /proc/self/status", o2(AT_FDCWD, "/proc/self/status", O_RDONLY, RESOLVE_NO_XDEV));
    show("no_xdev cwd to /usr/share (can)", o2(AT_FDCWD, "/usr/share", O_RDONLY | O_DIRECTORY, RESOLVE_NO_XDEV));
    show("no_xdev cwd to .", o2(AT_FDCWD, ".", O_RDONLY | O_DIRECTORY, RESOLVE_NO_XDEV));
    show("no_xdev cwd to sub", o2(AT_FDCWD, "sub", O_RDONLY | O_DIRECTORY, RESOLVE_NO_XDEV));
    show("no_xdev cwd to ..", o2(AT_FDCWD, "..", O_RDONLY | O_DIRECTORY, RESOLVE_NO_XDEV));
    show("no_xdev /dev fd to null", o2(dev, "null", O_RDONLY, RESOLVE_NO_XDEV));
    show("no_xdev /dev fd to shm", o2(dev, "shm", O_RDONLY | O_DIRECTORY, RESOLVE_NO_XDEV));
    show("no_xdev /dev fd to ..", o2(dev, "..", O_RDONLY | O_DIRECTORY, RESOLVE_NO_XDEV));
    show("no_xdev /proc fd to self/status", o2(proc, "self/status", O_RDONLY, RESOLVE_NO_XDEV));
    show("no_xdev host fd to file", o2(hd, "file", O_RDONLY, RESOLVE_NO_XDEV));
    show("no_xdev host fd to /dev/null (absolute)", o2(hd, "/dev/null", O_RDONLY, RESOLVE_NO_XDEV));
    /* the other flags on host-only walks */
    show("no_symlinks host fd to lnk", o2(hd, "lnk", O_RDONLY, RESOLVE_NO_SYMLINKS));
    show("no_symlinks host fd to file", o2(hd, "file", O_RDONLY, RESOLVE_NO_SYMLINKS));
    show("no_magiclinks /proc fd to self/status", o2(proc, "self/status", O_RDONLY, RESOLVE_NO_MAGICLINKS));
    show("no_magiclinks /proc fd to version", o2(proc, "version", O_RDONLY, RESOLVE_NO_MAGICLINKS));
    show("beneath host fd to sub", o2(hd, "sub", O_RDONLY | O_DIRECTORY, RESOLVE_BENEATH));
    show("beneath host fd to ..", o2(hd, "..", O_RDONLY | O_DIRECTORY, RESOLVE_BENEATH));
    show("beneath host fd to sub/..", o2(hd, "sub/..", O_RDONLY | O_DIRECTORY, RESOLVE_BENEATH));
    show("in_root host fd to /etc/passwd", o2(hd, "/etc/passwd", O_RDONLY, RESOLVE_IN_ROOT));
    show("in_root host fd to ../../../file", o2(hd, "../../../file", O_RDONLY, RESOLVE_IN_ROOT));
    show("in_root /dev fd to /null", o2(dev, "/null", O_RDONLY, RESOLVE_IN_ROOT));
    show("beneath|no_xdev /dev fd to shm", o2(dev, "shm", O_RDONLY | O_DIRECTORY, RESOLVE_BENEATH | RESOLVE_NO_XDEV));
    close(dev); close(proc); close(hd);
    return 0;
}
