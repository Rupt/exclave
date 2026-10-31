/* xattrat.c — listxattrat, of the *at xattr syscalls Linux 6.13 added (DESIGN.md 17.4), on a host identity file and on
 * a file of the tree. usage: xattrat; prints "<return> <errno>" for /etc/hostname, then for
 * /usr/share/exclave-test-marker. Exit 0 always. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/syscall.h>
#include <unistd.h>

#define SYS_LISTXATTRAT 465 /* the same on every architecture */

int main(void)
{
    static const char *const paths[] = {"/etc/hostname", "/usr/share/exclave-test-marker"};
    char b[64];
    for (unsigned i = 0; i < sizeof paths / sizeof *paths; i++) {
        errno = 0;
        long r = syscall(SYS_LISTXATTRAT, AT_FDCWD, paths[i], 0, b, sizeof b);
        printf("%ld %d\n", r, errno);
    }
    return 0;
}
