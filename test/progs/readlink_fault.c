/* readlink_fault.c — readlink into an unwritable buffer (DESIGN.md 7.5.6): the answer is EFAULT, as the kernel's, and
 * never a SIGSEGV in the handler's copy. usage: readlink_fault PATH...; prints "<return> <errno>" per path. Exit 0. */
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <unistd.h>

int main(int argc, char **argv)
{
    volatile uintptr_t page0 = 8; /* in the first page, never mapped; volatile, so the compiler cannot see it */
    char *bad = (char *)page0;
    for (int i = 1; i < argc; i++) {
        errno = 0;
        long r = readlink(argv[i], bad, 64);
        printf("%ld %d\n", r, errno);
    }
    return 0;
}
