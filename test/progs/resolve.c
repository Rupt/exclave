/* resolve.c — the launcher's side of the canonicalisation oracle: for each path on stdin, open it with
 * O_PATH (following the final symlink unless the line starts with "nofollow ") and print the virtual
 * path the descriptor names, or the errno. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

int main(void)
{
    char line[8192], buf[4096];
    while (fgets(line, sizeof line, stdin)) {
        size_t n = strlen(line);
        if (n && line[n - 1] == '\n') line[--n] = 0;
        int flags = O_PATH;
        char *p = line;
        if (!strncmp(p, "nofollow ", 9)) {
            flags |= O_NOFOLLOW;
            p += 9;
        }
        int fd = open(p, flags);
        if (fd < 0) {
            printf("ERR %d\n", errno);
            continue;
        }
        char l[64];
        snprintf(l, sizeof l, "/proc/self/fd/%d", fd);
        ssize_t r = readlink(l, buf, sizeof buf - 1);
        if (r < 0) printf("ERR readlink %d\n", errno);
        else {
            buf[r] = 0;
            printf("OK %s\n", buf);
        }
        close(fd);
    }
    return 0;
}
