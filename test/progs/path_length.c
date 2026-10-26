/* path_length.c — the answers for long paths (PROPOSAL.md 13 item 13, 17.4): each argument is stat'ed and opened, and
 * the errors named, so that an exclave path whose real spelling would not fit PATH_MAX is seen to be refused with
 * ENAMETOOLONG and never cut to a shorter name; "cd:DIR" changes the working directory first, for a relative path from a
 * deep one. usage: path_length [cd:DIR] PATH...; prints "<n>: stat=<e> open=<e>" per path. Exit 0 always. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static const char *en(int e)
{
    static char b[32];
    switch (e) {
    case 0: return "ok"; case ENOENT: return "ENOENT"; case ENAMETOOLONG: return "ENAMETOOLONG"; case ENOTDIR: return "ENOTDIR";
    default: snprintf(b, sizeof b, "errno=%d", e); return b;
    }
}

int main(int argc, char **argv)
{
    int n = 0;
    for (int i = 1; i < argc; i++) {
        if (strncmp(argv[i], "cd:", 3) == 0) { if (chdir(argv[i] + 3)) printf("cd: %s\n", en(errno)); continue; }
        struct stat st; int se = 0, oe = 0;
        if (stat(argv[i], &st)) se = errno;
        int fd = open(argv[i], O_RDONLY); if (fd < 0) oe = errno; else close(fd);
        printf("%d: stat=%s open=%s\n", ++n, en(se), en(oe));
    }
    return 0;
}
