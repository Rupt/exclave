/* fdpress.c — spawn a program with the descriptor table nearly full (review O4-8).
 *
 *   fdpress SPARE PROG ARGS...   RLIMIT_NOFILE is set to 64, /dev/null is opened until it fails, SPARE
 *                                descriptors are closed again, then PROG is posix_spawn'ed with the table
 *                                as it is; exit status is PROG's.
 */
#include <errno.h>
#include <fcntl.h>
#include <spawn.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <string.h>
#include <unistd.h>

extern char **environ;

int main(int argc, char **argv)
{
    if (argc < 3) { fprintf(stderr, "usage: fdpress SPARE PROG ARGS...\n"); return 2; }
    int spare = atoi(argv[1]);
    struct rlimit rl = { 64, 64 };
    if (setrlimit(RLIMIT_NOFILE, &rl) < 0) { perror("setrlimit"); return 2; }
    int last = -1, fd;
    while ((fd = open("/dev/null", O_RDONLY)) >= 0) last = fd;
    if (errno != EMFILE) { perror("open"); return 2; }
    for (int i = 0; i < spare && last >= 3; i++, last--) close(last);
    pid_t pid; int st;
    int r = posix_spawn(&pid, argv[2], 0, 0, argv + 2, environ);
    if (r) { fprintf(stderr, "posix_spawn: %s\n", strerror(r)); return 2; }
    if (waitpid(pid, &st, 0) < 0) { perror("waitpid"); return 2; }
    return WIFEXITED(st) ? WEXITSTATUS(st) : 128 + WTERMSIG(st);
}
