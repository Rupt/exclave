/* spawn_faults PROGRAM [ARGS...]: runs the program twenty times, one after another, and prints the page faults a run
 * took, the children's minor faults over their number (getrusage). The count is of a process's whole life, so inside an
 * exclave it holds the launcher's start too, and the difference from the kernel's own count for the same program is
 * what the launcher touches (DESIGN.md 16.4). posix_spawn, so that the child faults nothing of its parent's before its
 * exec. */
#include <spawn.h>
#include <stdio.h>
#include <sys/resource.h>
#include <sys/wait.h>

extern char **environ;

int main(int argc, char **argv)
{
    enum { RUNS = 20 };
    if (argc < 2) return 2;
    for (int i = 0; i < RUNS; i++) {
        pid_t pid;
        int st;
        if (posix_spawn(&pid, argv[1], 0, 0, argv + 1, environ)) {
            perror("posix_spawn");
            return 1;
        }
        if (waitpid(pid, &st, 0) != pid || !WIFEXITED(st) || WEXITSTATUS(st)) {
            printf("run %d: status %#x\n", i, st);
            return 1;
        }
    }
    struct rusage u;
    getrusage(RUSAGE_CHILDREN, &u);
    printf("%ld\n", (u.ru_minflt + RUNS / 2) / RUNS);
    return 0;
}
