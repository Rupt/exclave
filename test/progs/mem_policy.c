/* mem_policy.c — a process under prctl(PR_SET_MDWE), the policy systemd's MemoryDenyWriteExecute sets (6.3): no mapping
 * both writable and executable, and none made executable that was not (map_deny_write_exec, include/linux/mman.h),
 * inherited across execve (DESIGN.md 7.4.2). What the policy refuses, what it allows, and that a handler and the
 * programs the process then runs work under it. usage: mem_policy. Prints one line per case: the case and its answer
 * (test/kernel_answers.py has the kernel's). Three pages, no loop. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef PR_SET_MDWE
#define PR_SET_MDWE 65
#endif
#ifndef PR_GET_MDWE
#define PR_GET_MDWE 66
#endif
#ifndef PR_MDWE_REFUSE_EXEC_GAIN
#define PR_MDWE_REFUSE_EXEC_GAIN 1
#endif

static volatile sig_atomic_t ran;

static void on_usr1(int sig)
{
    (void)sig;
    ran = 1;
}

static const char *answer(int failed) { return failed ? strerror(errno) : "ok"; }

/* run argv and say how it ended */
static void run(const char *what, char *const argv[])
{
    fflush(stdout);
    pid_t pid = fork();
    if (pid == 0) {
        execvp(argv[0], argv);
        _exit(126);
    }
    int st = 0;
    if (pid < 0 || waitpid(pid, &st, 0) != pid) printf("%s: %s\n", what, strerror(errno));
    else if (WIFSIGNALED(st)) printf("%s: killed by signal %d\n", what, WTERMSIG(st));
    else printf("%s: exit %d\n", what, WEXITSTATUS(st));
}

int main(void)
{
    printf("the policy set: %s\n", answer(prctl(PR_SET_MDWE, PR_MDWE_REFUSE_EXEC_GAIN, 0, 0, 0) != 0));
    int got = prctl(PR_GET_MDWE, 0, 0, 0, 0);
    if (got < 0) printf("the policy read back: %s\n", strerror(errno));
    else printf("the policy read back: %d\n", got);

    void *p = mmap(0, 4096, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    printf("a writable and executable mapping: %s\n", answer(p == MAP_FAILED));
    p = mmap(0, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED) return 2;
    *(volatile char *)p = 1;
    printf("a written page made executable: %s\n", answer(mprotect(p, 4096, PROT_READ | PROT_EXEC) != 0));
    int fd = open("/proc/self/exe", O_RDONLY);
    p = mmap(0, 4096, PROT_READ | PROT_EXEC, MAP_PRIVATE, fd, 0);
    printf("a file's page mapped executable: %s\n", answer(p == MAP_FAILED));
    if (fd >= 0) close(fd);

    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = on_usr1;
    sigaction(SIGUSR1, &sa, 0);
    raise(SIGUSR1);
    printf("a handler under the policy: %s\n", ran ? "ran" : "did not run");

    char *one[] = {"true", 0};
    run("a program run under the policy", one);
    char *two[] = {"sh", "-c", "true && exit 7", 0};
    run("a shell running a program under the policy", two);
    return 0;
}
