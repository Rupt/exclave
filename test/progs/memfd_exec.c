/* memfd_exec.c — exec of a memfd (DESIGN.md 7.4.5, 13 item 25): the kernel's exec permission before its reading of
 * the header. A memfd sealed against execution (MFD_NOEXEC_SEAL, 6.3; a host's vm.memfd_noexec seals every memfd so)
 * is EACCES from execveat whatever it holds, while an executable memfd runs an ELF copied into it and refuses an
 * empty one with ENOEXEC. usage: memfd_exec, or "memfd_exec --ran" as the copy that runs. Prints one line per case,
 * "<case>: <answer>", the same in every world, so the kernel under bwrap is the oracle. Exit 0 always. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef MFD_NOEXEC_SEAL
#define MFD_NOEXEC_SEAL 0x0008U
#endif
#ifndef MFD_EXEC
#define MFD_EXEC 0x0010U
#endif

static const char *en(int e)
{
    static char b[32];
    switch (e) {
    case EACCES: return "EACCES";
    case ENOEXEC: return "ENOEXEC";
    case EINVAL: return "EINVAL";
    default: snprintf(b, sizeof b, "errno=%d", e); return b;
    }
}

/* execveat(fd, "", AT_EMPTY_PATH) in a child: "ran" from the copy, or the exec's error */
static void run_fd(const char *tag, int fd)
{
    int p[2];
    if (pipe(p)) {
        printf("%s: pipe errno=%d\n", tag, errno);
        return;
    }
    pid_t c = fork();
    if (c == 0) {
        dup2(p[1], 1);
        close(p[0]);
        close(p[1]);
        char a0[] = "memfd_exec", a1[] = "--ran";
        char *av[] = {a0, a1, 0};
        syscall(SYS_execveat, fd, "", av, environ, AT_EMPTY_PATH);
        printf("%s\n", en(errno)); /* after the case's own prefix */
        fflush(stdout);
        _exit(0);
    }
    close(p[1]);
    char buf[256];
    long n = 0, r;
    while ((r = read(p[0], buf + n, sizeof buf - 1 - (size_t)n)) > 0) n += r;
    buf[n > 0 ? n : 0] = 0;
    close(p[0]);
    waitpid(c, 0, 0);
    (void)tag;
    if (n <= 0) printf("no output\n");
    else fputs(buf, stdout);
}

/* a memfd made with flags, holding the program's own bytes when filled */
static int make(unsigned flags, int filled)
{
    int fd = (int)syscall(SYS_memfd_create, "probe", flags);
    if (fd < 0) return -errno;
    if (filled) {
        int self = open("/proc/self/exe", O_RDONLY);
        char buf[65536];
        long n;
        while (self >= 0 && (n = read(self, buf, sizeof buf)) > 0)
            if (write(fd, buf, (size_t)n) != n) break;
        if (self >= 0) close(self);
    }
    return fd;
}

int main(int argc, char **argv)
{
    if (argc == 2 && strcmp(argv[1], "--ran") == 0) {
        printf("ran\n");
        return 0;
    }
    setvbuf(stdout, 0, _IOLBF, 0);
    struct {
        const char *tag;
        unsigned flags;
        int filled;
    } cases[] = {
        {"executable memfd with the program", MFD_EXEC, 1},
        {"executable memfd, empty", MFD_EXEC, 0},
        {"sealed memfd with the program", MFD_NOEXEC_SEAL, 1},
        {"sealed memfd, empty", MFD_NOEXEC_SEAL, 0},
        /* a memfd made with no flag: executable where vm.memfd_noexec is 0, sealed where it is 1 */
        {"plain memfd with the program", 0, 1},
        {"plain memfd, empty", 0, 0},
    };
    for (unsigned i = 0; i < sizeof cases / sizeof *cases; i++) {
        int fd = make(cases[i].flags, cases[i].filled);
        if (fd < 0) {
            printf("%s: memfd_create %s\n", cases[i].tag, en(-fd));
            continue;
        }
        char tag[128];
        snprintf(tag, sizeof tag, "%s", cases[i].tag);
        /* the copy's own line is "ran": it is prefixed here by the case */
        printf("%s: ", tag);
        fflush(stdout);
        run_fd(tag, fd);
        close(fd);
    }
    /* the host's facts, last so that an oracle's one-line summary shows them: the sysctl, and a plain memfd's
     * mode, seals and exec permission as this kernel gives them */
    char sysctl[32] = "?";
    FILE *f = fopen("/proc/sys/vm/memfd_noexec", "r");
    if (f) {
        if (fgets(sysctl, sizeof sysctl, f)) sysctl[strcspn(sysctl, "\n")] = 0;
        fclose(f);
    }
    int fd = (int)syscall(SYS_memfd_create, "probe", 0);
    struct stat st;
    char link[64];
    snprintf(link, sizeof link, "/proc/self/fd/%d", fd);
    int seals = fd >= 0 ? fcntl(fd, F_GET_SEALS) : -1;
    printf("facts: memfd_noexec=%s plain mode=%o seals=%#x X_OK=%s\n", sysctl,
           fd >= 0 && fstat(fd, &st) == 0 ? st.st_mode & 07777 : 0, seals < 0 ? 0 : (unsigned)seals,
           fd >= 0 && access(link, X_OK) == 0 ? "yes" : "no");
    return 0;
}
