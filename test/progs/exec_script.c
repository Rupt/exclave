/* exec_script.c — what execve makes of a #! line and of a file that is no program (fs/binfmt_script.c, fs/exec.c;
 * DESIGN.md 7.4.5, 17.4): lines of 127, 128, 255 and 256 bytes with and without a newline, trailing blanks, an
 * argument with spaces, a NUL in the line, an empty interpreter, a script of nothing but "#!", interpreter chains four,
 * five and six deep, an interpreter that is a wrapper of the tree, a symlink, a directory, a FIFO, unreadable or
 * absent, a script through a descriptor opened O_PATH, O_RDONLY and O_CLOEXEC, and execve of a directory, a FIFO, a
 * socket, an empty file, a file of one byte, a file without an execute bit and one with the bit but unreadable.
 * usage: exec_script run HOSTDIR; any other argv[1] is the interpreter mode, which prints its argv. Prints one line per
 * case, "<case>: <answer>", the same in every world, so the kernel under bwrap is the oracle; a descriptor number is
 * printed as N, the host directory as $H and the program's own path as $E. Exit 0 always. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

extern char **environ;
static char *hd, *self;

static const char *en(int e)
{
    static char b[32];
    switch (e) {
    case ENOENT: return "ENOENT";
    case ENOEXEC: return "ENOEXEC";
    case EACCES: return "EACCES";
    case ELOOP: return "ELOOP";
    case EINVAL: return "EINVAL";
    case ENOTDIR: return "ENOTDIR";
    case ENXIO: return "ENXIO";
    case EISDIR: return "EISDIR";
    case EBADF: return "EBADF";
    case EPERM: return "EPERM";
    case E2BIG: return "E2BIG";
    case ENAMETOOLONG: return "ENAMETOOLONG";
    default: snprintf(b, sizeof b, "errno=%d", e); return b;
    }
}

/* print s with the host directory as $H, this program's path as $E and /dev/fd/<digits> as /dev/fd/N */
static void put(const char *s)
{
    size_t hl = hd ? strlen(hd) : 0, el = self ? strlen(self) : 0;
    while (*s) {
        if (hl && strncmp(s, hd, hl) == 0) {
            fputs("$H", stdout);
            s += hl;
        } else if (el && strncmp(s, self, el) == 0) {
            fputs("$E", stdout);
            s += el;
        } else if (strncmp(s, "/dev/fd/", 8) == 0 && s[8] >= '0' && s[8] <= '9') {
            fputs("/dev/fd/N", stdout);
            s += 8;
            while (*s >= '0' && *s <= '9') s++;
        } else putchar(*s++);
    }
}

/* exec in a child; the case line is the exec's error, or the status and the first line the child printed */
static void ex(const char *tag, int dfd, const char *path, char *const *av, int flags)
{
    int p[2];
    if (pipe(p)) {
        perror("pipe");
        return;
    }
    fflush(stdout);
    pid_t c = fork();
    if (c == 0) {
        dup2(p[1], 1);
        close(p[0]);
        close(p[1]);
        int dn = open("/dev/null", O_RDWR);
        dup2(dn, 0);
        dup2(dn, 2);
        syscall(SYS_execveat, dfd, path, av, environ, flags);
        _exit(100 + (errno & 0xff));
    }
    close(p[1]);
    char buf[4096];
    int n = 0, r;
    while ((r = (int)read(p[0], buf + n, sizeof buf - 1 - (size_t)n)) > 0) n += r;
    buf[n] = 0;
    close(p[0]);
    int st = 0;
    waitpid(c, &st, 0);
    buf[strcspn(buf, "\n")] = 0;
    if (WIFEXITED(st) && WEXITSTATUS(st) >= 100 && !buf[0]) {
        printf("%s: %s\n", tag, en(WEXITSTATUS(st) - 100));
        return;
    }
    if (WIFSIGNALED(st)) printf("%s: signal=%d out=", tag, WTERMSIG(st));
    else printf("%s: status=%d out=", tag, WEXITSTATUS(st));
    put(buf);
    putchar('\n');
}

/* a file in the host directory of n bytes and that mode; its path */
static const char *mk(const char *name, const char *text, size_t n, mode_t mode)
{
    static char p[4096];
    snprintf(p, sizeof p, "%s/%s", hd, name);
    int fd = open(p, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0 || write(fd, text, n) != (ssize_t)n) {
        perror(p);
        exit(2);
    }
    close(fd);
    chmod(p, mode);
    return p;
}

/* a script of "#!" + self + " interp " + an argument of a's, LINE bytes before the newline, with or without one */
static void shebang_length(size_t line, int newline)
{
    char text[600], name[64];
    int head = snprintf(text, sizeof text, "#!%s interp ", self);
    size_t k = line > (size_t)head ? line - (size_t)head : 0;
    memset(text + head, 'a', k);
    size_t n = (size_t)head + k;
    if (newline) text[n++] = '\n';
    snprintf(name, sizeof name, "line%zu%s", line, newline ? "" : "-nonl");
    char *const av[] = {"renamed", "x", 0};
    ex(name, AT_FDCWD, mk(name, text, n, 0755), av, 0);
}

static void script(const char *name, const char *line)
{
    char text[600];
    int n = snprintf(text, sizeof text, "%s\n", line);
    char *const av[] = {"renamed", "x", 0};
    ex(name, AT_FDCWD, mk(name, text, (size_t)n, 0755), av, 0);
}

int main(int argc, char **argv)
{
    if (argc < 3 || strcmp(argv[1], "run")) {
        /* the interpreter: what the kernel gave it; the host directory from the environment run set */
        hd = getenv("EXEC_SCRIPT_HOSTDIR");
        self = getenv("EXEC_SCRIPT_SELF");
        fputs("argv=[", stdout);
        for (int i = 0; i < argc; i++) {
            if (i) putchar('|');
            /* the padded argument of a line<N> script: "a*full" when every a arrived, "a*cut<K>" for the K the
             * kernel's buffer lost, so that the answer does not depend on this program's path */
            const char *b = argc > 2 ? strrchr(argv[2], '/') : 0;
            size_t line = 0;
            if (i == 1 && b && sscanf(b, "/line%zu", &line) == 1 && strncmp(argv[1], "interp a", 8) == 0 &&
                strspn(argv[1] + 7, "a") == strlen(argv[1] + 7) && self) {
                size_t want = line - (2 + strlen(self) + strlen(" interp ")), got = strlen(argv[1] + 7);
                if (got == want) printf("interp a*full");
                else printf("interp a*cut%zu", want - got);
                continue;
            }
            put(argv[i]);
        }
        puts("]");
        return 0;
    }
    hd = argv[2];
    setenv("EXEC_SCRIPT_HOSTDIR", hd, 1);
    static char exe[4096];
    ssize_t n = readlink("/proc/self/exe", exe, sizeof exe - 1);
    if (n < 0) {
        perror("readlink");
        return 2;
    }
    exe[n] = 0;
    self = exe;
    setenv("EXEC_SCRIPT_SELF", self, 1);
    char text[8192], p[4096], p2[4096];
    char *const av[] = {"renamed", "x", 0};

    /* the line's length (binfmt_script.c's BINPRM_BUF_SIZE of 256) */
    for (size_t line = 127; line <= 256; line += line == 128 ? 127 : 1) {
        shebang_length(line, 1);
        shebang_length(line, 0);
    }
    snprintf(text, sizeof text, "#!%s interp  \t \t", self);
    script("trailing blanks", text);
    snprintf(text, sizeof text, "#!%s interp one two  three", self);
    script("argument with spaces", text);
    snprintf(text, sizeof text, "#!  \t%s   interp", self);
    script("leading blanks", text);
    /* a NUL in the line: the name ends there */
    int k = snprintf(text, sizeof text, "#!%s", self);
    memcpy(text + k, "\0 interp\n", 9);
    ex("nul in line", AT_FDCWD, mk("nul", text, (size_t)k + 9, 0755), av, 0);
    script("empty interpreter", "#!");
    script("blank interpreter", "#! \t ");
    ex("only #! no newline", AT_FDCWD, mk("hashbang", "#!", 2, 0755), av, 0);
    ex("only # no newline", AT_FDCWD, mk("hash", "#", 1, 0755), av, 0);
    ex("empty file", AT_FDCWD, mk("empty", "", 0, 0755), av, 0);
    ex("one newline", AT_FDCWD, mk("newline", "\n", 1, 0755), av, 0);
    ex("text file", AT_FDCWD, mk("text", "hello\n", 6, 0755), av, 0);
    /* chains: c<i> names c<i+1>, the last names the interpreter; the kernel allows BINPRM_MAX_RECURSION */
    for (int depth = 3; depth <= 6; depth++) {
        for (int i = depth; i >= 1; i--) {
            char name[32];
            snprintf(name, sizeof name, "c%d-%d", depth, i);
            if (i == depth) snprintf(text, sizeof text, "#!%s interp\n", self);
            else snprintf(text, sizeof text, "#!%s/c%d-%d\n", hd, depth, i + 1);
            mk(name, text, strlen(text), 0755);
        }
        char tag[32];
        snprintf(tag, sizeof tag, "chain of %d", depth);
        snprintf(p, sizeof p, "%s/c%d-1", hd, depth);
        ex(tag, AT_FDCWD, p, av, 0);
    }
    /* the interpreter a wrapper of the tree, with and without an argument */
    script("sh interpreter", "#!/bin/sh\necho sh $0 $1");
    script("sh -e interpreter", "#!/bin/sh -e\necho she $0 $1");
    /* a symlink to the interpreter, a directory, a FIFO, an unreadable copy, an absent one */
    snprintf(p, sizeof p, "%s/interp-link", hd);
    if (symlink(self, p)) perror(p);
    snprintf(text, sizeof text, "#!%s interp", p);
    script("symlink interpreter", text);
    snprintf(text, sizeof text, "#!%s interp", hd);
    script("directory interpreter", text);
    snprintf(p, sizeof p, "%s/interp-fifo", hd);
    if (mkfifo(p, 0755)) perror(p);
    /* a writer held open: a kernel before 5.9 opened the file before checking that it was regular, and a FIFO's open
     * waits for a writer; with one it reaches the check and answers EACCES, as the newer kernels do at once */
    int fifo_writer = open(p, O_RDWR | O_CLOEXEC);
    snprintf(text, sizeof text, "#!%s interp", p);
    script("fifo interpreter", text);
    snprintf(text, sizeof text, "#!%s/absent interp", hd);
    script("absent interpreter", text);
    snprintf(text, sizeof text, "#!%s/empty interp", hd);
    script("empty-file interpreter", text);
    snprintf(text, sizeof text, "#!%s/text interp", hd);
    script("text-file interpreter", text);
    {
        /* the interpreter a copy of self with the execute bits only (DESIGN.md 13 item 12) */
        int i = open(self, O_RDONLY);
        snprintf(p, sizeof p, "%s/interp-0111", hd);
        int o = open(p, O_WRONLY | O_CREAT | O_TRUNC, 0755);
        char b[65536];
        ssize_t r;
        while ((r = read(i, b, sizeof b)) > 0)
            if (write(o, b, (size_t)r) != r) perror(p);
        close(i);
        close(o);
        chmod(p, 0111);
        snprintf(text, sizeof text, "#!%s interp", p);
        script("unreadable interpreter", text);
        ex("unreadable elf", AT_FDCWD, p, av, 0);
        snprintf(p2, sizeof p2, "%s/script-0111", hd);
        snprintf(text, sizeof text, "#!/bin/sh\necho ran $0\n");
        mk("script-0111", text, strlen(text), 0111);
        ex("unreadable script", AT_FDCWD, p2, av, 0);
        snprintf(text, sizeof text, "#!%s interp\n", self);
        mk("script-0111-interp", text, strlen(text), 0111);
        snprintf(p2, sizeof p2, "%s/script-0111-interp", hd);
        ex("unreadable script, elf interpreter", AT_FDCWD, p2, av, 0);
        mk("script-0644", text, strlen(text), 0644);
        snprintf(p2, sizeof p2, "%s/script-0644", hd);
        ex("script without x", AT_FDCWD, p2, av, 0);
        chmod(p, 0644);
        ex("elf without x", AT_FDCWD, p, av, 0);
        chmod(p, 0755);
        /* the interpreter has no execute bit */
        chmod(p, 0644);
        snprintf(text, sizeof text, "#!%s interp", p);
        script("interpreter without x", text);
        chmod(p, 0755);
    }
    /* a script through a descriptor: O_PATH, O_RDONLY, O_CLOEXEC, and relative to a directory descriptor */
    snprintf(text, sizeof text, "#!%s interp\n", self);
    const char *s = mk("fdscript", text, strlen(text), 0755);
    int fd = open(s, O_PATH);
    ex("script by O_PATH fd", fd, "", av, AT_EMPTY_PATH);
    close(fd);
    fd = open(s, O_RDONLY);
    ex("script by O_RDONLY fd", fd, "", av, AT_EMPTY_PATH);
    close(fd);
    fd = open(s, O_RDONLY | O_CLOEXEC);
    ex("script by O_CLOEXEC fd", fd, "", av, AT_EMPTY_PATH);
    close(fd);
    fd = open(hd, O_RDONLY | O_DIRECTORY);
    ex("script relative to dirfd", fd, "fdscript", av, 0);
    ex("script by dirfd O_PATH", fd, "fdscript", av, AT_SYMLINK_NOFOLLOW);
    close(fd);
    fd = open(hd, O_PATH | O_DIRECTORY);
    ex("script relative to O_PATH dirfd", fd, "fdscript", av, 0);
    close(fd);
    snprintf(p, sizeof p, "%s/fdscript-link", hd);
    if (symlink(s, p)) perror(p);
    ex("script symlink", AT_FDCWD, p, av, 0);
    ex("script symlink nofollow", AT_FDCWD, p, av, AT_SYMLINK_NOFOLLOW);
    snprintf(p, sizeof p, "%s/fdscript/", hd);
    ex("script with trailing slash", AT_FDCWD, p, av, 0);
    ex("bad flag", AT_FDCWD, s, av, 0x4000);
    ex("empty path without flag", AT_FDCWD, "", av, 0);
    /* an ELF through a descriptor, O_PATH and O_RDONLY */
    fd = open(self, O_PATH);
    char *const iav[] = {"renamed", "interp", 0};
    ex("elf by O_PATH fd", fd, "", iav, AT_EMPTY_PATH);
    close(fd);
    fd = open(self, O_RDONLY);
    ex("elf by O_RDONLY fd", fd, "", iav, AT_EMPTY_PATH);
    close(fd);
    /* files that are no program */
    ex("directory", AT_FDCWD, hd, av, 0);
    snprintf(p, sizeof p, "%s/fifo", hd);
    if (mkfifo(p, 0755)) perror(p);
    int fifo_writer2 = open(p, O_RDWR | O_CLOEXEC);
    ex("fifo", AT_FDCWD, p, av, 0);
    close(fifo_writer2);
    close(fifo_writer);
    snprintf(p, sizeof p, "%s/sock", hd);
    {
        int sk = socket(AF_UNIX, SOCK_STREAM, 0);
        struct sockaddr_un sa = {.sun_family = AF_UNIX};
        if (strlen(p) >= sizeof sa.sun_path) {
            printf("socket: host directory too deep for sun_path\n");
            return 0;
        }
        memcpy(sa.sun_path, p, strlen(p) + 1);
        if (bind(sk, (struct sockaddr *)&sa, sizeof sa)) perror(p);
        chmod(p, 0755);
        ex("socket", AT_FDCWD, p, av, 0);
        close(sk);
    }
    ex("/dev/null", AT_FDCWD, "/dev/null", av, 0);
    ex("absent", AT_FDCWD, "/nonexistent/prog", av, 0);
    snprintf(p, sizeof p, "%s/text/x", hd);
    ex("under a file", AT_FDCWD, p, av, 0);
    return 0;
}
