/* exec_identity.c — the identity a program exec'd from inside gets (DESIGN.md 7.4.5, 7.6, 17.4): comm, AT_EXECFN and a
 * script's $0 as the kernel spells them, for a host ELF exec'd by an absolute and by a relative path with argv[0]
 * renamed, a host script exec'd relative to a descriptor and through a descriptor alone (/dev/fd/N/name and /dev/fd/N),
 * a host ELF through a descriptor, a script of the tree through a descriptor alone when one is given, and execve's own
 * answers for a close-on-exec script descriptor, a header the loader cannot load, a loader the exclave lacks and
 * another machine's ELF. usage: exec_identity HOSTDIR [TREE-SCRIPT], or "exec_identity HOSTDIR --child LABEL" as the
 * program it copies and re-executes. Prints one line per case, "<case>: <answer>", the
 * same in every world, so the kernel under bwrap is the oracle; a descriptor number is printed as N. Exit 0 always. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/auxv.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

extern char **environ;

static const char *en(int e)
{
    static char b[32];
    switch (e) {
    case ENOENT: return "ENOENT";
    case ENOEXEC: return "ENOEXEC";
    case EACCES: return "EACCES";
    case ELOOP: return "ELOOP";
    default: snprintf(b, sizeof b, "errno=%d", e); return b;
    }
}

/* run the child's exec, print its lines with descriptor numbers normalised, then "<tag>: <exec's error>" if it fails */
static void child_lines(const char *tag, int dfd, const char *path, char *const *av, int flags)
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
        syscall(SYS_execveat, dfd, path, av, environ, flags);
        char line[128];
        int n = snprintf(line, sizeof line, "%s: %s\n", tag, en(errno));
        if (write(1, line, (size_t)n) < 0) perror(tag);
        _exit(1);
    }
    close(p[1]);
    char buf[8192];
    int n = 0, r;
    while ((r = (int)read(p[0], buf + n, sizeof buf - 1 - (size_t)n)) > 0) n += r;
    buf[n] = 0;
    close(p[0]);
    waitpid(c, 0, 0);
    for (char *s = buf; *s;) { /* /dev/fd/<digits> -> /dev/fd/N */
        if (strncmp(s, "/dev/fd/", 8) == 0 && s[8] >= '0' && s[8] <= '9') {
            fputs("/dev/fd/N", stdout);
            s += 8;
            while (*s >= '0' && *s <= '9') s++;
        } else putchar(*s++);
    }
}

static void copy_self(const char *to)
{
    int i = open("/proc/self/exe", O_RDONLY), o = open(to, O_WRONLY | O_CREAT | O_TRUNC, 0755);
    if (i < 0 || o < 0) {
        perror("copy self");
        exit(2);
    }
    char b[65536];
    ssize_t n;
    while ((n = read(i, b, sizeof b)) > 0)
        if (write(o, b, (size_t)n) != n) {
            perror("copy self");
            exit(2);
        }
    close(i);
    close(o);
}

/* change the last byte of the copy's PT_INTERP string: a loader that does not exist */
static int break_interp(const char *path)
{
    int fd = open(path, O_RDWR);
    if (fd < 0) return -1;
    unsigned char eh[64];
    if (pread(fd, eh, 64, 0) != 64) {
        close(fd);
        return -1;
    }
    uint64_t phoff;
    uint16_t phentsize, phnum;
    memcpy(&phoff, eh + 32, 8);
    memcpy(&phentsize, eh + 54, 2);
    memcpy(&phnum, eh + 56, 2);
    for (unsigned i = 0; i < phnum; i++) {
        unsigned char ph[56];
        if (pread(fd, ph, 56, (off_t)(phoff + i * phentsize)) != 56) break;
        uint32_t type;
        uint64_t off, filesz;
        memcpy(&type, ph, 4);
        memcpy(&off, ph + 8, 8);
        memcpy(&filesz, ph + 32, 8);
        /* the byte before the NUL */
        if (type == 3 && filesz >= 2) {
            char q = 'q';
            if (pwrite(fd, &q, 1, (off_t)(off + filesz - 2)) != 1) {
                perror("break interp");
                exit(2);
            }
            close(fd);
            return 0;
        }
    }
    close(fd);
    return -1;
}

int main(int argc, char **argv)
{
    if (argc >= 4 && strcmp(argv[2], "--child") == 0) {
        char c[64] = {0};
        int fd = open("/proc/self/comm", O_RDONLY);
        if (fd >= 0) {
            /* an unreadable comm leaves the line's answer empty */
            if (read(fd, c, 63) < 0) c[0] = 0;
            close(fd);
        }
        c[strcspn(c, "\n")] = 0;
        printf("%s comm: %s\n%s execfn: %s\n%s argv0: %s\n", argv[3], c, argv[3], (char *)getauxval(AT_EXECFN), argv[3],
               argv[0]);
        return 0;
    }
    if (argc < 2) {
        fprintf(stderr, "usage: exec_identity HOSTDIR\n");
        return 2;
    }
    char *const hd = argv[1];
    char p[4096];
    int hfd = open(hd, O_RDONLY | O_DIRECTORY);
    if (hfd < 0) {
        perror(hd);
        return 2;
    }
    /* a host ELF by an absolute path and by a relative one, argv[0] renamed: comm and AT_EXECFN are the path's */
    snprintf(p, sizeof p, "%s/prog2", hd);
    copy_self(p);
    char *const abs_av[] = {"renamed", hd, "--child", "abs", 0};
    child_lines("abs", AT_FDCWD, p, abs_av, 0);
    if (chdir(hd)) {
        perror("chdir");
        return 2;
    }
    char *const rel_av[] = {"renamed", hd, "--child", "rel", 0};
    child_lines("rel", AT_FDCWD, "prog2", rel_av, 0);
    /* a host script relative to a descriptor: the interpreter gets /dev/fd/N/name, comm is the name */
    snprintf(p, sizeof p, "%s/s.sh", hd);
    {
        FILE *f = fopen(p, "w");
        fputs("#!/bin/sh\necho \"$L argv0: $0\"\nread c < /proc/self/comm\necho \"$L comm: $c\"\n", f);
        fclose(f);
        chmod(p, 0755);
    }
    setenv("L", "dfd script", 1);
    char *const s_av[] = {"s.sh", 0};
    child_lines("dfd script", hfd, "s.sh", s_av, 0);
    /* the script through /dev/fd/N alone: comm the file's own name; close-on-exec refused before anything runs */
    int sfd = open(p, O_RDONLY | O_CLOEXEC);
    child_lines("cloexec script", sfd, "", s_av, AT_EMPTY_PATH);
    close(sfd);
    sfd = open(p, O_RDONLY);
    setenv("L", "fd script", 1);
    child_lines("fd script", sfd, "", s_av, AT_EMPTY_PATH);
    close(sfd);
    /* a script of the tree, a wrapped one under the launcher, through a descriptor alone: comm its interpreter's */
    if (argc >= 3) {
        sfd = open(argv[2], O_RDONLY);
        setenv("L", "fd tree script", 1);
        child_lines("fd tree script", sfd, "", s_av, AT_EMPTY_PATH);
        close(sfd);
    }
    /* a host ELF through a descriptor: comm the file's own name, AT_EXECFN /dev/fd/N */
    snprintf(p, sizeof p, "%s/prog2", hd);
    int efd = open(p, O_RDONLY);
    char *const fd_av[] = {"renamed", hd, "--child", "fd elf", 0};
    child_lines("fd elf", efd, "", fd_av, AT_EMPTY_PATH);
    close(efd);
    /* what execve itself answers: a 32-bit header the loader cannot load, and a loader the exclave lacks */
    snprintf(p, sizeof p, "%s/elf32", hd);
    {
        int o = open(p, O_WRONLY | O_CREAT | O_TRUNC, 0755);
        if (write(o,
                  "\x7f"
                  "ELF\x01\x01\x01\0\0\0\0\0\0\0\0\0\x02\0\x03\0\x01\0\0\0",
                  24) != 24) {
            perror(p);
            return 2;
        }
        close(o);
    }
    char *const b_av[] = {"elf32", 0};
    child_lines("elf32", AT_FDCWD, p, b_av, 0);
    snprintf(p, sizeof p, "%s/noloader", hd);
    copy_self(p);
    if (break_interp(p) == 0) child_lines("no loader", AT_FDCWD, p, b_av, 0);
    else printf("no loader: static (no PT_INTERP to break)\n");
    /* another machine's 64-bit ELF, which no binfmt handler takes */
    snprintf(p, sizeof p, "%s/foreign", hd);
    copy_self(p);
    {
        int o = open(p, O_WRONLY);
        if (o < 0 || pwrite(o, "\x34\x12", 2, 18) != 2) {
            perror(p);
            return 2;
        }
        close(o);
    }
    child_lines("foreign machine", AT_FDCWD, p, b_av, 0);
    return 0;
}
