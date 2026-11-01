/* exec_elf.c — what execve makes of ELF images the loader must judge (fs/binfmt_elf.c; DESIGN.md 7.3, 7.4.5, 17.4):
 * a hand-made static ELF of one segment whose entry exits 42, then its variants: no PT_LOAD, overlapping and
 * unordered PT_LOADs, p_memsz below p_filesz, a PT_INTERP naming a text file, a script, the program itself and an
 * absent path, a PT_INTERP without a NUL, two PT_INTERPs, an entry outside every segment and one of zero, a p_vaddr
 * and p_offset that differ within a page, a segment at address zero and one past the end of the file, a terabyte of
 * bss, PT_GNU_STACK absent, with PF_X and without, the 32-bit class, another machine, the other byte order, ET_REL,
 * e_phnum 0 and PN_XNUM, a wrong e_phentsize, an e_phoff past the file, and an ET_DYN at a fixed address. On x86-64
 * the entry copies the exit onto the stack and jumps there, so that the stack's executability shows in the answer; on
 * aarch64 it exits in place. usage: exec_elf HOSTDIR. Prints one line per case, "<case>: <answer>", the same in every
 * world, so the kernel under bwrap is the oracle. Exit 0 always. */
#define _GNU_SOURCE
#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

extern char **environ;
static const char *hd;

#if defined(__x86_64__)
#define MACHINE EM_X86_64
/* lea rsi,[rip+16]; sub rsp,16; mov rdi,rsp; mov ecx,12; rep movsb; jmp rsp; then: mov eax,60; mov edi,42; syscall */
static const unsigned char CODE[] = {0x48, 0x8d, 0x35, 0x10, 0x00, 0x00, 0x00, 0x48, 0x83, 0xec, 0x10, 0x48,
                                     0x89, 0xe7, 0xb9, 0x0c, 0x00, 0x00, 0x00, 0xf3, 0xa4, 0xff, 0xe4, 0xb8,
                                     0x3c, 0x00, 0x00, 0x00, 0xbf, 0x2a, 0x00, 0x00, 0x00, 0x0f, 0x05};
#elif defined(__aarch64__)
#define MACHINE EM_AARCH64
/* mov x8,#93; mov x0,#42; svc #0 */
static const unsigned char CODE[] = {0xa8, 0x0b, 0x80, 0xd2, 0x40, 0x05, 0x80, 0xd2, 0x01, 0x00, 0x00, 0xd4};
#else
#error "no exit code for this machine"
#endif

enum { PHOFF = 64, INTERP_OFF = 0x200, CODE_OFF = 0x300, BASE = 0x400000 };

struct img {
    unsigned char b[1 << 16];
    size_t n;
};

static Elf64_Ehdr *eh(struct img *m) { return (Elf64_Ehdr *)m->b; }
static Elf64_Phdr *ph(struct img *m, int i) { return (Elf64_Phdr *)(m->b + PHOFF) + i; }

/* the base image: one PT_LOAD over the whole file at BASE, a PT_GNU_STACK with PF_X, the exit code at CODE_OFF */
static void base(struct img *m)
{
    memset(m, 0, sizeof *m);
    m->n = CODE_OFF + sizeof CODE;
    memcpy(m->b + CODE_OFF, CODE, sizeof CODE);
    Elf64_Ehdr *e = eh(m);
    memcpy(e->e_ident, ELFMAG, SELFMAG);
    e->e_ident[EI_CLASS] = ELFCLASS64;
    e->e_ident[EI_DATA] = ELFDATA2LSB;
    e->e_ident[EI_VERSION] = EV_CURRENT;
    e->e_type = ET_EXEC;
    e->e_machine = MACHINE;
    e->e_version = EV_CURRENT;
    e->e_entry = BASE + CODE_OFF;
    e->e_phoff = PHOFF;
    e->e_ehsize = sizeof *e;
    e->e_phentsize = sizeof(Elf64_Phdr);
    e->e_phnum = 2;
    *ph(m, 0) = (Elf64_Phdr){.p_type = PT_LOAD,
                             .p_flags = PF_R | PF_X,
                             .p_offset = 0,
                             .p_vaddr = BASE,
                             .p_filesz = m->n,
                             .p_memsz = m->n,
                             .p_align = 0x1000};
    *ph(m, 1) = (Elf64_Phdr){.p_type = PT_GNU_STACK, .p_flags = PF_R | PF_W | PF_X, .p_align = 16};
}

static void interp(struct img *m, int i, const char *path, int nul)
{
    size_t n = strlen(path) + (nul ? 1 : 0);
    memcpy(m->b + INTERP_OFF, path, n);
    *ph(m, i) = (Elf64_Phdr){.p_type = PT_INTERP,
                             .p_flags = PF_R,
                             .p_offset = INTERP_OFF,
                             .p_vaddr = BASE + INTERP_OFF,
                             .p_filesz = n,
                             .p_memsz = n,
                             .p_align = 1};
}

static const char *en(int e)
{
    static char b[32];
    switch (e) {
    case ENOENT: return "ENOENT";
    case ENOEXEC: return "ENOEXEC";
    case EACCES: return "EACCES";
    case ELOOP: return "ELOOP";
    case EINVAL: return "EINVAL";
    case ELIBBAD: return "ELIBBAD";
    case EIO: return "EIO";
    case ENOMEM: return "ENOMEM";
    case E2BIG: return "E2BIG";
    default: snprintf(b, sizeof b, "errno=%d", e); return b;
    }
}

/* write the image as HOSTDIR/name and exec it: the exec's error, read from a close-on-exec pipe, or the child's
 * status or signal */
static void run(const char *name, struct img *m)
{
    char p[4096];
    snprintf(p, sizeof p, "%s/%s", hd, name);
    int fd = open(p, O_WRONLY | O_CREAT | O_TRUNC, 0755);
    if (fd < 0 || write(fd, m->b, m->n) != (ssize_t)m->n) {
        perror(p);
        exit(2);
    }
    close(fd);
    int ep[2];
    if (pipe2(ep, O_CLOEXEC)) {
        perror("pipe");
        exit(2);
    }
    fflush(stdout);
    pid_t c = fork();
    if (c == 0) {
        int dn = open("/dev/null", O_RDWR);
        dup2(dn, 0);
        dup2(dn, 1);
        dup2(dn, 2);
        char *const av[] = {p, 0};
        execve(p, av, environ);
        int e = errno;
        if (write(ep[1], &e, sizeof e) != sizeof e) _exit(99);
        _exit(98);
    }
    close(ep[1]);
    int e = 0, st = 0;
    ssize_t got = read(ep[0], &e, sizeof e);
    close(ep[0]);
    waitpid(c, &st, 0);
    if (got == sizeof e) printf("%s: %s\n", name, en(e));
    else if (WIFSIGNALED(st)) printf("%s: signal=%d\n", name, WTERMSIG(st));
    else printf("%s: status=%d\n", name, WEXITSTATUS(st));
}

/* a program the tree's compiler builds with flags and runs: its status, or "compile failed" where the tree cannot
 * build it, the same in both worlds */
static void built(const char *name, const char *flags)
{
    char cmd[8192];
    const char *cc = getenv("CC") ? getenv("CC") : "cc";
    snprintf(cmd, sizeof cmd, "%s %s -o '%s/%s' '%s/hello.c' >/dev/null 2>&1", cc, flags, hd, name, hd);
    fflush(stdout);
    if (system(cmd)) {
        printf("%s: compile failed\n", name);
        return;
    }
    snprintf(cmd, sizeof cmd, "'%s/%s'", hd, name);
    int st = system(cmd);
    if (st == -1) printf("%s: system failed\n", name);
    else if (WIFSIGNALED(st)) printf("%s: signal=%d\n", name, WTERMSIG(st));
    else printf("%s: status=%d\n", name, WEXITSTATUS(st));
}

int main(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stderr, "usage: exec_elf HOSTDIR\n");
        return 2;
    }
    hd = argv[1];
    static struct img m;
    char p[4096];
    base(&m);
    run("base", &m);
    /* the stack: no PT_GNU_STACK, and one without PF_X */
    base(&m);
    eh(&m)->e_phnum = 1;
    run("no PT_GNU_STACK", &m);
    base(&m);
    ph(&m, 1)->p_flags = PF_R | PF_W;
    run("PT_GNU_STACK without PF_X", &m);
    /* segments */
    base(&m);
    ph(&m, 0)->p_type = PT_NULL;
    run("no PT_LOAD", &m);
    base(&m);
    *ph(&m, 1) = *ph(&m, 0);
    run("two identical PT_LOADs", &m);
    base(&m);
    *ph(&m, 1) = *ph(&m, 0);
    ph(&m, 1)->p_vaddr = BASE + 0x1000;
    ph(&m, 1)->p_filesz = ph(&m, 1)->p_memsz = 0x100;
    run("PT_LOAD page overlapping the first", &m);
    base(&m);
    eh(&m)->e_phnum = 3;
    *ph(&m, 2) = *ph(&m, 1);
    *ph(&m, 1) = (Elf64_Phdr){.p_type = PT_LOAD,
                              .p_flags = PF_R | PF_W,
                              .p_offset = 0x1000,
                              .p_vaddr = BASE - 0x1000,
                              .p_filesz = 0,
                              .p_memsz = 0x100,
                              .p_align = 0x1000};
    run("PT_LOADs out of address order", &m);
    base(&m);
    ph(&m, 0)->p_memsz = CODE_OFF;
    run("p_memsz below p_filesz", &m);
    base(&m);
    ph(&m, 0)->p_memsz = 1ULL << 40;
    run("a terabyte of bss", &m);
    base(&m);
    ph(&m, 0)->p_vaddr = BASE + 0x10;
    eh(&m)->e_entry = BASE + 0x10 + CODE_OFF;
    run("p_vaddr off p_offset within the page", &m);
    base(&m);
    ph(&m, 0)->p_vaddr = 0;
    eh(&m)->e_entry = CODE_OFF;
    run("segment at address zero", &m);
    base(&m);
    ph(&m, 0)->p_vaddr = 0x10000;
    eh(&m)->e_entry = 0x10000 + CODE_OFF;
    run("segment at 0x10000", &m);
    base(&m);
    ph(&m, 0)->p_filesz = ph(&m, 0)->p_memsz = 0x3000;
    run("segment past the end of the file", &m);
    base(&m);
    ph(&m, 0)->p_offset = 0x3000;
    run("segment whose offset is past the file", &m);
    base(&m);
    ph(&m, 0)->p_flags = PF_R;
    run("code segment without PF_X", &m);
    base(&m);
    ph(&m, 0)->p_flags = 0;
    run("segment without permissions", &m);
    base(&m);
    ph(&m, 0)->p_align = 3;
    run("p_align 3", &m);
    /* the entry */
    base(&m);
    eh(&m)->e_entry = BASE + 0x10000;
    run("entry outside every segment", &m);
    base(&m);
    eh(&m)->e_entry = 0;
    run("entry zero", &m);
    /* PT_INTERP */
    snprintf(p, sizeof p, "%s/text", hd);
    {
        int fd = open(p, O_WRONLY | O_CREAT | O_TRUNC, 0755);
        if (write(fd, "hello\n", 6) != 6) perror(p);
        close(fd);
    }
    base(&m);
    eh(&m)->e_phnum = 3;
    interp(&m, 2, p, 1);
    run("PT_INTERP a text file", &m);
    snprintf(p, sizeof p, "%s/script", hd);
    {
        int fd = open(p, O_WRONLY | O_CREAT | O_TRUNC, 0755);
        if (write(fd, "#!/bin/sh\nexit 3\n", 17) != 17) perror(p);
        close(fd);
    }
    base(&m);
    eh(&m)->e_phnum = 3;
    interp(&m, 2, p, 1);
    run("PT_INTERP a script", &m);
    snprintf(p, sizeof p, "%s/base", hd);
    base(&m);
    eh(&m)->e_phnum = 3;
    interp(&m, 2, p, 1);
    run("PT_INTERP the base image", &m);
    snprintf(p, sizeof p, "%s/PT_INTERP itself", hd);
    base(&m);
    eh(&m)->e_phnum = 3;
    interp(&m, 2, p, 1);
    run("PT_INTERP itself", &m);
    snprintf(p, sizeof p, "%s/absent", hd);
    base(&m);
    eh(&m)->e_phnum = 3;
    interp(&m, 2, p, 1);
    run("PT_INTERP absent", &m);
    base(&m);
    eh(&m)->e_phnum = 3;
    interp(&m, 2, hd, 1);
    run("PT_INTERP a directory", &m);
    snprintf(p, sizeof p, "%s/text100", hd);
    {
        int fd = open(p, O_WRONLY | O_CREAT | O_TRUNC, 0755);
        for (int i = 0; i < 10; i++)
            if (write(fd, "0123456789", 10) != 10) perror(p);
        close(fd);
    }
    base(&m);
    eh(&m)->e_phnum = 3;
    interp(&m, 2, p, 1);
    run("PT_INTERP a text file of 100 bytes", &m);
    snprintf(p, sizeof p, "%s/absent", hd);
    base(&m);
    eh(&m)->e_phnum = 3;
    interp(&m, 2, p, 0);
    run("PT_INTERP without NUL", &m);
    base(&m);
    eh(&m)->e_phnum = 3;
    interp(&m, 2, "", 1);
    run("PT_INTERP empty", &m);
    base(&m);
    eh(&m)->e_phnum = 3;
    interp(&m, 2, p, 1);
    ph(&m, 2)->p_filesz = 0;
    run("PT_INTERP of zero size", &m);
    base(&m);
    eh(&m)->e_phnum = 3;
    interp(&m, 2, p, 1);
    ph(&m, 2)->p_filesz = 1 << 20;
    run("PT_INTERP of a megabyte", &m);
    snprintf(p, sizeof p, "%s/base", hd);
    base(&m);
    eh(&m)->e_phnum = 4;
    interp(&m, 2, "/nonexistent/ld.so", 1);
    *ph(&m, 3) = *ph(&m, 2);
    ph(&m, 3)->p_offset = INTERP_OFF + 32;
    ph(&m, 3)->p_vaddr = BASE + INTERP_OFF + 32;
    ph(&m, 3)->p_filesz = ph(&m, 3)->p_memsz = strlen(p) + 1;
    memcpy(m.b + INTERP_OFF + 32, p, strlen(p) + 1);
    run("two PT_INTERPs, the first absent", &m);
    /* the header */
    base(&m);
    eh(&m)->e_ident[EI_CLASS] = ELFCLASS32;
    run("EI_CLASS 32 on a 64-bit image", &m);
    base(&m);
    eh(&m)->e_ident[EI_DATA] = ELFDATA2MSB;
    run("EI_DATA big-endian", &m);
    base(&m);
    eh(&m)->e_ident[EI_VERSION] = 0;
    run("EI_VERSION 0", &m);
    base(&m);
    eh(&m)->e_version = 0;
    run("e_version 0", &m);
    base(&m);
    eh(&m)->e_ident[EI_OSABI] = ELFOSABI_FREEBSD;
    run("EI_OSABI FreeBSD", &m);
    base(&m);
    eh(&m)->e_machine = EM_PPC64;
    run("another machine", &m);
    base(&m);
    eh(&m)->e_type = ET_REL;
    run("ET_REL", &m);
    base(&m);
    eh(&m)->e_type = ET_CORE;
    run("ET_CORE", &m);
    base(&m);
    eh(&m)->e_phnum = 0;
    run("e_phnum 0", &m);
    base(&m);
    eh(&m)->e_phnum = PN_XNUM;
    run("e_phnum PN_XNUM", &m);
    base(&m);
    eh(&m)->e_phnum = 1171;
    run("e_phnum 1171", &m);
    base(&m);
    eh(&m)->e_phnum = 1170;
    run("e_phnum 1170", &m);
    base(&m);
    eh(&m)->e_phentsize = 64;
    run("e_phentsize 64", &m);
    base(&m);
    eh(&m)->e_phoff = 1 << 20;
    run("e_phoff past the file", &m);
    base(&m);
    eh(&m)->e_phoff = m.n - 8;
    run("e_phoff in the last bytes", &m);
    base(&m);
    eh(&m)->e_ehsize = 0;
    run("e_ehsize 0", &m);
    base(&m);
    eh(&m)->e_shoff = 1 << 30;
    eh(&m)->e_shnum = 50;
    run("sections past the file", &m);
    base(&m);
    m.n = 48;
    run("header cut at 48 bytes", &m);
    base(&m);
    m.n = PHOFF + 20;
    run("program headers cut", &m);
    /* ET_DYN: at a fixed address, at zero, and with the base's PT_INTERP */
    base(&m);
    eh(&m)->e_type = ET_DYN;
    run("ET_DYN at 0x400000", &m);
    base(&m);
    eh(&m)->e_type = ET_DYN;
    ph(&m, 0)->p_vaddr = 0;
    eh(&m)->e_entry = CODE_OFF;
    run("ET_DYN at zero", &m);
    base(&m);
    eh(&m)->e_type = ET_DYN;
    ph(&m, 0)->p_vaddr = 0x10;
    eh(&m)->e_entry = 0x10 + CODE_OFF;
    run("ET_DYN p_vaddr off p_offset", &m);
    base(&m);
    eh(&m)->e_type = ET_DYN;
    eh(&m)->e_phnum = 3;
    interp(&m, 2, p, 1);
    run("ET_DYN with PT_INTERP the base image", &m);
    base(&m);
    eh(&m)->e_type = ET_DYN;
    ph(&m, 0)->p_type = PT_NULL;
    run("ET_DYN without PT_LOAD", &m);
    /* what the tree's compiler builds: static, static-pie, and a PIE linked at a fixed text address */
    snprintf(p, sizeof p, "%s/hello.c", hd);
    {
        int fd = open(p, O_WRONLY | O_CREAT | O_TRUNC, 0644);
        static const char src[] = "int main(void){return 42;}\n";
        if (write(fd, src, sizeof src - 1) != (ssize_t)(sizeof src - 1)) perror(p);
        close(fd);
    }
    built("static", "-static");
    built("static-pie", "-static-pie");
    built("pie at 0x400000", "-pie -Wl,-Ttext-segment=0x400000");
    built("no-pie at 0x10000", "-no-pie -Wl,-Ttext-segment=0x10000");
    built("dynamic pie", "");
    built("dynamic pie execstack", "-z execstack");
    return 0;
}
