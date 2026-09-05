/* loader.c — userland ELF loader (PROPOSAL.md 7.3).
 *
 * Maps the payload and the can's one loader the way the kernel would, builds
 * the initial stack from the opener's own auxiliary vector, and jumps. Used
 * for every program: wrappers after the kernel has exec'd the opener under the
 * program's name, and loader-path programs re-exec'd with CAN_EXEC.
 */
#include "common.h"
#include "elf.h"

static Phdr ph_main[128], ph_interp[64];

static int open_elf(const char *real, Ehdr *eh, Phdr *ph, int maxph)
{
    long fd = sys_open(real, O_RDONLY | O_CLOEXEC, 0);
    if (fd < 0) die("cannot open program", real, fd);
    if (sys_pread((int)fd, eh, sizeof *eh, 0) != sizeof *eh || eh->e_ident[0] != 0x7f || eh->e_ident[1] != 'E') die("not an ELF file", real, 0);
    if (eh->e_ident[4] != ELFCLASS64 || eh->e_machine != EM_X86_64) die("not an x86-64 ELF file", real, 0);
    if (eh->e_phnum > maxph || eh->e_phentsize != sizeof(Phdr)) die("unsupported program headers", real, 0);
    if (sys_pread((int)fd, ph, (size_t)eh->e_phnum * sizeof(Phdr), (long)eh->e_phoff) != (long)(eh->e_phnum * sizeof(Phdr))) die("cannot read program headers", real, 0);
    return (int)fd;
}

/* map every PT_LOAD; returns the load bias; fills entry, phdr address, interp string */
static unsigned long map_elf(int fd, const Ehdr *eh, const Phdr *ph, unsigned long *entry, unsigned long *phdr_va, int *has_interp, char *interp, const char *name)
{
    unsigned long lo = ~0UL, hi = 0;
    *has_interp = 0;
    for (int i = 0; i < eh->e_phnum; i++) {
        if (ph[i].p_type == PT_INTERP) {
            if (ph[i].p_filesz >= PATH_MAX) die("interpreter path too long", name, 0);
            if (sys_pread(fd, interp, ph[i].p_filesz, (long)ph[i].p_offset) != (long)ph[i].p_filesz) die("cannot read interpreter path", name, 0);
            interp[ph[i].p_filesz] = 0; *has_interp = 1;
        }
        if (ph[i].p_type != PT_LOAD) continue;
        unsigned long s = ph[i].p_vaddr & ~0xfffUL, e = (ph[i].p_vaddr + ph[i].p_memsz + 0xfff) & ~0xfffUL;
        if (s < lo) lo = s;
        if (e > hi) hi = e;
    }
    if (lo == ~0UL) die("no loadable segment", name, 0);
    unsigned long bias = 0;
    if (eh->e_type == ET_DYN) {
        long base = sys_mmap(0, hi - lo, 0, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (base < 0 && base > -4096) die("cannot reserve address space", name, base);
        bias = (unsigned long)base - lo;
    }
    for (int i = 0; i < eh->e_phnum; i++) {
        if (ph[i].p_type != PT_LOAD) continue;
        int prot = (ph[i].p_flags & PF_R ? PROT_READ : 0) | (ph[i].p_flags & PF_W ? PROT_WRITE : 0) | (ph[i].p_flags & PF_X ? PROT_EXEC : 0);
        unsigned long va = bias + ph[i].p_vaddr, off = ph[i].p_vaddr & 0xfff;
        unsigned long mstart = va - off, flen = ph[i].p_filesz + off, mlen = ph[i].p_memsz + off;
        int fixed = (eh->e_type == ET_DYN) ? MAP_FIXED : MAP_FIXED_NOREPLACE;
        if (flen) {
            long m = sys_mmap((void *)mstart, flen, prot, MAP_PRIVATE | fixed, fd, (long)(ph[i].p_offset - off));
            if (m < 0 && m > -4096 && eh->e_type == ET_EXEC && m == -EINVAL)      /* kernel before 4.17: no NOREPLACE */
                m = sys_mmap((void *)mstart, flen, prot, MAP_PRIVATE | MAP_FIXED, fd, (long)(ph[i].p_offset - off));
            if (m < 0 && m > -4096) die("cannot map segment", name, m);
        }
        if (mlen > flen) {
            unsigned long fend = mstart + flen, zend = (fend + 0xfff) & ~0xfffUL;
            if ((ph[i].p_flags & PF_W) && flen) xmemset((void *)fend, 0, zend - fend);
            if (mstart + mlen > zend) {
                long m = sys_mmap((void *)zend, mstart + mlen - zend, prot, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
                if (m < 0 && m > -4096) die("cannot map bss", name, m);
            }
        }
    }
    *entry = bias + eh->e_entry; *phdr_va = 0;
    for (int i = 0; i < eh->e_phnum; i++) if (ph[i].p_type == PT_PHDR) *phdr_va = bias + ph[i].p_vaddr;
    if (!*phdr_va)
        for (int i = 0; i < eh->e_phnum; i++)
            if (ph[i].p_type == PT_LOAD && ph[i].p_offset <= eh->e_phoff && eh->e_phoff < ph[i].p_offset + ph[i].p_filesz) { *phdr_va = bias + ph[i].p_vaddr + (eh->e_phoff - ph[i].p_offset); break; }
    return bias;
}

/* 1: dynamic (interp filled), 0: static, <0: error. is_opener set from .note.cont. */
int elf_probe(const char *real, char *interp, int *is_opener)
{
    *is_opener = 0; interp[0] = 0;
    long fd = sys_open(real, O_RDONLY | O_CLOEXEC, 0); if (fd < 0) return (int)fd;
    Ehdr eh; static Phdr ph[64]; int ret = -ENOEXEC;
    if (sys_pread((int)fd, &eh, sizeof eh, 0) == sizeof eh && eh.e_ident[0] == 0x7f && eh.e_ident[1] == 'E'
        && eh.e_ident[4] == ELFCLASS64 && eh.e_machine == EM_X86_64 && eh.e_phnum <= 64 && eh.e_phentsize == sizeof(Phdr)
        && sys_pread((int)fd, ph, (size_t)eh.e_phnum * sizeof(Phdr), (long)eh.e_phoff) == (long)(eh.e_phnum * sizeof(Phdr))) {
        ret = 0;
        for (int i = 0; i < eh.e_phnum; i++) {
            if (ph[i].p_type == PT_INTERP && ph[i].p_filesz < PATH_MAX) {
                if (sys_pread((int)fd, interp, ph[i].p_filesz, (long)ph[i].p_offset) == (long)ph[i].p_filesz) { interp[ph[i].p_filesz] = 0; ret = 1; }
            } else if (ph[i].p_type == PT_NOTE && ph[i].p_filesz <= 512) {
                unsigned char nb[512]; long n = sys_pread((int)fd, nb, ph[i].p_filesz, (long)ph[i].p_offset); long o = 0;
                while (n >= 12 && o + 12 <= n) {
                    uint32_t nsz = *(uint32_t *)(nb + o), dsz = *(uint32_t *)(nb + o + 4);
                    if (nsz == 5 && o + 17 <= n && xmemcmp(nb + o + 12, "cont", 5) == 0) *is_opener = 1;
                    o += 12 + ((nsz + 3) & ~3u) + ((dsz + 3) & ~3u);
                }
            }
        }
    }
    sys_close((int)fd);
    return ret;
}

void loader_run(const char *vpath, const char *real, long argc, char **argv, char **envp, unsigned long *auxv)
{
    Ehdr eh; unsigned long entry, phdr_va, base = 0, jump; int has_interp; char interp_v[PATH_MAX];
    int fd = open_elf(real, &eh, ph_main, 128);
    map_elf(fd, &eh, ph_main, &entry, &phdr_va, &has_interp, interp_v, real);
    sys_close(fd);
    jump = entry;
    if (has_interp) {
        /* one loader per can (7.3): the payload's interpreter must be the index's */
        if (xstrcmp(interp_v, C.interp) != 0) die("program wants a different loader than this can's", interp_v, 0);
        static char ireal[PATH_MAX]; Ehdr ih; unsigned long ientry, iphdr; int ii; char dummy[PATH_MAX];
        struct scratch *S = scratch_get(); if (!S) die("out of memory", 0, ENOMEM);
        if (canon(S, C.interp, AT_FDCWD, 1, S->v) < 0) die("cannot resolve the loader", C.interp, 0);
        to_real(S->v, ireal, S->tmp);                      /* through the wrapper redirect: ld.so is wrapped */
        scratch_put(S);
        int ifd = open_elf(ireal, &ih, ph_interp, 64);
        base = map_elf(ifd, &ih, ph_interp, &ientry, &iphdr, &ii, dummy, ireal);
        sys_close(ifd);
        jump = ientry;
    }
    long auxc = 0; while (auxv[auxc * 2] != AT_NULL) auxc++;
    long envc = 0; while (envp[envc]) envc++;
    unsigned long words = 1 + argc + 1 + envc + 1 + (auxc + 1) * 2 + 2;
    unsigned long *sp = (unsigned long *)(((unsigned long)__builtin_alloca(words * 8 + 1024) + 15) & ~15UL), *w = sp;
    *w++ = (unsigned long)argc;
    for (long i = 0; i < argc; i++) *w++ = (unsigned long)argv[i];
    *w++ = 0;
    for (long i = 0; i < envc; i++) *w++ = (unsigned long)envp[i];
    *w++ = 0;
    int seen = 0;
    for (long i = 0; i < auxc; i++) {
        unsigned long k = auxv[i * 2], v = auxv[i * 2 + 1];
        switch (k) {
        case AT_PHDR: v = phdr_va; break;
        case AT_PHENT: v = sizeof(Phdr); break;
        case AT_PHNUM: v = eh.e_phnum; break;
        case AT_BASE: v = base; break;
        case AT_ENTRY: v = entry; break;
        case AT_EXECFN: v = (unsigned long)vpath; seen = 1; break;
        }
        *w++ = k; *w++ = v;
    }
    if (!seen) { *w++ = AT_EXECFN; *w++ = (unsigned long)vpath; }
    *w++ = AT_NULL; *w++ = 0;
    char nm[16]; scpy(nm, base_name(vpath), sizeof nm);
    sys_prctl(PR_SET_NAME, (unsigned long)nm, 0, 0, 0);
    log_line("load", 0, vpath);
    __asm__ volatile ("mov %0, %%rsp\n xor %%rdx, %%rdx\n xor %%rbp, %%rbp\n jmp *%1\n" : : "r"(sp), "r"(jump) : "memory");
    __builtin_unreachable();
}
