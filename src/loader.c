/* loader.c — userland ELF loader (DESIGN.md 7.3) and the debugger hooks (7.6).
 *
 * Maps the original and the loader its header names the way the kernel would, builds
 * the initial stack from the launcher's own auxiliary vector, and jumps. Used
 * for every program: wrappers after the kernel has exec'd the launcher under the
 * program's name, and loader-path programs re-exec'd with EXCLAVE_EXEC.
 */
#include "common.h"
#include "elf.h"

static Phdr ph_main[128], ph_interp[64];

/* 7.6: what a debugger needs, exported for the script the launcher carries in .debug_gdb_scripts (src/gdb.py):
 * where the program and its loader were mapped and which files they are, and a function gdb breakpoints to
 * learn them. The script adds the program's symbols at its base, walks the loader's link map for the
 * libraries and finds their originals through .real/, so gdb needs no manual command. The exported names are
 * aliases so that the code reaches the variables directly, without a GOT slot to relocate. */
static unsigned long payload_base, payload_entry, interp_base;
static char payload_path[PATH_MAX], interp_path[PATH_MAX];
static __attribute__((noinline, used)) void debug_hook(void) { __asm__ volatile("" ::: "memory"); }
extern unsigned long exclave_original_base __attribute__((alias("payload_base"), visibility("default")));
extern unsigned long exclave_original_entry __attribute__((alias("payload_entry"), visibility("default")));
extern unsigned long exclave_interp_base __attribute__((alias("interp_base"), visibility("default")));
extern char exclave_original_path[PATH_MAX] __attribute__((alias("payload_path"), visibility("default")));
extern char exclave_interp_path[PATH_MAX] __attribute__((alias("interp_path"), visibility("default")));
extern void exclave_debug_hook(void) __attribute__((alias("debug_hook"), visibility("default")));
__asm__(".pushsection .debug_gdb_scripts,\"MS\",@progbits,1\n"
        " .byte 4\n" /* SECTION_SCRIPT_ID_PYTHON_TEXT: the script's name, a newline, the text */
        " .ascii \"exclave-launcher.py\\n\"\n"
        " .incbin \"src/gdb.py\"\n"
        " .byte 0\n"
        ".popsection\n");

static int open_elf(const char *real, Ehdr *eh, Phdr *ph, int maxph)
{
    long fd = sys_open(real, O_RDONLY | O_CLOEXEC, 0);
    if (fd < 0) die("cannot open program", real, fd);
    if (sys_pread((int)fd, eh, sizeof *eh, 0) != sizeof *eh || eh->e_ident[0] != 0x7f || eh->e_ident[1] != 'E')
        die("not an ELF file", real, 0);
    if (eh->e_ident[4] != ELFCLASS64 || eh->e_machine != EM_NATIVE) die("not an ELF file for " ARCH_NAME, real, 0);
    if (eh->e_phnum > maxph || eh->e_phentsize != sizeof(Phdr)) die("unsupported program headers", real, 0);
    if (sys_pread((int)fd, ph, (size_t)eh->e_phnum * sizeof(Phdr), (long)eh->e_phoff) !=
        (long)(eh->e_phnum * sizeof(Phdr)))
        die("cannot read program headers", real, 0);
    return (int)fd;
}

/* map every PT_LOAD; returns the load bias; fills entry, phdr address, interp string */
static unsigned long map_elf(int fd, const Ehdr *eh, const Phdr *ph, unsigned long *entry, unsigned long *phdr_va,
                             int *has_interp, char *interp, const char *name)
{
    unsigned long lo = ~0UL, hi = 0, mask = C.pagesz - 1;   /* the kernel's page, as load_elf_binary rounds (7.3) */
    *has_interp = 0;
    for (int i = 0; i < eh->e_phnum; i++) {
        if (ph[i].p_type == PT_INTERP) {
            if (ph[i].p_filesz >= PATH_MAX) die("interpreter path too long", name, 0);
            if (sys_pread(fd, interp, ph[i].p_filesz, (long)ph[i].p_offset) != (long)ph[i].p_filesz)
                die("cannot read interpreter path", name, 0);
            interp[ph[i].p_filesz] = 0;
            *has_interp = 1;
        }
        if (ph[i].p_type != PT_LOAD) continue;
        /* an address and an offset that differ within a page cannot be mapped at this page size, and the kernel refuses
         * such a program too (EINVAL from its mmap): a binary linked for 4 KB pages on a 16 KB or 64 KB kernel */
        if ((ph[i].p_vaddr - ph[i].p_offset) & mask)
            die("a segment is not aligned to this kernel's page size", name, EINVAL);
        unsigned long s = ph[i].p_vaddr & ~mask, e = (ph[i].p_vaddr + ph[i].p_memsz + mask) & ~mask;
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
        int prot = (ph[i].p_flags & PF_R ? PROT_READ : 0) | (ph[i].p_flags & PF_W ? PROT_WRITE : 0) |
                   (ph[i].p_flags & PF_X ? PROT_EXEC : 0);
        unsigned long va = bias + ph[i].p_vaddr, off = ph[i].p_vaddr & mask;
        unsigned long mstart = va - off, flen = ph[i].p_filesz + off, mlen = ph[i].p_memsz + off;
        int fixed = (eh->e_type == ET_DYN) ? MAP_FIXED : MAP_FIXED_NOREPLACE;
        if (flen) {
            long m = sys_mmap((void *)mstart, flen, prot, MAP_PRIVATE | fixed, fd, (long)(ph[i].p_offset - off));
            if (m < 0 && m > -4096) die("cannot map segment", name, m);
            /* a kernel without MAP_FIXED_NOREPLACE treats the address as a hint and may map elsewhere */
            if ((unsigned long)m != mstart) die("segment address already in use", name, EEXIST);
        }
        if (mlen > flen) {
            unsigned long fend = mstart + flen, zend = (fend + mask) & ~mask;
            if ((ph[i].p_flags & PF_W) && flen) xmemset((void *)fend, 0, zend - fend);
            if (mstart + mlen > zend) {
                long m = sys_mmap((void *)zend, mstart + mlen - zend, prot, MAP_PRIVATE | MAP_ANONYMOUS | fixed, -1, 0);
                if (m < 0 && m > -4096) die("cannot map bss", name, m);
                if ((unsigned long)m != zend) die("bss address already in use", name, EEXIST);
            }
        }
    }
    *entry = bias + eh->e_entry;
    *phdr_va = 0;
    for (int i = 0; i < eh->e_phnum; i++)
        if (ph[i].p_type == PT_PHDR) *phdr_va = bias + ph[i].p_vaddr;
    if (!*phdr_va)
        for (int i = 0; i < eh->e_phnum; i++)
            if (ph[i].p_type == PT_LOAD && ph[i].p_offset <= eh->e_phoff &&
                eh->e_phoff < ph[i].p_offset + ph[i].p_filesz) {
                *phdr_va = bias + ph[i].p_vaddr + (eh->e_phoff - ph[i].p_offset);
                break;
            }
    return bias;
}

/* 1: dynamic (interp filled), 0: static, <0: error. is_launcher: the page generation a launcher's note carries, 0 without one. */
/* a PT_NOTE segment's launcher note, exclave or the earlier cont, read from fd into nb (512 bytes): its page generation, 1 for a note without one
 * (a launcher from before the word was added), 0 for no note of ours; the last such note counts */
static int note_gen(int fd, const Phdr *p, unsigned char *nb)
{
    long n = sys_pread(fd, nb, p->p_filesz, (long)p->p_offset), o = 0;
    int g = 0;
    while (n >= 12 && o + 12 <= n) {
        uint32_t nsz = *(uint32_t *)(nb + o), dsz = *(uint32_t *)(nb + o + 4);
        long w = o + 12 + (long)((nsz + 3) & ~3U);            /* the word after the name, padded to 4 */
        if ((nsz == 8 && o + 20 <= n && xmemcmp(nb + o + 12, "exclave", 8) == 0) ||
            (nsz == 5 && o + 17 <= n && xmemcmp(nb + o + 12, "cont", 5) == 0))
            g = dsz >= 4 && w + 4 <= n && *(uint32_t *)(nb + w) ? (int)*(uint32_t *)(nb + w) : 1;
        o += 12 + ((nsz + 3) & ~3U) + ((dsz + 3) & ~3U);
    }
    return g;
}

int elf_probe(const char *real, char *interp, int *is_launcher, void *buf)
{
    *is_launcher = 0;
    interp[0] = 0;
    long fd = sys_open(real, O_RDONLY | O_CLOEXEC, 0);
    /* a program at its descriptor limit: borrow one for the read (7.4.5) */
    if (fd == -EMFILE) {
        unsigned long lim[2], one[2];
        if (SC4(NR_prlimit64, 0, RLIMIT_NOFILE, 0, lim) == 0 && lim[0] < lim[1]) {
            one[0] = lim[0] + 1;
            one[1] = lim[1];
            SC4(NR_prlimit64, 0, RLIMIT_NOFILE, one, 0);
            fd = sys_open(real, O_RDONLY | O_CLOEXEC, 0);
            SC4(NR_prlimit64, 0, RLIMIT_NOFILE, lim, 0);
        }
    }
    if (fd < 0) return (int)fd;
    /* 7168 + 512 bytes: the loader's own limit of headers */
    Ehdr eh;
    Phdr *ph = (Phdr *)buf;
    unsigned char *nb = (unsigned char *)buf + 128 * sizeof(Phdr);
    int ret = -ENOEXEC;
    if (sys_pread((int)fd, &eh, sizeof eh, 0) == sizeof eh && eh.e_ident[0] == 0x7f && eh.e_ident[1] == 'E' &&
        eh.e_ident[4] == ELFCLASS64 && eh.e_machine == EM_NATIVE && eh.e_phnum <= 128 &&
        eh.e_phentsize == sizeof(Phdr) &&
        sys_pread((int)fd, ph, (size_t)eh.e_phnum * sizeof(Phdr), (long)eh.e_phoff) ==
            (long)(eh.e_phnum * sizeof(Phdr))) {
        ret = 0;
        for (int i = 0; i < eh.e_phnum; i++) {
            if (ph[i].p_type == PT_INTERP && ph[i].p_filesz < PATH_MAX) {
                if (sys_pread((int)fd, interp, ph[i].p_filesz, (long)ph[i].p_offset) == (long)ph[i].p_filesz) {
                    interp[ph[i].p_filesz] = 0;
                    ret = 1;
                }
            } else if (ph[i].p_type == PT_NOTE && ph[i].p_filesz <= 512) {
                int g = note_gen((int)fd, &ph[i], nb);
                if (g) *is_launcher = g;
            }
        }
    }
    sys_close((int)fd);
    return ret;
}

/* The kernel makes the initial stack executable when the program's PT_GNU_STACK asks for it (nested
 * functions, old assembly); the loader must do the same or the program dies on its first trampoline
 *. The stack is found in /proc/self/maps. */
#define PT_GNU_STACK 0x6474e551U
static int wants_exec_stack(const Phdr *ph, int n)
{
    for (int i = 0; i < n; i++)
        if (ph[i].p_type == PT_GNU_STACK) return (ph[i].p_flags & PF_X) != 0;
    return 0;
}
/* /proc's lowercase hex */
static unsigned long hex_digit(char c) { return (unsigned long)(c <= '9' ? c - '0' : c - 'a' + 10); }
static void stack_make_exec(void)
{
    static char maps[65536];
    long fd = sys_open("/proc/self/maps", O_RDONLY | O_CLOEXEC, 0);
    if (fd < 0) return;
    long n = 0, r;
    while (n < (long)sizeof maps - 1 && (r = sys_read((int)fd, maps + n, sizeof maps - 1 - (size_t)n)) > 0) n += r;
    sys_close((int)fd);
    maps[n] = 0;
    for (char *l = maps; l && *l;) {
        char *e = xstrchr(l, '\n');
        if (e) *e = 0;
        if (xstrstr(l, "[stack]")) {
            unsigned long lo = 0, hi = 0;
            char *p = l;
            for (; *p != '-'; p++) lo = lo * 16 + hex_digit(*p);
            for (p++; *p != ' '; p++) hi = hi * 16 + hex_digit(*p);
            sys_mprotect((void *)lo, hi - lo, PROT_READ | PROT_WRITE | PROT_EXEC);
            return;
        }
        l = e ? e + 1 : 0;
    }
}

void loader_run(const char *vpath, const char *real, long argc, char **argv, char **envp, const unsigned long *auxv)
{
    Ehdr eh;
    unsigned long entry, phdr_va, base = 0, jump;
    int has_interp;
    char interp_v[PATH_MAX];
    int fd = open_elf(real, &eh, ph_main, 128);
    /* another exclave's launcher from before the page moved, which a handler sends here (7.4.2) */
    static unsigned char nb[512];
    int gen = 0;
    for (int i = 0; i < eh.e_phnum; i++)
        if (ph_main[i].p_type == PT_NOTE && ph_main[i].p_filesz <= 512) {
            int g = note_gen(fd, &ph_main[i], nb);
            if (g) gen = g;
        }
    if (gen && gen < PAGE_GENERATION)
        die("a launcher from before the syscall page moved cannot run here; relink its exclave with the current tool, "
            "converting a can first (docs/DESIGN.md 13 item 45)",
            vpath, 0);
    payload_base = map_elf(fd, &eh, ph_main, &entry, &phdr_va, &has_interp, interp_v, real);
    /* a program run from a descriptor with no path (13 item 25): mapped, the dup goes */
    if (C.descfd > 2) {
        sys_close(C.descfd);
        C.descfd = -1;
    }
    sys_close(fd);
    jump = entry;
    payload_entry = entry;
    scpy(payload_path, real, PATH_MAX);
    if (has_interp) {
        /* the program's own PT_INTERP, resolved in the exclave as the kernel would resolve it in a chroot (7.3);
         * that every ELF in an exclave names one loader is the tool's static check, not a run-time rule */
        static char ireal[PATH_MAX];
        Ehdr ih;
        unsigned long ientry, iphdr;
        int ii;
        char dummy[PATH_MAX];
        struct scratch *S = scratch_get((pid_t)sys_getpid(), (pid_t)sys_gettid(), 0);
        if (!S) die("out of memory", 0, ENOMEM);
        struct kstat ist;
        /* through the wrapper redirect: ld.so is wrapped */
        if (canon(S, interp_v, AT_FDCWD, 1, S->v) < 0 || sys_stat(to_real(S->v, ireal, S->tmp), &ist) < 0)
            die("program wants a loader this exclave does not have", interp_v, 0);
        /* one world (7.4.5): the loader must be the exclave's own file, not one the visibility rule found on the
         * host (a Nix or --dynamic-linker binary) and not one parked in a data directory */
        if (!is_exclave_path(S->v) || vis_in_data(S->v))
            die("program wants a loader this exclave does not have", interp_v, 0);
        scratch_put(S);
        int ifd = open_elf(ireal, &ih, ph_interp, 64);
        base = map_elf(ifd, &ih, ph_interp, &ientry, &iphdr, &ii, dummy, ireal);
        sys_close(ifd);
        jump = ientry;
        interp_base = base;
        scpy(interp_path, ireal, PATH_MAX);
    }
    if (wants_exec_stack(ph_main, eh.e_phnum)) stack_make_exec();
    /* the program's own descriptor limit, as it had it (7.4.5) */
    if (C.borrowed) SC4(NR_prlimit64, 0, RLIMIT_NOFILE, C.rlim, 0);
    long auxc = 0;
    while (auxv[auxc * 2] != AT_NULL) auxc++;
    long envc = 0;
    while (envp[envc]) envc++;
    unsigned long words = (unsigned long)(1 + argc + 1 + envc + 1 + (auxc + 1) * 2 + 2);
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
        /* the path the program was exec'd by, the script's for a script, as the kernel gives it */
        case AT_EXECFN:
            v = (unsigned long)C.execfn;
            seen = 1;
            break;
        default: break;                                      /* every other entry as the kernel gave it */
        }
        *w++ = k;
        *w++ = v;
    }
    if (!seen) {
        *w++ = AT_EXECFN;
        *w++ = (unsigned long)C.execfn;
    }
    *w++ = AT_NULL;
    *w++ = 0;
    /* comm as the kernel sets it (7.6): the exec'd path's last component, never the interpreter's */
    sys_prctl(PR_SET_NAME, (unsigned long)C.comm, 0, 0, 0);
    log_line("load", 0, vpath);
    debug_hook();                                             /* 7.6: gdb, if present, learns the mappings here */
    /* the program's start: its stack, no rtld_fini in rdx (x0), as the kernel gives, and no frame to return to. The
     * inputs are pinned to registers the jump never writes: neither may share one with rdx, rbp, x0, x29 or x30 */
#if defined(__x86_64__)
    __asm__ volatile("mov %0, %%rsp\n xor %%rdx, %%rdx\n xor %%rbp, %%rbp\n jmp *%1\n"
                     :
                     : "S"(sp), "c"(jump)
                     : "memory");
#elif defined(__aarch64__)
    register unsigned long *start_sp __asm__("x1") = sp;
    register unsigned long start_pc __asm__("x2") = jump;
    __asm__ volatile("mov sp, %0\n mov x0, #0\n mov x29, #0\n mov x30, #0\n br %1\n"
                     :
                     : "r"(start_sp), "r"(start_pc)
                     : "memory");
#endif
    __builtin_unreachable();
}
