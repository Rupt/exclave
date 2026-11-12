/* loader.c — userland ELF loader (DESIGN.md 7.3) and the debugger hooks (7.6).
 *
 * Maps the original and the loader its header names the way the kernel would, builds
 * the initial stack from the launcher's own auxiliary vector, and jumps. Used
 * for every program: wrappers after the kernel has exec'd the launcher under the
 * program's name, and loader-path programs re-exec'd with EXCLAVE_EXEC.
 */
#include "common.h"
#include "elf.h"

/* the program's headers, then its loader's, are read into the start's chunk, S->extra, which the handler's probes of a
 * file use the same way (elf_probe) */
#define MAX_PHDRS 128
_Static_assert(MAX_PHDRS * sizeof(Phdr) <= sizeof((struct scratch *)0)->extra, "extra holds a program's headers");
_Static_assert(offsetof(struct scratch, extra) % _Alignof(Phdr) == 0, "extra is aligned for program headers");

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

/* The first bytes of the file being loaded, read once (16.4): its header, program headers, notes and PT_INTERP lie
 * there in nearly every file, so each is copied from them, and what lies beyond is read from the descriptor. Only the
 * startup's loading uses them; the handler's probes of a file read it themselves. They are the first page of the
 * start's chunk's rest, which a walk takes: loader_run reads all it needs of a file before it resolves the next. */
static const unsigned char *head;
static long head_n;
char *loader_real(void) { return payload_path; }
long loader_head(struct scratch *S, int fd, const char **bytes)
{
    head = (const unsigned char *)S->rest;
    head_n = sys_pread(fd, S->rest, 4096, 0);
    if (head_n < 0) head_n = 0;
    *bytes = S->rest;
    return head_n;
}
static long elf_read(int fd, void *dst, size_t n, unsigned long off)
{
    if (off <= (unsigned long)head_n && n <= (unsigned long)head_n - off) {
        xmemcpy(dst, head + off, n);
        return (long)n;
    }
    return sys_pread(fd, dst, n, (long)off);
}

/* Reads the ELF header of fd, the file real, into eh and its program headers, at most maxph, into ph, through head,
 * which loader_head has filled; exits with a message on any failure. */
static void read_elf(int fd, const char *real, Ehdr *eh, Phdr *ph, int maxph)
{
    if (elf_read(fd, eh, sizeof *eh, 0) != sizeof *eh || eh->e_ident[0] != 0x7f || eh->e_ident[1] != 'E')
        die("not an ELF file", real, 0);
    /* load_elf_binary's checks: the type, then the machine alone (elf_check_arch; the class byte is not read) */
    if (eh->e_type != ET_EXEC && eh->e_type != ET_DYN) die("not an executable", real, ENOEXEC);
    if (eh->e_machine != EM_NATIVE) die("not an ELF file for " ARCH_NAME, real, 0);
    if (eh->e_phnum == 0 || eh->e_phnum > maxph || eh->e_phentsize != sizeof(Phdr))
        die("unsupported program headers", real, 0);
    if (elf_read(fd, ph, (size_t)eh->e_phnum * sizeof(Phdr), eh->e_phoff) != (long)(eh->e_phnum * sizeof(Phdr)))
        die("cannot read program headers", real, 0);
}
/* The kernel's record of the image it exec'd: the bounds of its code and data, its break, where its stack starts and
 * where its argument and environment strings lie (mm_struct), from which it answers /proc/<pid>/stat, names [heap]
 * and [stack] and grows the break. It filled the record for the launcher. prctl(PR_SET_MM, PR_SET_MM_MAP) takes it
 * whole, as struct prctl_mm_map of include/uapi/linux/prctl.h, without a capability, where the kernel has the call
 * (3.18, built with CONFIG_CHECKPOINT_RESTORE), and the loader gives it the program's (7.3). The auxiliary vector is
 * not given: the kernel's copy stays the launcher's, beside the launcher's file in exe, as a debugger that reads the
 * two expects them (13 item 62). */
struct mm_map {
    uint64_t start_code, end_code, start_data, end_data, start_brk, brk, start_stack, arg_start, arg_end, env_start,
        env_end;
    uint64_t auxv;
    uint32_t auxv_size, exe_fd;
};
_Static_assert(sizeof(struct mm_map) == 104, "struct prctl_mm_map");
/* what places a program: the record, its stack and strings filled by loader_run, and the end of the stack the kernel
 * gave */
struct placing {
    struct mm_map mm;
    unsigned long stack_end;
};
/* gives the kernel the record of an image at bias, whose bounds b are load_elf_binary's; 0, or the kernel's refusal */
static long mm_give(struct mm_map *m, const unsigned long b[4], unsigned long bias)
{
    m->start_code = bias + b[0], m->end_code = bias + b[1];
    m->start_data = bias + b[2], m->end_data = bias + b[3];
    return sys_prctl(PR_SET_MM, PR_SET_MM_MAP, (unsigned long)m, sizeof *m, 0);
}
/* Where the kernel's exec puts a program and its break (load_elf_binary). An ET_EXEC lies where it is linked, at lo;
 * an ET_DYN that names a loader at ELF_ET_DYN_BASE, plus a random offset of mmap's width where the kernel randomizes,
 * the sum aligned down to the largest alignment a segment asks for. The break is at the image's end, or a page and a
 * random distance under 1 GB past it (arch_randomize_brk); under 32 MB, x86-64's own distance before 6.9, where the
 * image lies below the syscall page, which a break from there can grow only up to (13 item 24), so that the room it
 * has is nearly all there is, whatever the draw. Whether the kernel randomizes shows in the stack's end, which it
 * moves down by a random number of pages (randomize_stack_top). The address of the image, span bytes long, with its
 * break in *brk; 0 where there is none to give: no random number to be had, on a kernel before getrandom (3.17), an
 * alignment that leaves no address, or the launcher's own image two thirds up, where kernels 4.1 to 4.12 load a
 * static PIE and older ones do without randomization: the program's place and its break's room are the launcher's
 * there. */
static unsigned long place(int dyn, unsigned long stack_end, unsigned long lo, unsigned long span, unsigned long align,
                           unsigned long *brk)
{
    unsigned long at = dyn ? ET_DYN_BASE(stack_end) : lo, gap = 0, mask = C.pagesz - 1;
    if (dyn && C.text_lo >= at - (1UL << 30) && C.text_lo < at + MMAP_RND_SPAN + (1UL << 32)) return 0;
    if (stack_end != STACK_TOP(stack_end)) {
        unsigned long r[2];
        if (SC3(NR_getrandom, r, sizeof r, GRND_NONBLOCK) != (long)sizeof r) return 0;
        if (dyn) at += r[0] % MMAP_RND_SPAN;
        gap = C.pagesz + (r[1] % (!dyn && lo < SC_PAGE ? 1UL << 25 : 1UL << 30) & ~mask);
    }
    if (dyn) at &= ~((align < C.pagesz ? C.pagesz : align) - 1);
    *brk = at + span + gap;
    return at;
}

/* Maps every PT_LOAD of fd as the kernel would; returns the load bias, and sets *entry, the program headers' address
 * and, when the file names an interpreter, its path in interp; interp is null for a loader, whose own PT_INTERP the
 * kernel does not read either. pl is the program's placing, null for a loader: the image is placed and the kernel
 * given its record. A failure here is one the kernel meets past its point of no return, where it kills the new image
 * with SIGSEGV (bprm_execve): the message names the segment, then the process dies by that signal. */
static unsigned long map_elf(int fd, const Ehdr *eh, const Phdr *ph, unsigned long *entry, unsigned long *phdr_va,
                             int *has_interp, char *interp, const char *name, struct placing *pl)
{
    /* load_elf_binary's bounds of the code and of the data, before the bias, and the largest alignment a segment asks
     * for (maximum_alignment) */
    unsigned long b[4] = {~0UL, 0, 0, 0}, align = 0;
    unsigned long lo = ~0UL, hi = 0, mask = C.pagesz - 1;   /* the kernel's page, as load_elf_binary rounds (7.3) */
    *has_interp = 0;
    for (int i = 0; i < eh->e_phnum; i++) {
        if (ph[i].p_type == PT_INTERP && interp) {
            if (ph[i].p_filesz >= PATH_MAX) die("interpreter path too long", name, 0);
            if (elf_read(fd, interp, ph[i].p_filesz, ph[i].p_offset) != (long)ph[i].p_filesz)
                die("cannot read interpreter path", name, 0);
            interp[ph[i].p_filesz] = 0;
            *has_interp = 1;
        }
        if (ph[i].p_type != PT_LOAD) continue;
        /* an address and an offset that differ within a page cannot be mapped at this page size, and the kernel refuses
         * such a program too (EINVAL from its mmap): a binary linked for 4 KB pages on a 16 KB or 64 KB kernel. A
         * segment without file bytes has no offset to map: the kernel gives it memory at its page (elf_load, 6.7) */
        if (ph[i].p_filesz && ((ph[i].p_vaddr - ph[i].p_offset) & mask))
            die_signal(SIGSEGV, "a segment is not aligned to this kernel's page size", name, EINVAL);
        /* load_elf_binary: a segment with more file than memory, or past the task's address space, is EINVAL */
        if (ph[i].p_filesz > ph[i].p_memsz || ph[i].p_memsz > TASK_SIZE || ph[i].p_vaddr > TASK_SIZE - ph[i].p_memsz)
            die_signal(SIGSEGV, "a segment does not fit its memory", name, EINVAL);
        unsigned long s = ph[i].p_vaddr & ~mask, e = (ph[i].p_vaddr + ph[i].p_memsz + mask) & ~mask;
        if (s < lo) lo = s;
        if (e > hi) hi = e;
        unsigned long fe = ph[i].p_vaddr + ph[i].p_filesz, x = ph[i].p_flags & PF_X;
        if (x && ph[i].p_vaddr < b[0]) b[0] = ph[i].p_vaddr;
        if (x && fe > b[1]) b[1] = fe;
        if (ph[i].p_vaddr > b[2]) b[2] = ph[i].p_vaddr;
        if (fe > b[3]) b[3] = fe;
        if (ph[i].p_align > align && !(ph[i].p_align & (ph[i].p_align - 1))) align = ph[i].p_align;
    }
    if (lo == ~0UL) die_signal(SIGSEGV, "no loadable segment", name, 0);
    /* A program's break lies where the kernel's exec would put it, above its image, and an ET_DYN program that names
     * a loader goes where that exec would put it (7.3). An ET_DYN that names no loader, a static PIE or the loader run
     * as a program, the kernel maps where mmap does, with the break where the launcher's own is, a static PIE's.
     * given: the kernel has been given the record, or has refused it */
    unsigned long bias = 0, at = 0, brk = 0;
    int given = 0;
    if (pl && (eh->e_type == ET_EXEC || *has_interp))
        at = place(eh->e_type == ET_DYN, pl->stack_end, lo, hi - lo, align, &brk);
    if (eh->e_type == ET_DYN) {
        long base = -ENOMEM;
        if (at) base = sys_mmap((void *)at, hi - lo, 0, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);
        /* The place is the image's: the break goes above it. Where the kernel refuses the record the place is given
         * up, since an image two thirds up would stand in the way of the break the kernel left there, and the image
         * goes where mmap puts it, as it does when the place is in use, or when a kernel that reads the address as a
         * hint has mapped it elsewhere: the break is moved only above an image that is there */
        if (at && (unsigned long)base == at) {
            pl->mm.start_brk = pl->mm.brk = brk;
            given = 1;
            if (mm_give(&pl->mm, b, at - lo) < 0) {
                sys_munmap(at, hi - lo);
                base = -ENOMEM;
            }
        }
        if (map_failed(base)) base = sys_mmap(0, hi - lo, 0, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (map_failed(base)) die_signal(SIGSEGV, "cannot reserve address space", name, base);
        bias = (unsigned long)base - lo;
    } else if (at) {
        pl->mm.start_brk = pl->mm.brk = brk;
        given = 1;
        mm_give(&pl->mm, b, 0);
    }
    /* the record of an image where mmap put it, with the break where the kernel left it */
    if (pl && !given) {
        pl->mm.start_brk = pl->mm.brk = (unsigned long)SC1(NR_brk, 0);
        mm_give(&pl->mm, b, bias);
    }
    for (int i = 0; i < eh->e_phnum; i++) {
        if (ph[i].p_type != PT_LOAD) continue;
        int prot = (ph[i].p_flags & PF_R ? PROT_READ : 0) | (ph[i].p_flags & PF_W ? PROT_WRITE : 0) |
                   (ph[i].p_flags & PF_X ? PROT_EXEC : 0);
        unsigned long va = bias + ph[i].p_vaddr, off = ph[i].p_vaddr & mask;
        unsigned long mstart = va - off, flen = ph[i].p_filesz ? ph[i].p_filesz + off : 0,
                      mlen = ph[i].p_memsz ? ph[i].p_memsz + off : 0;
        int fixed = (eh->e_type == ET_DYN) ? MAP_FIXED : MAP_FIXED_NOREPLACE;
        if (flen) {
            long m = sys_mmap((void *)mstart, flen, prot, MAP_PRIVATE | fixed, fd, (long)(ph[i].p_offset - off));
            if (map_failed(m)) die_signal(SIGSEGV, "cannot map segment", name, m);
            /* a kernel without MAP_FIXED_NOREPLACE treats the address as a hint and may map elsewhere */
            if ((unsigned long)m != mstart) die_signal(SIGSEGV, "segment address already in use", name, EEXIST);
        }
        if (mlen > flen) {
            unsigned long fend = mstart + flen, zend = (fend + mask) & ~mask;
            if ((ph[i].p_flags & PF_W) && flen) xmemset((void *)fend, 0, zend - fend);
            if (mstart + mlen > zend) {
                long m = sys_mmap((void *)zend, mstart + mlen - zend, prot, MAP_PRIVATE | MAP_ANONYMOUS | fixed, -1, 0);
                if (map_failed(m)) die_signal(SIGSEGV, "cannot map bss", name, m);
                if ((unsigned long)m != zend) die_signal(SIGSEGV, "bss address already in use", name, EEXIST);
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

/* a PT_NOTE segment's launcher note, exclave, read from fd into nb (512 bytes), through head when loading: its page
 * generation, 1 for a note without a word, 0 for no note of ours, and in *ver its filter version, 0 for a note without
 * the second word (7.4.2); the last such note counts */
static int note_gen(int fd, const Phdr *p, unsigned char *nb, int loading, int *ver)
{
    long n = loading ? elf_read(fd, nb, p->p_filesz, p->p_offset) : sys_pread(fd, nb, p->p_filesz, (long)p->p_offset),
         o = 0;
    int g = 0;
    while (n >= 12 && o + 12 <= n) {
        uint32_t nsz = *(uint32_t *)(nb + o), dsz = *(uint32_t *)(nb + o + 4);
        long w = o + 12 + (long)((nsz + 3) & ~3U);            /* the word after the name, padded to 4 */
        if (nsz == 8 && o + 20 <= n && xmemcmp(nb + o + 12, "exclave", 8) == 0) {
            g = dsz >= 4 && w + 4 <= n && *(uint32_t *)(nb + w) ? (int)*(uint32_t *)(nb + w) : 1;
            *ver = dsz >= 8 && w + 8 <= n ? (int)*(uint32_t *)(nb + w + 4) : 0;
        }
        o += 12 + ((nsz + 3) & ~3U) + ((dsz + 3) & ~3U);
    }
    return g;
}

long open_borrowed(int dfd, const char *path, int flags)
{
    long fd = sys_openat(dfd, path, flags | O_CLOEXEC, 0);
    if (fd != -EMFILE) return fd;
    /* a program at its descriptor limit: the kernel's exec needs no descriptor, the launcher's one; the soft limit is
     * raised to the hard one for the open, since the lowest free number may lie anywhere above a limit a program
     * lowered below its open descriptors (7.4.5) */
    unsigned long lim[2], all[2];
    if (sys_prlimit(RLIMIT_NOFILE, 0, lim) < 0 || lim[0] >= lim[1]) return fd;
    all[0] = all[1] = lim[1];
    if (sys_prlimit(RLIMIT_NOFILE, all, 0) < 0) return fd;
    fd = sys_openat(dfd, path, flags | O_CLOEXEC, 0);
    sys_prlimit(RLIMIT_NOFILE, lim, 0);
    return fd;
}

/* the kernel's checks of an ELF header and its program headers' size (load_elf_binary, load_elf_phdrs): 0 or
 * -ENOEXEC. The class byte is not read: the machine decides, as elf_check_arch does. */
static int header_ok(const Ehdr *eh)
{
    if (eh->e_ident[0] != 0x7f || eh->e_ident[1] != 'E' || eh->e_ident[2] != 'L' || eh->e_ident[3] != 'F')
        return -ENOEXEC;
    if (eh->e_type != ET_EXEC && eh->e_type != ET_DYN) return -ENOEXEC;
    if (eh->e_machine != EM_NATIVE) return -ENOEXEC;
    if (eh->e_phentsize != sizeof(Phdr)) return -ENOEXEC;
    if (eh->e_phnum == 0 || (size_t)eh->e_phnum * sizeof(Phdr) > 65536) return -ENOEXEC;
    return 0;
}

long exec_file_checks(const char *real, struct kstat *st)
{
    long e = sys_stat(real, st);
    if (e < 0) return e;
    if ((st->st_mode & S_IFMT) != S_IFREG) return -EACCES;
    return sys_faccessat(AT_FDCWD, real, X_OK);
}

long exec_checks(const char *v, char *real, struct kstat *st)
{
    if (vis_in_data(v)) return -EACCES;
    to_real_exec(v, real);
    return exec_file_checks(real, st);
}

long launcher_unjudged(const char *real, int version, char *tmp, void *extra)
{
    if (!program_filters) return 0;
    if (version < 0) {
        int gen;
        if (elf_probe(real, tmp, &gen, &version, extra) < 0) version = 0;
    }
    if (version >= FILTER_JUDGE_SINCE) return 0;
    log_msg(UNJUDGED, real);
    return -EACCES;
}

/* 1: dynamic (interp filled), 0: static, <0: -errno as load_elf_binary answers before its point of no return (7.4.5),
 * the program headers beyond the loader's own table counted as a header it cannot load; is_launcher: a launcher
 * note's page generation, 0 without one */
int elf_probe(const char *real, char *interp, int *is_launcher, int *filter_version, void *buf)
{
    *is_launcher = 0;
    *filter_version = 0;
    interp[0] = 0;
    long fd = open_borrowed(AT_FDCWD, real, O_RDONLY);
    if (fd < 0) return (int)fd;
    /* 7168 + 512 bytes: the loader's own limit of headers */
    Ehdr eh;
    Phdr *ph = (Phdr *)buf;
    unsigned char *nb = (unsigned char *)buf + MAX_PHDRS * sizeof(Phdr);
    int ret = -ENOEXEC;
    if (sys_pread((int)fd, &eh, sizeof eh, 0) == sizeof eh && header_ok(&eh) == 0 && eh.e_phnum <= MAX_PHDRS &&
        sys_pread((int)fd, ph, (size_t)eh.e_phnum * sizeof(Phdr), (long)eh.e_phoff) ==
            (long)(eh.e_phnum * sizeof(Phdr))) {
        ret = 0;
        for (int i = 0; i < eh.e_phnum; i++) {
            if (ph[i].p_type == PT_INTERP && ret == 0) {
                /* the first PT_INTERP, as the kernel takes it: a path of 2 to PATH_MAX bytes ending in NUL, read
                 * whole, or ENOEXEC; one the file does not hold whole is EIO, elf_read's short read */
                if (ph[i].p_filesz > PATH_MAX || ph[i].p_filesz < 2) {
                    ret = -ENOEXEC;
                    break;
                }
                if (sys_pread((int)fd, interp, ph[i].p_filesz, (long)ph[i].p_offset) != (long)ph[i].p_filesz) {
                    ret = -EIO;
                    break;
                }
                if (interp[ph[i].p_filesz - 1] != 0) {
                    ret = -ENOEXEC;
                    break;
                }
                ret = 1;
            } else if (ph[i].p_type == PT_NOTE && ph[i].p_filesz <= 512) {
                int v = 0, g = note_gen((int)fd, &ph[i], nb, 0, &v);
                if (g) {
                    *is_launcher = g;
                    *filter_version = v;
                }
            }
        }
    }
    sys_close((int)fd);
    return ret;
}

int elf_interp_probe(const char *real, void *buf)
{
    long fd = open_borrowed(AT_FDCWD, real, O_RDONLY);
    if (fd < 0) return (int)fd;
    Ehdr *eh = (Ehdr *)buf;
    struct kstat *st = (struct kstat *)((char *)buf + sizeof *eh);
    long n = sys_pread((int)fd, eh, sizeof *eh, 0);
    int ret = 0;
    if (n != (long)sizeof *eh) ret = n < 0 ? (int)n : -EIO;
    /* the magic, the machine and the program headers' size and presence (load_elf_phdrs) are ELIBBAD, the type is not
     * looked at: an ET_EXEC interpreter loads */
    else if (eh->e_ident[0] != 0x7f || eh->e_ident[1] != 'E' || eh->e_ident[2] != 'L' || eh->e_ident[3] != 'F' ||
             eh->e_machine != EM_NATIVE || eh->e_phentsize != sizeof(Phdr) || eh->e_phnum == 0 ||
             (size_t)eh->e_phnum * sizeof(Phdr) > 65536 || sys_fstat(fd, st) < 0 ||
             eh->e_phoff > (unsigned long)st->st_size ||
             (unsigned long)st->st_size - eh->e_phoff < (size_t)eh->e_phnum * sizeof(Phdr))
        ret = -ELIBBAD;
    sys_close((int)fd);
    return ret;
}

/* The kernel makes the initial stack executable when the program's PT_GNU_STACK asks for it (nested functions, old
 * assembly); the loader must do the same or the program dies on its first trampoline. The stack is found in
 * /proc/self/maps, read through buf a line at a time: a line is a range, a few fields and a path, under two
 * PATH_MAXes, and one that does not fit size bytes is none of that file's. */
static int wants_exec_stack(const Phdr *ph, int n)
{
    for (int i = 0; i < n; i++)
        if (ph[i].p_type == PT_GNU_STACK) return (ph[i].p_flags & PF_X) != 0;
    return 0;
}
/* /proc's lowercase hex */
static unsigned long hex_digit(char c) { return (unsigned long)(c <= '9' ? c - '0' : c - 'a' + 10); }
static void stack_make_exec(char *buf, size_t size)
{
    long fd = sys_open("/proc/self/maps", O_RDONLY | O_CLOEXEC, 0);
    if (fd < 0) return;
    size_t have = 0;
    long r;
    while (have < size - 1 && (r = sys_read((int)fd, buf + have, size - 1 - have)) > 0) {
        have += (size_t)r;
        buf[have] = 0;
        char *l = buf;
        for (char *e; (e = xstrchr(l, '\n')); l = e + 1) {
            *e = 0;
            if (!xstrstr(l, "[stack]")) continue;
            unsigned long lo = 0, hi = 0;
            char *p = l;
            for (; *p != '-'; p++) lo = lo * 16 + hex_digit(*p);
            for (p++; *p != ' '; p++) hi = hi * 16 + hex_digit(*p);
            sys_close((int)fd);
            sys_mprotect((void *)lo, hi - lo, PROT_READ | PROT_WRITE | PROT_EXEC);
            return;
        }
        /* the line the read ended in, kept for the next */
        have -= (size_t)(l - buf);
        memmove(buf, l, have + 1);
    }
    sys_close((int)fd);
}

void loader_run(struct scratch *S, const char *vpath, int fd, long argc, char **argv, char **envp,
                const unsigned long *auxv)
{
    Ehdr eh;
    unsigned long entry, phdr_va, base = 0, jump;
    int has_interp;
    /* the start's chunk (launcher.c): the file's real path is where run resolved it, its headers go to extra, its notes
     * to comp and the loader's name, as the program spells it, to given, which no walk writes */
    const char *real = payload_path;
    Phdr *ph = (Phdr *)S->extra;
    unsigned char *nb = (unsigned char *)S->comp;
    char *interp_v = S->given;
    read_elf(fd, real, &eh, ph, MAX_PHDRS);
    /* another exclave's launcher of an older page generation, which a handler sends here (7.4.2) */
    int gen = 0;
    for (int i = 0; i < eh.e_phnum; i++)
        if (ph[i].p_type == PT_NOTE && ph[i].p_filesz <= 512) {
            int v, g = note_gen(fd, &ph[i], nb, 1, &v);
            if (g) gen = g;
        }
    if (gen && gen < PAGE_GENERATION)
        die("a launcher from before the syscall page moved cannot run here; relink its exclave with the current "
            "launcher (docs/DESIGN.md 13 item 45)",
            vpath, 0);
    /* the program's first stack, laid out below this frame once the program is mapped; where it starts and where the
     * kernel laid the strings are part of the kernel's record of the image: the arguments, the environment after them
     * and after that the name the kernel was given, a pointer short of the stack's end (bprm_mm_init,
     * create_elf_tables) */
    long auxc = 0;
    while (auxv[auxc * 2] != AT_NULL) auxc++;
    long envc = 0;
    while (envp[envc]) envc++;
    unsigned long words = (unsigned long)(1 + argc + 1 + envc + 1 + (auxc + 1) * 2 + 2);
    unsigned long *sp = (unsigned long *)(((unsigned long)__builtin_alloca(words * 8 + 1024) + 15) & ~15UL), *w = sp;
    struct placing pl;
    unsigned long kfn = 0;
    for (long i = 0; i < auxc; i++)
        if (auxv[i * 2] == AT_EXECFN) kfn = auxv[i * 2 + 1];
    if (kfn) {
        pl.mm.start_stack = (unsigned long)sp;
        pl.mm.env_end = kfn;
        pl.mm.arg_end = pl.mm.env_start = C.arg_end ? C.arg_end : kfn;
        pl.mm.arg_start = C.arg_start ? C.arg_start : pl.mm.arg_end;
        pl.mm.auxv = 0, pl.mm.auxv_size = 0, pl.mm.exe_fd = (uint32_t)-1;
        pl.stack_end = (kfn + xstrlen((const char *)kfn) + 1 + sizeof(void *) + C.pagesz - 1) & ~(C.pagesz - 1);
    }
    payload_base = map_elf(fd, &eh, ph, &entry, &phdr_va, &has_interp, interp_v, real, kfn ? &pl : 0);
    int exec_stack = wants_exec_stack(ph, eh.e_phnum);
    /* a program run from a descriptor with no path (13 item 25): mapped, the dup goes */
    if (C.descfd > 2) {
        sys_close(C.descfd);
        C.descfd = -1;
    }
    sys_close(fd);
    head_n = 0;                                               /* the head's page is the walk's from here */
    jump = entry;
    payload_entry = entry;
    if (has_interp) {
        /* the program's own PT_INTERP, resolved in the exclave as the kernel would resolve it in a chroot (7.3);
         * that every ELF in an exclave names one loader is the tool's static check, not a run-time rule */
        Ehdr ih;
        unsigned long ientry, iphdr;
        int ii;
        /* through the wrapper redirect: ld.so is wrapped; a loader that is not there fails to open, below */
        long r = canon(S, interp_v, AT_FDCWD, WALK_FOLLOW, S->v);
        /* a walk's other error is said, a top-level directory's that could not be read say (8.1.1) */
        if (r < 0) die("program wants a loader this exclave does not have", interp_v, r == -ENOENT ? 0 : r);
        to_real(S->v, interp_path, S->tmp);
        /* one world (7.4.5): the loader must be the exclave's own file, not one the visibility rule found on the
         * host (a Nix or --dynamic-linker binary) and not one parked in a data directory */
        if (!is_exclave_path(S->v) || vis_in_data(S->v))
            die("program wants a loader this exclave does not have", interp_v, 0);
        long ifd = sys_open(interp_path, O_RDONLY | O_CLOEXEC, 0);
        if (ifd < 0) die("program wants a loader this exclave does not have", interp_v, 0);
        const char *ihead;
        loader_head(S, (int)ifd, &ihead);
        /* a loader's headers are at most half a program's */
        read_elf((int)ifd, interp_path, &ih, ph, MAX_PHDRS / 2);
        base = map_elf((int)ifd, &ih, ph, &ientry, &iphdr, &ii, 0, interp_path, 0);
        sys_close((int)ifd);
        jump = ientry;
        interp_base = base;
    }
    if (exec_stack) stack_make_exec(S->rest, sizeof S->rest);
    /* the chunk goes back before the program runs: its first trapped call claims it */
    scratch_put(S);
    /* the program's own descriptor limit, as it had it (7.4.5) */
    if (C.borrowed) sys_prlimit(RLIMIT_NOFILE, C.rlim, 0);
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
    /* comm as the kernel sets it (7.6): the exec'd path's last component, never the interpreter's, or, left empty by
     * a handler for an exec through a bare descriptor, this file's own name, a wrapped script's interpreter's */
    sys_prctl(PR_SET_NAME, (unsigned long)(C.comm[0] ? C.comm : base_name(vpath)), 0, 0, 0);
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
