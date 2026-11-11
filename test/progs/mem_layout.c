/* mem_layout.c — where a program's memory lies and how it grows (fs/binfmt_elf.c's load_elf_binary, mm/mmap.c;
 * DESIGN.md 7.3, 17 item 4): the break against the image, its growth, the image against its loader and the stack, the
 * named mappings, the kernel's record of the image in /proc/self/stat, what /proc/self/exe holds, the kernel's copy of
 * the auxiliary vector, and an exec of itself under a lowered RLIMIT_AS and RLIMIT_DATA, without randomization, where
 * the image lies at the kernel's base, and with the argument area full. usage:
 * mem_layout; "mem_layout --child LABEL" is the program it re-executes. Prints one line per case, "<case>:
 * <answer>", the same in every world, so the kernel under bwrap is the oracle. Exit 0 always. */
#define _GNU_SOURCE
#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <link.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/auxv.h>
#include <sys/mman.h>
#include <sys/personality.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

extern char **environ;
extern char end[];
static char self[4096];

static const char *yn(int b) { return b ? "yes" : "no"; }

/* the bounds of the mapping holding a, and the name of the first mapping named NAME */
static int maps_find(uintptr_t a, const char *name, uintptr_t *lo, uintptr_t *hi)
{
    char line[512];
    FILE *f = fopen("/proc/self/maps", "r");
    int found = 0;
    if (!f) return 0;
    while (fgets(line, sizeof line, f)) {
        unsigned long l, h;
        char path[400] = "";
        if (sscanf(line, "%lx-%lx %*s %*s %*s %*s %399[^\n]", &l, &h, path) < 2) continue;
        if (name ? strcmp(path, name) == 0 : (a >= l && a < h)) {
            *lo = l, *hi = h;
            found = 1;
            break;
        }
    }
    fclose(f);
    return found;
}

/* the image's lowest and highest mapped address, from its program headers */
static void image_span(uintptr_t *lo, uintptr_t *hi)
{
    const ElfW(Phdr) *ph = (const ElfW(Phdr) *)getauxval(AT_PHDR);
    size_t n = getauxval(AT_PHNUM);
    uintptr_t bias = 0;
    for (size_t i = 0; i < n; i++)
        if (ph[i].p_type == PT_PHDR) bias = (uintptr_t)ph - ph[i].p_vaddr;
    *lo = UINTPTR_MAX, *hi = 0;
    for (size_t i = 0; i < n; i++) {
        if (ph[i].p_type != PT_LOAD) continue;
        uintptr_t l = bias + ph[i].p_vaddr, h = l + ph[i].p_memsz;
        if (l < *lo) *lo = l;
        if (h > *hi) *hi = h;
    }
}

/* field n of /proc/self/stat, counted from 1 as proc(5) counts them, 0 where it cannot be read */
static uintptr_t stat_field(int n)
{
    char buf[2048];
    int fd = open("/proc/self/stat", O_RDONLY);
    ssize_t len = fd < 0 ? -1 : read(fd, buf, sizeof buf - 1);
    if (fd >= 0) close(fd);
    if (len <= 0) return 0;
    buf[len] = 0;
    /* the comm, field 2, may hold spaces and parentheses: the fields after it follow its last one */
    const char *p = strrchr(buf, ')');
    for (int i = 2; p && i < n; i++) p = strchr(p + 1, ' ');
    return p ? (uintptr_t)strtoul(p + 1, 0, 10) : 0;
}

/* the kernel's record of the image's data and of its break (mm_struct, proc(5)'s fields 45 to 47) against the
 * program's own; exec_auxv measures the record's code, stack and strings */
static void record(const char *label)
{
    uintptr_t ilo, ihi;
    image_span(&ilo, &ihi);
    uintptr_t sd = stat_field(45), ed = stat_field(46), sb = stat_field(47);
    printf("%s stat data in the image: %s\n", label, yn(sd >= ilo && sd <= ed && ed <= ihi));
    printf("%s stat start_brk within 1 GB above image end: %s\n", label, yn(sb >= ihi && sb - ihi <= (1UL << 30)));
}

/* whether a mapping named [heap] holds the megabyte from a, and where the first of that name starts, read by the
 * calls themselves: a libc's stream may take its buffer from the break. musl's allocator maps guard pages into the
 * break, so several mappings bear the name */
static int heap_holds(uintptr_t a, uintptr_t *first)
{
    char buf[1 << 15]; /* on the stack: the image's own data is what the lowered RLIMIT_DATA cases measure */
    int fd = open("/proc/self/maps", O_RDONLY), holds = 0;
    ssize_t n = 0, r;
    while (fd >= 0 && n < (ssize_t)sizeof buf - 1 && (r = read(fd, buf + n, sizeof buf - 1 - (size_t)n)) > 0) n += r;
    if (fd >= 0) close(fd);
    buf[n] = 0;
    *first = 0;
    for (char *l = buf, *nl; (nl = strchr(l, '\n')); l = nl + 1) {
        *nl = 0;
        if (!strstr(l, "[heap]")) continue;
        char *e;
        uintptr_t lo = strtoul(l, &e, 16), hi = strtoul(e + 1, 0, 16);
        if (!*first) *first = lo;
        if (lo <= a && hi >= a + (1 << 20)) holds = 1;
    }
    return holds;
}

static void report(const char *label)
{
    uintptr_t ilo, ihi, slo, shi, llo = 0, lhi = 0;
    image_span(&ilo, &ihi);
    /* the break by the call itself, which answers where the break is: musl's sbrk grows nothing */
    uintptr_t brk0 = (uintptr_t)syscall(SYS_brk, 0);
    printf("%s brk above image end: %s\n", label, yn(brk0 >= ihi));
    printf("%s brk within 1 GB above image end: %s\n", label, yn(brk0 >= ihi && brk0 - ihi <= (1UL << 30)));
    printf("%s brk above end symbol: %s\n", label, yn(brk0 >= (uintptr_t)end));
    printf("%s brk page aligned: %s\n", label, yn(brk0 % 4096 == 0));
    /* a megabyte further from where the break is by now, a libc's first buffer taken: the libc keeps its own note of
     * the break, so nothing of its that may take memory runs until the break is back */
    uintptr_t cur = (uintptr_t)syscall(SYS_brk, 0);
    int grew = (uintptr_t)syscall(SYS_brk, cur + (1 << 20)) == cur + (1 << 20);
    uintptr_t hlo = 0;
    int heap = 0;
    if (grew) {
        memset((void *)cur, 1, 1 << 20);
        heap = heap_holds(cur, &hlo);
        syscall(SYS_brk, cur);
    }
    printf("%s brk 1 MB further: %s\n", label, grew ? "ok" : "refused");
    if (grew) {
        printf("%s [heap] holds it: %s\n", label, yn(heap));
        printf("%s [heap] starts at the first break: %s\n", label, yn(hlo == brk0));
    }
    const char *at_base = (const char *)getauxval(AT_BASE);
    int has_loader = at_base != 0;
    if (has_loader) maps_find((uintptr_t)at_base, 0, &llo, &lhi);
    printf("%s image below loader: %s\n", label, has_loader ? yn(ilo < llo) : "static");
    maps_find(0, "[stack]", &slo, &shi);
    printf("%s image below stack: %s\n", label, yn(ihi <= slo));
    uintptr_t vlo, vhi;
    printf("%s [vdso]: %s\n", label, yn(maps_find(0, "[vdso]", &vlo, &vhi)));
    printf("%s [vvar]: %s\n", label, yn(maps_find(0, "[vvar]", &vlo, &vhi)));
    printf("%s [stack] holds sp: %s\n", label, yn(slo <= (uintptr_t)&ilo && (uintptr_t)&ilo < shi));
}

/* the image as /proc/self/exe holds it: its header against the program's own */
static void exe_file(const char *label)
{
    ElfW(Ehdr) eh;
    int fd = open("/proc/self/exe", O_RDONLY);
    if (fd < 0) {
        printf("%s /proc/self/exe open: %s\n", label, strerror(errno));
        return;
    }
    int ok = pread(fd, &eh, sizeof eh, 0) == sizeof eh;
    const ElfW(Ehdr) *me = (const ElfW(Ehdr) *)((uintptr_t)getauxval(AT_PHDR) - sizeof(ElfW(Ehdr)));
    /* a PIE's header is mapped at its base; compare what does not move */
    printf("%s /proc/self/exe header is ours: %s\n", label,
           yn(ok && eh.e_phnum == getauxval(AT_PHNUM) && eh.e_type == me->e_type && eh.e_phoff == sizeof eh));
    close(fd);
    const char *fn = (const char *)getauxval(AT_EXECFN);
    fd = open(fn, O_RDONLY);
    printf("%s AT_EXECFN opens: %s\n", label, fd < 0 ? strerror(errno) : "ok");
    if (fd >= 0) close(fd);
}

#ifndef PR_GET_AUXV
#define PR_GET_AUXV 0x41555856
#endif
#ifndef PR_SET_MM_MAP_SIZE
#define PR_SET_MM_MAP_SIZE 15
#endif
#ifndef GRND_NONBLOCK
#define GRND_NONBLOCK 1
#endif
#ifndef SYS_getrandom
#define SYS_getrandom (-1)
#endif
/* the kernel's copy of the auxiliary vector, from /proc/self/auxv and PR_GET_AUXV (6.4), against the program's */
static void kernel_auxv(const char *label)
{
    static unsigned long a[512];
    static const struct {
        const char *name;
        unsigned long type;
    } t[] = {{"AT_PHDR", AT_PHDR}, {"AT_ENTRY", AT_ENTRY}, {"AT_BASE", AT_BASE}};
    for (int how = 0; how < 2; how++) {
        long n;
        if (how == 0) {
            int fd = open("/proc/self/auxv", O_RDONLY);
            n = fd < 0 ? -1 : read(fd, a, sizeof a);
            if (fd >= 0) close(fd);
        } else {
            n = prctl(PR_GET_AUXV, (unsigned long)a, sizeof a, 0, 0);
        }
        const char *src = how ? "PR_GET_AUXV" : "/proc/self/auxv";
        for (unsigned k = 0; k < sizeof t / sizeof *t; k++) {
            const char *ans = n < 0 ? "refused" : "absent";
            for (long i = 0; n > 0 && i + 1 < n / 8 && a[i]; i += 2)
                if (a[i] == t[k].type) ans = a[i + 1] == getauxval(t[k].type) ? "the program's" : "another";
            printf("%s %s %s: %s\n", label, src, t[k].name, ans);
        }
    }
}

/* where the kernel puts a program without randomization: where it is linked, or, a position-independent one that
 * names a loader, two thirds up the address space (ELF_ET_DYN_BASE), which ends where the stack does then, aligned
 * down as the image asks */
static uintptr_t et_dyn_base(void)
{
    uintptr_t slo, shi, base;
    const ElfW(Ehdr) *eh = (const ElfW(Ehdr) *)((uintptr_t)getauxval(AT_PHDR) - sizeof(ElfW(Ehdr)));
    if (eh->e_type == ET_EXEC) {
        image_span(&slo, &shi);
        return slo & ~((uintptr_t)sysconf(_SC_PAGESIZE) - 1);
    }
    if (!maps_find(0, "[stack]", &slo, &shi)) return 0;
#if defined(__x86_64__)
    base = 0x555555554000UL;
#else
    base = 2 * (1UL << (64 - __builtin_clzl(shi - 1))) / 3;
#endif
    const ElfW(Phdr) *ph = (const ElfW(Phdr) *)getauxval(AT_PHDR);
    uintptr_t align = (uintptr_t)sysconf(_SC_PAGESIZE);
    for (size_t i = 0; i < getauxval(AT_PHNUM); i++)
        if (ph[i].p_type == PT_LOAD && ph[i].p_align > align && !(ph[i].p_align & (ph[i].p_align - 1)))
            align = ph[i].p_align;
    return base & ~(align - 1);
}

static void child(const char *label)
{
    if (strcmp(label, "plain") == 0) {
        report(label);
        record(label);
        exe_file(label);
    } else if (strcmp(label, "norand") == 0) {
        uintptr_t ilo, ihi, llo = 0, lhi = 0;
        image_span(&ilo, &ihi);
        uintptr_t b = (uintptr_t)syscall(SYS_brk, 0);
        printf("norand personality: %s\n", yn(personality(0xffffffff) & ADDR_NO_RANDOMIZE));
        printf("norand image at the kernel's base: %s\n", yn(ilo == et_dyn_base()));
        printf("norand brk above image end: %s\n", yn(b >= ihi));
        printf("norand brk within 1 MB above image end: %s\n", yn(b >= ihi && b - ihi <= (1UL << 20)));
        const char *at_base = (const char *)getauxval(AT_BASE);
        if (at_base) maps_find((uintptr_t)at_base, 0, &llo, &lhi);
        printf("norand image below loader: %s\n", at_base ? yn(ilo < llo) : "static");
    } else if (strcmp(label, "aslr") == 0) {
        uintptr_t ilo, ihi;
        image_span(&ilo, &ihi);
        printf("%#lx %#lx\n", (unsigned long)ilo, (unsigned long)syscall(SYS_brk, 0));
    } else {
        printf("%s: ran\n", label);
    }
    fflush(stdout);
}

/* label's run of this program by exec, with a soft limit lowered to soft or the personality pers */
static void run(const char *label, int resource, rlim_t soft, unsigned long pers)
{
    fflush(stdout);
    pid_t pid = fork();
    if (pid == 0) {
        if (resource >= 0) {
            /* a loader that cannot map its libraries under the limit says so, and so does the launcher: the status
             * is the answer */
            int quiet = open("/dev/null", O_WRONLY);
            if (quiet >= 0) dup2(quiet, 2);
            struct rlimit rl;
            getrlimit(resource, &rl);
            if (soft < rl.rlim_cur) rl.rlim_cur = soft;
            if (setrlimit(resource, &rl)) printf("%s: setrlimit %s\n", label, strerror(errno));
        }
        if (pers) personality(pers);
        char lab[64];
        snprintf(lab, sizeof lab, "%s", label);
        char *argv[] = {self, "--child", lab, 0};
        execve(self, argv, environ);
        printf("%s: exec %s\n", label, strerror(errno));
        fflush(stdout);
        _exit(0); /* its line is written: a status is the new image's */
    }
    int st;
    waitpid(pid, &st, 0);
    if (WIFSIGNALED(st)) printf("%s: signal %d\n", label, WTERMSIG(st));
    else if (WIFEXITED(st) && WEXITSTATUS(st)) printf("%s: status %d\n", label, WEXITSTATUS(st));
}

/* the largest argument that still execs with the environment as it is, against the kernel's rule (bprm_stack_limits:
 * a quarter of a 1 MB stack limit, lowered, less the pointers, the strings counted with their NULs) */
static void arg_limit(void)
{
    struct rlimit rl;
    getrlimit(RLIMIT_STACK, &rl);
    if (rl.rlim_cur < (1 << 20)) return;
    rl.rlim_cur = 1 << 20;
    setrlimit(RLIMIT_STACK, &rl);
    size_t envb = 0, envc = 0;
    for (char **e = environ; *e; e++) envb += strlen(*e) + 1, envc++;
    /* two 64 KB strings and one of the size probed */
    size_t nbig = 2;
    static char big[64 << 10];
    memset(big, 'x', sizeof big - 1);
    size_t lo = 0, hi = 128 << 10;
    char *tail = malloc(hi + 1);
    while (lo + 1 < hi) {
        size_t mid = (lo + hi) / 2;
        memset(tail, 'y', mid);
        tail[mid] = 0;
        char *argv[40];
        int k = 0;
        argv[k++] = self, argv[k++] = "--child", argv[k++] = "big";
        for (size_t i = 0; i < nbig; i++) argv[k++] = big;
        argv[k++] = tail;
        argv[k] = 0;
        pid_t pid = fork();
        if (pid == 0) {
            int devnull = open("/dev/null", O_WRONLY);
            dup2(devnull, 1);
            execve(self, argv, environ);
            _exit(errno == E2BIG ? 100 : 101);
        }
        int st;
        waitpid(pid, &st, 0);
        if (WIFEXITED(st) && WEXITSTATUS(st) == 0) lo = mid;
        else hi = mid;
    }
    size_t argc = 3 + nbig + 1;
    size_t used = strlen(self) + 1 + 8 + 4 + nbig * sizeof big + lo + 1 + envb + (argc + envc) * sizeof(void *);
    /* the filename is counted once more, as bprm->exec */
    used += strlen(self) + 1;
    long slack = (long)(256 << 10) - (long)used;
    printf("arg limit slack under 64 bytes: %s\n", yn(slack >= 0 && slack < 64));
    printf("arg limit E2BIG past it: %s\n", yn(hi < (128 << 10)));
    free(tail);
}

int main(int argc, char **argv)
{
    ssize_t n = readlink("/proc/self/exe", self, sizeof self - 1);
    if (n < 0) return 0;
    self[n] = 0;
    setvbuf(stdout, 0, _IOLBF, 0);
    if (argc >= 3 && strcmp(argv[1], "--child") == 0) {
        child(argv[2]);
        return 0;
    }
    /* whether this kernel lets a process give it the record of its image, and has random numbers to place one by:
     * the launcher places a program as the kernel does where both hold (7.3) */
    unsigned size = 0;
    unsigned long rnd;
    printf("PR_SET_MM_MAP and getrandom: %s\n",
           yn(prctl(PR_SET_MM, PR_SET_MM_MAP_SIZE, &size, 0, 0) == 0 &&
              syscall(SYS_getrandom, &rnd, sizeof rnd, GRND_NONBLOCK) == (long)sizeof rnd));
    report("own");
    record("own");
    exe_file("own");
    kernel_auxv("own");
    run("plain", -1, 0, 0);
    run("norand", -1, 0, ADDR_NO_RANDOMIZE);
    /* two runs place the image and the break apart */
    char out[2][128] = {{0}, {0}};
    for (int i = 0; i < 2; i++) {
        int pfd[2];
        if (pipe(pfd)) return 0;
        pid_t pid = fork();
        if (pid == 0) {
            dup2(pfd[1], 1);
            char *av[] = {self, "--child", "aslr", 0};
            execve(self, av, environ);
            _exit(127);
        }
        close(pfd[1]);
        ssize_t r = read(pfd[0], out[i], sizeof out[i] - 1);
        (void)r;
        close(pfd[0]);
        waitpid(pid, 0, 0);
    }
    printf("aslr two runs differ: %s\n", yn(strcmp(out[0], out[1]) != 0 && out[0][0]));
    static const long as_mb[] = {64, 16};
    for (size_t i = 0; i < sizeof as_mb / sizeof *as_mb; i++) {
        char label[32];
        snprintf(label, sizeof label, "AS %ldMB", as_mb[i]);
        run(label, RLIMIT_AS, (rlim_t)as_mb[i] << 20, 0);
    }
    static const long data_kb[] = {4096, 1024, 128};
    for (size_t i = 0; i < sizeof data_kb / sizeof *data_kb; i++) {
        char label[32];
        snprintf(label, sizeof label, "DATA %ldKB", data_kb[i]);
        run(label, RLIMIT_DATA, (rlim_t)data_kb[i] << 10, 0);
    }
    arg_limit();
    return 0;
}
