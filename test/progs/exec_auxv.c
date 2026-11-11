/* exec_auxv.c — the initial stack and the auxiliary vector a program gets (fs/binfmt_elf.c's create_elf_tables;
 * DESIGN.md 7.3, 17.4), from its own run and from an exec of itself: each AT_ entry against the program's own header,
 * entry and loader, AT_RANDOM's place and freshness, the order and placement of argc, argv, envp, the auxiliary vector
 * and the strings, /proc/self/stat's code, stack and argument fields against the program's own, cmdline against argv, a
 * setuid and a setgid copy, and the descriptors an exec'd program finds open under soft limits of 3, 4 and 8 and a hard
 * limit of 3. usage: exec_auxv HOSTDIR; "exec_auxv --child LABEL" is the program it re-executes. Prints one line per
 * case, "<case>: <answer>", the same in every world, so the kernel under bwrap is the oracle. Exit 0 always. */
#define _GNU_SOURCE
#include <dirent.h>
#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/auxv.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#ifndef PR_SET_MM_MAP_SIZE
#define PR_SET_MM_MAP_SIZE 15
#endif

extern char **environ;
#ifdef __GLIBC__
extern void *__libc_stack_end;
#endif
extern const Elf64_Ehdr __ehdr_start;
extern void _start(void);
int main(int argc, char **argv);

static const char *yes_no(int b) { return b ? "yes" : "no"; }

/* the file mapped at address a, its last component, from /proc/self/maps */
static const char *mapping_of(uintptr_t a)
{
    static char line[512], name[400];
    FILE *f = fopen("/proc/self/maps", "r");
    strcpy(name, "none");
    if (!f) return name;
    while (fgets(line, sizeof line, f)) {
        unsigned long lo, hi;
        char path[400] = "";
        if (sscanf(line, "%lx-%lx %*s %*s %*s %*s %399[^\n]", &lo, &hi, path) < 2) continue;
        if (a >= lo && a < hi) {
            const char *b = strrchr(path, '/');
            snprintf(name, sizeof name, "%s", b ? b + 1 : (path[0] ? path : "anonymous"));
            break;
        }
    }
    fclose(f);
    return name;
}

/* the stack mapping's bounds */
static void stack_bounds(uintptr_t *lo, uintptr_t *hi)
{
    char line[512];
    FILE *f = fopen("/proc/self/maps", "r");
    *lo = *hi = 0;
    if (!f) return;
    while (fgets(line, sizeof line, f)) {
        unsigned long a, b;
        if (sscanf(line, "%lx-%lx", &a, &b) == 2 && strstr(line, "[stack]")) {
            *lo = a;
            *hi = b;
        }
    }
    fclose(f);
}

static unsigned long stat_field(int n)
{
    char buf[4096];
    int fd = open("/proc/self/stat", O_RDONLY);
    ssize_t r = fd < 0 ? -1 : read(fd, buf, sizeof buf - 1);
    if (fd >= 0) close(fd);
    if (r <= 0) return 0;
    buf[r] = 0;
    char *s = strrchr(buf, ')');
    if (!s) return 0;
    s += 2; /* field 3 */
    for (int i = 3; i < n; i++) {
        s = strchr(s, ' ');
        if (!s) return 0;
        s++;
    }
    return strtoul(s, 0, 10);
}

static void report(const char *L, int argc, char **argv)
{
    char **envp = environ, **e = envp;
    while (*e) e++;
    int nenv = (int)(e - envp);
    Elf64_auxv_t *auxv = (Elf64_auxv_t *)(e + 1);
    /* glibc records the initial stack pointer; musl does not, and there argv - 1 is where the kernel put argc, so the
     * two placement lines below hold by construction and the rest still compares (17 item 4) */
#ifdef __GLIBC__
    uintptr_t *sp = (uintptr_t *)__libc_stack_end;
#else
    uintptr_t *sp = (uintptr_t *)(argv - 1);
#endif
    printf("%s sp aligned 16: %s\n", L, yes_no(((uintptr_t)sp & 15) == 0));
    printf("%s argc at sp: %s\n", L, yes_no(sp[0] == (uintptr_t)argc));
    printf("%s argv at sp+8: %s\n", L, yes_no((uintptr_t *)argv == sp + 1));
    printf("%s envp after argv's NULL: %s\n", L, yes_no(envp == argv + argc + 1));
    printf("%s auxv after envp's NULL: %s\n", L, yes_no((char **)auxv == e + 1));
    int n = 0;
    char types[512] = "";
    for (Elf64_auxv_t *a = auxv; a->a_type != AT_NULL; a++, n++) {
        char t[32];
        snprintf(t, sizeof t, "%s%lu", n ? "," : "", (unsigned long)a->a_type);
        strncat(types, t, sizeof types - strlen(types) - 1);
    }
    printf("%s auxv types: %s\n", L, types);
    printf("%s auxv entries: %d\n", L, n);
    const Elf64_Ehdr *h = &__ehdr_start;
    printf("%s AT_PHDR own: %s\n", L, yes_no(getauxval(AT_PHDR) == (uintptr_t)h + h->e_phoff));
    printf("%s AT_PHENT: %lu\n", L, getauxval(AT_PHENT));
    printf("%s AT_PHNUM own: %s\n", L, yes_no(getauxval(AT_PHNUM) == h->e_phnum));
    printf("%s AT_PAGESZ: %lu\n", L, getauxval(AT_PAGESZ));
    printf("%s AT_ENTRY own: %s\n", L, yes_no(getauxval(AT_ENTRY) == (uintptr_t)_start));
    printf("%s AT_BASE maps: %s\n", L, mapping_of(getauxval(AT_BASE)));
    printf("%s AT_BASE page aligned: %s\n", L, yes_no((getauxval(AT_BASE) & 4095) == 0));
    printf("%s AT_FLAGS: %lu\n", L, getauxval(AT_FLAGS));
    printf("%s AT_UID/EUID/GID/EGID own: %s\n", L,
           yes_no(getauxval(AT_UID) == getuid() && getauxval(AT_EUID) == geteuid() && getauxval(AT_GID) == getgid() &&
                  getauxval(AT_EGID) == getegid()));
    printf("%s AT_SECURE: %lu\n", L, getauxval(AT_SECURE));
    printf("%s AT_PLATFORM: %s\n", L, (const char *)getauxval(AT_PLATFORM));
    printf("%s AT_HWCAP nonzero: %s\n", L, yes_no(getauxval(AT_HWCAP) != 0));
    printf("%s AT_HWCAP2: %lu\n", L, getauxval(AT_HWCAP2));
    printf("%s AT_CLKTCK: %lu\n", L, getauxval(AT_CLKTCK));
    printf("%s AT_MINSIGSTKSZ: %lu\n", L, getauxval(AT_MINSIGSTKSZ));
    printf("%s AT_RSEQ_FEATURE_SIZE: %lu\n", L, getauxval(27));
    printf("%s AT_RSEQ_ALIGN: %lu\n", L, getauxval(28));
    const unsigned char *v = (const unsigned char *)getauxval(AT_SYSINFO_EHDR);
    printf("%s AT_SYSINFO_EHDR: %s\n", L, v && !memcmp(v, ELFMAG, SELFMAG) ? "an ELF" : "none");
    printf("%s AT_SYSINFO_EHDR maps: %s\n", L, mapping_of((uintptr_t)v));
    errno = 0;
    (void)getauxval(AT_EXECFD);
    printf("%s AT_EXECFD: %s\n", L, errno == ENOENT ? "absent" : "present");
    const char *fn = (const char *)getauxval(AT_EXECFN);
    const char *b = fn ? strrchr(fn, '/') : 0;
    printf("%s AT_EXECFN last component: %s\n", L, fn ? (b ? b + 1 : fn) : "none");
    const unsigned char *rnd = (const unsigned char *)getauxval(AT_RANDOM);
    char hex[40] = "";
    for (int i = 0; rnd && i < 16; i++) snprintf(hex + 2 * i, 3, "%02x", rnd[i]);
    const char *parent = getenv("EXEC_AUXV_PARENT_RANDOM");
    printf("%s AT_RANDOM fresh: %s\n", L, parent ? yes_no(strcmp(parent, hex) != 0) : "no parent");
    /* placement: the strings above the vectors, argv ascending and contiguous, envp after them, AT_EXECFN the top
     * string, the platform string and the random bytes below the strings (create_elf_tables) */
    uintptr_t slo, shi;
    stack_bounds(&slo, &shi);
    uintptr_t a0 = (uintptr_t)argv[0], top = (uintptr_t)fn + strlen(fn) + 1;
    printf("%s vectors on the stack mapping: %s\n", L, yes_no((uintptr_t)sp >= slo && (uintptr_t)sp < shi));
    printf("%s strings on the stack mapping: %s\n", L, yes_no(a0 >= slo && a0 < shi));
    printf("%s strings above the vectors: %s\n", L, yes_no(a0 > (uintptr_t)auxv));
    int contig = 1;
    for (int i = 0; i + 1 < argc; i++) contig &= argv[i + 1] == argv[i] + strlen(argv[i]) + 1;
    printf("%s argv strings contiguous ascending: %s\n", L, yes_no(contig));
    printf("%s envp[0] after argv's last: %s\n", L,
           yes_no(nenv == 0 || envp[0] == argv[argc - 1] + strlen(argv[argc - 1]) + 1));
    contig = 1;
    for (int i = 0; i + 1 < nenv; i++) contig &= envp[i + 1] == envp[i] + strlen(envp[i]) + 1;
    printf("%s envp strings contiguous ascending: %s\n", L, yes_no(contig));
    printf("%s AT_EXECFN after envp's last: %s\n", L,
           yes_no(nenv == 0 || fn == envp[nenv - 1] + strlen(envp[nenv - 1]) + 1));
    printf("%s AT_EXECFN ends 8 below the stack top: %s\n", L, yes_no(top == shi - 8));
    const char *plat = (const char *)getauxval(AT_PLATFORM);
    printf("%s AT_PLATFORM below argv[0]: %s\n", L, yes_no((uintptr_t)plat < a0 && (uintptr_t)plat > (uintptr_t)auxv));
    printf("%s AT_RANDOM below AT_PLATFORM: %s\n", L,
           yes_no((uintptr_t)rnd < (uintptr_t)plat && (uintptr_t)rnd > (uintptr_t)auxv));
    printf("%s AT_PLATFORM just below argv[0]: %s\n", L, yes_no((uintptr_t)plat + strlen(plat) + 1 == a0));
    printf("%s AT_RANDOM just below AT_PLATFORM: %s\n", L, yes_no((uintptr_t)rnd + 16 == (uintptr_t)plat));
    /* /proc/self/stat: startcode..endcode hold main, startstack is the initial sp, arg_start the argv strings,
     * env_start the envp strings, env_end the last string's end */
    unsigned long startcode = stat_field(26), endcode = stat_field(27), startstack = stat_field(28);
    unsigned long arg_start = stat_field(48), arg_end = stat_field(49), env_start = stat_field(50),
                  env_end = stat_field(51);
    printf("%s stat code holds main: %s\n", L, yes_no((uintptr_t)main >= startcode && (uintptr_t)main < endcode));
    printf("%s stat startstack is sp: %s\n", L, yes_no(startstack == (uintptr_t)sp));
    printf("%s stat arg_start is argv[0]: %s\n", L, yes_no(arg_start == a0));
    printf("%s stat arg_end is envp[0]: %s\n", L, yes_no(nenv == 0 || arg_end == (uintptr_t)envp[0]));
    printf("%s stat env_start is envp[0]: %s\n", L, yes_no(nenv == 0 || env_start == (uintptr_t)envp[0]));
    printf("%s stat env_end is AT_EXECFN: %s\n", L, yes_no(env_end == (uintptr_t)fn));
    char cmd[4096];
    int fd = open("/proc/self/cmdline", O_RDONLY);
    ssize_t r = fd < 0 ? -1 : read(fd, cmd, sizeof cmd);
    if (fd >= 0) close(fd);
    int same = r > 0;
    size_t off = 0;
    for (int i = 0; same && i < argc; i++) {
        size_t l = strlen(argv[i]) + 1;
        same = off + l <= (size_t)r && !memcmp(cmd + off, argv[i], l);
        off += l;
    }
    printf("%s cmdline is argv: %s\n", L, yes_no(same && off == (size_t)r));
    char comm[64] = "";
    fd = open("/proc/self/comm", O_RDONLY);
    r = fd < 0 ? -1 : read(fd, comm, sizeof comm - 1);
    if (fd >= 0) close(fd);
    if (r > 0) comm[r] = 0;
    comm[strcspn(comm, "\n")] = 0;
    printf("%s comm: %s\n", L, comm);
    printf("%s uid=euid: %s\n", L, yes_no(getuid() == geteuid()));
    /* for the next exec: after the placement checks, since setenv moves a string off the kernel's area */
    setenv("EXEC_AUXV_PARENT_RANDOM", hex, 1);
}

/* the program the descriptor cases exec: static, so that no loader needs a descriptor of its own; it lists its open
 * descriptors, the one it lists with left out, and its soft limit */
/* the program the descriptor cases exec: static, so that no loader needs a descriptor of its own; it lists its open
 * descriptors, the one it lists with and the launcher's log (EXCLAVE_LOG, which a loader-path program inherits) left
 * out, and its soft limit */
static const char FDS_SRC[] =
    "#include <dirent.h>\n#include <errno.h>\n#include <stdio.h>\n#include <stdlib.h>\n#include <string.h>\n"
    "#include <sys/resource.h>\n#include <unistd.h>\n"
    "static int is_log(const char *n) { char p[64], t[4096]; const char *l = getenv(\"EXCLAVE_LOG\");\n"
    "  snprintf(p, sizeof p, \"/proc/self/fd/%s\", n); ssize_t r = readlink(p, t, sizeof t - 1);\n"
    "  if (r < 0 || !l) return 0; t[r] = 0; return strcmp(t, l) == 0; }\n"
    "int main(int argc, char **argv) { struct rlimit rl; getrlimit(RLIMIT_NOFILE, &rl);\n"
    "  DIR *d = opendir(\"/proc/self/fd\"); const char *L = argc > 1 ? argv[1] : \"?\";\n"
    "  if (!d) { printf(\"%s open fds: opendir %s\\n\", L, errno == EMFILE ? \"EMFILE\" : "
    "strerror(errno)); }\n"
    "  else { int dfd = dirfd(d); char list[256] = \"\"; struct dirent *e;\n"
    "    while ((e = readdir(d))) if (e->d_name[0] != '.' && atoi(e->d_name) != dfd && !is_log(e->d_name)) {\n"
    "      if (list[0]) strcat(list, \" \"); strcat(list, e->d_name); }\n"
    "    closedir(d); printf(\"%s open fds: %s\\n\", L, list); }\n"
    "  printf(\"%s soft limit: %lu\\n\", L, (unsigned long)rl.rlim_cur); return 0; }\n";

static void copy_self(const char *to, mode_t mode)
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
    chmod(to, mode);
}

/* run path with argv in a child, the output through; on a failed exec print the errno */
static void child(const char *tag, const char *path, char *const *av, void (*prep)(void))
{
    fflush(stdout);
    int ep[2];
    if (pipe2(ep, O_CLOEXEC)) {
        perror("pipe");
        exit(2);
    }
    pid_t c = fork();
    if (c == 0) {
        close(ep[0]);
        if (prep) prep();
        execve(path, av, environ);
        int e = errno;
        if (write(ep[1], &e, sizeof e) != sizeof e) _exit(99);
        _exit(98);
    }
    close(ep[1]);
    int e = 0;
    ssize_t got = read(ep[0], &e, sizeof e);
    close(ep[0]);
    int st;
    waitpid(c, &st, 0);
    if (got == sizeof e) { /* the lines the program would have printed, each with the exec's error */
        const char *en = e == EMFILE ? "EMFILE" : e == EACCES ? "EACCES" : strerror(e);
        printf("%s open fds: exec %s\n%s soft limit: exec %s\n", tag, en, tag, en);
    }
}

static int soft_limit;
static void limit(void)
{
    struct rlimit rl = {(rlim_t)soft_limit, 1024};
    if (setrlimit(RLIMIT_NOFILE, &rl)) perror("setrlimit");
}
static void hard3(void)
{
    struct rlimit rl = {3, 3};
    if (setrlimit(RLIMIT_NOFILE, &rl)) perror("setrlimit");
}

int main(int argc, char **argv)
{
    if (argc >= 3 && !strcmp(argv[1], "--child")) {
        report(argv[2], argc, argv);
        return 0;
    }
    if (argc < 2) {
        fprintf(stderr, "usage: exec_auxv HOSTDIR\n");
        return 2;
    }
    const char *hd = argv[1];
    static char exe[4096];
    char p[4096];
    /* whether this kernel lets a process give it the record of its image, as the launcher does (7.3) */
    unsigned size = 0;
    printf("PR_SET_MM_MAP: %s\n", yes_no(prctl(PR_SET_MM, PR_SET_MM_MAP_SIZE, &size, 0, 0) == 0));
    ssize_t n = readlink("/proc/self/exe", exe, sizeof exe - 1);
    if (n < 0) {
        perror("readlink");
        return 2;
    }
    exe[n] = 0;
    char *self = exe;
    report("own", argc, argv);
    char *const av[] = {self, "--child", "exec", 0};
    child("exec", self, av, 0);
    snprintf(p, sizeof p, "%s/suid", hd);
    copy_self(p, 04755);
    char *const sav[] = {p, "--child", "suid", 0};
    child("suid", p, sav, 0);
    snprintf(p, sizeof p, "%s/sgid", hd);
    copy_self(p, 02755);
    char *const gav[] = {p, "--child", "sgid", 0};
    child("sgid", p, gav, 0);
    /* the descriptors an exec'd program finds: one kept open and one close-on-exec, under the soft limits 3, 4 and 8
     * lowered below the open descriptors, and a hard limit of 3 */
    snprintf(p, sizeof p, "%s/fds.c", hd);
    {
        int fd = open(p, O_WRONLY | O_CREAT | O_TRUNC, 0644);
        if (write(fd, FDS_SRC, sizeof FDS_SRC - 1) != (ssize_t)(sizeof FDS_SRC - 1)) perror(p);
        close(fd);
    }
    char cmd[16384], fdsprog[4096];
    snprintf(fdsprog, sizeof fdsprog, "%s/fds", hd);
    /* the compiler's complaint is not the program's: a tree without a static libc gets the line below in its place */
    snprintf(cmd, sizeof cmd, "%s -static -o %s/fds %s/fds.c 2>/dev/null", getenv("CC") ? getenv("CC") : "cc", hd, hd);
    fflush(stdout);
    if (system(cmd)) {
        printf("fds: cannot build the static program\n");
        return 0;
    }
    int keep = open("/dev/null", O_RDONLY), gone = open("/dev/null", O_RDONLY | O_CLOEXEC);
    (void)keep;
    (void)gone;
    char *const fav[] = {fdsprog, "fds", 0};
    child("fds", fdsprog, fav, 0);
    for (soft_limit = 3; soft_limit <= 8; soft_limit += soft_limit == 4 ? 4 : 1) {
        char tag[32];
        snprintf(tag, sizeof tag, "soft %d", soft_limit);
        char *const lav[] = {fdsprog, tag, 0};
        child(tag, fdsprog, lav, limit);
    }
    char *const hav[] = {fdsprog, "hard 3", 0};
    child("hard 3", fdsprog, hav, hard3);
    return 0;
}
