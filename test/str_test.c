/* str_test.c — the parsers of src/str.c: the launcher's own variables told from a string's head, the TracerPid of a
 * status file's head, and the #! line rules of shebang_argv, against fs/binfmt_script.c's load_script. Built by
 * scripts/gate's unit step with src/str.c.
 *
 * Each case gives the first bytes of a file, as many as the kernel reads (BINPRM_BUF_SIZE), and the argv the kernel
 * builds from them, or ENOEXEC. Prints one line per failure and a summary; exit 0 when every case holds. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../src/common.h"

struct exclave C;
void die(const char *what, const char *detail, long err)
{
    fprintf(stderr, "die: %s %s %ld\n", what, detail ? detail : "", err);
    exit(99);
}

static int fails, runs;

/* want: the interpreter and the argument joined by '|', or NULL for ENOEXEC */
static void expect(const char *name, const char *text, size_t n, const char *want)
{
    static char line[BINPRM_BUF_SIZE + 1], script[] = "/s", arg0[] = "script", arg1[] = "a1";
    char *argv[] = {arg0, arg1, 0}, *nargv[8], got[2 * BINPRM_BUF_SIZE] = "";
    memcpy(line, text, n);
    long k = shebang_argv(line, (long)n, script, argv, 2, nargv, 8);
    if (k > 0) snprintf(got, sizeof got, "%s%s%s", nargv[0], k == 4 ? "|" : "", k == 4 ? nargv[1] : "");
    runs++;
    int ok = want ? k > 0 && strcmp(got, want) == 0 && strcmp(nargv[k - 2], "/s") == 0 && !strcmp(nargv[k - 1], "a1")
                  : k == -1;
    if (!ok) {
        fails++;
        printf("FAIL %s: k=%ld got \"%s\", wanted %s\n", name, k, got, want ? want : "ENOEXEC");
    }
}
/* the bytes of s at dst, with no NUL after them: a file's head is not a string */
static void put(char *dst, const char *s)
{
    while (*s) *dst++ = *s++;
}
#define CASE(name, text, want) expect(name, text, sizeof(text) - 1, want)

int main(void)
{
    static char buf[BINPRM_BUF_SIZE + 1];
    CASE("plain", "#!/bin/sh\necho\n", "/bin/sh");
    CASE("argument", "#!/bin/sh -e\n", "/bin/sh|-e");
    CASE("blanks around", "#!  \t/bin/sh \t -e x \t\n", "/bin/sh|-e x");
    CASE("no newline", "#!/bin/sh", "/bin/sh");
    CASE("not a #! line", "echo\n", NULL);
    CASE("one byte", "#", NULL);
    CASE("no interpreter", "#!   \n", NULL);
    /* NUL padding ends the blanks: an empty interpreter name, which the exec then looks up */
    CASE("blanks only, no newline", "#!   ", "");
    CASE("NUL ends the interpreter", "#!/bin/sh\0 -e\n", "/bin/sh");

    /* no newline in the buffer: an interpreter path no blank ends within 255 bytes is refused, never cut */
    memset(buf, 'x', sizeof buf);
    put(buf, "#!/");
    expect("interpreter past the buffer", buf, BINPRM_BUF_SIZE, NULL);
    /* the same with a blank in the buffer: the argument runs to the 255th byte and is cut there */
    put(buf + 3, "bin/sh ");
    char want[BINPRM_BUF_SIZE] = "/bin/sh|";
    memset(want + 8, 'x', BINPRM_BUF_SIZE - 1 - 10);
    expect("argument cut", buf, BINPRM_BUF_SIZE, want);
    /* a newline in the 256th byte still ends the line */
    memset(buf, 'x', sizeof buf);
    put(buf, "#!/");
    buf[BINPRM_BUF_SIZE - 1] = '\n';
    memset(want, 0, sizeof want);
    want[0] = '/';
    memset(want + 1, 'x', BINPRM_BUF_SIZE - 4);
    expect("newline in the last byte", buf, BINPRM_BUF_SIZE, want);

    /* nargv of cap entries, on the heap so that a write past it is ASan's: the interpreter, its argument, the script,
     * argv[1] and the NULL take argc + 3, and one fewer is refused (-2) */
    for (long cap = 4; cap <= 5; cap++) {
        static char line[BINPRM_BUF_SIZE + 1], script[] = "/s", arg0[] = "script", arg1[] = "a1";
        char *argv[] = {arg0, arg1, 0}, **nargv = (char **)malloc((size_t)cap * sizeof *nargv);
        snprintf(line, sizeof line, "#!/bin/sh -e\n");
        long k = shebang_argv(line, 13, script, argv, 2, nargv, cap), w = cap == 4 ? -2 : 4;
        runs++;
        if (k != w || (k == 4 && nargv[4] != NULL)) {
            fails++;
            printf("FAIL nargv of %ld entries for argc 2: k=%ld, wanted %ld\n", cap, k, w);
        }
        free((void *)nargv);
    }

    /* the launcher's own variables (7.4.5), told from a string's first bytes: each name with its =, and nothing else */
    static const struct {
        const char *s;
        long n;
        int want;
    } vars[] = {
        {"EXCLAVE_EXEC=/usr/bin/true", 26, IS_EXEC},
        {"EXCLAVE_EXECFN=true", 19, IS_EXECFN},
        {"EXCLAVE_COMM=true", 17, IS_COMM},
        {"EXCLAVE_TRACED=1", 16, IS_TRACED},
        {"EXCLAVE_CWD=64768.2", 19, IS_CWD},
        {"EXCLAVE_EXEC", 12, 0},          /* no = */
        {"EXCLAVE_EXECFN=true", 14, 0},   /* cut before its = */
        {"EXCLAVE_EXECX=1", 15, 0},
        {"EXCLAVE_LOG=/tmp/log", 20, 0},  /* the user's knob, not the protocol's */
        {"PATH=/usr/bin", 13, 0},
        {"", 0, 0},
    };
    for (unsigned i = 0; i < sizeof vars / sizeof vars[0]; i++) {
        /* on the heap at its exact length, so that a read past n is ASan's */
        char *copy = (char *)malloc((size_t)vars[i].n + 1);
        if (!copy) return 2;
        memcpy(copy, vars[i].s, (size_t)vars[i].n);
        int got = internal_var(copy, vars[i].n);
        runs++;
        if (got != vars[i].want) {
            fails++;
            printf("FAIL internal_var of %.*s: %d, wanted %d\n", (int)vars[i].n, vars[i].s, got, vars[i].want);
        }
        free(copy);
    }

    /* the TracerPid of a status file's head: the number on its line, 0 where the line is absent or cut */
    static const struct {
        const char *s;
        long want;
    } heads[] = {
        {"Name:\tsh\nPid:\t7\nTracerPid:\t4242\nUid:\t1000\n", 4242},
        {"Name:\tsh\nTracerPid:\t0\n", 0},
        {"Name:\tsh\nTracerPid:\t77", 0},   /* cut before the line ends */
        {"Name:\tTracerPid:\t9\n", 0},        /* in the name, not at a line's start */
        {"Name:\tsh\n", 0},
        {"", 0},
    };
    for (unsigned i = 0; i < sizeof heads / sizeof heads[0]; i++) {
        long got = status_tracer(heads[i].s, (long)strlen(heads[i].s));
        runs++;
        if (got != heads[i].want) {
            fails++;
            printf("FAIL status_tracer of case %u: %ld, wanted %ld\n", i, got, heads[i].want);
        }
    }

    printf("%s #! lines, variables and status heads: %d cases, %d failures\n", fails ? "FAIL" : "PASS", runs, fails);
    return fails != 0;
}
