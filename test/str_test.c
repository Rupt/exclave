/* str_test.c — the #! line rules of shebang_argv (src/str.c), against fs/binfmt_script.c's load_script. Built by
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

    printf("%s #! lines: %d cases, %d failures\n", fails ? "FAIL" : "PASS", runs, fails);
    return fails != 0;
}
