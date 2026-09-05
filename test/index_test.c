/* index_test.c — host-side tests for the strict index grammar (PROPOSAL.md 6.2). Built by `make unit`. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../src/common.h"

struct can C;
void die(const char *what, const char *detail, long err) { fprintf(stderr, "die: %s %s %ld\n", what, detail ? detail : "", err); exit(99); }

static int fails, runs;
static void expect(const char *name, const char *text, int want_ok, const char *want_err)
{
    char err[256] = ""; struct can c; memset(&c, 0, sizeof c);
    int r = index_parse(text, strlen(text), &c, err, sizeof err);
    runs++;
    int ok = (r == 0) == (want_ok != 0) && (!want_err || strstr(err, want_err));
    if (!ok) { fails++; printf("FAIL %s: r=%d err=\"%s\" (wanted %s%s%s)\n", name, r, err, want_ok ? "ok" : "error", want_err ? " containing " : "", want_err ? want_err : ""); }
}
#define OK(name, text) expect(name, text, 1, 0)
#define BAD(name, text, why) expect(name, text, 0, why)

int main(void)
{
    const char *head = "index 1\n\narch \"x86_64\"\n\nisa \"x86-64\"\n\n";
    OK("minimal", "index 1\n\narch \"x86_64\"\n\nisa \"x86-64\"\n");
    OK("full", "# a can\nindex 1\n\narch \"x86_64\"\n\nisa \"x86-64-v2\"\n\nlibc \"glibc\" \"2.39\"\n\ninterp \"/lib64/ld-linux-x86-64.so.2\"\n\nown \"/usr\"\nown \"/etc\"\n\nhost \"/etc/passwd\"\n\ndata \"/usr/share/x\"\n\nenv \"CC\" \"gcc\"\n\nwrap \"/usr/bin/gcc\"\n\nuse \"../base\" \"/opt\"\nuse \"../other\"\n");
    OK("escapes", "index 1\narch \"x86_64\"\nisa \"x86-64\"\nown \"/a\\\\b\\\"c\\n\\t\\x01\\xff\"\n");
    OK("utf8", "index 1\narch \"x86_64\"\nisa \"x86-64\"\nown \"/caf\xc3\xa9/\xe2\x82\xac/\xf0\x9f\x98\x80\"\n# comment with \xc3\xa9 and\ttab\nenv \"A\" \"\"\n");
    OK("comment between", "index 1\n# about arch\narch \"x86_64\"\nisa \"x86-64\"\n");
    BAD("no final lf", "index 1\narch \"x86_64\"\nisa \"x86-64\"", "end with LF");
    BAD("bom", "\xef\xbb\xbfindex 1\narch \"x86_64\"\nisa \"x86-64\"\n", "byte order mark");
    BAD("cr", "index 1\r\narch \"x86_64\"\nisa \"x86-64\"\n", "CR");
    BAD("tab", "index 1\narch\t\"x86_64\"\nisa \"x86-64\"\n", "tab");
    BAD("trailing space", "index 1\narch \"x86_64\" \nisa \"x86-64\"\n", "trailing space");
    BAD("double space", "index 1\narch  \"x86_64\"\nisa \"x86-64\"\n", "multiple spaces");
    BAD("unknown escape", "index 1\narch \"x86_64\"\nisa \"x86-64\"\nown \"/\\q\"\n", "unknown escape");
    BAD("uppercase hex", "index 1\narch \"x86_64\"\nisa \"x86-64\"\nown \"/\\xFF\"\n", "hex");
    BAD("raw control", "index 1\narch \"x86_64\"\nisa \"x86-64\"\nown \"/a\x01\"\n", "control");
    BAD("raw del", "index 1\narch \"x86_64\"\nisa \"x86-64\"\nown \"/a\x7f\"\n", "control");
    BAD("c1 control", "index 1\narch \"x86_64\"\nisa \"x86-64\"\nown \"/a\xc2\x85\"\n", "control");
    BAD("overlong", "index 1\narch \"x86_64\"\nisa \"x86-64\"\nown \"/a\xc0\x80\"\n", "UTF-8");
    BAD("surrogate", "index 1\narch \"x86_64\"\nisa \"x86-64\"\nown \"/a\xed\xa0\x80\"\n", "UTF-8");
    BAD("f5", "index 1\narch \"x86_64\"\nisa \"x86-64\"\nown \"/a\xf5\x80\x80\x80\"\n", "UTF-8");
    BAD("truncated seq", "index 1\narch \"x86_64\"\nisa \"x86-64\"\nown \"/a\xe2\x82\"\n", "UTF-8");
    BAD("bad utf8 in comment", "index 1\n# \xff\narch \"x86_64\"\nisa \"x86-64\"\n", "UTF-8");
    BAD("unterminated", "index 1\narch \"x86_64\nisa \"x86-64\"\n", "unterminated");
    BAD("trailing comment", "index 1\narch \"x86_64\"\nisa \"x86-64\"\n# end\n", "comment after");
    BAD("dup arch", "index 1\narch \"x86_64\"\narch \"x86_64\"\nisa \"x86-64\"\n", "duplicate");
    BAD("unknown key", "index 1\narch \"x86_64\"\nisa \"x86-64\"\nfoo \"x\"\n", "unknown key");
    BAD("uppercase key", "index 1\nArch \"x86_64\"\nisa \"x86-64\"\n", "lowercase key");
    BAD("arity", "index 1\narch \"x86_64\" \"y\"\nisa \"x86-64\"\n", "field count");
    BAD("type", "index 1\narch x86_64\nisa \"x86-64\"\n", "field type");
    BAD("index not first", "arch \"x86_64\"\nindex 1\nisa \"x86-64\"\n", "first record must be index");
    BAD("index version", "index 2\narch \"x86_64\"\nisa \"x86-64\"\n", "unsupported index version");
    BAD("missing isa", "index 1\narch \"x86_64\"\n", "required");
    BAD("relative own", "index 1\narch \"x86_64\"\nisa \"x86-64\"\nown \"usr\"\n", "absolute");
    BAD("env with =", "index 1\narch \"x86_64\"\nisa \"x86-64\"\nenv \"A=B\" \"c\"\n", "env name");
    BAD("use three fields", "index 1\narch \"x86_64\"\nisa \"x86-64\"\nuse \"a\" \"b\" \"c\"\n", "use takes");
    BAD("empty", "", "end with LF");
    BAD("only blank", "\n", "empty index");
    BAD("bare quote field", "index 1\narch \"x86_64\"\nisa \"x86-64\"\nown \"/a\" x\n", "field count");
    /* decoded values */
    {
        struct can c; memset(&c, 0, sizeof c); char err[256];
        char text[512]; snprintf(text, sizeof text, "%sown \"/a\\\\b\\\"c\\n\\t\\x01\"\n\nenv \"K\" \"v \\x41\"\n", head);
        runs++;
        if (index_parse(text, strlen(text), &c, err, sizeof err) != 0 || c.nown != 1 || strcmp(c.own[0], "/a\\b\"c\n\t\x01") != 0 || c.nenv != 1 || strcmp(c.envset[0], "K=v A") != 0)
            { fails++; printf("FAIL decode: %s own=%s env=%s\n", err, c.nown ? c.own[0] : "-", c.nenv ? c.envset[0] : "-"); }
    }
    printf("%d tests, %d failures\n", runs, fails);
    return fails ? 1 : 0;
}
