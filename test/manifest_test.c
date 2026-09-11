/* manifest_test.c — host-side tests for the strict manifest grammar (PROPOSAL.md 6.2). Built by `make unit`. */
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
    int r = manifest_parse(text, strlen(text), &c, err, sizeof err);
    runs++;
    int ok = (r == 0) == (want_ok != 0) && (!want_err || strstr(err, want_err));
    if (!ok) { fails++; printf("FAIL %s: r=%d err=\"%s\" (wanted %s%s%s)\n", name, r, err, want_ok ? "ok" : "error", want_err ? " containing " : "", want_err ? want_err : ""); }
}
#define OK(name, text) expect(name, text, 1, 0)
#define BAD(name, text, why) expect(name, text, 0, why)

/* with a file argument: parse it and exit 0 or 1, for test/grammar_test.py's comparison with the Python parser */
static int parse_file(const char *path)
{
    static char buf[1 << 20]; FILE *f = fopen(path, "rb"); if (!f) return 2;
    size_t n = fread(buf, 1, sizeof buf, f); fclose(f);
    char err[256] = ""; struct can c; memset(&c, 0, sizeof c);
    int r = manifest_parse(buf, n, &c, err, sizeof err);
    if (r) fprintf(stderr, "%s\n", err);
    return r ? 1 : 0;
}

int main(int argc, char **argv)
{
    if (argc == 2) return parse_file(argv[1]);
    OK("minimal", "can 1\n");
    OK("full", "# a can\ncan 1\n\nisa \"x86-64-v2\"\n\ndata \"/opt/musl-sysroot\"\n\nhost \"/usr/local/share/fonts\"\n\nown \"/etc/hosts\"\nown \"/usr\"\n");
    OK("escapes", "can 1\nown \"/a\\\\b\\\"c\\n\\t\\x01\\xff\"\n");
    OK("utf8", "can 1\nown \"/caf\xc3\xa9/\xe2\x82\xac/\xf0\x9f\x98\x80\"\n# comment with \xc3\xa9 and\ttab\nhost \"/x\"\n");
    OK("comment between", "can 1\n# about the claim\nown \"/opt\"\n");
    OK("non-canonical spelling accepted", "can 1\nown \"/\\x41\"\n");
    BAD("no final lf", "can 1\nown \"/a\"", "end with LF");
    BAD("bom", "\xef\xbb\xbf" "can 1\n", "byte order mark");
    BAD("cr", "can 1\r\n", "CR");
    BAD("tab", "can 1\nown\t\"/a\"\n", "tab");
    BAD("trailing space", "can 1\nown \"/a\" \n", "trailing space");
    BAD("double space", "can 1\nown  \"/a\"\n", "multiple spaces");
    BAD("unknown escape", "can 1\nown \"/\\q\"\n", "unknown escape");
    BAD("uppercase hex", "can 1\nown \"/\\xFF\"\n", "hex");
    BAD("raw control", "can 1\nown \"/a\x01\"\n", "control");
    BAD("raw del", "can 1\nown \"/a\x7f\"\n", "control");
    BAD("c1 control", "can 1\nown \"/a\xc2\x85\"\n", "control");
    BAD("overlong", "can 1\nown \"/a\xc0\x80\"\n", "UTF-8");
    BAD("surrogate", "can 1\nown \"/a\xed\xa0\x80\"\n", "UTF-8");
    BAD("f5", "can 1\nown \"/a\xf5\x80\x80\x80\"\n", "UTF-8");
    BAD("truncated seq", "can 1\nown \"/a\xe2\x82\"\n", "UTF-8");
    BAD("bad utf8 in comment", "can 1\n# \xff\nown \"/a\"\n", "UTF-8");
    BAD("unterminated", "can 1\nown \"/a\n", "unterminated");
    BAD("trailing comment", "can 1\nown \"/a\"\n# end\n", "comment after");
    BAD("dup isa", "can 1\nisa \"x86-64\"\nisa \"x86-64\"\n", "duplicate");
    BAD("unknown key", "can 1\nfoo \"x\"\n", "unknown key");
    BAD("old index key", "can 1\ninterp \"/lib64/ld-linux-x86-64.so.2\"\n", "unknown key");
    BAD("old env key", "can 1\nenv \"CC\" \"gcc\"\n", "unknown key");
    BAD("old entry key", "can 1\nentry \"gcc\" \"/usr/bin/gcc\"\n", "unknown key");
    BAD("old use key", "can 1\nuse \"../other\"\n", "unknown key");
    BAD("uppercase key", "can 1\nOwn \"/a\"\n", "lowercase key");
    BAD("arity", "can 1\nown \"/a\" \"/b\"\n", "field count");
    BAD("type", "can 1\nown a\n", "field type");
    BAD("can not first", "own \"/a\"\ncan 1\n", "first record must be can");
    BAD("can version", "can 2\n", "unsupported can version");
    BAD("relative own", "can 1\nown \"usr\"\n", "absolute");
    BAD("relative host", "can 1\nhost \"usr\"\n", "absolute");
    BAD("relative data", "can 1\ndata \"opt\"\n", "absolute");
    BAD("trailing slash", "can 1\nown \"/usr/\"\n", "normalised");
    BAD("double slash", "can 1\nhost \"/usr//share\"\n", "normalised");
    BAD("dot component", "can 1\ndata \"/opt/./x\"\n", "normalised");
    BAD("dotdot component", "can 1\nown \"/usr/../etc\"\n", "normalised");
    OK("root itself", "can 1\nown \"/\"\n");
    BAD("empty", "", "end with LF");
    BAD("only blank", "\n", "empty manifest");
    BAD("bare quote field", "can 1\nown \"/a\" x\n", "field count");
    /* decoded values, and the ISA default */
    {
        struct can c; memset(&c, 0, sizeof c); char err[256];
        const char *text = "can 1\n\nhost \"/srv/h\"\n\nown \"/a\\\\b\\\"c\\n\\t\\x01\"\nown \"/etc/hosts\"\n";
        runs++;
        if (manifest_parse(text, strlen(text), &c, err, sizeof err) != 0 || c.nown != 2 || strcmp(c.own[0], "/a\\b\"c\n\t\x01") != 0
            || strcmp(c.own[1], "/etc/hosts") != 0 || c.nhost != 1 || strcmp(c.host[0].v, "/srv/h") != 0 || strcmp(c.isa, "x86-64") != 0)
            { fails++; printf("FAIL decode: %s nown=%d nhost=%d isa=%s\n", err, c.nown, c.nhost, c.isa); }
    }
    printf("%d tests, %d failures\n", runs, fails);
    return fails ? 1 : 0;
}
