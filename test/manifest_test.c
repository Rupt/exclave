/* manifest_test.c — host-side tests for the strict manifest grammar (DESIGN.md 6.2).
 * Built by scripts/gate's unit step. */
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
static void expect(const char *name, const char *text, int want_ok, const char *want_err)
{
    char err[256] = "";
    struct exclave c;
    memset(&c, 0, sizeof c);
    int r = manifest_parse(text, strlen(text), &c, err, sizeof err);
    runs++;
    int ok = (r == 0) == (want_ok != 0) && (!want_err || strstr(err, want_err));
    if (!ok) {
        fails++;
        printf("FAIL %s: r=%d err=\"%s\" (wanted %s%s%s)\n", name, r, err, want_ok ? "ok" : "error",
               want_err ? " containing " : "", want_err ? want_err : "");
    }
}
#define OK(name, text) expect(name, text, 1, 0)
#define BAD(name, text, why) expect(name, text, 0, why)

/* with file arguments: parse each and print one line for it, "ok" and each own value in hex, or the error, for
 * test/grammar_test.py's comparison with the command's parser; a line each as it goes, so that the file a sanitiser's
 * finding stopped on is the one after the last line */
void arena_reset(void);
static int parse_files(int n, char **paths)
{
    static char buf[1 << 20];
    setvbuf(stdout, NULL, _IOLBF, 0);
    for (int i = 0; i < n; i++) {
        FILE *f = fopen(paths[i], "rb");
        if (!f) return fprintf(stderr, "cannot open %s\n", paths[i]), 2;
        size_t len = fread(buf, 1, sizeof buf, f);
        fclose(f);
        if (len == sizeof buf) return fprintf(stderr, "%s fills the buffer\n", paths[i]), 2;
        char err[256] = "";
        struct exclave c;
        memset(&c, 0, sizeof c);
        arena_reset();
        if (manifest_parse(buf, len, &c, err, sizeof err)) {
            printf("%s\n", err);
            continue;
        }
        printf("ok");
        for (int k = 0; k < c.nown; k++) {
            putchar(' ');
            for (const unsigned char *b = (const unsigned char *)c.own[k]; *b; b++) printf("%02x", *b);
        }
        putchar('\n');
    }
    return 0;
}

int main(int argc, char **argv)
{
    if (argc > 1) return parse_files(argc - 1, argv + 1);
    OK("minimal", "exclave 1\n");
    OK("full", "# an exclave\nexclave 1\n\ncpu \"x86-64-v2\"\n\ndata \"/opt/musl-sysroot\"\n\nhost "
               "\"/usr/local/share/fonts\"\n\nown \"/etc/hosts\"\nown \"/usr\"\n");
    OK("escapes", "exclave 1\nown \"/a\\\\b\\\"c\\n\\t\\x01\\xff\"\n");
    OK("utf8", "exclave 1\nown \"/caf\xc3\xa9/\xe2\x82\xac/\xf0\x9f\x98\x80\"\n# comment with \xc3\xa9 and\ttab\nhost "
               "\"/x\"\n");
    OK("comment between", "exclave 1\n# about the own record\nown \"/opt\"\n");
    OK("non-canonical spelling accepted", "exclave 1\nown \"/\\x41\"\n");
    BAD("no final lf", "exclave 1\nown \"/a\"", "end with LF");
    BAD("bom",
        "\xef\xbb\xbf"
        "exclave 1\n",
        "byte order mark");
    BAD("cr", "exclave 1\r\n", "CR");
    BAD("tab", "exclave 1\nown\t\"/a\"\n", "tab");
    BAD("trailing space", "exclave 1\nown \"/a\" \n", "trailing space");
    BAD("double space", "exclave 1\nown  \"/a\"\n", "multiple spaces");
    BAD("unknown escape", "exclave 1\nown \"/\\q\"\n", "unknown escape");
    BAD("uppercase hex", "exclave 1\nown \"/\\xFF\"\n", "hex");
    BAD("raw control", "exclave 1\nown \"/a\x01\"\n", "control");
    BAD("raw del", "exclave 1\nown \"/a\x7f\"\n", "control");
    BAD("c1 control", "exclave 1\nown \"/a\xc2\x85\"\n", "control");
    BAD("overlong", "exclave 1\nown \"/a\xc0\x80\"\n", "UTF-8");
    BAD("surrogate", "exclave 1\nown \"/a\xed\xa0\x80\"\n", "UTF-8");
    BAD("f5", "exclave 1\nown \"/a\xf5\x80\x80\x80\"\n", "UTF-8");
    BAD("truncated seq", "exclave 1\nown \"/a\xe2\x82\"\n", "UTF-8");
    BAD("bad utf8 in comment", "exclave 1\n# \xff\nown \"/a\"\n", "UTF-8");
    BAD("unterminated", "exclave 1\nown \"/a\n", "unterminated");
    BAD("trailing comment", "exclave 1\nown \"/a\"\n# end\n", "comment after");
    BAD("dup cpu", "exclave 1\ncpu \"x86-64\"\ncpu \"x86-64\"\n", "duplicate");
    BAD("cpu with a NUL", "exclave 1\ncpu \"x86-64\\x00junk\"\n", "NUL");
    BAD("unknown key", "exclave 1\nfoo \"x\"\n", "unknown key");
    BAD("unknown key interp", "exclave 1\ninterp \"/lib64/ld-linux-x86-64.so.2\"\n", "unknown key");
    BAD("unknown key env", "exclave 1\nenv \"CC\" \"gcc\"\n", "unknown key");
    BAD("unknown key entry", "exclave 1\nentry \"gcc\" \"/usr/bin/gcc\"\n", "unknown key");
    BAD("unknown key use", "exclave 1\nuse \"../other\"\n", "unknown key");
    BAD("uppercase key", "exclave 1\nOwn \"/a\"\n", "lowercase key");
    BAD("arity", "exclave 1\nown \"/a\" \"/b\"\n", "field count");
    BAD("type", "exclave 1\nown a\n", "field type");
    BAD("exclave not first", "own \"/a\"\nexclave 1\n", "first record must be exclave");
    BAD("exclave version", "exclave 2\n", "unsupported exclave version");
    BAD("relative own", "exclave 1\nown \"usr\"\n", "absolute");
    BAD("relative host", "exclave 1\nhost \"usr\"\n", "absolute");
    BAD("relative data", "exclave 1\ndata \"opt\"\n", "absolute");
    BAD("trailing slash", "exclave 1\nown \"/usr/\"\n", "normalised");
    BAD("double slash", "exclave 1\nhost \"/usr//share\"\n", "normalised");
    BAD("dot component", "exclave 1\ndata \"/opt/./x\"\n", "normalised");
    BAD("dotdot component", "exclave 1\nown \"/usr/../etc\"\n", "normalised");
    OK("root itself", "exclave 1\nown \"/\"\n");
    BAD("empty", "", "end with LF");
    BAD("only blank", "\n", "empty manifest");
    BAD("bare quote field", "exclave 1\nown \"/a\" x\n", "field count");
    BAD("nine fields", "exclave 1\nown \"/a\" \"/b\" \"/c\" \"/d\" \"/e\" \"/f\" \"/g\" \"/h\" \"/i\"\n",
        "too many fields");
    BAD("31-character key", "exclave 1\naaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa \"/x\"\n", "unknown key");
    BAD("32-character key", "exclave 1\naaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa \"/x\"\n", "key too long");
    BAD("second exclave", "exclave 1\nexclave 1\n", "exclave must be the first record");
    BAD("exclave as a string", "exclave \"1\"\n", "field type");
    BAD("truncated \\x", "exclave 1\nown \"/\\x\n", "truncated \\x escape");
    /* a field's limit, a string's decoded bytes and a token's (6.2) */
    {
        static char text[2 * PATH_MAX + 64];
        char *v = text + snprintf(text, 64, "exclave 1\nown \"/");
        memset(v, 'a', MANIFEST_FIELD_MAX - 1);
        memcpy(v + MANIFEST_FIELD_MAX - 1, "\"\n", 3);
        OK("the longest string", text);
        v = text + snprintf(text, 64, "exclave 1\nown \"/");
        memset(v, 'a', MANIFEST_FIELD_MAX - 2);
        memcpy(v + MANIFEST_FIELD_MAX - 2, "\\x61\\x62\"\n", 11);
        BAD("a string a byte too long", text, "line 2 col 4104: string too long");
        v = text + snprintf(text, 64, "exclave 1\ncpu ");
        memset(v, '1', MANIFEST_FIELD_MAX + 1);
        memcpy(v + MANIFEST_FIELD_MAX + 1, "\n", 2);
        BAD("a token a byte too long", text, "line 2 col 4100: token too long");
    }
    /* the largest manifest the limits allow, and a record of the most fields, each the longest, refused after it: the
     * arena holds them all, so the refusal names its line rather than the launcher dying of a full arena (exit 99) */
    {
        size_t cap =
            (size_t)(2 + MAX_OWN_RECORDS + MAX_HOST_RECORDS + MAX_DATA_RECORDS + MANIFEST_FIELDS) * (PATH_MAX + 16);
        char *text = malloc(cap), *t = text, *field = malloc(PATH_MAX);
        memset(field, 'a', MANIFEST_FIELD_MAX);
        field[0] = '/';
        field[MANIFEST_FIELD_MAX] = 0;
        t += sprintf(t, "exclave 1\ncpu \"%s\"\n", field);
        for (int i = 0; i < MAX_DATA_RECORDS; i++) t += sprintf(t, "data \"%s\"\n", field);
        for (int i = 0; i < MAX_HOST_RECORDS; i++) t += sprintf(t, "host \"%s\"\n", field);
        for (int i = 0; i < MAX_OWN_RECORDS; i++) t += sprintf(t, "own \"%s\"\n", field);
        t += sprintf(t, "own");
        for (int i = 0; i < MANIFEST_FIELDS; i++) t += sprintf(t, " \"%s\"", field);
        sprintf(t, "\n");
        BAD("the largest manifest", text, "line 323 col 1: wrong field count");
        free(field);
        free(text);
    }
    /* decoded values, and the CPU level default */
    {
        struct exclave c;
        memset(&c, 0, sizeof c);
        char err[256] = "";
        const char *text = "exclave 1\n\nhost \"/srv/h\"\n\nown \"/a\\\\b\\\"c\\n\\t\\x01\"\nown \"/etc/hosts\"\n";
        runs++;
        /* the CPU level default is the machine's own (sys.h) */
        if (manifest_parse(text, strlen(text), &c, err, sizeof err) != 0 || c.nown != 2 ||
            strcmp(c.own[0], "/a\\b\"c\n\t\x01") != 0 || strcmp(c.own[1], "/etc/hosts") != 0 || c.nhost != 1 ||
            strcmp(c.host[0].v, "/srv/h") != 0 || strcmp(c.cpu, ARCH_ISA_DEFAULT) != 0) {
            fails++;
            printf("FAIL decode: %s nown=%d nhost=%d cpu=%s\n", err, c.nown, c.nhost, c.cpu);
        }
    }
    printf("%d tests, %d failures\n", runs, fails);
    return fails ? 1 : 0;
}
