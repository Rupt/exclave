/* tool_test.c — the exclave command's BLAKE2b (tool/blake2b.c) against RFC 7693 and Python's hashlib. Built by
 * scripts/gate's unit step with tool/blake2b.c and tool/main.c.
 *
 * BLAKE2b-512 of "abc" is the RFC's appendix A; the BLAKE2b-256 digests of a byte pattern, at the lengths about the
 * 128-byte block, are hashlib's. Every length up to 300 is also hashed in two pieces at every split, which must agree
 * with the one piece. Prints one line per failure and a summary; exit 0 when every case holds. */
#include <stdio.h>
#include <string.h>
#include "../tool/tool.h"

static int fails, runs;

static void hex(const uint8_t *d, size_t n, char *out)
{
    for (size_t i = 0; i < n; i++) sprintf(out + 2 * i, "%02x", d[i]);
}

static void pattern(uint8_t *p, size_t n)
{
    for (size_t i = 0; i < n; i++) p[i] = (uint8_t)(i * 7 + 3);
}

static void expect(const char *name, const char *got, const char *want)
{
    runs++;
    if (strcmp(got, want) != 0) {
        fails++;
        printf("FAIL %s: got %s, wanted %s\n", name, got, want);
    }
}

int main(void)
{
    static uint8_t data[1 << 20];
    struct blake2b s;
    uint8_t d[64];
    char got[129];

    b2_init(&s, 64);
    b2_update(&s, "abc", 3);
    b2_final(&s, d);
    hex(d, 64, got);
    expect("RFC 7693 appendix A", got,
           "ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d1"
           "7d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923");

    static const struct {
        size_t n;
        const char *digest;
    } cases[] = {
        {0, "0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8"},
        {3, "9facd640130c81e7f318a8d5c660bc1b0f5d03861ffbd4cc1358e0e904593c28"},
        {127, "c9ae3859964b35f04c54b36d33cf299d7290ee621005d28e51598a943560aaaa"},
        {128, "f0501d06597880592bc49234eef100ec1ff349058d0e9d9b753504e24af86dd6"},
        {129, "a34a4e1e03c541dfbf3099c4b6c143c022ced65c28bd7e8a10e0a098461aecf0"},
        {255, "f2d64a40e9412a3414161ff6250075225418fd7c271c1123e162e1bca0de9f93"},
        {256, "d93ebb9c802f5630ab22516fd82b6c21bc8bd551d531349b715f046ed11ed871"},
        {257, "4ce481b24d387422d2bc2baa03d1afd55a1327939ff537c71eb9b38709268649"},
        {1 << 20, "65c804268df52a2d78034f9a50113d0c5d9a5e592ea3735012ebc798f3271a6b"},
    };
    pattern(data, sizeof data);
    for (size_t i = 0; i < sizeof cases / sizeof *cases; i++) {
        char name[32];
        snprintf(name, sizeof name, "hashlib, %zu bytes", cases[i].n);
        b2_init(&s, 32);
        b2_update(&s, data, cases[i].n);
        b2_final(&s, d);
        hex(d, 32, got);
        expect(name, got, cases[i].digest);
    }
    for (size_t n = 0; n <= 300; n++) {
        char whole[65];
        b2_init(&s, 32);
        b2_update(&s, data, n);
        b2_final(&s, d);
        hex(d, 32, whole);
        for (size_t k = 0; k <= n; k++) {
            char name[48];
            snprintf(name, sizeof name, "%zu bytes split at %zu", n, k);
            b2_init(&s, 32);
            b2_update(&s, data, k);
            b2_update(&s, data + k, n - k);
            b2_final(&s, d);
            hex(d, 32, got);
            expect(name, got, whole);
        }
    }
    printf("%s BLAKE2b: %d cases, %d failures\n", fails ? "FAIL" : "PASS", runs, fails);
    return fails != 0;
}
