/* low_image.c — a program laid out as Go's aarch64 linker lays one out, text from 0x10000 and an image reaching past
 * 0x3f0000, where the syscall page lay in early versions (DESIGN.md 13 item 24). Built -no-pie with
 * -Wl,-Ttext-segment=0x10000. Prints where its text and bss lie, writes the bss across 0x3f0000, and makes a
 * trapped syscall; exit 0 when all of that worked. */
#include <stdint.h>
#include <stdio.h>
#include <unistd.h>

static char big[8 << 20];                                      /* bss from just above the text to past 0x3f0000 */

int main(void)
{
    uintptr_t lo = (uintptr_t)big, hi = lo + sizeof big;
    if (lo > 0x3f0000 || hi < 0x3f1000) {
        printf("FAIL bss %#lx-%#lx does not cover 0x3f0000\n", (unsigned long)lo, (unsigned long)hi);
        return 1;
    }
    for (uintptr_t a = 0x3f0000; a < 0x3f1000; a += 64) big[a - lo] = 1;
    int seen = access("/usr/share/exclave-test-marker", R_OK);    /* a path the exclave owns, through the handler */
    printf("text %#lx bss %#lx-%#lx marker %d\n", (unsigned long)(uintptr_t)main, (unsigned long)lo, (unsigned long)hi,
           seen);
    return seen == 0 ? 0 : 1;
}
