/* decompress.c — zstd and xz for the package files unpack reads, through the system's libzstd and liblzma (DESIGN.md
 * 10.1, 10.5), with what Python's compression.zstd.decompress and lzma.decompress accept: every zstd frame in turn,
 * skippable ones included, to the last byte; and every xz or .lzma stream in turn, where what follows a whole stream
 * and is not one is ignored, as Python ignores it, but a stream cut short is not. Where the build found no copies of
 * the libraries for its architecture (scripts/build), NO_ZSTD_XZ is defined and both refuse, naming the lack. */
#include <stdio.h>
#include "tool.h"

#ifdef NO_ZSTD_XZ

int unzstd(const uint8_t *in, size_t n, struct buf *out, char why[INFLATE_WHY])
{
    (void)in, (void)n, (void)out;
    snprintf(why, INFLATE_WHY, "zstd, which this build of the command lacks (DESIGN.md 13 item 48)");
    return -1;
}

int unxz(const uint8_t *in, size_t n, struct buf *out, char why[INFLATE_WHY])
{
    (void)in, (void)n, (void)out;
    snprintf(why, INFLATE_WHY, "xz, which this build of the command lacks (DESIGN.md 13 item 48)");
    return -1;
}

#else

#include <lzma.h>
#include <zstd.h>

/* room in out for at least one more chunk */
static void reserve(struct buf *out)
{
    if (out->cap - out->n < 1 << 16) {
        out->cap = out->cap ? 2 * out->cap : 1 << 20;
        out->p = xrealloc(out->p, out->cap);
    }
}

int unzstd(const uint8_t *in, size_t n, struct buf *out, char why[INFLATE_WHY])
{
    ZSTD_DCtx *d = ZSTD_createDCtx();
    if (!d) fail("out of memory");
    ZSTD_inBuffer src = {in, n, 0};
    size_t left = 1; /* nothing read yet: a frame is still owed */
    int rc = 0;
    while (src.pos < src.size || left) {
        reserve(out);
        ZSTD_outBuffer dst = {out->p + out->n, out->cap - out->n, 0};
        size_t before = src.pos;
        left = ZSTD_decompressStream(d, &dst, &src);
        out->n += dst.pos;
        if (ZSTD_isError(left)) {
            snprintf(why, INFLATE_WHY, "%s", ZSTD_getErrorName(left));
            rc = -1;
            break;
        }
        /* the input is spent and the frame is not finished: it was cut short */
        if (left && src.pos == src.size && src.pos == before && !dst.pos) {
            snprintf(why, INFLATE_WHY, "the data ends before the end of a zstd frame");
            rc = -1;
            break;
        }
    }
    ZSTD_freeDCtx(d);
    return rc;
}

int unxz(const uint8_t *in, size_t n, struct buf *out, char why[INFLATE_WHY])
{
    size_t pos = 0;
    int streams = 0;
    do {
        lzma_stream s = LZMA_STREAM_INIT;
        if (lzma_auto_decoder(&s, UINT64_MAX, LZMA_TELL_ANY_CHECK | LZMA_TELL_NO_CHECK) != LZMA_OK)
            fail("out of memory");
        s.next_in = in + pos;
        s.avail_in = n - pos;
        size_t start = out->n;
        lzma_ret r;
        do {
            reserve(out);
            s.next_out = (uint8_t *)out->p + out->n;
            s.avail_out = out->cap - out->n;
            r = lzma_code(&s, LZMA_RUN);
            out->n = out->cap - s.avail_out;
        } while (r == LZMA_OK || r == LZMA_GET_CHECK || r == LZMA_NO_CHECK);
        pos = n - s.avail_in;
        lzma_end(&s);
        if (r == LZMA_STREAM_END) {
            streams++;
            continue;
        }
        if (r == LZMA_BUF_ERROR && !s.avail_in) {
            snprintf(why, INFLATE_WHY, "the data ends before the end of an xz stream");
            return -1;
        }
        out->n = start; /* what is not a stream after a whole one is ignored */
        if (streams) return 0;
        snprintf(why, INFLATE_WHY, "%s",
                 r == LZMA_FORMAT_ERROR    ? "not xz or lzma data"
                 : r == LZMA_DATA_ERROR    ? "corrupt xz data"
                 : r == LZMA_OPTIONS_ERROR ? "xz options this liblzma does not support"
                                           : "an xz error");
        return -1;
    } while (pos < n);
    return 0;
}

#endif
