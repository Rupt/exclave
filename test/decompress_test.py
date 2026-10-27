"""Compare the command's zstd, xz and gzip decoders with Python's (DESIGN.md 10.1, 17 item 3).

    test/decompress_test.py [--seed S] [--c-decoder PATH]

The C decoders (tool/decompress.c through libzstd and liblzma, tool/inflate.c by hand), built as a
filter by scripts/gate's unit step, are given the same bytes as compression.zstd.decompress,
lzma.decompress and gzip.decompress, which scripts/unpack uses: both must decompress to the same
bytes, or both refuse. The inputs: every compression level the formats name, frames and streams back
to back, zstd's skippable frames, frames without a checksum or a content size, a dictionary frame,
xz's integrity checks, filters and stream padding, the legacy .lzma format, and each of those cut
short, with a byte flipped and with data after it. Prints one line per difference and a summary;
exit status 1 when one is found.
"""

import argparse
import gzip
import lzma
import os
import random
import subprocess
import sys
import zlib
from compression import zstd
lazy from collections.abc import Callable

HERE = os.path.dirname(os.path.abspath(__file__))


def sample(rng: random.Random, n: int) -> bytes:
    """Text, runs and noise: something every encoder has work to do on."""
    words = [b"exclave", b"tree", b"launcher", b"\n", b" ", b"usr/lib/", b"\0" * 7]
    out = bytearray()
    while len(out) < n:
        r = rng.random()
        if r < 0.6:
            out += rng.choice(words)
        elif r < 0.8:
            out += bytes([rng.randrange(256)]) * rng.randrange(1, 300)
        else:
            out += rng.randbytes(rng.randrange(1, 64))
    return bytes(out[:n])


def zstd_frame(data: bytes, **options: int) -> bytes:
    params = {getattr(zstd.CompressionParameter, k): v for k, v in options.items()}
    c = zstd.ZstdCompressor(options=params)
    return c.compress(data, zstd.ZstdCompressor.FLUSH_FRAME)


def skippable(payload: bytes, magic: int = 0x184D2A50) -> bytes:
    return magic.to_bytes(4, "little") + len(payload).to_bytes(4, "little") + payload


def damaged(rng: random.Random, name: str, good: bytes) -> list[tuple[str, bytes]]:
    """The input cut short at a few places, with a byte flipped, and with junk or zeros after it."""
    out = [(f"{name}-cut-{k}", good[:k]) for k in sorted({0, 1, 4, len(good) // 2, len(good) - 1})]
    for i in range(3):
        b = bytearray(good)
        b[rng.randrange(len(b))] ^= 1 << rng.randrange(8)
        out.append((f"{name}-flip-{i}", bytes(b)))
    out += [(f"{name}-junk", good + b"junk"), (f"{name}-zeros", good + b"\0" * 4)]
    return out


def zstd_cases(rng: random.Random) -> list[tuple[str, bytes]]:
    a, b = sample(rng, 200_000), sample(rng, 3000)
    frames = {f"level{lv}": zstd_frame(a, compression_level=lv) for lv in (-5, 1, 3, 9, 19)} | {
        "no-checksum": zstd_frame(a, checksum_flag=0),
        "checksum": zstd_frame(a, checksum_flag=1),
        "no-size": zstd_frame(a, content_size_flag=0),
        "window-27": zstd_frame(a, window_log=27),
        "empty": zstd.compress(b""),
        "two": zstd.compress(a) + zstd.compress(b),
        "skippable": skippable(b"x" * 9) + zstd.compress(b) + skippable(b"", 0x184D2A5F),
        "only-skippable": skippable(b"meta"),
        "dictionary": zstd.compress(b, zstd_dict=zstd.ZstdDict(sample(rng, 5000), is_raw=True)),
    }
    cases = list(frames.items())
    for name in ("level3", "two", "skippable", "no-checksum"):
        cases += damaged(rng, name, frames[name])
    return cases


def xz_cases(rng: random.Random) -> list[tuple[str, bytes]]:
    a, b = sample(rng, 200_000), sample(rng, 3000)
    streams = (
        {f"preset{p}": lzma.compress(a, preset=p) for p in (0, 6, 9 | lzma.PRESET_EXTREME)}
        | {
            f"check{c}": lzma.compress(b, check=c)
            for c in (lzma.CHECK_NONE, lzma.CHECK_CRC32, lzma.CHECK_CRC64, lzma.CHECK_SHA256)
        }
        | {
            "alone": lzma.compress(a, format=lzma.FORMAT_ALONE),
            "bcj": lzma.compress(
                a, filters=[{"id": lzma.FILTER_X86}, {"id": lzma.FILTER_LZMA2, "preset": 6}]
            ),
            "delta": lzma.compress(
                a, filters=[{"id": lzma.FILTER_DELTA, "dist": 4}, {"id": lzma.FILTER_LZMA2}]
            ),
            "empty": lzma.compress(b""),
            "two": lzma.compress(a) + lzma.compress(b),
            "padded": lzma.compress(b) + b"\0" * 4 + lzma.compress(b) + b"\0" * 8,
            "second-cut": lzma.compress(b) + lzma.compress(b)[:30],
            "second-corrupt": lzma.compress(b) + lzma.compress(b)[:20] + b"\xff" * 40,
        }
    )
    cases = list(streams.items())
    for name in ("preset6", "check10", "alone", "two"):
        cases += damaged(rng, name, streams[name])
    return cases


def gzip_cases(rng: random.Random) -> list[tuple[str, bytes]]:
    a = sample(rng, 200_000)
    members = {f"level{lv}": gzip.compress(a, compresslevel=lv, mtime=0) for lv in (0, 1, 6, 9)}
    members["two"] = gzip.compress(a[:5000], mtime=0) + gzip.compress(a[5000:9000], mtime=0)
    cases = list(members.items())
    for name in ("level6", "two"):
        cases += damaged(rng, name, members[name])
    return cases


def python_answer(fn: Callable[[bytes], bytes], data: bytes) -> bytes | None:
    try:
        return fn(data)
    except zstd.ZstdError, lzma.LZMAError, EOFError, OSError, zlib.error:
        return None


def main() -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument(
        "--c-decoder",
        default=os.path.join(os.path.dirname(HERE), "build", "gate", "decompress_test"),
    )
    args = ap.parse_args()
    rng = random.Random(args.seed)
    kinds: list[tuple[str, Callable[[bytes], bytes], list[tuple[str, bytes]]]] = [
        ("zstd", zstd.decompress, zstd_cases(rng)),
        ("xz", lzma.decompress, xz_cases(rng)),
        ("gzip", gzip.decompress, gzip_cases(rng)),
    ]
    runs = bad = refused = 0
    for kind, fn, cases in kinds:
        for name, data in cases:
            want = python_answer(fn, data)
            p = subprocess.run(
                [args.c_decoder, kind], input=data, capture_output=True, check=False, timeout=60
            )
            got = p.stdout if p.returncode == 0 else None
            runs += 1
            refused += want is None
            if p.returncode not in (0, 1) or got != want:
                bad += 1
                said = "refused" if want is None else f"{len(want)} bytes"
                print(
                    f"FAIL {kind} {name}: Python {said}, C exit {p.returncode}, "
                    f"{len(p.stdout)} bytes, {p.stderr.decode(errors='replace').strip()[:200]}"
                )
    print(f"decoders: {runs} inputs, {refused} refused by both, {bad} differences")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
