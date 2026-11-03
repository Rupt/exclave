"""BLAKE3-256, from its specification, for the tests' own statement of the hashes file (6.4).

The standard library has no BLAKE3, and the tests run on it alone, here and in the matrix's VMs,
so the hash a test states is computed here: plainly and slowly, a megabyte in seconds, for the
small trees and files a test makes. Unkeyed, with the 32-byte output the format uses.
"""

import struct

IV = (
    *(0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A),
    *(0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19),
)
CHUNK_START, CHUNK_END, PARENT, ROOT = 1, 2, 4, 8
CHUNK, BLOCK = 1024, 64
M = 0xFFFFFFFF
# the message words each round reads, the permutation applied once more per round
SCHEDULE: list[tuple[int, ...]] = []
_order = tuple(range(16))
for _ in range(7):
    SCHEDULE.append(_order)
    _order = tuple(_order[i] for i in (2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8))
COLUMNS = ((0, 4, 8, 12), (1, 5, 9, 13), (2, 6, 10, 14), (3, 7, 11, 15))
DIAGONALS = ((0, 5, 10, 15), (1, 6, 11, 12), (2, 7, 8, 13), (3, 4, 9, 14))


def compress(cv: tuple[int, ...], block: bytes, counter: int, length: int, flags: int) -> list[int]:
    """The compression function: the 16 output words of one block of up to 64 bytes."""
    m = struct.unpack("<16I", block.ljust(BLOCK, b"\0"))
    v = [*cv, *IV[:4], counter & M, counter >> 32 & M, length, flags]
    for order in SCHEDULE:
        for i, (a, b, c, d) in enumerate(COLUMNS + DIAGONALS):
            x, y = m[order[2 * i]], m[order[2 * i + 1]]
            v[a] = (v[a] + v[b] + x) & M
            t = v[d] ^ v[a]
            v[d] = (t >> 16 | t << 16) & M
            v[c] = (v[c] + v[d]) & M
            t = v[b] ^ v[c]
            v[b] = (t >> 12 | t << 20) & M
            v[a] = (v[a] + v[b] + y) & M
            t = v[d] ^ v[a]
            v[d] = (t >> 8 | t << 24) & M
            v[c] = (v[c] + v[d]) & M
            t = v[b] ^ v[c]
            v[b] = (t >> 7 | t << 25) & M
    return [v[i] ^ v[i + 8] for i in range(8)] + [v[i + 8] ^ cv[i] for i in range(8)]


def chunk(data: bytes, counter: int, *, root: bool) -> tuple[int, ...]:
    """A chunk's chaining value, or with root its output's first eight words."""
    cv = IV
    blocks = [data[i : i + BLOCK] for i in range(0, len(data), BLOCK)] or [b""]
    for i, block in enumerate(blocks):
        flags = (CHUNK_START if i == 0 else 0) | (CHUNK_END if i == len(blocks) - 1 else 0)
        if root and i == len(blocks) - 1:
            flags |= ROOT
        cv = tuple(compress(cv, block, counter, len(block), flags)[:8])
    return cv


def parent(left: tuple[int, ...], right: tuple[int, ...], *, root: bool) -> tuple[int, ...]:
    block = struct.pack("<16I", *left, *right)
    return tuple(compress(IV, block, 0, BLOCK, PARENT | (ROOT if root else 0))[:8])


def subtree(data: bytes, counter: int, *, root: bool) -> tuple[int, ...]:
    """The chaining value of data's chunks from chunk counter.

    The left subtree holds the largest power of two of whole chunks short of all of them.
    """
    if len(data) <= CHUNK:
        return chunk(data, counter, root=root)
    n = (len(data) + CHUNK - 1) // CHUNK
    left = 1 << (n - 1).bit_length() - 1
    return parent(
        subtree(data[: left * CHUNK], counter, root=False),
        subtree(data[left * CHUNK :], counter + left, root=False),
        root=root,
    )


def blake3(data: bytes) -> str:
    """The lowercase hex of the BLAKE3-256 of data."""
    return struct.pack("<8I", *subtree(data, 0, root=True)).hex()
