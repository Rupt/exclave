"""The strict grammar of the manifest and the hashes file (DESIGN.md 6.2, 6.4).

Both files are lines of records: a lowercase key, then fields separated by single spaces, each a
bare token or a double-quoted string. `parse` accepts exactly one spelling of each file and `dump`
produces it, so a file that `parse` accepts and `dump` reproduces byte for byte is canonical.
"""

import re
from dataclasses import dataclass, field
from typing import Literal, Never
lazy from collections.abc import Iterable

type Kind = Literal["exclave", "hashes"]
# A field's kind: "s" a quoted string, "t" a bare token.
type Field = tuple[Literal["s", "t"], bytes]

# The canonical order of each file's keys.
KEY_ORDER: dict[Kind, list[str]] = {
    "exclave": ["exclave", "cpu", "data", "host", "own"],
    "hashes": ["hashes", "tool", "launcher", "pkg", "manifest", "tree"],
}
# Each key's field count and the kind of each field, in order.
SCHEMA = {
    "exclave": "t",
    "cpu": "s",
    "data": "s",
    "host": "s",
    "own": "s",
    "hashes": "t",
    "tool": "s",
    "launcher": "s",
    "pkg": "ssss",
    "manifest": "s",
    "tree": "s",
}
ONCE = {"exclave", "cpu", "hashes", "tool", "launcher", "manifest", "tree"}
# The sizes of the launcher's tables (8.1): the most records of each key a manifest may carry, and
# the most top-level entries a tree may have.
LIMITS = {"own": 256, "host": 32, "data": 32, "top": 256}


class GrammarError(Exception):
    """A file that the grammar refuses, with the line and column of the first fault."""


@dataclass(slots=True)
class Record:
    """One record: its key, its fields, the comment lines above it, and its line number."""

    key: str
    fields: list[Field]
    comments: list[str] = field(default_factory=list)
    line: int = 0


def _fail(line: int, col: int, why: str) -> Never:
    msg = f"line {line} col {col}: {why}"
    raise GrammarError(msg)


def _utf8_len(b: bytes, i: int) -> int:
    """Return the length of the well-formed UTF-8 sequence at b[i], or 0 if it is malformed.

    Well-formed is as Unicode's Table 3-7 defines it: no overlong forms, no surrogates, nothing
    above U+10FFFF.
    """
    c = b[i]
    n = len(b) - i
    if c < 0x80:
        return 1
    if c < 0xC2:
        return 0
    if c < 0xE0:
        return 2 if n >= 2 and 0x80 <= b[i + 1] <= 0xBF else 0
    if c < 0xF0:
        if n < 3 or not (0x80 <= b[i + 2] <= 0xBF):
            return 0
        lo, hi = (0xA0, 0xBF) if c == 0xE0 else (0x80, 0x9F) if c == 0xED else (0x80, 0xBF)
        return 3 if lo <= b[i + 1] <= hi else 0
    if c < 0xF5:
        if n < 4 or not (0x80 <= b[i + 2] <= 0xBF) or not (0x80 <= b[i + 3] <= 0xBF):
            return 0
        lo, hi = (0x90, 0xBF) if c == 0xF0 else (0x80, 0x8F) if c == 0xF4 else (0x80, 0xBF)
        return 4 if lo <= b[i + 1] <= hi else 0
    return 0


def parse(data: bytes, kind: Kind = "exclave") -> list[Record]:
    """Parse a manifest or a hashes file strictly.

    Args:
        data: The file's bytes.
        kind: Which file it is, which decides the keys allowed and the first record.

    Returns:
        The records in file order.

    Raises:
        GrammarError: At the first byte the grammar does not allow.
    """
    if not isinstance(data, bytes):
        msg = "bytes expected"
        raise TypeError(msg)
    if not data or data[-1:] != b"\n":
        _fail(1, 1, "file must end with LF")
    if data.startswith(b"\xef\xbb\xbf"):
        _fail(1, 1, "byte order mark")
    i, line = 0, 1
    while i < len(data):
        if data[i] == 0x0D:
            _fail(line, 1, "CR not allowed")
        n = _utf8_len(data, i)
        if not n:
            _fail(line, 1, "malformed UTF-8")
        if data[i] == 0x0A:
            line += 1
        i += n
    records: list[Record] = []
    comments: list[str] = []
    counts: dict[str, int] = {}
    pos, line = 0, 1
    while pos < len(data):
        end = data.index(b"\n", pos)
        raw = data[pos:end]
        if raw == b"":
            pos, line = end + 1, line + 1
            continue
        if raw[:1] == b"#":
            comments.append(raw[1:].decode("utf-8"))
            pos, line = end + 1, line + 1
            continue
        m = re.match(rb"[a-z][a-z0-9-]*", raw)
        if not m:
            _fail(line, 1, "record must start with a lowercase key")
        key = m.group(0).decode()
        col = m.end()
        fields: list[Field] = []
        while col < len(raw):
            if raw[col : col + 1] != b" ":
                _fail(
                    line,
                    col + 1,
                    "tab outside a string"
                    if raw[col] == 9
                    else "expected a single space between fields",
                )
            col += 1
            if col >= len(raw):
                _fail(line, col + 1, "trailing space")
            if raw[col] == 0x20:
                _fail(line, col + 1, "multiple spaces")
            if raw[col] == 0x22:
                val, col = _parse_string(raw, col, line)
                fields.append(("s", val))
            else:
                m = re.match(rb"[A-Za-z0-9_.+-]+", raw[col:])
                if not m:
                    _fail(line, col + 1, "expected a string or token")
                fields.append(("t", m.group(0)))
                col += m.end()
        rec = Record(key, fields, comments, line)
        comments = []
        _check_record(rec, kind)
        # refused here where the launcher's tables would refuse it (8.1)
        if kind == "exclave" and key in LIMITS:
            counts[key] = counts.get(key, 0) + 1
            if counts[key] > LIMITS[key]:
                _fail(line, 1, f"more than {LIMITS[key]} {key} records")
        records.append(rec)
        pos, line = end + 1, line + 1
    if comments:
        _fail(line, 1, "comment after the last record")
    if not records:
        _fail(line, 1, "empty file")
    if records[0].key != kind or records[0].fields[0] != ("t", b"1"):
        _fail(records[0].line, 1, f"first record must be {kind} 1")
    seen = set()
    for r in records:
        if r.key in ONCE:
            if r.key in seen:
                _fail(r.line, 1, "duplicate " + r.key)
            seen.add(r.key)
    return records


def _parse_string(raw: bytes, col: int, line: int) -> tuple[bytes, int]:
    """Parse the quoted string that starts at raw[col]; return its value and the column after it."""
    out = bytearray()
    col += 1
    while True:
        if col >= len(raw):
            _fail(line, col + 1, "unterminated string")
        c = raw[col]
        if c == 0x22:
            return bytes(out), col + 1
        if c == 0x5C:
            e = raw[col + 1 : col + 2]
            if e in (b"\\", b'"'):
                out += e
                col += 2
            elif e == b"n":
                out += b"\n"
                col += 2
            elif e == b"t":
                out += b"\t"
                col += 2
            elif e == b"x":
                h = raw[col + 2 : col + 4]
                if not re.fullmatch(rb"[0-9a-f]{2}", h):
                    _fail(line, col + 1, "\\x needs two lowercase hex digits")
                out.append(int(h, 16))
                col += 4
            else:
                _fail(line, col + 1, "unknown escape")
            continue
        n = _utf8_len(raw, col)
        o = ord(raw[col : col + n].decode("utf-8"))
        if o < 0x20 or 0x7F <= o <= 0x9F:
            _fail(line, col + 1, "control character must be escaped")
        out += raw[col : col + n]
        col += n


def _check_record(rec: Record, kind: Kind) -> None:
    if rec.key not in SCHEMA or rec.key not in KEY_ORDER[kind]:
        _fail(rec.line, 1, "unknown key " + rec.key)
    if [k for k, _ in rec.fields] != list(SCHEMA[rec.key]):
        _fail(rec.line, 1, "wrong field count or type for " + rec.key)
    if rec.key in ("own", "host", "data") and not _normalised_abs(rec.fields[0][1]):
        _fail(rec.line, 1, rec.key + " must be a normalised absolute path")
    if rec.key == "cpu" and b"\0" in rec.fields[0][1]:
        _fail(rec.line, 1, "cpu must not contain NUL")


def _normalised_abs(b: bytes) -> bool:
    """Return whether b is an absolute path in its one spelling (6.2).

    That is: no NUL; no empty, "." or ".." component; and no trailing slash, except on "/" itself.
    """
    if not b.startswith(b"/") or b"\0" in b:
        return False
    if b == b"/":
        return True
    return not b.endswith(b"/") and all(c not in (b"", b".", b"..") for c in b[1:].split(b"/"))


def quote(b: bytes) -> str:
    r"""Return the canonical string literal for b.

    Printable UTF-8 is written as itself. Backslash, double quote, newline and tab take their
    one-letter escapes, and every other control character or malformed byte becomes `\xHH`.
    """
    out = ['"']
    i = 0
    while i < len(b):
        c = b[i]
        n = _utf8_len(b, i)
        if c == 0x5C:
            out.append("\\\\")
        elif c == 0x22:
            out.append('\\"')
        elif c == 0x0A:
            out.append("\\n")
        elif c == 0x09:
            out.append("\\t")
        elif n == 0:
            out.append(f"\\x{c:02x}")
        else:
            s = b[i : i + n].decode("utf-8")
            o = ord(s)
            if o < 0x20 or o == 0x7F:
                out.append(f"\\x{o:02x}")
            elif 0x80 <= o <= 0x9F:  # a C1 control: escaped byte by byte
                out.extend(f"\\x{x:02x}" for x in b[i : i + n])
            else:
                out.append(s)
        i += max(n, 1)
    out.append('"')
    return "".join(out)


def dump(records: Iterable[Record], kind: Kind = "exclave") -> bytes:
    """Return the canonical form of a file's records (6.2).

    Records are grouped by key in the file's key order, sorted within a group, and the groups are
    separated by one blank line. Each record keeps its comment lines above it.
    """
    groups: dict[str, list[Record]] = {}
    for r in records:
        groups.setdefault(r.key, []).append(r)
    out: list[str] = []
    for key in KEY_ORDER[kind]:
        if key not in groups:
            continue
        if out:
            out.append("")
        for r in sorted(groups[key], key=lambda r: [v for _, v in r.fields]):
            out.extend("#" + c for c in r.comments)
            out.append(
                " ".join([key] + [v.decode() if k == "t" else quote(v) for k, v in r.fields])
            )
    return ("\n".join(out) + "\n").encode("utf-8")


def load(path: str, kind: Kind) -> list[Record]:
    """Parse the file at path."""
    with open(path, "rb") as f:
        return parse(f.read(), kind)


def values(records: Iterable[Record], key: str) -> list[list[bytes]]:
    """Return the field values of every record with the given key."""
    return [[v for _, v in r.fields] for r in records if r.key == key]
