"""The interface every package reader provides, and the streams they read (DESIGN.md 10.1).

`unpack.deb`, `unpack.apk` and `unpack.rpm` each satisfy `Reader`, and `unpack.steps` picks one
by the package file's name. A reader presents its format in Debian's terms: control fields named as
dpkg names them, and the payload as members shaped like `tarfile.TarInfo`, handed out in the
archive's order as it is decompressed, so that a payload is never held whole in memory.
"""

import io
import lzma
import tarfile
import zlib
from compression import zstd
from typing import IO, Any, Protocol, Self
lazy from collections.abc import Callable, Iterator
lazy from types import TracebackType

# One alternative of a dependency: (name, operator, version), the last two None when unversioned.
type Dep = tuple[str, str | None, str | None]


class PackageError(Exception):
    """A package file that cannot be read: truncated, corrupt, or not of its format."""


class Readable(Protocol):
    """A stream of bytes read forward: a file, or a decompressor reading one."""

    def read(self, size: int = -1, /) -> bytes: ...
    def close(self) -> None: ...


# what a decompressor raises on data it cannot decode or that ends early
CORRUPT = (lzma.LZMAError, zstd.ZstdError, OSError, EOFError, ValueError, zlib.error)


class Window(io.RawIOBase):
    """A stream read forward only, its last 64 KiB kept so that a short step back costs nothing.

    tarfile steps back one byte between members, and the end-of-archive check goes back to the
    block where the reader stopped; a decompressor would have to start again from the beginning
    for either. A decompressor's error becomes a PackageError naming label.
    """

    KEEP = 1 << 16

    def __init__(self, stream: Readable, label: str) -> None:
        super().__init__()
        self.stream, self.label = stream, label
        self.pos = 0  # the reader's position
        self.kept = bytearray()  # the stream's bytes from start to end, the last read
        self.start = self.end = 0

    def readable(self) -> bool:
        return True

    def seekable(self) -> bool:
        return True

    def tell(self) -> int:
        return self.pos

    def seek(self, offset: int, whence: int = io.SEEK_SET) -> int:
        pos = {io.SEEK_SET: offset, io.SEEK_CUR: self.pos + offset}.get(whence)
        if pos is None or pos < self.start:
            msg = "a stream read forward cannot go back that far"
            raise io.UnsupportedOperation(msg)
        self.pos = pos
        return pos

    def _more(self, n: int) -> bool:
        """Read up to n more bytes of the stream into the window; false at its end."""
        try:
            chunk = self.stream.read(n)
        except CORRUPT as e:
            msg = f"{self.label}: {e}"
            raise PackageError(msg) from e
        if not chunk:
            return False
        self.kept += chunk
        self.end += len(chunk)
        # drop what lies more than KEEP bytes behind, never what the reader has yet to take
        drop = min(self.pos, self.end - self.KEEP) - self.start
        if drop > self.KEEP:
            del self.kept[:drop]
            self.start += drop
        return True

    def read(self, size: int = -1) -> bytes:
        while self.pos > self.end:  # a seek forward: what lies between is read and dropped
            if not self._more(min(self.pos - self.end, 1 << 20)):
                return b""
        want = size if size >= 0 else 1 << 62
        while self.end - self.pos < want and self._more(max(want - (self.end - self.pos), 1 << 16)):
            pass
        out = bytes(self.kept[self.pos - self.start : self.pos - self.start + want])
        self.pos += len(out)
        return out

    def readinto(self, b: Any) -> int:  # noqa: ANN401 -- io's own buffer type
        data = self.read(len(b))
        b[: len(data)] = data
        return len(data)

    def after_end(self, end: int) -> str | None:
        """Name what follows an archive's end at offset end, unless it is nothing but NUL padding.

        tarfile stops at a header it cannot read, and a cpio reader at its trailer; what lies past
        either could hold members another reader would extract, so it is refused (10.1).
        """
        self.seek(end)
        n = 0
        while chunk := self.read(1 << 16):
            if chunk.strip(b"\0"):
                return f"data after the archive's end at byte {end}, not padding"
            n += len(chunk)
        return None

    def close(self) -> None:
        self.stream.close()
        super().close()


class StreamTar:
    """A tar archive in a Window, its members handed out as they come, in the archive's order.

    keep chooses the members a caller sees; every header is read, and when the last has been,
    anything but NUL padding after the archive's end is refused. A member's contents are read
    while it is the current one.
    """

    def __init__(
        self, window: Window, label: str, keep: Callable[[tarfile.TarInfo], bool] | None = None
    ) -> None:
        self.window, self.label, self.keep = window, label, keep
        try:
            self.tar = tarfile.open(fileobj=window, mode="r:")  # noqa: SIM115 -- closed by __exit__
        except tarfile.TarError as e:
            window.close()
            msg = f"{label}: {e}"
            raise PackageError(msg) from e

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *_: object) -> None:
        self.tar.close()
        self.window.close()

    def __iter__(self) -> Iterator[tarfile.TarInfo]:
        while True:
            try:
                m = self.tar.next()
            except tarfile.TarError as e:
                msg = f"{self.label}: {e}"
                raise PackageError(msg) from e
            if m is None:
                break
            if self.keep is None or self.keep(m):
                yield m
        if why := self.window.after_end(self.tar.offset):
            msg = f"{self.label}: {why}"
            raise PackageError(msg)

    def extractfile(self, m: tarfile.TarInfo) -> IO[bytes] | None:
        return self.tar.extractfile(m)


class Member(Protocol):
    """One entry of a package's payload, as `tarfile.TarInfo` presents it."""

    @property
    def name(self) -> str: ...
    @property
    def linkname(self) -> str: ...
    @property
    def mode(self) -> int: ...
    @property
    def mtime(self) -> float: ...
    def isdir(self) -> bool: ...
    def isfile(self) -> bool: ...
    def issym(self) -> bool: ...
    def islnk(self) -> bool: ...


class Archive[M: Member](Protocol):
    """A package's payload, opened as a context manager and iterated once, in its order.

    A member's contents are read with extractfile while it is the current member.
    """

    def __enter__(self) -> Self: ...
    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
        /,
    ) -> object: ...
    def __iter__(self) -> Iterator[M]: ...
    def extractfile(self, member: M, /) -> IO[bytes] | None: ...


class Reader(Protocol):
    """A package format: the module that reads it."""

    # Whether the format's distributions merge /bin, /sbin and /lib into /usr.
    MERGED_USR: bool

    def control(self, path: str) -> tuple[dict[str, str], dict[str, str]]:
        """Return the package's control fields and its maintainer scripts by name."""
        ...

    def open_data(self, path: str) -> Archive[Any]:
        """Return the package's payload, the files it installs."""
        ...

    def parse_deps(self, field: str | None) -> list[list[Dep]]:
        """Parse a dependency field into groups of alternatives."""
        ...

    def satisfies(self, version: str, op: str | None, want: str | None) -> bool:
        """Return whether version meets the constraint `op want`; no operator is always met."""
        ...
