"""The interface every package reader provides (DESIGN.md 10.1).

`unpack.deb`, `unpack.apk` and `unpack.rpm` each satisfy `Reader`, and `unpack.steps` picks one
by the package file's name. A reader presents its format in Debian's terms: control fields named as
dpkg names them, and the payload as members shaped like `tarfile.TarInfo`.
"""

from typing import IO, Any, Protocol, Self
lazy from types import TracebackType

# One alternative of a dependency: (name, operator, version), the last two None when unversioned.
type Dep = tuple[str, str | None, str | None]


class PackageError(Exception):
    """A package file that cannot be read: truncated, corrupt, or not of its format."""


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
    """A package's payload, opened as a context manager."""

    def __enter__(self) -> Self: ...
    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
        /,
    ) -> object: ...
    def getmembers(self) -> list[M]: ...
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
