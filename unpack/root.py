"""The tree being made, with every path in it resolved as if the tree were / (DESIGN.md 10.1).

A package installs into a root, and its symlinks mean what they mean there: an absolute target
starts at the root, and `..` stops at it. dpkg resolves them in the system it installs into; unpack
resolves them in the tree, so no member, link or synthesised file reaches past it, whatever the
packages ship. A virtual path is walked one component at a time from a descriptor of the tree:
each directory opened with O_PATH and O_NOFOLLOW relative to the one before, each symlink read and
its target walked in turn, at most 40 of them as the kernel allows. Every read and write then
happens relative to a directory descriptor, on a name that is no longer a path.
"""

import collections
import contextlib
import os
import shutil
import stat
from typing import Self
lazy from collections.abc import Generator

# the kernel's limit on symlinks followed in one resolution (ELOOP)
MAX_LINKS = 40
# what a write leaves free on the tree's filesystem, at the least: a payload that decompresses
# without end is refused rather than filling the disk
MARGIN = 256 << 20


class RootError(Exception):
    """A path in the tree that cannot be resolved or written as asked."""


class _Missing(Exception):  # noqa: N818 -- a resolution's internal signal, not an error shown
    """A directory on the way to a path does not exist."""


def _parts(path: str) -> list[str]:
    return [p for p in path.split("/") if p not in ("", ".")]


class Root:
    """The tree at path, open for the length of a with block."""

    def __init__(self, path: str) -> None:
        self.path = path
        self.fd = os.open(path, os.O_PATH | os.O_DIRECTORY | os.O_CLOEXEC)
        # descriptors of directories walked recently, by their components from the root; any
        # removal or replacement forgets them all
        self._dirs: collections.OrderedDict[tuple[str, ...], int] = collections.OrderedDict()

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *_: object) -> None:
        self._forget()
        os.close(self.fd)

    def _forget(self) -> None:
        for fd in self._dirs.values():
            os.close(fd)
        self._dirs.clear()

    def _open_dir(self, comps: tuple[str, ...]) -> int:
        """A descriptor of the directory at comps, every component a directory, none followed."""
        if not comps:
            return self.fd
        fd = self._dirs.get(comps)
        if fd is not None:
            self._dirs.move_to_end(comps)
            return fd
        parent = self._open_dir(comps[:-1])
        try:
            fd = os.open(
                comps[-1], os.O_PATH | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent
            )
        except (FileNotFoundError, NotADirectoryError) as e:
            raise _Missing from e
        except OSError as e:  # ELOOP: the component became a symlink since it was walked
            msg = f"/{'/'.join(comps)}: {e.strerror}"
            raise RootError(msg) from e
        self._dirs[comps] = fd
        if len(self._dirs) > 64:
            os.close(self._dirs.popitem(last=False)[1])
        return fd

    def _walk(self, vpath: str, *, follow: bool, create: bool) -> tuple[tuple[str, ...], str]:
        """Return (the directory holding vpath's last component, from the root; its name).

        Every directory on the way is resolved in the tree; with follow, the last component is too,
        when it is a symlink. With create, a directory missing on the way is made.

        Raises:
            _Missing: When a directory on the way does not exist and create is false.
            RootError: When one is not a directory, or the links go round more than 40 times.
        """
        todo = collections.deque(_parts(vpath))
        comps: list[str] = []
        links = 0
        while todo:
            name = todo.popleft()
            if name == "..":
                if comps:
                    comps.pop()
                continue
            last = not todo
            dfd = self._open_dir(tuple(comps))
            if last and not follow:
                return tuple(comps), name
            try:
                st = os.lstat(name, dir_fd=dfd)
            except FileNotFoundError, NotADirectoryError:
                if last:
                    return tuple(comps), name
                if not create:
                    raise _Missing from None
                os.mkdir(name, 0o777, dir_fd=dfd)
                comps.append(name)
                continue
            if stat.S_ISLNK(st.st_mode):
                links += 1
                if links > MAX_LINKS:
                    msg = f"{vpath}: more than {MAX_LINKS} symlinks on the way (ELOOP)"
                    raise RootError(msg)
                target = os.readlink(name, dir_fd=dfd)
                if target.startswith("/"):
                    comps = []
                todo.extendleft(reversed(_parts(target)))
                continue
            if last:
                return tuple(comps), name
            if not stat.S_ISDIR(st.st_mode):
                msg = f"{vpath}: /{'/'.join([*comps, name])} is not a directory"
                raise RootError(msg)
            comps.append(name)
        # the path, or a link at its end, names a directory already walked: the tree's root, or one
        # of its directories, which is then the last component
        if not comps:
            msg = f"{vpath} resolves to the tree's root"
            raise RootError(msg)
        return tuple(comps[:-1]), comps[-1]

    def _at(self, vpath: str, *, follow: bool, create: bool) -> tuple[int, str]:
        """Return (a descriptor of the directory holding vpath's last component, its name)."""
        comps, name = self._walk(vpath, follow=follow, create=create)
        return self._open_dir(comps), name

    def real(self, vpath: str) -> str:
        """Return the host's path of what vpath names, every symlink on the way resolved inside.

        For a program to run from the tree, whose path the host resolves again: unpack is the only
        writer of the tree, so the path stays as resolved.
        """
        try:
            comps, name = self._walk(vpath, follow=True, create=False)
        except _Missing:
            raise FileNotFoundError(vpath) from None
        return os.path.join(self.path, *comps, name)

    def _lstat(self, vpath: str, *, follow: bool) -> os.stat_result | None:
        try:
            dfd, name = self._at(vpath, follow=follow, create=False)
            return os.lstat(name, dir_fd=dfd)
        except _Missing, RootError, FileNotFoundError, NotADirectoryError:
            return None

    # ------------------------------------------------------------ questions, as os.path asks them
    def lexists(self, vpath: str) -> bool:
        return self._lstat(vpath, follow=False) is not None

    def exists(self, vpath: str) -> bool:
        return self._lstat(vpath, follow=True) is not None

    def islink(self, vpath: str) -> bool:
        st = self._lstat(vpath, follow=False)
        return st is not None and stat.S_ISLNK(st.st_mode)

    def isdir(self, vpath: str) -> bool:
        st = self._lstat(vpath, follow=True)
        return st is not None and stat.S_ISDIR(st.st_mode)

    def isfile(self, vpath: str) -> bool:
        st = self._lstat(vpath, follow=True)
        return st is not None and stat.S_ISREG(st.st_mode)

    def readlink(self, vpath: str) -> str:
        dfd, name = self._at(vpath, follow=False, create=False)
        return os.readlink(name, dir_fd=dfd)

    # ------------------------------------------------------------ reading
    @contextlib.contextmanager
    def _open(self, vpath: str, flags: int) -> Generator[int]:
        try:
            dfd, name = self._at(vpath, follow=True, create=False)
        except _Missing:
            raise FileNotFoundError(vpath) from None
        fd = os.open(name, flags | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=dfd)
        try:
            yield fd
        finally:
            os.close(fd)

    def read_bytes(self, vpath: str, limit: int = -1) -> bytes:
        with self._open(vpath, os.O_RDONLY) as fd, os.fdopen(os.dup(fd), "rb") as f:
            return f.read(limit)

    def read_text(self, vpath: str) -> str:
        """Return the text as open(path, errors="replace") reads it, every line end a newline."""
        text = self.read_bytes(vpath).decode("utf-8", "replace")
        return text.replace("\r\n", "\n").replace("\r", "\n")

    def listdir(self, vpath: str) -> list[str]:
        """The names in the directory at vpath, sorted; none when it is no directory."""
        try:
            with self._open(vpath, os.O_RDONLY | os.O_DIRECTORY) as fd:
                return sorted(os.listdir(fd))
        except FileNotFoundError, NotADirectoryError, RootError:
            return []

    # ------------------------------------------------------------ writing
    def makedirs(self, vpath: str) -> None:
        """Make the directory at vpath and those on the way, as os.makedirs with exist_ok."""
        dfd, name = self._at(vpath, follow=True, create=True)
        try:
            os.mkdir(name, 0o777, dir_fd=dfd)
        except FileExistsError:
            if not self.isdir(vpath):
                msg = f"{vpath}: something other than a directory stands there"
                raise RootError(msg) from None

    def _parent(self, vpath: str) -> tuple[int, str]:
        """Return the directory holding vpath's last component, made where missing, and its name."""
        return self._at(vpath, follow=False, create=True)

    def symlink(self, target: str, vpath: str) -> None:
        dfd, name = self._parent(vpath)
        os.symlink(target, name, dir_fd=dfd)

    def link(self, src: str, dst: str) -> None:
        """A hard link at dst to the entry src names, which is not followed."""
        try:
            sfd, sname = self._at(src, follow=False, create=False)
            dfd, dname = self._parent(dst)
            os.link(sname, dname, src_dir_fd=sfd, dst_dir_fd=dfd, follow_symlinks=False)
        except _Missing, FileNotFoundError:
            msg = f"the hard link /{dst.lstrip('/')} names {src}, which the tree does not hold"
            raise RootError(msg) from None

    def remove(self, vpath: str) -> None:
        self._forget()  # before the walk, whose descriptor the call uses
        dfd, name = self._at(vpath, follow=False, create=False)
        os.unlink(name, dir_fd=dfd)

    def rmdir(self, vpath: str) -> None:
        self._forget()  # before the walk, whose descriptor the call uses
        dfd, name = self._at(vpath, follow=False, create=False)
        os.rmdir(name, dir_fd=dfd)

    def rmtree(self, vpath: str) -> None:
        """Remove the directory at vpath and everything in it, following no symlink."""
        self._forget()  # before the walk, whose descriptor the call uses
        dfd, name = self._at(vpath, follow=False, create=False)
        shutil.rmtree(name, dir_fd=dfd)

    def chmod_dir(self, vpath: str, mode: int) -> None:
        with self._open(vpath, os.O_RDONLY | os.O_DIRECTORY) as fd:
            os.fchmod(fd, mode)

    def room(self, size: int, what: str) -> None:
        """Refuse size bytes more in the tree that would leave less than MARGIN free beside it."""
        st = os.statvfs(self.fd)
        free = st.f_bavail * st.f_frsize
        if size > free - MARGIN:
            msg = (
                f"{what} {size} bytes, which would leave less than {MARGIN >> 20} MiB free on the "
                f"output's filesystem ({free >> 20} MiB free)"
            )
            raise RootError(msg)

    def create(self, vpath: str, size: int) -> int:
        """A new file at vpath for size bytes, open for writing, mode 0600 until set."""
        self.room(size, f"/{vpath.lstrip('/')} declares")
        dfd, name = self._parent(vpath)
        return os.open(
            name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
            0o600,
            dir_fd=dfd,
        )

    def write_bytes(self, vpath: str, data: bytes, mode: int = 0o666) -> None:
        """Write data as the whole file at vpath, following a link there as open(path, "w") does."""
        self.room(len(data), f"/{vpath.lstrip('/')} would hold")
        dfd, name = self._at(vpath, follow=True, create=True)
        fd = os.open(
            name,
            os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW | os.O_CLOEXEC,
            mode,
            dir_fd=dfd,
        )
        with os.fdopen(fd, "wb") as f:
            f.write(data)
