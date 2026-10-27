"""Resolve a package closure from yum/dnf repositories and download its .rpm files.

    scripts/fetch-rpms --repo URL [--repo URL]... [--arch x86_64] [--cache DIR]
                       [--choose VIRTUAL=PKG]... [--no-base] --out DIR PACKAGE...

Each --repo is a repository root holding repodata/repomd.xml, such as Fedora's
Everything/x86_64/os, Rocky's BaseOS and AppStream, or CentOS 7's os on vault.centos.org. The
fetcher reads each repository's primary.xml, keeps the packages built for --arch or noarch, and
follows Requires from the requested packages, adding the base set (setup, filesystem, basesystem,
bash) unless --no-base is given. A dependency may be a package name, a versioned constraint, a
capability such as `libc.so.6(GLIBC_2.2.5)(64bit)`, or a file, which is met through the files
primary.xml lists. Rich dependencies and rpmlib() features are skipped. A name no package has is
met by the package --choose names for it, else a provider already selected, else a provider named
like the dependency, else the first provider by name.

The primary index is checked against the checksum in repomd.xml, and each package against the
SHA-256 its index records. The metadata signature is not checked, so the mirror is trusted.
Package files are cached, since their names carry their versions, and so is a primary index whose
name carries its checksum; repomd.xml is fetched on every run.

Neither unpack nor the tool fetches: `scripts/unpack OUT DIR/*.rpm` takes whatever directory of
.rpm files this fetcher, dnf, a mirror or a person has made (DESIGN.md 10.1). The fetcher is not
part of the tool's own exclave.
"""

import argparse
import gzip
import hashlib
import importlib.metadata
import lzma
import os
import re
import sys
import urllib.request
import xml.etree.ElementTree as ET
from compression import zstd
from typing import NoReturn, TypedDict

from unpack import rpm

BASE = ["setup", "filesystem", "basesystem", "bash"]
NS = {
    "c": "http://linux.duke.edu/metadata/common",
    "r": "http://linux.duke.edu/metadata/rpm",
    "m": "http://linux.duke.edu/metadata/repo",
}
FLAGS = {"EQ": "=", "LT": "<", "GT": ">", "LE": "<=", "GE": ">="}
USER_AGENT = f"exclave/{importlib.metadata.version('exclave')}"


class RepoError(Exception):
    pass


class Package(TypedDict):
    """A package of primary.xml, as the resolver reads it."""

    name: str
    version: str
    arch: str
    href: str
    sha256: str | None
    size: int
    _repo: str
    requires: list[tuple[str, str | None, str | None]]
    provides: list[tuple[str, str | None]]
    files: list[str]


def log(*parts: object) -> None:
    print(*parts, file=sys.stderr)


def _child(el: ET.Element, path: str) -> ET.Element:
    found = el.find(path, NS)
    if found is None:
        msg = f"repository metadata: no {path} in {el.tag}"
        raise RepoError(msg)
    return found


def _attr(el: ET.Element, name: str) -> str:
    value = el.get(name)
    if value is None:
        msg = f"repository metadata: no {name} attribute in {el.tag}"
        raise RepoError(msg)
    return value


def _text(el: ET.Element, path: str) -> str:
    text = _child(el, path).text
    if text is None:
        msg = f"repository metadata: an empty {path} in {el.tag}"
        raise RepoError(msg)
    return text


def _decompress(name: str, data: bytes) -> bytes:
    if name.endswith(".gz"):
        return gzip.decompress(data)
    if name.endswith(".xz"):
        return lzma.decompress(data)
    if name.endswith(".zst"):
        return zstd.decompress(data)
    return data


def _evr(el: ET.Element) -> str:
    """Return the [epoch:]version[-release] of a version or dependency entry."""
    epoch, rel = el.get("epoch"), el.get("rel")
    ver = (epoch + ":" if epoch and epoch != "0" else "") + (el.get("ver") or "")
    if rel:
        ver += "-" + rel
    return ver


class Repo:
    """The primary indexes of yum/dnf repositories, and the resolver that reads them."""

    def __init__(self, urls: list[str], arch: str, cache: str) -> None:
        self.urls = [u.rstrip("/") for u in urls]
        self.arch = arch
        self.cache = cache
        # The highest version of each package across the repositories.
        self.index: dict[str, Package] = {}
        # The packages that provide each capability, with the version they provide, if any.
        self.provides: dict[str, list[tuple[Package, str | None]]] = {}
        # The packages that ship each file primary.xml lists.
        self.files: dict[str, list[Package]] = {}
        os.makedirs(cache, exist_ok=True)

    def _path(self, url: str) -> str:
        """Return the cache file for url."""
        return os.path.join(self.cache, re.sub(r"[^A-Za-z0-9._-]", "_", url)[-200:])

    def _get(self, url: str, *, mutable: bool = False) -> bytes:
        """Return the file at url, read from the cache unless it is mutable.

        A file whose URL names its content is cached. A mutable file, whose content can change at
        the same URL, is fetched every time.
        """
        path = self._path(url)
        if not mutable and os.path.exists(path):
            with open(path, "rb") as f:
                return f.read()
        log(f"fetch {url}")
        request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
        with urllib.request.urlopen(request, timeout=300) as response:
            data = response.read()
        if not mutable:
            tmp = f"{path}.tmp{os.getpid()}"  # several runs may share the cache
            with open(tmp, "wb") as f:
                f.write(data)
            os.replace(tmp, path)
        return data

    def _reject(self, url: str, msg: str) -> NoReturn:
        """Remove url's file from the cache, so that the next run fetches it again, and raise."""
        path = self._path(url)
        try:
            os.remove(path)
        except FileNotFoundError:
            pass
        else:
            msg += f"; removed {path} from the cache"
        raise RepoError(msg)

    def _primary(self, url: str) -> bytes:
        """Fetch a repository's primary index, check it against repomd.xml and decompress it."""
        repomd = ET.fromstring(self._get(f"{url}/repodata/repomd.xml", mutable=True))
        entries = [d for d in repomd.findall("m:data", NS) if d.get("type") == "primary"]
        if not entries:
            msg = f"{url}: no primary index in repomd.xml"
            raise RepoError(msg)
        href = _attr(_child(entries[0], "m:location"), "href")
        kind = _attr(_child(entries[0], "m:checksum"), "type")
        kind = "sha1" if kind == "sha" else kind  # yum's old name for it
        want = _text(entries[0], "m:checksum")
        if kind not in hashlib.algorithms_available:
            msg = f"{url}: repomd.xml uses an unknown checksum, {kind}"
            raise RepoError(msg)
        primary_url = f"{url}/{href}"
        # createrepo names the file by its checksum unless told not to.
        raw = self._get(primary_url, mutable=want not in href)
        if hashlib.new(kind, raw).hexdigest() != want:
            self._reject(primary_url, f"{href}: the index does not match repomd.xml")
        return _decompress(href, raw)

    def load_index(self) -> None:
        """Read the primary index of every repository."""
        for url in self.urls:
            count = 0
            for pkg in ET.fromstring(self._primary(url)).findall("c:package", NS):
                name, arch = _text(pkg, "c:name"), _text(pkg, "c:arch")
                if arch not in (self.arch, "noarch"):
                    continue
                ver = _evr(_child(pkg, "c:version"))
                if name in self.index and rpm.vercmp(self.index[name]["version"], ver) >= 0:
                    continue
                fmt = _child(pkg, "c:format")
                checksum = _child(pkg, "c:checksum")
                self.index[name] = {
                    "name": name,
                    "version": ver,
                    "arch": arch,
                    "href": _attr(_child(pkg, "c:location"), "href"),
                    "sha256": checksum.text if checksum.get("type") == "sha256" else None,
                    "size": int(_attr(_child(pkg, "c:size"), "package")),
                    "_repo": url,
                    # Every Requires, including those marked pre="1" (Requires(pre) and the
                    # like), since dnf installs those too.
                    "requires": [
                        (
                            _attr(entry, "name"),
                            FLAGS.get(entry.get("flags") or ""),
                            _evr(entry) if entry.get("flags") else None,
                        )
                        for entry in fmt.findall("r:requires/r:entry", NS)
                    ],
                    "provides": [
                        (_attr(entry, "name"), _evr(entry) if entry.get("ver") else None)
                        for entry in fmt.findall("r:provides/r:entry", NS)
                    ],
                    "files": [f.text for f in fmt.findall("c:file", NS) if f.text],
                }
                count += 1
            log(f"index {url}: {count} packages")
        for st in self.index.values():
            for capability, provided in st["provides"]:
                self.provides.setdefault(capability, []).append((st, provided))
            for path in st["files"]:
                self.files.setdefault(path, []).append(st)

    def _pick(
        self,
        name: str,
        op: str | None,
        ver: str | None,
        selected: dict[str, Package],
        choose: dict[str, str],
    ) -> Package | None:
        """Return the package that meets one dependency, or None.

        The package --choose names for it wins, then the package of that name when its version
        meets the constraint. Otherwise a provider is used, or for a path a package that ships
        it: one already selected, else one named like the dependency, else the first by name.
        """
        if name in choose:
            return self.index.get(choose[name])
        st = self.index.get(name)
        if st is not None and rpm.satisfies(st["version"], op, ver):
            return st
        candidates = [
            (st, provided)
            for st, provided in self.provides.get(name, [])
            if op is None or (provided and rpm.satisfies(provided, op, ver))
        ]
        if not candidates and name.startswith("/"):
            candidates = [(st, None) for st in self.files.get(name, [])]
        for st, _ in candidates:
            if st["name"] in selected:
                return st
        for st, _ in candidates:
            if st["name"] == name:
                return st
        candidates.sort(key=lambda c: c[0]["name"])
        return candidates[0][0] if candidates else None

    def resolve(
        self, wanted: list[str], *, base: bool = True, choose: dict[str, str] | None = None
    ) -> tuple[dict[str, Package], list[str]]:
        """Return the closure of Requires over wanted, by package name, and notes for the user.

        A file dependency no indexed package ships is noted rather than refused, since
        primary.xml lists only some of each package's files.

        Args:
            wanted: The package names requested.
            base: Whether to add the base set to the request.
            choose: The package to use for a capability, by name.

        Raises:
            RepoError: When a requested package or a dependency cannot be met.
        """
        choose = choose or {}
        selected: dict[str, Package] = {}
        notes: list[str] = []
        queue = [(n, "requested") for n in wanted] + ([(n, "base") for n in BASE] if base else [])
        while queue:
            name, why = queue.pop(0)
            if name in selected:
                continue
            st = self._pick(name, None, None, selected, choose)
            if st is None:
                msg = f"no package provides {name} (needed by {why})"
                raise RepoError(msg)
            if st["name"] in selected:
                continue
            selected[st["name"]] = st
            for dep, op, ver in st["requires"]:
                if dep.startswith(("rpmlib(", "(")):
                    continue
                if dep in selected and rpm.satisfies(selected[dep]["version"], op, ver):
                    continue
                chosen = self._pick(dep, op, ver, selected, choose)
                if chosen is None:
                    if dep.startswith("/"):
                        notes.append(f"{st['name']} needs {dep}, which no indexed package ships")
                        continue
                    want = f"{dep} {op} {ver}" if op else dep
                    has = self.index.get(dep)
                    have = f"; the index has {has['version']}" if has else ""
                    msg = f"cannot satisfy {want} of {st['name']}{have}"
                    raise RepoError(msg)
                if chosen["name"] not in selected:
                    queue.append((chosen["name"], st["name"]))
        return selected, notes

    def download(self, st: Package) -> tuple[str, bytes]:
        """Fetch one package, check it against the index, and return its file name and contents."""
        name = os.path.basename(st["href"])
        if not st["sha256"]:
            msg = f"{name}: the index carries no SHA-256 for it; refusing an unverifiable download"
            raise RepoError(msg)
        url = f"{st['_repo']}/{st['href']}"
        data = self._get(url)
        if hashlib.sha256(data).hexdigest() != st["sha256"]:
            self._reject(url, f"{name}: SHA-256 does not match the index")
        if len(data) != st["size"]:
            self._reject(url, f"{name}: size does not match the index")
        return name, data


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        prog="fetch-rpms", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("packages", nargs="+")
    parser.add_argument("--out", required=True, help="directory to fill with .rpm files")
    parser.add_argument(
        "--repo", action="append", required=True, help="repository root holding repodata/"
    )
    parser.add_argument("--arch", default="x86_64", help="architecture to take besides noarch")
    parser.add_argument(
        "--cache", default=os.path.join(os.path.expanduser("~"), ".cache", "exclave-rpms")
    )
    parser.add_argument("--choose", action="append", default=[], metavar="VIRTUAL=PKG")
    parser.add_argument("--no-base", action="store_true")
    args = parser.parse_args(argv)
    choose = dict(c.split("=", 1) for c in args.choose)
    repo = Repo(args.repo, args.arch, args.cache)
    try:
        repo.load_index()
        selected, notes = repo.resolve(args.packages, base=not args.no_base, choose=choose)
        for note in notes:
            log(f"note: {note}")
        os.makedirs(args.out, exist_ok=True)
        for name in sorted(selected):
            filename, data = repo.download(selected[name])
            with open(os.path.join(args.out, filename), "wb") as f:
                f.write(data)
        log(f"{len(selected)} packages in {args.out}")
    except (RepoError, rpm.RpmError, OSError, ET.ParseError, lzma.LZMAError, zstd.ZstdError) as e:
        sys.exit(f"fetch-rpms: {e}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
