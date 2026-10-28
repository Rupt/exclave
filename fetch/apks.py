"""Resolve a package closure from an Alpine repository and download its .apk files.

    scripts/fetch-apks --key FILE... [--branch v3.21] [--repos main,community] [--arch x86_64]
                       [--mirror URL] [--cache DIR] [--no-base] --out DIR PACKAGE...

The fetcher reads each repository's APKINDEX and follows the `D:` dependencies from the requested
packages, adding the base set (alpine-baselayout, busybox) unless --no-base is given. A `so:`,
`cmd:` or `pc:` name is met by a package that provides it (`p:`): one already selected, else the
one of highest `k:` priority, else the first by name. When several repositories list a package,
the first repository given wins.

Each APKINDEX is checked against the key its signature names, as apk checks it against
/etc/apk/keys: a --key is a PEM public key whose file name is the key's, such as
alpine-devel@lists.alpinelinux.org-6165ee59.rsa.pub from https://alpinelinux.org/keys/, and the
signature is RSA over the index's bytes (SHA-1 for the signatures Alpine makes, which the
design records). Each package is then checked against the checksum its index records (the SHA-1
apk-tools uses), and its data against the datahash in its .PKGINFO, so the chain from the key to
every file is checked and the mirror is trusted for nothing but availability. Package files are
cached, since their names carry their versions; APKINDEX is fetched on every run.

Neither unpack nor the tool fetches: `scripts/unpack OUT DIR/*.apk` takes whatever directory of
.apk files this fetcher, apk, a mirror or a person has made (DESIGN.md 10.1). The fetcher is not
part of the tool's own exclave.
"""

import argparse
import base64
import hashlib
import importlib.metadata
import io
import os
import re
import sys
import tarfile
import urllib.request
import zlib
from typing import NoReturn

import verify

from unpack import apk

DEFAULT_MIRROR = "https://dl-cdn.alpinelinux.org/alpine"
BASE = ["alpine-baselayout", "busybox"]
USER_AGENT = f"exclave/{importlib.metadata.version('exclave')}"


class RepoError(Exception):
    pass


# An APKINDEX entry, field letter to value, with `_repo` added for the repository it came from.
type Stanza = dict[str, str]


def log(*parts: object) -> None:
    print(*parts, file=sys.stderr)


class Repo:
    """The APKINDEX of each repository of an Alpine branch, and the resolver that reads them."""

    def __init__(
        self, mirror: str, branch: str, repos: list[str], arch: str, cache: str, *, keys: list[str]
    ) -> None:
        self.mirror = mirror.rstrip("/")
        self.branch = branch
        self.repos = repos
        self.arch = arch
        self.cache = cache
        self.keys = {os.path.basename(k): k for k in keys}  # as apk names them in /etc/apk/keys
        # Each package, from the first repository that lists it.
        self.index: dict[str, Stanza] = {}
        # The packages that provide each name, with the version they provide, if any.
        self.provides: dict[str, list[tuple[Stanza, str | None]]] = {}
        os.makedirs(cache, exist_ok=True)

    def _path(self, url: str) -> str:
        """Return the cache file for url."""
        return os.path.join(self.cache, re.sub(r"[^A-Za-z0-9._-]", "_", url))

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
        with urllib.request.urlopen(request, timeout=120) as response:
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

    def _signed_index(self, url: str) -> bytes:
        """Return the index archive's bytes after its signature, once that verifies.

        The archive's first gzip member holds the signature, .SIGN.RSA*.KEYNAME, over every byte
        that follows it; the key is the one of that name among those given.
        """
        data = self._get(url, mutable=True)
        try:  # the first member alone: the rest is decompressed once its signature verifies
            stream = zlib.decompressobj(31)
            plain = stream.decompress(data)
            first = data[: len(data) - len(stream.unused_data)]
        except zlib.error as e:
            self._reject(url, f"{url}: not an index archive: {e}")
        with tarfile.open(fileobj=io.BytesIO(plain + b"\0" * 1024), mode="r:") as tar:
            signatures = [m for m in tar.getmembers() if m.name.startswith(".SIGN.")]
            if len(signatures) != 1:
                self._reject(url, f"{url}: the index archive carries {len(signatures)} signatures")
            kind, _, keyname = signatures[0].name.removeprefix(".SIGN.").partition(".")
            if kind not in verify.APK_DIGESTS:
                self._reject(url, f"{url}: a signature of an unknown kind, .SIGN.{kind}")
            if keyname not in self.keys:
                self._reject(url, f"{url}: signed by {keyname}, which no --key gives")
            member = tar.extractfile(signatures[0])
            if member is None:
                self._reject(url, f"{url}: the signature is not a file")
            signature = member.read()
        try:
            verify.rsa(data[len(first) :], signature, self.keys[keyname], verify.APK_DIGESTS[kind])
        except verify.VerifyError as e:
            self._reject(url, f"{url}: {e}")
        log(f"{url}: signature verified against {keyname}")
        return data[len(first) :]

    def load_index(self) -> None:
        """Read the APKINDEX of every repository, once its signature verifies."""
        for repo in self.repos:
            url = f"{self.mirror}/{self.branch}/{repo}/{self.arch}/APKINDEX.tar.gz"
            with tarfile.open(fileobj=io.BytesIO(self._signed_index(url)), mode="r:gz") as tar:
                member = tar.extractfile("APKINDEX")
                if member is None:
                    msg = f"{self.branch}/{repo}: APKINDEX in the index archive is not a file"
                    raise RepoError(msg)
                text = member.read().decode("utf-8", "replace")
            count = 0
            for block in text.split("\n\n"):
                st: Stanza = {}
                for line in block.split("\n"):
                    if len(line) > 2 and line[1] == ":":
                        st[line[0]] = line[2:]
                if "P" not in st or "V" not in st or st["P"] in self.index:
                    continue
                st["_repo"] = repo
                self.index[st["P"]] = st
                for alts in apk.parse_deps(st.get("p", "")):
                    for name, op, ver in alts:
                        provided = ver if op == "=" else None
                        self.provides.setdefault(name, []).append((st, provided))
                count += 1
            log(f"index {self.branch}/{repo}: {count} packages")

    def _pick(
        self, name: str, op: str | None, ver: str | None, selected: dict[str, Stanza]
    ) -> Stanza | None:
        """Return the package that meets one dependency, or None.

        The package of that name wins when its version meets the constraint. Otherwise a provider
        is used: one already selected, else the one of highest priority, else the first by name.
        A versioned dependency is met only by a provider that provides a version.
        """
        st = self.index.get(name)
        if st is not None and apk.satisfies(st["V"], op, ver):
            return st
        providers = [
            (st, provided)
            for st, provided in self.provides.get(name, [])
            if op is None or (provided and apk.satisfies(provided, op, ver))
        ]
        for st, _ in providers:
            if st["P"] in selected:
                return st
        providers.sort(key=lambda p: (-int(p[0].get("k", "0") or 0), p[0]["P"]))
        return providers[0][0] if providers else None

    def resolve(self, wanted: list[str], *, base: bool = True) -> dict[str, Stanza]:
        """Return the closure of `D:` dependencies over wanted, by package name.

        Args:
            wanted: The package names requested.
            base: Whether to add the base set to the request.

        Raises:
            RepoError: When a requested package or a dependency cannot be met.
        """
        selected: dict[str, Stanza] = {}
        queue = [(n, "requested") for n in wanted] + ([(n, "base") for n in BASE] if base else [])
        while queue:
            name, why = queue.pop(0)
            if name in selected:
                continue
            st = self._pick(name, None, None, selected)
            if st is None:
                msg = f"no package provides {name} (needed by {why})"
                raise RepoError(msg)
            if st["P"] in selected:
                continue
            selected[st["P"]] = st
            for alts in apk.parse_deps(st.get("D", "")):
                dep, op, ver = alts[0]
                # A file dependency is left to whichever selected package ships the file.
                if dep in selected or dep.startswith("/"):
                    continue
                chosen = self._pick(dep, op, ver, selected)
                if chosen is None:
                    want = f"{dep}{op}{ver}" if op else dep
                    have = f"; the index has {self.index[dep]['V']}" if dep in self.index else ""
                    msg = f"cannot satisfy {want} of {st['P']}{have}"
                    raise RepoError(msg)
                if chosen["P"] not in selected:
                    queue.append((chosen["P"], st["P"]))
        return selected

    def download(self, st: Stanza) -> tuple[str, bytes]:
        """Fetch one package, check it the way apk does, and return its file name and contents.

        The index's checksum is the SHA-1 of the control section, the gzip member that holds
        .PKGINFO. The datahash in .PKGINFO is the SHA-256 of the compressed data member, as abuild
        computes it.
        """
        name = f"{st['P']}-{st['V']}.apk"
        want = st.get("C", "")
        if not want.startswith("Q1"):
            msg = f"{name}: the index carries no checksum for it; refusing an unverifiable download"
            raise RepoError(msg)
        url = f"{self.mirror}/{self.branch}/{st['_repo']}/{self.arch}/{name}"
        data = self._get(url)
        if "S" in st and len(data) != int(st["S"]):
            self._reject(url, f"{name}: size does not match the index")
        try:
            members = _gzip_members(data)
        except zlib.error as e:
            self._reject(url, f"{name}: not an apk: {e}")
        control = [i for i, (_, plain) in enumerate(members) if b".PKGINFO" in plain[:4096]]
        if control != [len(members) - 2]:
            self._reject(url, f"{name}: not an apk: no control section before the data")
        raw, plain = members[control[0]]
        sha1 = hashlib.sha1(raw).digest()  # noqa: S324 -- apk's index records SHA-1
        if base64.b64encode(sha1).decode() != want[2:]:
            self._reject(url, f"{name}: checksum does not match the index")
        match = re.search(rb"^datahash = ([0-9a-f]{64})$", plain, re.MULTILINE)
        if not match or hashlib.sha256(members[-1][0]).hexdigest() != match.group(1).decode():
            self._reject(url, f"{name}: the data section does not match the datahash of .PKGINFO")
        return name, data


def _gzip_members(data: bytes) -> list[tuple[bytes, bytes]]:
    """Split a concatenated gzip stream into its members, each compressed and decompressed."""
    out: list[tuple[bytes, bytes]] = []
    pos = 0
    while pos < len(data):
        stream = zlib.decompressobj(31)
        plain = stream.decompress(data[pos:])
        end = len(data) - len(stream.unused_data)
        out.append((data[pos:end], plain))
        pos = end
    return out


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        prog="fetch-apks", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("packages", nargs="+")
    parser.add_argument("--out", required=True, help="directory to fill with .apk files")
    parser.add_argument(
        "--key",
        action="append",
        required=True,
        metavar="FILE",
        help="a PEM public key an index may be signed by, named as apk names it",
    )
    parser.add_argument("--branch", default="v3.21")
    parser.add_argument("--repos", default="main,community")
    parser.add_argument("--arch", default="x86_64")
    parser.add_argument("--mirror", default=DEFAULT_MIRROR)
    parser.add_argument(
        "--cache", default=os.path.join(os.path.expanduser("~"), ".cache", "exclave-apks")
    )
    parser.add_argument("--no-base", action="store_true")
    args = parser.parse_args(argv)
    repo = Repo(
        args.mirror, args.branch, args.repos.split(","), args.arch, args.cache, keys=args.key
    )
    try:
        repo.load_index()
        selected = repo.resolve(args.packages, base=not args.no_base)
        os.makedirs(args.out, exist_ok=True)
        for name in sorted(selected):
            filename, data = repo.download(selected[name])
            with open(os.path.join(args.out, filename), "wb") as f:
                f.write(data)
        log(f"{len(selected)} packages in {args.out}")
    except (RepoError, apk.ApkError, verify.VerifyError, OSError, tarfile.TarError) as e:
        sys.exit(f"fetch-apks: {e}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
