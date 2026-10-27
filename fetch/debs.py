"""Resolve a package closure from a Debian or Ubuntu archive and download its .deb files.

    scripts/fetch-debs [--distro ubuntu|debian] [--suite S]... [--arch amd64]
                       [--components main,universe] [--mirror URL | --snapshot DATE]
                       [--cache DIR] [--no-essential] [--choose VIRTUAL=PKG]...
                       --out DIR PACKAGE...

The fetcher reads the Packages index of each suite and component, and follows Depends and
Pre-Depends from the requested packages, adding the Essential set unless --no-essential is given.
Of a dependency's alternatives, one already selected is used, and otherwise the first one the
index can meet. A virtual package is met by a provider already selected, and otherwise by the
provider of highest Priority. --choose names the package to use for a virtual package or an
alternative instead.

Each Packages index is checked against the suite's Release file, and each package against the
SHA256 its index records. The Release signature is not checked, so the mirror is trusted. Package
files and by-hash indexes are cached, since their URLs name their content. The Release file, and
an index the suite does not serve by hash, are fetched on every run unless the mirror is a
snapshot, which never changes.

Neither unpack nor the tool fetches: `scripts/unpack OUT DIR/*.deb` takes whatever directory of
.deb files this fetcher, apt, a mirror or a person has made (DESIGN.md 10.1). The fetcher is not
part of the tool's own exclave.
"""

import argparse
import functools
import hashlib
import importlib.metadata
import os
import re
import shutil
import sys
import urllib.request
from typing import NoReturn

from unpack import deb

DEFAULT_MIRROR = {
    "ubuntu": "http://archive.ubuntu.com/ubuntu",
    "debian": "http://deb.debian.org/debian",
}
SNAPSHOT_BASE = {
    "ubuntu": "https://snapshot.ubuntu.com/ubuntu",
    "debian": "https://snapshot.debian.org/archive/debian",
}
DEFAULT_SUITES = {"ubuntu": ["noble", "noble-updates", "noble-security"], "debian": ["bookworm"]}
PRIORITY = {"required": 0, "important": 1, "standard": 2, "optional": 3, "extra": 4}
USER_AGENT = f"exclave/{importlib.metadata.version('exclave')}"

_version_key = functools.cmp_to_key(deb.vercmp)


class RepoError(Exception):
    pass


# A Packages stanza, field name to value, with `_suite` added for the suite it came from.
type Stanza = dict[str, str]

# A dependency's alternatives, each a package name with an optional operator and version.
type Alternatives = list[tuple[str, str | None, str | None]]


def log(*parts: object) -> None:
    print(*parts, file=sys.stderr)


class Repo:
    """The Packages indexes of a Debian-family archive, and the resolver that reads them."""

    def __init__(
        self,
        distro: str,
        suites: list[str],
        arch: str,
        components: list[str],
        cache: str,
        *,
        mirror: str | None = None,
        snapshot: str | None = None,
    ) -> None:
        if snapshot:
            stamp = snapshot if "T" in snapshot else snapshot.replace("-", "") + "T000000Z"
            mirror = f"{SNAPSHOT_BASE[distro]}/{stamp}"
        self.mirror = (mirror or DEFAULT_MIRROR[distro]).rstrip("/")
        self.snapshot = bool(snapshot)
        self.suites = suites
        self.arch = arch
        self.components = components
        self.cache = cache
        # Every version of each package, highest first.
        self.index: dict[str, list[Stanza]] = {}
        # The packages that provide each virtual name, with the version they provide, if any.
        self.provides: dict[str, list[tuple[Stanza, str | None]]] = {}
        os.makedirs(cache, exist_ok=True)

    # ------------------------------------------------------------ fetching
    def _path(self, url: str) -> str:
        """Return the cache file for url."""
        return os.path.join(self.cache, re.sub(r"[^A-Za-z0-9._-]", "_", url))

    def _get(self, url: str, *, mutable: bool = False) -> bytes:
        """Return the file at url, read from the cache when it can be kept there.

        A file whose URL names its content is cached. A mutable file, whose content can change at
        the same URL, is fetched every time unless the mirror is a snapshot.
        """
        path = self._path(url)
        keep = self.snapshot or not mutable
        if keep and os.path.exists(path):
            with open(path, "rb") as f:
                return f.read()
        log(f"fetch {url}")
        request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
        with urllib.request.urlopen(request, timeout=120) as response:
            data = response.read()
        if keep:
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

    def _release(self, suite: str) -> tuple[dict[str, tuple[str, int]], bool]:
        """Read a suite's Release file.

        Returns:
            The SHA256 digest and size of each file it lists, by path, and whether the suite
            serves its indexes by hash.
        """
        text = self._get(f"{self.mirror}/dists/{suite}/Release", mutable=True)
        fields = deb.parse_stanzas(text.decode("utf-8", "replace"))[0]
        digests: dict[str, tuple[str, int]] = {}
        for line in fields.get("SHA256", "").split("\n"):
            parts = line.split()
            if len(parts) == 3:
                digests[parts[2]] = (parts[0], int(parts[1]))
        return digests, fields.get("Acquire-By-Hash") == "yes"

    def load_index(self) -> None:
        """Read the Packages index of every suite and component."""
        for suite in self.suites:
            dists = f"{self.mirror}/dists/{suite}"
            digests, by_hash = self._release(suite)
            for comp in self.components:
                base = f"{comp}/binary-{self.arch}"
                rel = f"{base}/Packages.xz"
                if rel not in digests:
                    rel = f"{base}/Packages.gz"
                if rel not in digests:
                    log(f"no Packages index for {suite}/{comp}, skipping")
                    continue
                want, size = digests[rel]
                url = f"{dists}/{base}/by-hash/SHA256/{want}" if by_hash else f"{dists}/{rel}"
                data = self._get(url, mutable=not by_hash)
                if len(data) != size or hashlib.sha256(data).hexdigest() != want:
                    self._reject(url, f"{suite}/{rel}: the index does not match the Release file")
                count = 0
                for st in deb.parse_stanzas(deb.decompress(rel, data).decode("utf-8", "replace")):
                    if "Package" not in st or "Version" not in st:
                        continue
                    st["_suite"] = suite
                    self.index.setdefault(st["Package"], []).append(st)
                    for alts in deb.parse_deps(st.get("Provides", "")):
                        for name, op, ver in alts:
                            provided = ver if op == "=" else None
                            self.provides.setdefault(name, []).append((st, provided))
                    count += 1
                log(f"index {suite}/{comp}: {count} packages")
        for versions in self.index.values():
            versions.sort(key=lambda st: _version_key(st["Version"]), reverse=True)

    # ------------------------------------------------------------ resolution
    def best(self, name: str, op: str | None = None, ver: str | None = None) -> Stanza | None:
        """Return the highest version of the package name that meets the constraint, or None."""
        for st in self.index.get(name, []):
            if deb.satisfies(st["Version"], op, ver):
                return st
        return None

    def essential(self) -> list[str]:
        """Return the names of the packages whose highest version is Essential."""
        return sorted(n for n, sts in self.index.items() if sts[0].get("Essential") == "yes")

    def resolve(
        self, wanted: list[str], *, essential: bool = True, choose: dict[str, str] | None = None
    ) -> dict[str, Stanza]:
        """Return the closure of Depends and Pre-Depends over wanted, by package name.

        Args:
            wanted: The package names requested.
            essential: Whether to add the Essential set to the request.
            choose: The package to use for a virtual package or an alternative, by name.

        Raises:
            RepoError: When a requested package or a dependency cannot be met.
        """
        choose = choose or {}
        selected: dict[str, Stanza] = {}
        queue = [(n, "requested") for n in wanted]
        if essential:
            queue += [(n, "essential") for n in self.essential()]
        while queue:
            name, why = queue.pop(0)
            if name in selected:
                continue
            st = self._pick(name, None, None, selected, choose)
            if st is None:
                msg = f"no package provides {name} (needed by {why})"
                raise RepoError(msg)
            if st["Package"] in selected:
                continue
            selected[st["Package"]] = st
            for field in ("Pre-Depends", "Depends"):
                for alts in deb.parse_deps(st.get(field, "")):
                    chosen = self._alternative(alts, selected, choose)
                    if chosen is None:
                        unmet = self._unmet(alts, selected)
                        msg = f"cannot satisfy {field} of {st['Package']}: {unmet}"
                        raise RepoError(msg)
                    if chosen["Package"] not in selected:
                        queue.append((chosen["Package"], st["Package"]))
        return selected

    def _alternative(
        self, alts: Alternatives, selected: dict[str, Stanza], choose: dict[str, str]
    ) -> Stanza | None:
        """Return the package that meets one of a dependency's alternatives, or None.

        An alternative already selected at a version that meets it wins. Otherwise the first
        alternative the index can meet is used. An alternative selected at a version that does
        not meet it is passed over, since only one version of a package can be selected.
        """
        for name, op, ver in alts:
            if name in selected and deb.satisfies(selected[name]["Version"], op, ver):
                return selected[name]
        for name, op, ver in alts:
            if name in selected:
                continue
            st = self._pick(name, op, ver, selected, choose)
            if st is not None:
                return st
        return None

    def _unmet(self, alts: Alternatives, selected: dict[str, Stanza]) -> str:
        """Describe each of a dependency's alternatives and what the index has for it."""
        parts = []
        for name, op, ver in alts:
            if name in selected:
                have = f"{selected[name]['Version']} is selected"
            elif name in self.index:
                have = "the index has " + ", ".join(st["Version"] for st in self.index[name])
            elif name in self.provides:
                have = "no provider meets the constraint"
            else:
                have = "not in the index"
            parts.append(f"{name} {op} {ver} ({have})" if op else f"{name} ({have})")
        return " | ".join(parts)

    def _pick(
        self,
        name: str,
        op: str | None,
        ver: str | None,
        selected: dict[str, Stanza],
        choose: dict[str, str],
    ) -> Stanza | None:
        """Return the package that meets one dependency, or None.

        The package --choose names for it wins, then the highest version of the package of that
        name that meets the constraint. Otherwise a provider is used: one already selected, else
        the one of highest Priority. A versioned dependency is met only by a provider that
        provides a version.
        """
        if name in choose:
            return self.best(choose[name])
        st = self.best(name, op, ver)
        if st is not None:
            return st
        providers = [
            (st, provided)
            for st, provided in self.provides.get(name, [])
            if op is None or (provided and deb.satisfies(provided, op, ver))
        ]
        for st, _ in providers:
            if st["Package"] in selected:
                return st
        providers.sort(
            key=lambda p: (PRIORITY.get(p[0].get("Priority", "optional"), 9), p[0]["Package"])
        )
        return providers[0][0] if providers else None

    # ------------------------------------------------------------ packages
    def download(self, st: Stanza) -> str:
        """Fetch one package, check it against the index, and return its path in the cache."""
        filename = st["Filename"]
        if "SHA256" not in st:
            msg = (
                f"{filename}: the index carries no SHA256 for it; refusing an unverifiable download"
            )
            raise RepoError(msg)
        url = f"{self.mirror}/{filename}"
        data = self._get(url)
        if hashlib.sha256(data).hexdigest() != st["SHA256"]:
            self._reject(url, f"{filename}: SHA256 does not match the index")
        if "Size" in st and len(data) != int(st["Size"]):
            self._reject(url, f"{filename}: size does not match the index")
        return self._path(url)


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        prog="fetch-debs", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("packages", nargs="+")
    parser.add_argument("--out", required=True, help="directory to fill with .deb files")
    parser.add_argument("--distro", default="ubuntu", choices=["ubuntu", "debian"])
    parser.add_argument("--suite", action="append", default=[])
    parser.add_argument("--arch", default="amd64")
    parser.add_argument("--components", default="main,universe")
    source = parser.add_mutually_exclusive_group()
    source.add_argument("--mirror")
    source.add_argument("--snapshot")
    parser.add_argument(
        "--cache", default=os.path.join(os.path.expanduser("~"), ".cache", "exclave-debs")
    )
    parser.add_argument("--no-essential", action="store_true")
    parser.add_argument("--choose", action="append", default=[], metavar="VIRTUAL=PKG")
    args = parser.parse_args(argv)
    suites = [s for arg in args.suite for s in arg.split(",")] or DEFAULT_SUITES[args.distro]
    repo = Repo(
        args.distro,
        suites,
        args.arch,
        args.components.split(","),
        args.cache,
        mirror=args.mirror,
        snapshot=args.snapshot,
    )
    try:
        repo.load_index()
        choose = dict(c.split("=", 1) for c in args.choose)
        selected = repo.resolve(args.packages, essential=not args.no_essential, choose=choose)
        os.makedirs(args.out, exist_ok=True)
        for name in sorted(selected):
            src = repo.download(selected[name])
            dst = os.path.join(args.out, os.path.basename(selected[name]["Filename"]))
            if os.path.exists(dst):
                os.remove(dst)
            try:
                os.link(src, dst)
            except OSError:
                shutil.copy2(src, dst)
        log(f"{len(selected)} packages in {args.out}")
    except (RepoError, deb.DebError, OSError) as e:
        sys.exit(f"fetch-debs: {e}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
