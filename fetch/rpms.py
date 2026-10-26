"""fetch/rpms.py — the step before the tool, for a yum/dnf repository.

An example of the step before the tool for rpm distributions: resolve a package closure from a
yum/dnf repository's metadata and download it into a directory of .rpm files (DESIGN.md 10.1).

    scripts/fetch-rpms --repo URL [--repo URL]... [--cache DIR] [--choose VIRTUAL=PKG]...
                       [--no-base] --out DIR PACKAGE...

Each --repo is a repository root holding repodata/repomd.xml (Fedora's Everything/x86_64/os,
Rocky's BaseOS and AppStream, CentOS 7's os on vault.centos.org). The closure of Requires is
resolved against primary.xml: names, versioned constraints, the so-called provides
(`libc.so.6(GLIBC_2.2.5)(64bit)`), file dependencies through the files the index lists, rich
dependencies and rpmlib() features skipped; a virtual name is satisfied by a --choose, an already
selected provider, a provider named like the dependency, else the first provider by name. The base
set (setup, filesystem, basesystem, bash) is added unless --no-base. Every download is verified
against the index's SHA-256; the metadata signature is not verified, so the mirror is trusted. The
tool itself never fetches: `exclave unpack OUT DIR/*.rpm` takes what this tool, dnf, a mirror or a
hand-made directory has put on disk. Not part of the tool's own exclave.
"""

import argparse
import gzip
import hashlib
import lzma
import os
import re
import sys
import urllib.request
import xml.etree.ElementTree as ET
from compression import zstd
from typing import TypedDict

from exclave import rpm

BASE = ["setup", "filesystem", "basesystem", "bash"]
NS = {
    "c": "http://linux.duke.edu/metadata/common",
    "r": "http://linux.duke.edu/metadata/rpm",
    "m": "http://linux.duke.edu/metadata/repo",
}
FLAGS = {"EQ": "=", "LT": "<", "GT": ">", "LE": "<=", "GE": ">="}


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


def log(*a: object) -> None:
    print(*a, file=sys.stderr)


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


def _evr(e: ET.Element) -> str:
    epoch, rel = e.get("epoch"), e.get("rel")
    ver = (epoch + ":" if epoch and epoch != "0" else "") + (e.get("ver") or "")
    if rel:
        ver += "-" + rel
    return ver


class Repo:
    def __init__(self, urls: list[str], cache: str) -> None:
        self.urls, self.cache = [u.rstrip("/") for u in urls], cache
        self.index: dict[str, Package] = {}
        self.provides: dict[str, list[tuple[Package, str | None]]] = {}
        self.files: dict[str | None, list[Package]] = {}
        os.makedirs(cache, exist_ok=True)

    def _get(self, url: str) -> bytes:
        key = re.sub(r"[^A-Za-z0-9._-]", "_", url)[-200:]
        path = os.path.join(self.cache, key)
        if os.path.exists(path):
            with open(path, "rb") as f:
                return f.read()
        log("fetch " + url)
        req = urllib.request.Request(url, headers={"User-Agent": "exclave/0.1"})
        with urllib.request.urlopen(req, timeout=300) as r:
            data = r.read()
        with open(f"{path}.tmp{os.getpid()}", "wb") as f:
            f.write(data)
        os.replace(f"{path}.tmp{os.getpid()}", path)  # two fetches may share the cache
        return data

    def load_index(self) -> None:
        for url in self.urls:
            md = ET.fromstring(self._get(url + "/repodata/repomd.xml"))
            loc = None
            for d in md.findall("m:data", NS):
                if d.get("type") == "primary":
                    loc = _child(d, "m:location").get("href")
            if not loc:
                msg = f"{url}: no primary index in repomd.xml"
                raise RepoError(msg)
            text = _decompress(loc, self._get(url + "/" + loc))
            n = 0
            for pkg in ET.fromstring(text).findall("c:package", NS):
                name, arch = _text(pkg, "c:name"), _text(pkg, "c:arch")
                if arch not in ("x86_64", "noarch"):
                    continue
                ver = _evr(_child(pkg, "c:version"))
                fmt = _child(pkg, "c:format")
                st: Package = {
                    "name": name,
                    "version": ver,
                    "arch": arch,
                    "href": _attr(_child(pkg, "c:location"), "href"),
                    "sha256": _child(pkg, "c:checksum").text
                    if _child(pkg, "c:checksum").get("type") == "sha256"
                    else None,
                    "size": int(_attr(_child(pkg, "c:size"), "package")),
                    "_repo": url,
                    "requires": [],
                    "provides": [],
                }
                for e in fmt.findall("r:requires/r:entry", NS):
                    if e.get("pre") == "1" or True:
                        st["requires"].append(
                            (
                                _attr(e, "name"),
                                FLAGS.get(e.get("flags") or ""),
                                _evr(e) if e.get("flags") else None,
                            )
                        )
                for e in fmt.findall("r:provides/r:entry", NS):
                    st["provides"].append((_attr(e, "name"), _evr(e) if e.get("ver") else None))
                for fe in fmt.findall("c:file", NS):
                    self.files.setdefault(fe.text, []).append(st)
                if name in self.index and rpm.vercmp(self.index[name]["version"], ver) >= 0:
                    continue
                self.index[name] = st
                n += 1
            log(f"index {url}: {n} packages")
        for st in self.index.values():
            for pname, pver in st["provides"]:
                self.provides.setdefault(pname, []).append((st, pver))

    def _pick(
        self,
        name: str,
        op: str | None,
        ver: str | None,
        selected: dict[str, Package],
        choose: dict[str, str],
    ) -> Package | None:
        if name in choose:
            return self.index.get(choose[name])
        st = self.index.get(name)
        if st is not None and rpm.satisfies(st["version"], op, ver):
            return st
        cands = [
            (s, pv)
            for s, pv in self.provides.get(name, [])
            if op is None or (pv and rpm.satisfies(pv, op, ver))
        ]
        if not cands and name.startswith("/"):
            cands = [(s, None) for s in self.files.get(name, [])]
        for s, _pv in cands:
            if s["name"] in selected:
                return s
        for s, _pv in cands:
            if s["name"] == name:
                return s
        cands.sort(key=lambda c: c[0]["name"])
        return cands[0][0] if cands else None

    def resolve(
        self, wanted: list[str], *, base: bool = True, choose: dict[str, str] | None = None
    ) -> tuple[dict[str, Package], list[str]]:
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
                if dep in selected and (
                    op is None or rpm.satisfies(selected[dep]["version"], op, ver)
                ):
                    continue
                chosen = self._pick(dep, op, ver, selected, choose)
                if chosen is None:
                    if dep.startswith("/"):
                        notes.append(
                            "{} needs {}, which no indexed package provides".format(st["name"], dep)
                        )
                        continue
                    msg = "cannot satisfy {} of {}".format(dep, st["name"])
                    raise RepoError(msg)
                if chosen["name"] not in selected:
                    queue.append((chosen["name"], st["name"]))
        return selected, notes

    def download(self, st: Package) -> tuple[str, bytes]:
        name = os.path.basename(st["href"])
        data = self._get(st["_repo"] + "/" + st["href"])
        if not st["sha256"]:
            msg = f"{name}: the index carries no SHA-256 for it; refusing an unverifiable download"
            raise RepoError(msg)
        if hashlib.sha256(data).hexdigest() != st["sha256"]:
            msg = f"{name}: SHA-256 does not match the index"
            raise RepoError(msg)
        if len(data) != st["size"]:
            msg = f"{name}: size does not match the index"
            raise RepoError(msg)
        return name, data


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(
        prog="fetch-rpms", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument("packages", nargs="+")
    ap.add_argument("--out", required=True, help="directory to fill with .rpm files")
    ap.add_argument(
        "--repo", action="append", required=True, help="repository root holding repodata/"
    )
    ap.add_argument(
        "--cache", default=os.path.join(os.path.expanduser("~"), ".cache", "exclave-rpms")
    )
    ap.add_argument("--choose", action="append", default=[], metavar="VIRTUAL=PKG")
    ap.add_argument("--no-base", action="store_true")
    a = ap.parse_args(argv)
    choose = dict(c.split("=", 1) for c in a.choose)
    repo = Repo(a.repo, a.cache)
    try:
        repo.load_index()
        selected, notes = repo.resolve(a.packages, base=not a.no_base, choose=choose)
        for n in notes:
            log("note: " + n)
        os.makedirs(a.out, exist_ok=True)
        for name in sorted(selected):
            fname, data = repo.download(selected[name])
            with open(os.path.join(a.out, fname), "wb") as f:
                f.write(data)
        log(f"{len(selected)} packages in {a.out}")
    except (RepoError, rpm.RpmError, OSError, ET.ParseError) as e:
        sys.exit(f"fetch-rpms: {e}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
