#!/usr/bin/env python3
"""fetch-rpms.py — an example of the step before the tool for rpm distributions: resolve a package closure
from a yum/dnf repository's metadata and download it into a directory of .rpm files (DESIGN.md 10.1).

    tools/fetch-rpms.py --repo URL [--repo URL]... [--cache DIR] [--choose VIRTUAL=PKG]... [--no-base] --out DIR PACKAGE...

Each --repo is a repository root holding repodata/repomd.xml (Fedora's Everything/x86_64/os, Rocky's
BaseOS and AppStream, CentOS 7's os on vault.centos.org). The closure of Requires is resolved against
primary.xml: names, versioned constraints, the so-called provides (`libc.so.6(GLIBC_2.2.5)(64bit)`),
file dependencies through the files the index lists, rich dependencies and rpmlib() features skipped; a
virtual name is satisfied by a --choose, an already selected provider, a provider named like the
dependency, else the first provider by name. The base set (setup, filesystem, basesystem, bash) is added
unless --no-base. Every download is verified against the index's SHA-256; the metadata signature is not
verified, so the mirror is trusted. The tool itself never fetches: `exclave unpack OUT DIR/*.rpm`
takes what this tool, dnf, a mirror or a hand-made directory has put on disk. Not part of the tool's own exclave.
"""
import argparse
import gzip
import hashlib
import lzma
import os
import re
import shutil
import subprocess
import sys
import urllib.request
import xml.etree.ElementTree as ET
from compression import zstd

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "exclave"))
import rpm  # noqa: E402

BASE = ["setup", "filesystem", "basesystem", "bash"]
NS = {"c": "http://linux.duke.edu/metadata/common", "r": "http://linux.duke.edu/metadata/rpm", "m": "http://linux.duke.edu/metadata/repo"}
FLAGS = {"EQ": "=", "LT": "<", "GT": ">", "LE": "<=", "GE": ">="}


class RepoError(Exception):
    pass


def log(*a):
    print(*a, file=sys.stderr)


def _decompress(name, data):
    if name.endswith(".gz"):
        return gzip.decompress(data)
    if name.endswith(".xz"):
        return lzma.decompress(data)
    if name.endswith(".zst"):
        return zstd.decompress(data)
    return data


def _evr(e):
    ver = (e.get("epoch") + ":" if e.get("epoch") and e.get("epoch") != "0" else "") + (e.get("ver") or "")
    if e.get("rel"):
        ver += "-" + e.get("rel")
    return ver


class Repo:
    def __init__(self, urls, cache):
        self.urls, self.cache = [u.rstrip("/") for u in urls], cache
        self.index, self.provides, self.files = {}, {}, {}
        os.makedirs(cache, exist_ok=True)

    def _get(self, url):
        key = re.sub(r"[^A-Za-z0-9._-]", "_", url)[-200:]
        path = os.path.join(self.cache, key)
        if os.path.exists(path):
            with open(path, "rb") as f:
                return f.read()
        log("fetch " + url)
        req = urllib.request.Request(url, headers={"User-Agent": "exclave/0.1"})
        with urllib.request.urlopen(req, timeout=300) as r:
            data = r.read()
        with open(path + ".tmp%d" % os.getpid(), "wb") as f:
            f.write(data)
        os.replace(path + ".tmp%d" % os.getpid(), path)   # two fetches may share the cache
        return data

    def load_index(self):
        for url in self.urls:
            md = ET.fromstring(self._get(url + "/repodata/repomd.xml"))
            loc = None
            for d in md.findall("m:data", NS):
                if d.get("type") == "primary":
                    loc = d.find("m:location", NS).get("href")
            if not loc:
                raise RepoError("%s: no primary index in repomd.xml" % url)
            text = _decompress(loc, self._get(url + "/" + loc))
            n = 0
            for pkg in ET.fromstring(text).findall("c:package", NS):
                name, arch = pkg.find("c:name", NS).text, pkg.find("c:arch", NS).text
                if arch not in ("x86_64", "noarch"):
                    continue
                ver = _evr(pkg.find("c:version", NS))
                fmt = pkg.find("c:format", NS)
                st = {"name": name, "version": ver, "arch": arch, "href": pkg.find("c:location", NS).get("href"),
                      "sha256": pkg.find("c:checksum", NS).text if pkg.find("c:checksum", NS).get("type") == "sha256" else None,
                      "size": int(pkg.find("c:size", NS).get("package")), "_repo": url, "requires": [], "provides": []}
                for e in fmt.findall("r:requires/r:entry", NS):
                    if e.get("pre") == "1" or True:
                        st["requires"].append((e.get("name"), FLAGS.get(e.get("flags")), _evr(e) if e.get("flags") else None))
                for e in fmt.findall("r:provides/r:entry", NS):
                    st["provides"].append((e.get("name"), _evr(e) if e.get("ver") else None))
                for fe in fmt.findall("c:file", NS):
                    self.files.setdefault(fe.text, []).append(st)
                if name in self.index and rpm.vercmp(self.index[name]["version"], ver) >= 0:
                    continue
                self.index[name] = st
                n += 1
            log("index %s: %d packages" % (url, n))
        for st in self.index.values():
            for pname, pver in st["provides"]:
                self.provides.setdefault(pname, []).append((st, pver))

    def _pick(self, name, op, ver, selected, choose):
        if name in choose:
            return self.index.get(choose[name])
        st = self.index.get(name)
        if st is not None and rpm.satisfies(st["version"], op, ver):
            return st
        cands = [(s, pv) for s, pv in self.provides.get(name, []) if op is None or (pv and rpm.satisfies(pv, op, ver))]
        if not cands and name.startswith("/"):
            cands = [(s, None) for s in self.files.get(name, [])]
        for s, pv in cands:
            if s["name"] in selected:
                return s
        for s, pv in cands:
            if s["name"] == name:
                return s
        cands.sort(key=lambda c: c[0]["name"])
        return cands[0][0] if cands else None

    def resolve(self, wanted, base=True, choose=None):
        choose = choose or {}
        selected, notes = {}, []
        queue = [(n, "requested") for n in wanted] + ([(n, "base") for n in BASE] if base else [])
        while queue:
            name, why = queue.pop(0)
            if name in selected:
                continue
            st = self._pick(name, None, None, selected, choose)
            if st is None:
                raise RepoError("no package provides %s (needed by %s)" % (name, why))
            if st["name"] in selected:
                continue
            selected[st["name"]] = st
            for dep, op, ver in st["requires"]:
                if dep.startswith("rpmlib(") or dep.startswith("("):
                    continue
                if dep in selected and (op is None or rpm.satisfies(selected[dep]["version"], op, ver)):
                    continue
                chosen = self._pick(dep, op, ver, selected, choose)
                if chosen is None:
                    if dep.startswith("/"):
                        notes.append("%s needs %s, which no indexed package provides" % (st["name"], dep))
                        continue
                    raise RepoError("cannot satisfy %s of %s" % (dep, st["name"]))
                if chosen["name"] not in selected:
                    queue.append((chosen["name"], st["name"]))
        return selected, notes

    def download(self, st):
        name = os.path.basename(st["href"])
        data = self._get(st["_repo"] + "/" + st["href"])
        if not st["sha256"]:
            raise RepoError("%s: the index carries no SHA-256 for it; refusing an unverifiable download" % name)
        if hashlib.sha256(data).hexdigest() != st["sha256"]:
            raise RepoError("%s: SHA-256 does not match the index" % name)
        if len(data) != st["size"]:
            raise RepoError("%s: size does not match the index" % name)
        return name, data


def main(argv):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("packages", nargs="+")
    ap.add_argument("--out", required=True, help="directory to fill with .rpm files")
    ap.add_argument("--repo", action="append", required=True, help="repository root holding repodata/")
    ap.add_argument("--cache", default=os.path.join(os.path.expanduser("~"), ".cache", "exclave-rpms"))
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
        log("%d packages in %s" % (len(selected), a.out))
    except (RepoError, rpm.RpmError, OSError, ET.ParseError) as e:
        sys.exit("fetch-rpms: %s" % e)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
