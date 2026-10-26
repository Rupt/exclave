"""fetch-apks.py — an example of the step before the tool for Alpine: resolve a package closure from an
Alpine repository index and download it into a directory of .apk files (DESIGN.md 10.1).

    scripts/fetch-apks [--branch v3.21] [--repos main,community] [--arch x86_64] [--mirror URL]
                        [--cache DIR] [--no-base] --out DIR PACKAGE...

The closure of `D:` dependencies is resolved against APKINDEX, `so:`, `cmd:` and `pc:` names through the
`p:` provides, a provider by its `k:` priority then by name, and the base set (alpine-baselayout, busybox)
added unless --no-base. Every package is verified against the index's checksum (the SHA-1 apk-tools
records); the index signature is not verified, so the mirror is trusted. The tool itself never
fetches: `exclave unpack OUT DIR/*.apk` takes what this tool, apk, a mirror or a hand-made directory has
put on disk. Not part of the tool's own exclave.
"""

import argparse
import base64
import hashlib
import io
import os
import re
import shutil
import sys
import tarfile
import urllib.request

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "exclave"))
import apk  # noqa: E402

DEFAULT_MIRROR = "https://dl-cdn.alpinelinux.org/alpine"
BASE = ["alpine-baselayout", "busybox"]


class RepoError(Exception):
    pass


def log(*a):
    print(*a, file=sys.stderr)


class Repo:
    def __init__(self, mirror, branch, repos, arch, cache):
        self.mirror, self.branch, self.repos, self.arch, self.cache = (
            mirror.rstrip("/"),
            branch,
            repos,
            arch,
            cache,
        )
        self.index, self.provides = {}, {}
        os.makedirs(cache, exist_ok=True)

    def _get(self, url):
        key = re.sub(r"[^A-Za-z0-9._-]", "_", url)
        path = os.path.join(self.cache, key)
        if os.path.exists(path):
            with open(path, "rb") as f:
                return f.read()
        log("fetch " + url)
        req = urllib.request.Request(url, headers={"User-Agent": "exclave/0.1"})
        with urllib.request.urlopen(req, timeout=120) as r:
            data = r.read()
        with open(path + ".tmp%d" % os.getpid(), "wb") as f:
            f.write(data)
        os.replace(path + ".tmp%d" % os.getpid(), path)  # two fetches may share the cache
        return data

    def load_index(self):
        for repo in self.repos:
            data = self._get(
                "%s/%s/%s/%s/APKINDEX.tar.gz" % (self.mirror, self.branch, repo, self.arch)
            )
            with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as t:
                text = t.extractfile("APKINDEX").read().decode("utf-8", "replace")
            n = 0
            for block in text.split("\n\n"):
                st = {}
                for line in block.split("\n"):
                    if len(line) > 2 and line[1] == ":":
                        st[line[0]] = line[2:]
                if "P" not in st or "V" not in st:
                    continue
                st["_repo"] = repo
                if st["P"] in self.index:
                    continue  # the first repository listed wins
                self.index[st["P"]] = st
                for alts in apk.parse_deps(st.get("p", "")):
                    for name, op, ver in alts:
                        self.provides.setdefault(name, []).append((st, ver if op == "=" else None))
                n += 1
            log("index %s/%s: %d packages" % (self.branch, repo, n))

    def _pick(self, name, op, ver, selected):
        st = self.index.get(name)
        if st is not None and apk.satisfies(st["V"], op, ver):
            return st
        if st is not None and op:
            raise RepoError("%s %s %s wanted; the index has %s" % (name, op, ver, st["V"]))
        providers = [
            (s, pv)
            for s, pv in self.provides.get(name, [])
            if op is None or (pv and apk.satisfies(pv, op, ver))
        ]
        for s, pv in providers:
            if s["P"] in selected:
                return s
        providers.sort(key=lambda p: (-int(p[0].get("k", "0") or 0), p[0]["P"]))
        return providers[0][0] if providers else None

    def resolve(self, wanted, base=True):
        selected = {}
        queue = [(n, "requested") for n in wanted] + ([(n, "base") for n in BASE] if base else [])
        while queue:
            name, why = queue.pop(0)
            if name in selected:
                continue
            st = self._pick(name, None, None, selected)
            if st is None:
                raise RepoError("no package provides %s (needed by %s)" % (name, why))
            if st["P"] in selected:
                continue
            selected[st["P"]] = st
            for alts in apk.parse_deps(st.get("D", "")):
                dep, op, ver = alts[0]
                if dep in selected or dep.startswith(
                    "/"
                ):  # a file dependency: satisfied by whatever ships it
                    continue
                chosen = self._pick(dep, op, ver, selected)
                if chosen is None:
                    raise RepoError("cannot satisfy %s of %s" % (dep, st["P"]))
                if chosen["P"] not in selected:
                    queue.append((chosen["P"], st["P"]))
        return selected

    def download(self, st):
        """Fetch one package and verify it the way apk does: the index's checksum is the SHA-1 of the control
        section, the gzip member holding .PKGINFO, and .PKGINFO's datahash is the SHA-256 of the compressed data member."""
        name = "%s-%s.apk" % (st["P"], st["V"])
        data = self._get(
            "%s/%s/%s/%s/%s" % (self.mirror, self.branch, st["_repo"], self.arch, name)
        )
        want = st.get("C", "")
        if not want.startswith("Q1"):
            raise RepoError(
                "%s: the index carries no checksum for it; refusing an unverifiable download" % name
            )
        if "S" in st and len(data) != int(st["S"]):
            raise RepoError("%s: size does not match the index" % name)
        members = _gzip_members(data)
        control = [i for i, (raw, plain) in enumerate(members) if b".PKGINFO" in plain[:4096]]
        if control != [len(members) - 2]:
            raise RepoError("%s: not an apk: no control section before the data" % name)
        raw, plain = members[control[0]]
        if base64.b64encode(hashlib.sha1(raw).digest()).decode() != want[2:]:
            raise RepoError("%s: checksum does not match the index" % name)
        m = re.search(rb"^datahash = ([0-9a-f]{64})$", plain, re.M)
        if (
            not m or hashlib.sha256(members[-1][0]).hexdigest() != m.group(1).decode()
        ):  # over the compressed data member, as abuild computes it
            raise RepoError(
                "%s: the data section does not match the datahash of its .PKGINFO" % name
            )
        return name, data


def _gzip_members(data):
    """[(compressed bytes, decompressed bytes)] for each gzip member of a concatenated stream."""
    import zlib

    out, pos = [], 0
    while pos < len(data):
        d = zlib.decompressobj(31)
        plain = d.decompress(data[pos:])
        end = len(data) - len(d.unused_data)
        out.append((data[pos:end], plain))
        pos = end
    return out


def main(argv):
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument("packages", nargs="+")
    ap.add_argument("--out", required=True, help="directory to fill with .apk files")
    ap.add_argument("--branch", default="v3.21")
    ap.add_argument("--repos", default="main,community")
    ap.add_argument("--arch", default="x86_64")
    ap.add_argument("--mirror", default=DEFAULT_MIRROR)
    ap.add_argument(
        "--cache", default=os.path.join(os.path.expanduser("~"), ".cache", "exclave-apks")
    )
    ap.add_argument("--no-base", action="store_true")
    a = ap.parse_args(argv)
    repo = Repo(a.mirror, a.branch, a.repos.split(","), a.arch, a.cache)
    try:
        repo.load_index()
        selected = repo.resolve(a.packages, base=not a.no_base)
        os.makedirs(a.out, exist_ok=True)
        for name in sorted(selected):
            fname, data = repo.download(selected[name])
            with open(os.path.join(a.out, fname), "wb") as f:
                f.write(data)
        log("%d packages in %s" % (len(selected), a.out))
    except (RepoError, apk.ApkError, OSError) as e:
        sys.exit("fetch-apks: %s" % e)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
