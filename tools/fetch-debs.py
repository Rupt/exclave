"""fetch-debs.py — an example of the step before the tool: resolve a package closure from a Debian-family
archive and download it into a directory of .deb files (DESIGN.md 10.1).

    scripts/fetch-debs [--distro ubuntu|debian] [--suite S]... [--arch amd64] [--components main,universe]
                        [--mirror URL | --snapshot DATE] [--cache DIR] [--no-essential] [--choose VIRTUAL=PKG]...
                        --out DIR PACKAGE...

The closure of Depends and Pre-Depends is resolved against the archive's Packages index, the Essential
set added unless --no-essential, virtual packages satisfied by the provider of highest priority unless
--choose says otherwise. Packages files are verified against the suite's Release digests and every
package against the index's SHA256; the Release signature is not verified, so the mirror is trusted.
The tool itself never fetches: `exclave unpack OUT DIR/*.deb` takes what this tool, apt, a mirror or
a hand-made directory has put on disk. Not part of the tool's own exclave.
"""

import argparse
import hashlib
import os
import re
import shutil
import sys
import urllib.request

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "exclave"))
import deb  # noqa: E402


class RepoError(Exception):
    pass


DEFAULT_MIRROR = {
    "ubuntu": "http://archive.ubuntu.com/ubuntu",
    "debian": "http://deb.debian.org/debian",
}
SNAPSHOT_BASE = {
    "ubuntu": "https://snapshot.ubuntu.com/ubuntu",
    "debian": "https://snapshot.debian.org/archive/debian",
}


class Repo:
    def __init__(
        self, distro, suites, arch, components, cache, mirror=None, snapshot=None, log=print
    ):
        self.distro, self.suites, self.arch, self.components, self.cache, self.log = (
            distro,
            suites,
            arch,
            components,
            cache,
            log,
        )
        if snapshot:
            ts = snapshot if "T" in snapshot else snapshot.replace("-", "") + "T000000Z"
            self.mirror = SNAPSHOT_BASE[distro] + "/" + ts
        else:
            self.mirror = mirror or DEFAULT_MIRROR[distro]
        self.mirror = self.mirror.rstrip("/")
        self.snapshot = snapshot
        self.index = {}  # name -> [stanza] (all versions)
        self.provides = {}  # virtual name -> [(stanza, version or None)]
        os.makedirs(cache, exist_ok=True)

    # ------------------------------------------------------------ fetching
    def _get(self, url):
        key = re.sub(r"[^A-Za-z0-9._-]", "_", url)
        path = os.path.join(self.cache, key)
        if os.path.exists(path):
            with open(path, "rb") as f:
                return f.read()
        self.log("fetch " + url)
        req = urllib.request.Request(url, headers={"User-Agent": "exclave/0.1"})
        with urllib.request.urlopen(req, timeout=120) as r:
            data = r.read()
        with open(path + ".tmp%d" % os.getpid(), "wb") as f:
            f.write(data)
        os.replace(path + ".tmp%d" % os.getpid(), path)  # two fetches may share the cache
        return data

    def _release_digests(self, suite):
        text = self._get("%s/dists/%s/Release" % (self.mirror, suite)).decode("utf-8", "replace")
        digests, in_sha = {}, False
        for line in text.split("\n"):
            if line.startswith("SHA256:"):
                in_sha = True
                continue
            if in_sha and line.startswith(" "):
                parts = line.split()
                if len(parts) == 3:
                    digests[parts[2]] = (parts[0], int(parts[1]))
            elif in_sha and not line.startswith(" "):
                in_sha = False
        return digests

    def load_index(self):
        for suite in self.suites:
            digests = self._release_digests(suite)
            for comp in self.components:
                rel = "%s/binary-%s/Packages.xz" % (comp, self.arch)
                if rel not in digests:
                    rel = "%s/binary-%s/Packages.gz" % (comp, self.arch)
                if rel not in digests:
                    self.log("no Packages index for %s/%s, skipping" % (suite, comp))
                    continue
                data = self._get("%s/dists/%s/%s" % (self.mirror, suite, rel))
                want, size = digests[rel]
                if len(data) != size or hashlib.sha256(data).hexdigest() != want:
                    raise RepoError(
                        "%s/%s: Packages index does not match the Release digest" % (suite, rel)
                    )
                text = deb.decompress(rel, data).decode("utf-8", "replace")
                n = 0
                for st in deb.parse_stanzas(text):
                    if "Package" not in st or "Version" not in st:
                        continue
                    st["_suite"] = suite
                    self.index.setdefault(st["Package"], []).append(st)
                    for alts in deb.parse_deps(st.get("Provides", "")):
                        for name, op, ver in alts:
                            self.provides.setdefault(name, []).append(
                                (st, ver if op == "=" else None)
                            )
                    n += 1
                self.log("index %s/%s: %d packages" % (suite, comp, n))
        for name in self.index:
            self.index[name].sort(key=lambda s: _VersionKey(s["Version"]), reverse=True)

    # ------------------------------------------------------------ resolution
    def best(self, name, op=None, ver=None):
        """The highest version of a real package satisfying a constraint, or None."""
        for st in self.index.get(name, []):
            if deb.satisfies(st["Version"], op, ver):
                return st
        return None

    def essential(self):
        return sorted(n for n, sts in self.index.items() if sts[0].get("Essential") == "yes")

    def resolve(self, wanted, essential=True, choose=None):
        """Closure of Depends and Pre-Depends: {name: stanza}. Alternatives by one already selected, else the first
        satisfiable; virtual packages by a selected provider, else the highest Priority; unless `choose` maps a
        virtual or alternative name to a package."""
        choose = choose or {}
        selected, notes = {}, []
        queue = [(n, "requested") for n in wanted]
        if essential:
            queue += [(n, "essential") for n in self.essential()]
        while queue:
            name, why = queue.pop(0)
            if name in selected:
                continue
            st = self._pick(name, None, None, selected, choose, why)
            if st is None:
                raise RepoError("no package provides %s (needed by %s)" % (name, why))
            if st["Package"] in selected:
                continue
            selected[st["Package"]] = st
            for field in ("Pre-Depends", "Depends"):
                for alts in deb.parse_deps(st.get(field, "")):
                    pick = None
                    for cand, op, ver in alts:
                        if cand in selected:
                            pick = (cand, op, ver)
                            break
                    if pick is None:
                        for cand, op, ver in alts:
                            if cand in choose:
                                pick = (choose[cand], None, None)
                                break
                            if (
                                self._pick(cand, op, ver, selected, choose, st["Package"])
                                is not None
                            ):
                                pick = (cand, op, ver)
                                break
                    if pick is None:
                        raise RepoError(
                            "cannot satisfy %s of %s: %s"
                            % (field, st["Package"], " | ".join(a[0] for a in alts))
                        )
                    cand, op, ver = pick
                    if cand not in selected:
                        chosen = self._pick(cand, op, ver, selected, choose, st["Package"])
                        queue.append((chosen["Package"], st["Package"]))
                    elif op and not deb.satisfies(selected[cand]["Version"], op, ver):
                        raise RepoError(
                            "%s needs %s %s %s but %s is selected"
                            % (st["Package"], cand, op, ver, selected[cand]["Version"])
                        )
        return selected, notes

    def _pick(self, name, op, ver, selected, choose, why):
        if name in choose:
            return self.best(choose[name])
        st = self.best(name, op, ver)
        if st is not None:
            return st
        if name in self.index and op:
            avail = ", ".join(s["Version"] for s in self.index[name])
            raise RepoError(
                "%s needs %s %s %s; the index has %s (versions are pinned to the index)"
                % (why, name, op, ver, avail)
            )
        providers = self.provides.get(name, [])
        for st, pver in providers:  # a provider already selected wins
            if st["Package"] in selected and (
                op is None or (pver and deb.satisfies(pver, op, ver))
            ):
                return st
        for st, pver in sorted(
            providers,
            key=lambda p: (_PRIORITY.get(p[0].get("Priority", "optional"), 9), p[0]["Package"]),
        ):
            if op is None or (pver and deb.satisfies(pver, op, ver)):
                return st
        return None

    # ------------------------------------------------------------ packages
    def download(self, st):
        """Fetch one package, verify it against the index, return its path in the cache."""
        url = "%s/%s" % (self.mirror, st["Filename"])
        if "SHA256" not in st:
            raise RepoError(
                "%s: the index carries no SHA256 for it; refusing an unverifiable download"
                % st["Filename"]
            )
        data = self._get(url)
        if hashlib.sha256(data).hexdigest() != st["SHA256"]:
            raise RepoError("%s: SHA256 does not match the index" % st["Filename"])
        if "Size" in st and len(data) != int(st["Size"]):
            raise RepoError("%s: size does not match the index" % st["Filename"])
        key = re.sub(r"[^A-Za-z0-9._-]", "_", url)
        return os.path.join(self.cache, key)


_PRIORITY = {"required": 0, "important": 1, "standard": 2, "optional": 3, "extra": 4}


class _VersionKey:
    __slots__ = ("v",)

    def __init__(self, v):
        self.v = v

    def __lt__(self, o):
        return deb.vercmp(self.v, o.v) < 0

    def __eq__(self, o):
        return deb.vercmp(self.v, o.v) == 0


def main(argv):
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument("packages", nargs="+")
    ap.add_argument("--out", required=True, help="directory to fill with .deb files")
    ap.add_argument("--distro", default="ubuntu", choices=["ubuntu", "debian"])
    ap.add_argument("--suite", action="append", default=[])
    ap.add_argument("--arch", default="amd64")
    ap.add_argument("--components", default="main,universe")
    ap.add_argument("--mirror")
    ap.add_argument("--snapshot")
    ap.add_argument(
        "--cache", default=os.path.join(os.path.expanduser("~"), ".cache", "exclave-debs")
    )
    ap.add_argument("--no-essential", action="store_true")
    ap.add_argument("--choose", action="append", default=[], metavar="VIRTUAL=PKG")
    a = ap.parse_args(argv)
    suites = [s for x in a.suite for s in x.split(",")] or {
        "ubuntu": ["noble", "noble-updates", "noble-security"],
        "debian": ["bookworm"],
    }[a.distro]
    r = Repo(a.distro, suites, a.arch, a.components.split(","), a.cache, a.mirror, a.snapshot)
    r.load_index()
    selected, notes = r.resolve(
        a.packages, essential=not a.no_essential, choose=dict(x.split("=", 1) for x in a.choose)
    )
    os.makedirs(a.out, exist_ok=True)
    for name in sorted(selected):
        src = r.download(selected[name])
        dst = os.path.join(a.out, os.path.basename(selected[name]["Filename"]))
        if os.path.exists(dst):
            os.remove(dst)
        try:
            os.link(src, dst)
        except OSError:
            shutil.copy2(src, dst)
    print("%d packages in %s" % (len(selected), a.out))
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv[1:]))
    except (RepoError, deb.DebError) as e:
        sys.exit("fetch-debs: %s" % e)
