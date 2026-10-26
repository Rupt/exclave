"""fetch/debs.py — the step before the tool, for a Debian-family archive.

An example of the step before the tool: resolve a package closure from a Debian-family archive and
download it into a directory of .deb files (DESIGN.md 10.1).

    scripts/fetch-debs [--distro ubuntu|debian] [--suite S]... [--arch amd64]
                       [--components main,universe] [--mirror URL | --snapshot DATE]
                       [--cache DIR] [--no-essential] [--choose VIRTUAL=PKG]...
                       --out DIR PACKAGE...

The closure of Depends and Pre-Depends is resolved against the archive's Packages index, the
Essential set added unless --no-essential, virtual packages satisfied by the provider of highest
priority unless --choose says otherwise. Packages files are verified against the suite's Release
digests and every package against the index's SHA256; the Release signature is not verified, so the
mirror is trusted. The tool itself never fetches: `exclave unpack OUT DIR/*.deb` takes what this
tool, apt, a mirror or a hand-made directory has put on disk. Not part of the tool's own exclave.
"""

import argparse
import hashlib
import os
import re
import shutil
import sys
import urllib.request
lazy from collections.abc import Callable

from exclave import deb


class RepoError(Exception):
    pass


# A Packages stanza, field name to value, with `_suite` added for the suite it came from.
type Stanza = dict[str, str]


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
        self,
        distro: str,
        suites: list[str],
        arch: str,
        components: list[str],
        cache: str,
        *,
        mirror: str | None = None,
        snapshot: str | None = None,
        log: Callable[[str], None] = print,
    ) -> None:
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
        self.index: dict[str, list[Stanza]] = {}  # name -> [stanza] (all versions)
        # virtual name -> [(stanza, version or None)]
        self.provides: dict[str, list[tuple[Stanza, str | None]]] = {}
        os.makedirs(cache, exist_ok=True)

    # ------------------------------------------------------------ fetching
    def _get(self, url: str) -> bytes:
        key = re.sub(r"[^A-Za-z0-9._-]", "_", url)
        path = os.path.join(self.cache, key)
        if os.path.exists(path):
            with open(path, "rb") as f:
                return f.read()
        self.log("fetch " + url)
        req = urllib.request.Request(url, headers={"User-Agent": "exclave/0.1"})
        with urllib.request.urlopen(req, timeout=120) as r:
            data = r.read()
        with open(f"{path}.tmp{os.getpid()}", "wb") as f:
            f.write(data)
        os.replace(f"{path}.tmp{os.getpid()}", path)  # two fetches may share the cache
        return data

    def _release_digests(self, suite: str) -> dict[str, tuple[str, int]]:
        text = self._get(f"{self.mirror}/dists/{suite}/Release").decode("utf-8", "replace")
        digests: dict[str, tuple[str, int]] = {}
        in_sha = False
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

    def load_index(self) -> None:
        for suite in self.suites:
            digests = self._release_digests(suite)
            for comp in self.components:
                rel = f"{comp}/binary-{self.arch}/Packages.xz"
                if rel not in digests:
                    rel = f"{comp}/binary-{self.arch}/Packages.gz"
                if rel not in digests:
                    self.log(f"no Packages index for {suite}/{comp}, skipping")
                    continue
                data = self._get(f"{self.mirror}/dists/{suite}/{rel}")
                want, size = digests[rel]
                if len(data) != size or hashlib.sha256(data).hexdigest() != want:
                    msg = f"{suite}/{rel}: Packages index does not match the Release digest"
                    raise RepoError(msg)
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
                self.log(f"index {suite}/{comp}: {n} packages")
        for name in self.index:
            self.index[name].sort(key=lambda s: _VersionKey(s["Version"]), reverse=True)

    # ------------------------------------------------------------ resolution
    def best(self, name: str, op: str | None = None, ver: str | None = None) -> Stanza | None:
        """The highest version of a real package satisfying a constraint, or None."""
        for st in self.index.get(name, []):
            if deb.satisfies(st["Version"], op, ver):
                return st
        return None

    def essential(self) -> list[str]:
        return sorted(n for n, sts in self.index.items() if sts[0].get("Essential") == "yes")

    def resolve(
        self, wanted: list[str], *, essential: bool = True, choose: dict[str, str] | None = None
    ) -> tuple[dict[str, Stanza], list[str]]:
        """Closure of Depends and Pre-Depends: {name: stanza}.

        Alternatives by one already selected, else the first satisfiable; virtual packages by a
        selected provider, else the highest Priority; unless `choose` maps a virtual or alternative
        name to a package.
        """
        choose = choose or {}
        selected: dict[str, Stanza] = {}
        notes: list[str] = []
        queue = [(n, "requested") for n in wanted]
        if essential:
            queue += [(n, "essential") for n in self.essential()]
        while queue:
            name, why = queue.pop(0)
            if name in selected:
                continue
            st = self._pick(name, None, None, selected, choose, why=why)
            if st is None:
                msg = f"no package provides {name} (needed by {why})"
                raise RepoError(msg)
            if st["Package"] in selected:
                continue
            selected[st["Package"]] = st
            for field in ("Pre-Depends", "Depends"):
                for alts in deb.parse_deps(st.get(field, "")):
                    pick: tuple[str, str | None, str | None] | None = None
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
                                self._pick(cand, op, ver, selected, choose, why=st["Package"])
                                is not None
                            ):
                                pick = (cand, op, ver)
                                break
                    if pick is None:
                        msg = "cannot satisfy {} of {}: {}".format(
                            field, st["Package"], " | ".join(a[0] for a in alts)
                        )
                        raise RepoError(msg)
                    cand, op, ver = pick
                    if cand not in selected:
                        chosen = self._pick(cand, op, ver, selected, choose, why=st["Package"])
                        if chosen is None:
                            msg = "no package provides {} (needed by {})".format(
                                cand, st["Package"]
                            )
                            raise RepoError(msg)
                        queue.append((chosen["Package"], st["Package"]))
                    elif op and not deb.satisfies(selected[cand]["Version"], op, ver):
                        msg = "{} needs {} {} {} but {} is selected".format(
                            st["Package"], cand, op, ver, selected[cand]["Version"]
                        )
                        raise RepoError(msg)
        return selected, notes

    def _pick(
        self,
        name: str,
        op: str | None,
        ver: str | None,
        selected: dict[str, Stanza],
        choose: dict[str, str],
        *,
        why: str,
    ) -> Stanza | None:
        if name in choose:
            return self.best(choose[name])
        st = self.best(name, op, ver)
        if st is not None:
            return st
        if name in self.index and op:
            avail = ", ".join(s["Version"] for s in self.index[name])
            msg = (
                f"{why} needs {name} {op} {ver}; the index has {avail}"
                " (versions are pinned to the index)"
            )
            raise RepoError(msg)
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
    def download(self, st: Stanza) -> str:
        """Fetch one package, verify it against the index, return its path in the cache."""
        url = "{}/{}".format(self.mirror, st["Filename"])
        if "SHA256" not in st:
            msg = (
                "{}: the index carries no SHA256 for it; refusing an unverifiable download".format(
                    st["Filename"]
                )
            )
            raise RepoError(msg)
        data = self._get(url)
        if hashlib.sha256(data).hexdigest() != st["SHA256"]:
            msg = "{}: SHA256 does not match the index".format(st["Filename"])
            raise RepoError(msg)
        if "Size" in st and len(data) != int(st["Size"]):
            msg = "{}: size does not match the index".format(st["Filename"])
            raise RepoError(msg)
        key = re.sub(r"[^A-Za-z0-9._-]", "_", url)
        return os.path.join(self.cache, key)


_PRIORITY = {"required": 0, "important": 1, "standard": 2, "optional": 3, "extra": 4}


class _VersionKey:
    __slots__ = ("v",)
    # As defining __eq__ alone implies: a key is compared, never hashed.
    __hash__ = None

    def __init__(self, v: str) -> None:
        self.v = v

    def __lt__(self, o: _VersionKey) -> bool:
        return deb.vercmp(self.v, o.v) < 0

    def __eq__(self, o: object) -> bool:
        if not isinstance(o, _VersionKey):
            return NotImplemented
        return deb.vercmp(self.v, o.v) == 0


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(
        prog="fetch-debs", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
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
    r = Repo(
        a.distro,
        suites,
        a.arch,
        a.components.split(","),
        a.cache,
        mirror=a.mirror,
        snapshot=a.snapshot,
    )
    r.load_index()
    selected, _notes = r.resolve(
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
    print(f"{len(selected)} packages in {a.out}")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv[1:]))
    except (RepoError, deb.DebError) as e:
        sys.exit(f"fetch-debs: {e}")
