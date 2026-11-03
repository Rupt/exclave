// Resolve a package closure from a Debian or Ubuntu archive and download its .deb files.
//
//	fetch debs --keyring FILE... [--distro ubuntu|debian] [--suite S]... [--arch amd64]
//	           [--components main,universe] [--mirror URL | --snapshot DATE]
//	           [--cache DIR] [--no-essential] [--choose VIRTUAL=PKG]... --out DIR PACKAGE...
//
// The fetcher reads the Packages index of each suite and component, and follows Depends and
// Pre-Depends from the requested packages, adding the Essential set unless --no-essential is
// given. Of a dependency's alternatives, one already selected is used, and otherwise the first
// one the index can meet. A virtual package is met by a provider already selected, and otherwise
// by the provider of highest Priority. --choose names the package to use for a virtual package or
// an alternative instead.
//
// Each suite's InRelease file is checked against the keyrings given (the archive's signing keys,
// such as /usr/share/keyrings/ubuntu-archive-keyring.gpg, or a key file in ASCII armour), each
// Packages index against the Release file it carries, and each package against the SHA256 its
// index records, so the chain from the keyring to every file is checked and the mirror is
// trusted for nothing but availability. Package files and indexes are cached under the SHA256
// the signed files give them, whatever mirror served them, and fetched again only when that
// changes; the InRelease file is fetched on every run unless the mirror is a snapshot, which never
// changes.

package fetch

import (
	"crypto/sha256"
	"errors"
	"exclave/unpack/deb"
	"exclave/unpack/reader"
	"flag"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

var (
	debMirrors = map[string]string{
		"ubuntu": "http://archive.ubuntu.com/ubuntu", "debian": "http://deb.debian.org/debian",
	}
	snapshotBase = map[string]string{
		"ubuntu": "https://snapshot.ubuntu.com/ubuntu", "debian": "https://snapshot.debian.org/archive/debian",
	}
	debSuites  = map[string][]string{"ubuntu": {"noble", "noble-updates", "noble-security"}, "debian": {"bookworm"}}
	priorities = map[string]int{"required": 0, "important": 1, "standard": 2, "optional": 3, "extra": 4}
)

// stanza is a Packages stanza, field name to value, with `_suite` added for the suite it came from.
type stanza map[string]string

// provider is a package that provides a virtual name, with the version it provides, if any.
type provider struct {
	st       stanza
	provided string
}

// debRepo is the Packages indexes of a Debian-family archive, and the resolver that reads them.
type debRepo struct {
	mirror     string
	suites     []string
	arch       string
	components []string
	cache      *cache
	keyring    *keyring
	index      map[string][]stanza // every version of each package, highest first
	provides   map[string][]provider
}

func newDebRepo(distro string, suites []string, arch string, components []string, cacheDir string,
	keys *keyring, mirror, snapshot string) (*debRepo, error) {
	if snapshot != "" {
		stamp := snapshot
		if !strings.Contains(snapshot, "T") {
			stamp = strings.ReplaceAll(snapshot, "-", "") + "T000000Z"
		}
		mirror = snapshotBase[distro] + "/" + stamp
	}
	if mirror == "" {
		mirror = debMirrors[distro]
	}
	c, err := newCache(cacheDir, 120*time.Second, 0)
	if err != nil {
		return nil, err
	}
	c.snapshot = snapshot != ""
	return &debRepo{
		mirror: strings.TrimRight(mirror, "/"), suites: suites, arch: arch, components: components,
		cache: c, keyring: keys, index: map[string][]stanza{}, provides: map[string][]provider{},
	}, nil
}

// release reads a suite's InRelease file, once its signature verifies against the keyrings, and
// returns the SHA256 digest and size of each file it lists, by path, and whether the suite
// serves its indexes by hash.
func (r *debRepo) release(suite string) (map[string][2]string, bool, error) {
	u := fmt.Sprintf("%s/dists/%s/InRelease", r.mirror, suite)
	signed, err := r.cache.get(u)
	if err != nil {
		return nil, false, err
	}
	text, err := r.keyring.clearsigned(signed)
	if err != nil {
		return nil, false, r.cache.reject(u, fmt.Sprintf("%s/InRelease: its signature does not verify: %s", suite, err))
	}
	log(suite + "/InRelease: signature verified")
	stanzas := deb.ParseStanzas(string(text))
	fields := stanza{}
	if len(stanzas) > 0 {
		fields = stanzas[0]
	}
	// the file must be the suite's, and current: a mirror could otherwise serve another suite's
	// signed file, or a past one, at the suite's URL
	if fields["Suite"] != suite && fields["Codename"] != suite {
		return nil, false, r.cache.reject(u, fmt.Sprintf("%s/InRelease: it is %s's, not %s's",
			suite, strings.TrimSpace(fields["Suite"]+" "+fields["Codename"]), suite))
	}
	if until := fields["Valid-Until"]; until != "" && !r.cache.snapshot {
		t, err := time.Parse(time.RFC1123, until)
		if err != nil {
			return nil, false, r.cache.reject(u,
				fmt.Sprintf("%s/InRelease: Valid-Until %q cannot be read", suite, until))
		}
		if time.Now().After(t) {
			return nil, false, r.cache.reject(u, fmt.Sprintf("%s/InRelease: expired on %s", suite, until))
		}
	}
	digests := map[string][2]string{}
	for line := range strings.SplitSeq(fields["SHA256"], "\n") {
		parts := strings.Fields(line)
		if len(parts) == 3 {
			digests[parts[2]] = [2]string{parts[0], parts[1]}
		}
	}
	return digests, fields["Acquire-By-Hash"] == "yes", nil
}

// loadIndex reads the Packages index of every suite and component.
func (r *debRepo) loadIndex() error {
	for _, suite := range r.suites {
		dists := fmt.Sprintf("%s/dists/%s", r.mirror, suite)
		digests, byHash, err := r.release(suite)
		if err != nil {
			return err
		}
		for _, comp := range r.components {
			// gzip before xz, which the archives also serve: the same index, larger to fetch
			// but decompressed in a fraction of the time, which is most of a warm fetch's
			base := fmt.Sprintf("%s/binary-%s", comp, r.arch)
			rel := base + "/Packages.gz"
			if _, ok := digests[rel]; !ok {
				rel = base + "/Packages.xz"
			}
			want, ok := digests[rel]
			if !ok {
				log(fmt.Sprintf("no Packages index for %s/%s, skipping", suite, comp))
				continue
			}
			u := dists + "/" + rel
			if byHash {
				u = fmt.Sprintf("%s/%s/by-hash/SHA256/%s", dists, base, want[0])
			}
			// kept by the digest the signed Release file gives, so an index that has not changed
			// is not fetched again whatever its URL
			size, err := strconv.ParseInt(want[1], 10, 64)
			if err != nil {
				return fmt.Errorf("%s/%s: the Release file gives its size as %q", suite, rel, want[1])
			}
			p, err := r.cache.keyed("sha256", want[0])
			if err != nil {
				return fmt.Errorf("%s/%s: %w", suite, rel, err)
			}
			err = r.cache.getVerified(u, p, func(f string) error { return checkFile(f, sha256.New, want[0], size) })
			if _, ok := errors.AsType[mismatch](err); ok {
				return fmt.Errorf("%s/%s: the index does not match the Release file", suite, rel)
			} else if err != nil {
				return err
			}
			data, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			plain, err := deb.Decompress(rel, data)
			if err != nil {
				return err
			}
			count := 0
			for _, st := range deb.ParseStanzas(string(plain)) {
				if st["Package"] == "" || st["Version"] == "" {
					continue
				}
				st["_suite"] = suite
				r.index[st["Package"]] = append(r.index[st["Package"]], st)
				groups, err := deb.ParseDeps(st["Provides"])
				if err != nil {
					return err
				}
				for _, alts := range groups {
					for _, d := range alts {
						provided := ""
						if d.Op == "=" {
							provided = d.Version
						}
						r.provides[d.Name] = append(r.provides[d.Name], provider{st, provided})
					}
				}
				count++
			}
			log(fmt.Sprintf("index %s/%s: %d packages", suite, comp, count))
		}
	}
	for _, versions := range r.index {
		sort.SliceStable(versions, func(i, j int) bool {
			return deb.Vercmp(versions[i]["Version"], versions[j]["Version"]) > 0
		})
	}
	return nil
}

// best returns the highest version of the package name that meets the constraint, or nil.
func (r *debRepo) best(name, op, ver string) stanza {
	for _, st := range r.index[name] {
		if deb.Satisfies(st["Version"], op, ver) {
			return st
		}
	}
	return nil
}

// essential returns the names of the packages whose highest version is Essential.
func (r *debRepo) essential() []string {
	var out []string
	for n, sts := range r.index {
		if sts[0]["Essential"] == "yes" {
			out = append(out, n)
		}
	}
	sort.Strings(out)
	return out
}

// queued is a package to select: the stanza already chosen for it, where a dependency chose
// one at a version that meets it, else the name to pick for.
type queued struct {
	name, why string
	st        stanza
}

// resolve returns the closure of Depends and Pre-Depends over wanted, by package name, with the
// Essential set added when essential is true; choose names the package to use for a virtual
// package or an alternative. A requested package or a dependency that cannot be met is an error.
func (r *debRepo) resolve(wanted []string, essential bool, choose map[string]string) (map[string]stanza, error) {
	selected := map[string]stanza{}
	var queue []queued
	for _, n := range wanted {
		queue = append(queue, queued{name: n, why: "requested"})
	}
	if essential {
		for _, n := range r.essential() {
			queue = append(queue, queued{name: n, why: "essential"})
		}
	}
	for len(queue) > 0 {
		q := queue[0]
		queue = queue[1:]
		if _, ok := selected[q.name]; ok {
			continue
		}
		st := q.st
		if st == nil {
			st = r.pick(q.name, "", "", selected, choose)
		}
		if st == nil {
			return nil, fmt.Errorf("no package provides %s (needed by %s)", q.name, q.why)
		}
		if _, ok := selected[st["Package"]]; ok {
			continue
		}
		selected[st["Package"]] = st
		for _, field := range []string{"Pre-Depends", "Depends"} {
			groups, err := deb.ParseDeps(st[field])
			if err != nil {
				return nil, err
			}
			for _, alts := range groups {
				chosen := r.alternative(alts, selected, choose)
				if chosen == nil {
					return nil, fmt.Errorf("cannot satisfy %s of %s: %s", field, st["Package"], r.unmet(alts, selected))
				}
				if _, ok := selected[chosen["Package"]]; !ok {
					// the stanza that met the constraint, not the name's highest version
					queue = append(queue, queued{chosen["Package"], st["Package"], chosen})
				}
			}
		}
	}
	return selected, nil
}

// alternative returns the package that meets one of a dependency's alternatives, or nil. An
// alternative already selected at a version that meets it wins. Otherwise the first alternative
// the index can meet is used. An alternative selected at a version that does not meet it is
// passed over, since only one version of a package can be selected.
func (r *debRepo) alternative(alts []reader.Dep, selected map[string]stanza, choose map[string]string) stanza {
	for _, d := range alts {
		if st, ok := selected[d.Name]; ok && deb.Satisfies(st["Version"], d.Op, d.Version) {
			return st
		}
	}
	for _, d := range alts {
		if _, ok := selected[d.Name]; ok {
			continue
		}
		if st := r.pick(d.Name, d.Op, d.Version, selected, choose); st != nil {
			return st
		}
	}
	return nil
}

// unmet describes each of a dependency's alternatives and what the index has for it.
func (r *debRepo) unmet(alts []reader.Dep, selected map[string]stanza) string {
	var parts []string
	for _, d := range alts {
		var have string
		if st, ok := selected[d.Name]; ok {
			have = st["Version"] + " is selected"
		} else if sts, ok := r.index[d.Name]; ok {
			var vs []string
			for _, st := range sts {
				vs = append(vs, st["Version"])
			}
			have = "the index has " + strings.Join(vs, ", ")
		} else if _, ok := r.provides[d.Name]; ok {
			have = "no provider meets the constraint"
		} else {
			have = "not in the index"
		}
		if d.Op != "" {
			parts = append(parts, fmt.Sprintf("%s %s %s (%s)", d.Name, d.Op, d.Version, have))
		} else {
			parts = append(parts, fmt.Sprintf("%s (%s)", d.Name, have))
		}
	}
	return strings.Join(parts, " | ")
}

// pick returns the package that meets one dependency, or nil. The package --choose names for it
// wins, then the highest version of the package of that name that meets the constraint.
// Otherwise a provider is used: one already selected, else the one of highest Priority, at its
// highest version that provides the name. A versioned dependency is met only by a provider that
// provides a version.
func (r *debRepo) pick(name, op, ver string, selected map[string]stanza, choose map[string]string) stanza {
	if c, ok := choose[name]; ok {
		return r.best(c, "", "")
	}
	if st := r.best(name, op, ver); st != nil {
		return st
	}
	var providers []provider
	for _, p := range r.provides[name] {
		if op == "" || (p.provided != "" && deb.Satisfies(p.provided, op, ver)) {
			providers = append(providers, p)
		}
	}
	for _, p := range providers {
		if _, ok := selected[p.st["Package"]]; ok {
			return p.st
		}
	}
	priority := func(p provider) int {
		if pr, ok := priorities[p.st["Priority"]]; ok {
			return pr
		}
		if p.st["Priority"] == "" {
			return priorities["optional"]
		}
		return 9
	}
	sort.SliceStable(providers, func(i, j int) bool {
		pi, pj := priority(providers[i]), priority(providers[j])
		if pi != pj {
			return pi < pj
		}
		if a, b := providers[i].st["Package"], providers[j].st["Package"]; a != b {
			return a < b
		}
		return deb.Vercmp(providers[i].st["Version"], providers[j].st["Version"]) > 0
	})
	if len(providers) == 0 {
		return nil
	}
	return providers[0].st
}

// download fetches one package, checks it against the index, and puts it at dst as a hard link
// to the cache's copy where the filesystem allows one. The file at dst is checked again once it
// is there: another run sharing the cache could have replaced the cache's file between the
// check and the link, and a rename never changes a file in place, so the link's bytes are what
// was checked or another file whole.
func (r *debRepo) download(st stanza, dst string) error {
	filename := st["Filename"]
	if st["SHA256"] == "" {
		return fmt.Errorf("%s: the index carries no SHA256 for it; refusing an unverifiable download", filename)
	}
	size := int64(-1)
	if s, ok := st["Size"]; ok {
		n, err := strconv.ParseInt(s, 10, 64)
		if err != nil {
			return fmt.Errorf("%s: the index gives its size as %q", filename, s)
		}
		size = n
	}
	p, err := r.cache.keyed("sha256", st["SHA256"])
	if err != nil {
		return fmt.Errorf("%s: %w", filename, err)
	}
	verify := func(f string) error { return checkFile(f, sha256.New, st["SHA256"], size) }
	switch err := r.cache.getVerified(r.mirror+"/"+filename, p, verify); err {
	case nil:
	case errDigest:
		return errors.New(filename + ": SHA256 does not match the index")
	case errSize:
		return errors.New(filename + ": size does not match the index")
	default:
		return err
	}
	return place(p, dst, verify)
}

func fetchDebs(args []string) error {
	fs := flag.NewFlagSet("exclave fetch debs", flag.ContinueOnError)
	var keyrings, suites, choose multi
	out := fs.String("out", "", "directory to fill with .deb files")
	fs.Var(&keyrings, "keyring", "a keyring InRelease must be signed by: binary, or a key file in ASCII armour")
	distro := fs.String("distro", "ubuntu", "ubuntu or debian")
	fs.Var(&suites, "suite", "a suite, or several separated by commas")
	arch := fs.String("arch", "amd64", "architecture")
	components := fs.String("components", "main,universe", "components, separated by commas")
	mirror := fs.String("mirror", "", "the archive's URL")
	snapshot := fs.String("snapshot", "", "a snapshot service date instead of a mirror")
	cacheDir := fs.String("cache", filepath.Join(homeDir(), ".cache", "exclave-debs"), "the cache directory")
	noEssential := fs.Bool("no-essential", false, "leave the Essential set out")
	fs.Var(&choose, "choose", "VIRTUAL=PKG, the package to use for a virtual package or an alternative")
	packages, err := parseArgs(fs, args)
	if err != nil {
		return err
	}
	switch {
	case len(packages) == 0 || *out == "" || len(keyrings) == 0:
		return &usageError{"--out, --keyring and at least one PACKAGE are required"}
	case *distro != "ubuntu" && *distro != "debian":
		return &usageError{"--distro takes ubuntu or debian"}
	case *mirror != "" && *snapshot != "":
		return &usageError{"--mirror and --snapshot exclude each other"}
	}
	var suiteList []string
	for _, s := range suites {
		suiteList = append(suiteList, strings.Split(s, ",")...)
	}
	if len(suiteList) == 0 {
		suiteList = debSuites[*distro]
	}
	keys, err := readKeyrings(keyrings)
	if err != nil {
		return err
	}
	repo, err := newDebRepo(*distro, suiteList, *arch, strings.Split(*components, ","), *cacheDir, keys,
		*mirror, *snapshot)
	if err != nil {
		return err
	}
	if err := repo.loadIndex(); err != nil {
		return err
	}
	chosen, err := splitChoices(choose)
	if err != nil {
		return err
	}
	selected, err := repo.resolve(packages, !*noEssential, chosen)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(*out, 0o777); err != nil {
		return err
	}
	names := make([]string, 0, len(selected))
	for n := range selected {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, name := range names {
		dst := filepath.Join(*out, path.Base(selected[name]["Filename"]))
		if err := repo.download(selected[name], dst); err != nil {
			return err
		}
	}
	log(fmt.Sprintf("%d packages in %s", len(selected), *out))
	return nil
}

func homeDir() string {
	if h, err := os.UserHomeDir(); err == nil {
		return h
	}
	return "."
}
