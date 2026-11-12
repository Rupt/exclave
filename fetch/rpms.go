// Resolve a package closure from yum/dnf repositories and download its .rpm files.
//
//	fetch rpms --keyring FILE... --repo URL [--repo URL]... [--arch x86_64]
//	           [--cache DIR] [--choose VIRTUAL=PKG]... [--no-base] --out DIR PACKAGE...
//
// Each --repo is a repository root holding repodata/repomd.xml, such as Fedora's
// Everything/x86_64/os, Rocky's BaseOS and AppStream, or CentOS 7's os on vault.centos.org. The
// fetcher reads each repository's primary.xml, keeps the packages built for --arch or noarch, and
// follows Requires from the requested packages, adding the base set (setup, filesystem,
// basesystem, bash) unless --no-base is given. A dependency may be a package name, a versioned
// constraint, a capability such as `libc.so.6(GLIBC_2.2.5)(64bit)`, or a file, which is met
// through the files primary.xml lists. Rich dependencies and rpmlib() features are skipped. A
// name no package has is met by the package --choose names for it, else a provider already
// selected, else a provider named like the dependency, else the first provider by name.
//
// Every rpm's own signature is checked against the keyrings given (the distribution's
// RPM-GPG-KEY file, or a binary keyring) as rpm checks it: the header signature over the header
// section, and the payload against the digest the header records, or, for a package signed
// before rpm 4.14 recorded one, a signature over header and payload together. A repository that
// signs its metadata, repomd.xml.asc beside repomd.xml, as CentOS does and Fedora does not, has
// that signature checked too, which holds the index itself to the key; without it the index is
// the mirror's, and the fetcher says so. The primary index is checked against the checksum in
// repomd.xml, and each package against the SHA-256 its index records. Package files and the
// primary index are cached under those digests, whatever mirror served them; repomd.xml is
// fetched on every run.

package fetch

import (
	"bytes"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/xml"
	"errors"
	"exclave/unpack/reader"
	"exclave/unpack/rpm"
	"flag"
	"fmt"
	"hash"
	"io"
	"maps"
	"os"
	"path"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"
)

var (
	rpmBase  = []string{"setup", "filesystem", "basesystem", "bash"}
	rpmFlags = map[string]string{"EQ": "=", "LT": "<", "GT": ">", "LE": "<=", "GE": ">="}
)

// rpmPackage is a package of primary.xml, as the resolver reads it.
type rpmPackage struct {
	name     string
	version  string
	arch     string
	href     string
	sha256   string
	size     int64
	repo     string
	requires []reader.Dep
	provides []provided
	files    []string
}

type provided struct{ name, version string }

type rpmProvider struct {
	pkg      *rpmPackage
	provided string
}

// the XML of a primary index and of repomd.xml, as encoding/xml reads them
type xmlEntry struct {
	Name  string `xml:"name,attr"`
	Flags string `xml:"flags,attr"`
	Epoch string `xml:"epoch,attr"`
	Ver   string `xml:"ver,attr"`
	Rel   string `xml:"rel,attr"`
}

type xmlPackage struct {
	Name    string `xml:"name"`
	Arch    string `xml:"arch"`
	Version *struct {
		Epoch string `xml:"epoch,attr"`
		Ver   string `xml:"ver,attr"`
		Rel   string `xml:"rel,attr"`
	} `xml:"version"`
	Checksum *struct {
		Type  string `xml:"type,attr"`
		Value string `xml:",chardata"`
	} `xml:"checksum"`
	Size *struct {
		Package string `xml:"package,attr"`
	} `xml:"size"`
	Location *struct {
		Href string `xml:"href,attr"`
	} `xml:"location"`
	Format *struct {
		Requires []xmlEntry `xml:"requires>entry"`
		Provides []xmlEntry `xml:"provides>entry"`
		Files    []string   `xml:"file"`
	} `xml:"format"`
}

type xmlRepomd struct {
	Data []struct {
		Type     string `xml:"type,attr"`
		Checksum *struct {
			Type  string `xml:"type,attr"`
			Value string `xml:",chardata"`
		} `xml:"checksum"`
		Location *struct {
			Href string `xml:"href,attr"`
		} `xml:"location"`
	} `xml:"data"`
}

// evr returns the [epoch:]version[-release] of a version or dependency entry.
func evr(epoch, ver, rel string) string {
	v := ver
	if epoch != "" && epoch != "0" {
		v = epoch + ":" + ver
	}
	if rel != "" {
		v += "-" + rel
	}
	return v
}

// rpmRepo is the primary indexes of yum/dnf repositories, and the resolver that reads them.
type rpmRepo struct {
	urls     []string
	arch     string
	cache    *cache
	keyring  *keyring
	index    map[string]*rpmPackage // the highest version of each package across the repositories
	order    []string               // the packages' names, in the order first seen
	provides map[string][]rpmProvider
	files    map[string][]*rpmPackage
}

func newRpmRepo(urls []string, arch, cacheDir string, keys *keyring) (*rpmRepo, error) {
	c, err := newCache(cacheDir, 300*time.Second, 200)
	if err != nil {
		return nil, err
	}
	r := &rpmRepo{
		arch: arch, cache: c, keyring: keys, index: map[string]*rpmPackage{},
		provides: map[string][]rpmProvider{}, files: map[string][]*rpmPackage{},
	}
	for _, u := range urls {
		r.urls = append(r.urls, strings.TrimRight(u, "/"))
	}
	return r, nil
}

// repomd fetches a repository's repomd.xml, checked against its signature where there is one.
func (r *rpmRepo) repomd(u string) ([]byte, error) {
	data, err := r.cache.get(u + "/repodata/repomd.xml")
	if err != nil {
		return nil, err
	}
	signature, err := r.cache.get(u + "/repodata/repomd.xml.asc")
	if err != nil {
		if !missing(err) {
			return nil, err
		}
		log(u + ": repomd.xml is not signed by this repository: the index is the mirror's")
		return data, nil
	}
	if err := r.keyring.detached(data, signature); err != nil {
		return nil, r.cache.reject(u+"/repodata/repomd.xml",
			fmt.Sprintf("%s: repomd.xml's signature does not verify: %s", u, err))
	}
	log(u + ": repomd.xml signature verified")
	return data, nil
}

func newHash(kind string) hash.Hash {
	switch kind {
	case "md5":
		return md5.New()
	case "sha1":
		return sha1.New()
	case "sha256":
		return sha256.New()
	case "sha512":
		return sha512.New()
	}
	return nil
}

// primary fetches a repository's primary index, checks it against repomd.xml and returns it
// decompressing, read as a stream.
func (r *rpmRepo) primary(u string) (io.ReadCloser, error) {
	data, err := r.repomd(u)
	if err != nil {
		return nil, err
	}
	var md xmlRepomd
	if err := xml.Unmarshal(data, &md); err != nil {
		return nil, fmt.Errorf("%s/repodata/repomd.xml: %s", u, err)
	}
	for _, d := range md.Data {
		if d.Type != "primary" {
			continue
		}
		if d.Location == nil {
			return nil, errors.New("repository metadata: no location in data")
		}
		if d.Checksum == nil {
			return nil, errors.New("repository metadata: no checksum in data")
		}
		kind := d.Checksum.Type
		if kind == "sha" { // yum's old name for it
			kind = "sha1"
		}
		want := strings.TrimSpace(d.Checksum.Value)
		if newHash(kind) == nil {
			return nil, fmt.Errorf("%s: repomd.xml uses an unknown checksum, %s", u, kind)
		}
		href := d.Location.Href
		// kept by the checksum the signed repomd.xml gives, whatever its name or mirror
		p, err := r.cache.keyed(kind, want)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", href, err)
		}
		err = r.cache.getVerified(u+"/"+href, p, func(f string) error {
			return checkFile(f, func() hash.Hash { return newHash(kind) }, want, -1)
		})
		if _, ok := errors.AsType[mismatch](err); ok {
			return nil, errors.New(href + ": the index does not match repomd.xml")
		} else if err != nil {
			return nil, err
		}
		raw, err := os.ReadFile(p)
		if err != nil {
			return nil, err
		}
		comp, ok := reader.Suffixes[path.Ext(href)]
		if !ok {
			return io.NopCloser(bytes.NewReader(raw)), nil
		}
		s, err := reader.Decompress(comp, bytes.NewReader(raw))
		if err != nil {
			return nil, fmt.Errorf("%s: %s", href, err)
		}
		return s, nil
	}
	return nil, fmt.Errorf("%s: no primary index in repomd.xml", u)
}

// loadIndex reads the primary index of every repository.
func (r *rpmRepo) loadIndex() error {
	for _, u := range r.urls {
		stream, err := r.primary(u)
		if err != nil {
			return err
		}
		defer stream.Close()
		count := 0
		dec := xml.NewDecoder(stream)
		for {
			tok, err := dec.Token()
			if err == io.EOF {
				break
			}
			if err != nil {
				return fmt.Errorf("%s: primary.xml: %s", u, err)
			}
			se, ok := tok.(xml.StartElement)
			if !ok || se.Name.Local != "package" {
				continue
			}
			var p xmlPackage
			if err := dec.DecodeElement(&p, &se); err != nil {
				return fmt.Errorf("%s: primary.xml: %s", u, err)
			}
			if p.Name == "" || p.Arch == "" {
				return fmt.Errorf("repository metadata: no name or arch in package")
			}
			if p.Arch != r.arch && p.Arch != "noarch" {
				continue
			}
			if p.Version == nil {
				return fmt.Errorf("repository metadata: no version in package")
			}
			ver := evr(p.Version.Epoch, p.Version.Ver, p.Version.Rel)
			if have, ok := r.index[p.Name]; ok && rpm.Vercmp(have.version, ver) >= 0 {
				continue
			}
			if p.Format == nil || p.Checksum == nil || p.Location == nil || p.Size == nil {
				return fmt.Errorf("repository metadata: no format, checksum, location or size in package %s", p.Name)
			}
			size, err := strconv.ParseInt(p.Size.Package, 10, 64)
			if err != nil {
				return fmt.Errorf("repository metadata: no package attribute in size of %s", p.Name)
			}
			pkg := &rpmPackage{name: p.Name, version: ver, arch: p.Arch, href: p.Location.Href, size: size, repo: u}
			if p.Checksum.Type == "sha256" {
				pkg.sha256 = strings.TrimSpace(p.Checksum.Value)
			}
			// Every Requires, including those marked pre="1" (Requires(pre) and the like), since
			// dnf installs those too.
			for _, e := range p.Format.Requires {
				d := reader.Dep{Name: e.Name}
				if e.Flags != "" {
					d.Op, d.Version = rpmFlags[e.Flags], evr(e.Epoch, e.Ver, e.Rel)
				}
				pkg.requires = append(pkg.requires, d)
			}
			for _, e := range p.Format.Provides {
				v := ""
				if e.Ver != "" {
					v = evr(e.Epoch, e.Ver, e.Rel)
				}
				pkg.provides = append(pkg.provides, provided{e.Name, v})
			}
			for _, f := range p.Format.Files {
				if f != "" {
					pkg.files = append(pkg.files, f)
				}
			}
			if _, ok := r.index[p.Name]; !ok {
				r.order = append(r.order, p.Name)
			}
			r.index[p.Name] = pkg
			count++
		}
		log(fmt.Sprintf("index %s: %d packages", u, count))
	}
	for _, name := range r.order {
		pkg := r.index[name]
		for _, p := range pkg.provides {
			r.provides[p.name] = append(r.provides[p.name], rpmProvider{pkg, p.version})
		}
		for _, f := range pkg.files {
			r.files[f] = append(r.files[f], pkg)
		}
	}
	return nil
}

// pick returns the package that meets one dependency, or nil. The package --choose names for it
// wins, then the package of that name when its version meets the constraint. Otherwise a
// provider is used, or for a path a package that ships it: one already selected, else one named
// like the dependency, else the first by name.
func (r *rpmRepo) pick(name, op, ver string, selected map[string]*rpmPackage, choose map[string]string) *rpmPackage {
	if c, ok := choose[name]; ok {
		return r.index[c]
	}
	if pkg, ok := r.index[name]; ok && rpm.Satisfies(pkg.version, op, ver) {
		return pkg
	}
	var candidates []*rpmPackage
	for _, p := range r.provides[name] {
		if op == "" || (p.provided != "" && rpm.Satisfies(p.provided, op, ver)) {
			candidates = append(candidates, p.pkg)
		}
	}
	if len(candidates) == 0 && strings.HasPrefix(name, "/") {
		candidates = append(candidates, r.files[name]...)
	}
	for _, c := range candidates {
		if _, ok := selected[c.name]; ok {
			return c
		}
	}
	for _, c := range candidates {
		if c.name == name {
			return c
		}
	}
	sort.SliceStable(candidates, func(i, j int) bool { return candidates[i].name < candidates[j].name })
	if len(candidates) == 0 {
		return nil
	}
	return candidates[0]
}

// resolve returns the closure of Requires over wanted, by package name, and notes for the user:
// a file dependency no indexed package ships is noted rather than refused, since primary.xml
// lists only some of each package's files. The base set is added when base is true; choose
// names the package to use for a capability. A requested package or a dependency that cannot be
// met is an error.
func (r *rpmRepo) resolve(wanted []string, base bool, choose map[string]string) (
	map[string]*rpmPackage, []string, error,
) {
	selected := map[string]*rpmPackage{}
	var notes []string
	var queue []queued
	for _, n := range wanted {
		queue = append(queue, queued{name: n, why: "requested"})
	}
	if base {
		for _, n := range rpmBase {
			queue = append(queue, queued{name: n, why: "base"})
		}
	}
	for len(queue) > 0 {
		q := queue[0]
		queue = queue[1:]
		if _, ok := selected[q.name]; ok {
			continue
		}
		pkg := r.pick(q.name, "", "", selected, choose)
		if pkg == nil {
			return nil, nil, fmt.Errorf("no package provides %s (needed by %s)", q.name, q.why)
		}
		if _, ok := selected[pkg.name]; ok {
			continue
		}
		selected[pkg.name] = pkg
		for _, d := range pkg.requires {
			if strings.HasPrefix(d.Name, "rpmlib(") || strings.HasPrefix(d.Name, "(") {
				continue
			}
			if s, ok := selected[d.Name]; ok && rpm.Satisfies(s.version, d.Op, d.Version) {
				continue
			}
			chosen := r.pick(d.Name, d.Op, d.Version, selected, choose)
			if chosen == nil {
				if strings.HasPrefix(d.Name, "/") {
					notes = append(notes, fmt.Sprintf("%s needs %s, which no indexed package ships", pkg.name, d.Name))
					continue
				}
				want := d.Name
				if d.Op != "" {
					want = fmt.Sprintf("%s %s %s", d.Name, d.Op, d.Version)
				}
				have := ""
				if has, ok := r.index[d.Name]; ok {
					have = "; the index has " + has.version
				}
				return nil, nil, fmt.Errorf("cannot satisfy %s of %s%s", want, pkg.name, have)
			}
			if _, ok := selected[chosen.name]; !ok {
				queue = append(queue, queued{name: chosen.name, why: pkg.name})
			}
		}
	}
	return selected, notes, nil
}

// download fetches one package into the cache, checks it against the index and its signatures,
// and returns its file name and the cache's file.
func (r *rpmRepo) download(pkg *rpmPackage) (fetched, error) {
	name := path.Base(pkg.href)
	if pkg.sha256 == "" {
		return fetched{}, fmt.Errorf("%s: the index carries no SHA-256 for it; refusing an unverifiable download", name)
	}
	p, err := r.cache.keyed("sha256", pkg.sha256)
	if err != nil {
		return fetched{}, fmt.Errorf("%s: %w", name, err)
	}
	// the digest and size the signed index gives, then the package's own signatures
	verify := func(f string) error {
		if err := checkFile(f, sha256.New, pkg.sha256, pkg.size); err != nil {
			return err
		}
		data, err := os.ReadFile(f)
		if err != nil {
			return err
		}
		if err := r.verifyPackage(name, data); err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
		return nil
	}
	switch err := r.cache.getVerified(pkg.repo+"/"+pkg.href, p, verify); err {
	case nil:
		return fetched{name, p, verify}, nil
	case errDigest:
		return fetched{}, errors.New(name + ": SHA-256 does not match the index")
	case errSize:
		return fetched{}, errors.New(name + ": size does not match the index")
	default:
		return fetched{}, err
	}
}

// verifyPackage checks a package's signatures as rpm does. A header signature (RPMSIGTAG_RSA or
// _DSA) covers the header section, whose RPMTAG_PAYLOADDIGEST covers the payload; a signature
// over header and payload together (RPMSIGTAG_PGP or _GPG), which rpm made before 4.14 recorded
// a digest, covers both. Every signature the package carries must verify, and one of the two
// must cover the payload.
func (r *rpmRepo) verifyPackage(name string, data []byte) error {
	parts, err := rpm.ReadSectionsFrom(bytes.NewReader(data), name)
	if err != nil {
		return err
	}
	if parts.Payload > int64(len(data)) {
		return verifyErrorf("the header runs past the end of the file")
	}
	payload := data[parts.Payload:]
	headerSig := sigValue(parts.Signature, 268, 267)
	wholeSig := sigValue(parts.Signature, 1002, 1005)
	if headerSig != nil {
		if err := r.keyring.detached(parts.HeaderBytes, headerSig); err != nil {
			return err
		}
	}
	if wholeSig != nil {
		return r.keyring.detached(append(append([]byte(nil), parts.HeaderBytes...), payload...), wholeSig)
	}
	if headerSig == nil {
		return verifyErrorf("the package carries no signature")
	}
	digests, ok := parts.Header[5092]
	if !ok || len(digests.Strs) == 0 {
		return verifyErrorf("the signed header records no payload digest, and no signature covers the payload")
	}
	if algo, ok := parts.Header.Int(5093); ok && algo != 8 { // PGPHASHALGO_SHA256, the one rpm writes
		return verifyErrorf("the payload digest uses algorithm %d, not SHA-256", algo)
	}
	if sha256hex(payload) != digests.Strs[0] {
		return verifyErrorf("the payload does not match the digest in the signed header")
	}
	return nil
}

// sigValue returns the first of the tags' binary values in the signature header, or nil.
func sigValue(h rpm.Header, tags ...uint32) []byte {
	for _, t := range tags {
		if v, ok := h[t]; ok && v.Bin != nil {
			return v.Bin
		}
	}
	return nil
}

func fetchRpms(args []string) error {
	fs := flag.NewFlagSet("exclave-fetch rpms", flag.ContinueOnError)
	var keyrings, repos, choose multi
	out := fs.String("out", "", "directory to fill with .rpm files")
	fs.Var(&keyrings, "keyring", "a keyring the packages must be signed by: an RPM-GPG-KEY file, or a binary keyring")
	fs.Var(&repos, "repo", "a repository root holding repodata/")
	arch := fs.String("arch", "x86_64", "architecture to take besides noarch")
	cacheDir := fs.String("cache", "", "a directory to keep files in between runs, or none")
	fs.Var(&choose, "choose", "VIRTUAL=PKG, the package to use for a capability")
	noBase := fs.Bool("no-base", false, "leave the base set out")
	packages, err := parseArgs(fs, args)
	if err != nil {
		return err
	}
	if len(packages) == 0 || *out == "" || len(keyrings) == 0 || len(repos) == 0 {
		return &usageError{"--out, --keyring, --repo and at least one PACKAGE are required"}
	}
	keys, err := readKeyrings(keyrings)
	if err != nil {
		return err
	}
	cdir, done, err := cacheIn(*cacheDir, *out)
	if err != nil {
		return err
	}
	defer done()
	repo, err := newRpmRepo(repos, *arch, cdir, keys)
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
	selected, notes, err := repo.resolve(packages, !*noBase, chosen)
	if err != nil {
		return err
	}
	for _, note := range notes {
		log("note: " + note)
	}
	names := slices.Sorted(maps.Keys(selected))
	return fill(*out, len(names), func(i int) (fetched, error) { return repo.download(selected[names[i]]) })
}
