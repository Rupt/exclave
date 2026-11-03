// Resolve a package closure from an Alpine repository and download its .apk files.
//
//	fetch apks --key FILE... [--branch v3.21] [--repos main,community] [--arch x86_64]
//	           [--mirror URL] [--cache DIR] [--no-base] --out DIR PACKAGE...
//
// The fetcher reads each repository's APKINDEX and follows the `D:` dependencies from the
// requested packages, adding the base set (alpine-baselayout, busybox) unless --no-base is given.
// A `so:`, `cmd:` or `pc:` name is met by a package that provides it (`p:`): one already
// selected, else the one of highest `k:` priority, else the first by name. When several
// repositories list a package, the first repository given wins.
//
// Each APKINDEX is checked against the key its signature names, as apk checks it against
// /etc/apk/keys: a --key is a PEM public key whose file name is the key's, such as
// alpine-devel@lists.alpinelinux.org-6165ee59.rsa.pub from https://alpinelinux.org/keys/, and the
// signature is RSA over the index's bytes (SHA-1 for the signatures Alpine makes, which the
// design records). Each package is then checked against the checksum its index records (the
// SHA-1 apk-tools uses), and its data against the datahash in its .PKGINFO, so the chain from
// the key to every file is checked and the mirror is trusted for nothing but availability.
// Package files are cached, since their names carry their versions; APKINDEX is fetched on every
// run.

package fetch

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha1"
	"encoding/base64"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"exclave/unpack/apk"
)

const apkMirror = "https://dl-cdn.alpinelinux.org/alpine"

var apkBase = []string{"alpine-baselayout", "busybox"}

// apkRepo is the APKINDEX of each repository of an Alpine branch, and the resolver that reads
// them.
type apkRepo struct {
	mirror   string
	branch   string
	repos    []string
	arch     string
	cache    *cache
	keys     map[string]string // the key files given, by name, as apk names them in /etc/apk/keys
	index    map[string]stanza // each package, from the first repository that lists it
	provides map[string][]provider
}

func newApkRepo(mirror, branch string, repos []string, arch, cacheDir string, keys []string) (*apkRepo, error) {
	c, err := newCache(cacheDir, 120*time.Second, 0)
	if err != nil {
		return nil, err
	}
	r := &apkRepo{
		mirror: strings.TrimRight(mirror, "/"), branch: branch, repos: repos, arch: arch, cache: c,
		keys: map[string]string{}, index: map[string]stanza{}, provides: map[string][]provider{},
	}
	for _, k := range keys {
		r.keys[filepath.Base(k)] = k
	}
	return r, nil
}

// plainCap bounds what of a gzip member's plaintext is kept: the signature and control
// sections are small, and the data section's plaintext is not read, only its end found.
const plainCap = 4 << 20

// gzipMember is one member of a concatenated gzip stream: its compressed bytes, and its
// plaintext up to plainCap, which whole says the member was no larger.
type gzipMember struct {
	raw   []byte
	plain []byte
	whole bool
}

// gzipMembers splits a concatenated gzip stream into its members, each inflated to find its end.
func gzipMembers(data []byte) ([]gzipMember, error) {
	var out []gzipMember
	pos := 0
	for pos < len(data) {
		br := bytes.NewReader(data[pos:])
		z, err := gzip.NewReader(br)
		if err != nil {
			return nil, err
		}
		z.Multistream(false)
		plain, err := io.ReadAll(io.LimitReader(z, plainCap+1))
		if err != nil {
			return nil, err
		}
		whole := len(plain) <= plainCap
		if !whole {
			plain = plain[:plainCap]
			if _, err := io.Copy(io.Discard, z); err != nil {
				return nil, err
			}
		}
		end := pos + len(data[pos:]) - br.Len()
		out = append(out, gzipMember{data[pos:end], plain, whole})
		pos = end
	}
	return out, nil
}

// signaturesOnly says whether a tar stream, a signature section's, holds nothing but regular
// files named .SIGN.* at the top, as apk-tools writes one.
func signaturesOnly(plain []byte) bool {
	t := tar.NewReader(bytes.NewReader(append(plain, make([]byte, 1024)...)))
	for {
		h, err := t.Next()
		if err == io.EOF {
			return true
		}
		if err != nil || !strings.HasPrefix(h.Name, ".SIGN.") || strings.Contains(h.Name, "/") ||
			h.Typeflag != tar.TypeReg {
			return false
		}
	}
}

// signedIndex returns the index archive's bytes after its signature, once that verifies. The
// archive's first gzip member holds the signature, .SIGN.RSA*.KEYNAME, over every byte that
// follows it; the key is the one of that name among those given.
func (r *apkRepo) signedIndex(u string) ([]byte, error) {
	data, err := r.cache.get(u, true)
	if err != nil {
		return nil, err
	}
	// the first member alone: the rest is decompressed once its signature verifies
	br := bytes.NewReader(data)
	z, err := gzip.NewReader(br)
	if err != nil {
		return nil, r.cache.reject(u, fmt.Sprintf("%s: not an index archive: %s", u, err))
	}
	z.Multistream(false)
	plain, err := io.ReadAll(io.LimitReader(z, plainCap))
	if err != nil {
		return nil, r.cache.reject(u, fmt.Sprintf("%s: not an index archive: %s", u, err))
	}
	if _, err := io.Copy(io.Discard, z); err != nil {
		return nil, r.cache.reject(u, fmt.Sprintf("%s: not an index archive: %s", u, err))
	}
	first := len(data) - br.Len()
	var signatures []*tar.Header
	var signature []byte
	t := tar.NewReader(bytes.NewReader(append(plain, make([]byte, 1024)...)))
	for {
		h, err := t.Next()
		if err != nil {
			break
		}
		if strings.HasPrefix(h.Name, ".SIGN.") {
			signatures = append(signatures, h)
			if h.Typeflag == tar.TypeReg {
				signature, _ = io.ReadAll(t)
			} else {
				signature = nil
			}
		}
	}
	if len(signatures) != 1 {
		return nil, r.cache.reject(u, fmt.Sprintf("%s: the index archive carries %d signatures", u, len(signatures)))
	}
	kind, keyname, _ := strings.Cut(strings.TrimPrefix(signatures[0].Name, ".SIGN."), ".")
	digest, ok := apkDigests[kind]
	if !ok {
		return nil, r.cache.reject(u, fmt.Sprintf("%s: a signature of an unknown kind, .SIGN.%s", u, kind))
	}
	keyFile, ok := r.keys[keyname]
	if !ok {
		return nil, r.cache.reject(u, fmt.Sprintf("%s: signed by %s, which no --key gives", u, keyname))
	}
	if signature == nil {
		return nil, r.cache.reject(u, u+": the signature is not a file")
	}
	if err := checkRSA(data[first:], signature, keyFile, digest); err != nil {
		return nil, r.cache.reject(u, fmt.Sprintf("%s: %s", u, err))
	}
	log(fmt.Sprintf("%s: signature verified against %s", u, keyname))
	return data[first:], nil
}

// loadIndex reads the APKINDEX of every repository, once its signature verifies.
func (r *apkRepo) loadIndex() error {
	for _, repo := range r.repos {
		u := fmt.Sprintf("%s/%s/%s/%s/APKINDEX.tar.gz", r.mirror, r.branch, repo, r.arch)
		signed, err := r.signedIndex(u)
		if err != nil {
			return err
		}
		z, err := gzip.NewReader(bytes.NewReader(signed))
		if err != nil {
			return fmt.Errorf("%s: %s", u, err)
		}
		var text []byte
		found := false
		t := tar.NewReader(z)
		for {
			h, err := t.Next()
			if err == io.EOF {
				break
			}
			if err != nil {
				return fmt.Errorf("%s: %s", u, err)
			}
			if h.Name == "APKINDEX" {
				if h.Typeflag != tar.TypeReg {
					return fmt.Errorf("%s/%s: APKINDEX in the index archive is not a file", r.branch, repo)
				}
				if text, err = io.ReadAll(t); err != nil {
					return fmt.Errorf("%s: %s", u, err)
				}
				found = true
			}
		}
		if !found {
			return fmt.Errorf("%s/%s: APKINDEX in the index archive is not a file", r.branch, repo)
		}
		count := 0
		for block := range strings.SplitSeq(string(text), "\n\n") {
			st := stanza{}
			for line := range strings.SplitSeq(block, "\n") {
				if len(line) > 2 && line[1] == ':' {
					st[line[:1]] = line[2:]
				}
			}
			if _, ok := r.index[st["P"]]; st["P"] == "" || st["V"] == "" || ok {
				continue
			}
			st["_repo"] = repo
			r.index[st["P"]] = st
			groups, err := apk.ParseDeps(st["p"])
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
		log(fmt.Sprintf("index %s/%s: %d packages", r.branch, repo, count))
	}
	return nil
}

// pick returns the package that meets one dependency, or nil. The package of that name wins
// when its version meets the constraint. Otherwise a provider is used: one already selected,
// else the one of highest priority, else the first by name. A versioned dependency is met only
// by a provider that provides a version.
func (r *apkRepo) pick(name, op, ver string, selected map[string]stanza) stanza {
	if st, ok := r.index[name]; ok && apk.Satisfies(st["V"], op, ver) {
		return st
	}
	var providers []provider
	for _, p := range r.provides[name] {
		if op == "" || (p.provided != "" && apk.Satisfies(p.provided, op, ver)) {
			providers = append(providers, p)
		}
	}
	for _, p := range providers {
		if _, ok := selected[p.st["P"]]; ok {
			return p.st
		}
	}
	priority := func(p provider) int64 {
		n, _ := strconv.ParseInt(p.st["k"], 10, 64)
		return n
	}
	sort.SliceStable(providers, func(i, j int) bool {
		pi, pj := priority(providers[i]), priority(providers[j])
		if pi != pj {
			return pi > pj
		}
		return providers[i].st["P"] < providers[j].st["P"]
	})
	if len(providers) == 0 {
		return nil
	}
	return providers[0].st
}

// resolve returns the closure of `D:` dependencies over wanted, by package name, with the base
// set added when base is true. A requested package or a dependency that cannot be met is an
// error.
func (r *apkRepo) resolve(wanted []string, base bool) (map[string]stanza, error) {
	selected := map[string]stanza{}
	var queue []queued
	for _, n := range wanted {
		queue = append(queue, queued{name: n, why: "requested"})
	}
	if base {
		for _, n := range apkBase {
			queue = append(queue, queued{name: n, why: "base"})
		}
	}
	for len(queue) > 0 {
		q := queue[0]
		queue = queue[1:]
		if _, ok := selected[q.name]; ok {
			continue
		}
		st := r.pick(q.name, "", "", selected)
		if st == nil {
			return nil, fmt.Errorf("no package provides %s (needed by %s)", q.name, q.why)
		}
		if _, ok := selected[st["P"]]; ok {
			continue
		}
		selected[st["P"]] = st
		groups, err := apk.ParseDeps(st["D"])
		if err != nil {
			return nil, err
		}
		for _, alts := range groups {
			d := alts[0]
			// A file dependency is left to whichever selected package ships the file.
			if _, ok := selected[d.Name]; ok || strings.HasPrefix(d.Name, "/") {
				continue
			}
			chosen := r.pick(d.Name, d.Op, d.Version, selected)
			if chosen == nil {
				want := d.Name
				if d.Op != "" {
					want = d.Name + d.Op + d.Version
				}
				have := ""
				if has, ok := r.index[d.Name]; ok {
					have = "; the index has " + has["V"]
				}
				return nil, fmt.Errorf("cannot satisfy %s of %s%s", want, st["P"], have)
			}
			if _, ok := selected[chosen["P"]]; !ok {
				queue = append(queue, queued{name: chosen["P"], why: st["P"]})
			}
		}
	}
	return selected, nil
}

var datahashRe = regexp.MustCompile(`(?m)^datahash = ([0-9a-f]{64})$`)

// download fetches one package, checks it the way apk does, and returns its file name and
// contents. The index's checksum is the SHA-1 of the control section, the gzip member that
// holds .PKGINFO. The datahash in .PKGINFO is the SHA-256 of the compressed data member, as
// abuild computes it. The sections before the control section may hold nothing but signatures,
// since unpack reads every section as one archive: a member planted there would be extracted
// with no digest over it.
func (r *apkRepo) download(st stanza) (string, []byte, error) {
	name := fmt.Sprintf("%s-%s.apk", st["P"], st["V"])
	want := st["C"]
	if !strings.HasPrefix(want, "Q1") {
		return "", nil, fmt.Errorf("%s: the index carries no checksum for it; refusing an unverifiable download", name)
	}
	u := fmt.Sprintf("%s/%s/%s/%s/%s", r.mirror, r.branch, st["_repo"], r.arch, name)
	data, err := r.cache.get(u, false)
	if err != nil {
		return "", nil, err
	}
	if size, ok := st["S"]; ok && strconv.Itoa(len(data)) != size {
		return "", nil, r.cache.reject(u, name+": size does not match the index")
	}
	members, err := gzipMembers(data)
	if err != nil {
		return "", nil, r.cache.reject(u, fmt.Sprintf("%s: not an apk: %s", name, err))
	}
	var control []int
	for i, m := range members {
		head := m.plain
		if len(head) > 4096 {
			head = head[:4096]
		}
		if bytes.Contains(head, []byte(".PKGINFO")) {
			control = append(control, i)
		}
	}
	if len(control) != 1 || control[0] != len(members)-2 || len(members) > 3 {
		return "", nil, r.cache.reject(u, name+": not an apk: no control section before the data, "+
			"or more than three sections")
	}
	for _, m := range members[:control[0]] {
		if !m.whole || !signaturesOnly(m.plain) {
			return "", nil, r.cache.reject(u, name+": not an apk: the signature section holds more than signatures")
		}
	}
	raw, plain := members[control[0]].raw, members[control[0]].plain
	if !members[control[0]].whole {
		return "", nil, r.cache.reject(u, name+": not an apk: the control section is too large")
	}
	sum := sha1.Sum(raw) // apk's index records SHA-1
	if base64.StdEncoding.EncodeToString(sum[:]) != want[2:] {
		return "", nil, r.cache.reject(u, name+": checksum does not match the index")
	}
	m := datahashRe.FindSubmatch(plain)
	if m == nil || sha256hex(members[len(members)-1].raw) != string(m[1]) {
		return "", nil, r.cache.reject(u, name+": the data section does not match the datahash of .PKGINFO")
	}
	return name, data, nil
}

func fetchApks(args []string) error {
	fs := flag.NewFlagSet("fetch-apks", flag.ContinueOnError)
	var keys multi
	out := fs.String("out", "", "directory to fill with .apk files")
	fs.Var(&keys, "key", "a PEM public key an index may be signed by, named as apk names it")
	branch := fs.String("branch", "v3.21", "the branch")
	repos := fs.String("repos", "main,community", "repositories, separated by commas")
	arch := fs.String("arch", "x86_64", "architecture")
	mirror := fs.String("mirror", apkMirror, "the mirror's URL")
	cacheDir := fs.String("cache", filepath.Join(homeDir(), ".cache", "exclave-apks"), "the cache directory")
	noBase := fs.Bool("no-base", false, "leave the base set out")
	packages, err := parseArgs(fs, args)
	if err != nil {
		return err
	}
	if len(packages) == 0 || *out == "" || len(keys) == 0 {
		return &usageError{"--out, --key and at least one PACKAGE are required"}
	}
	repo, err := newApkRepo(*mirror, *branch, strings.Split(*repos, ","), *arch, *cacheDir, keys)
	if err != nil {
		return err
	}
	if err := repo.loadIndex(); err != nil {
		return err
	}
	selected, err := repo.resolve(packages, !*noBase)
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
		filename, data, err := repo.download(selected[name])
		if err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(*out, filename), data, 0o666); err != nil {
			return err
		}
	}
	log(fmt.Sprintf("%d packages in %s", len(selected), *out))
	return nil
}
