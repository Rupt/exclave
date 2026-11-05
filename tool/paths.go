// Virtual paths in an exclave's tree, resolved as a chroot would, and the prefixes the visibility
// rule compares them with (DESIGN.md 6.1, 8.1); path spelling as Python's posixpath.

package main

import (
	"os"
	"slices"
	"strings"
)

// The host's volatile directories (8.1): always the host's at run time.
var volatileDirs = []string{"/proc", "/dev", "/sys", "/tmp", "/var/tmp", "/run"}

// under reports whether v is prefix or lies below it.
func under(v, prefix string) bool {
	p := strings.TrimRight(prefix, "/")
	return v == prefix || strings.HasPrefix(v, p+"/")
}

func underAny(v string, prefixes []string) bool {
	for _, p := range prefixes {
		if under(v, p) {
			return true
		}
	}
	return false
}

func volatilePath(v string) bool { return underAny(v, volatileDirs) }

func longest(v string, prefixes []string) int {
	best := -1
	for _, p := range prefixes {
		if under(v, p) && len(p) > best {
			best = len(p)
		}
	}
	return best
}

// The own prefixes, the manifest's own records and rule 1's top-level names; and its hosts.
type ownership struct {
	own, host []string
}

// hostOwned reports whether the launcher resolves v on the host (8.1): under a volatile prefix, or
// when the longest host record covering it is at least as long as the longest own prefix covering
// it. A path covered by neither is the host's.
func hostOwned(v string, o *ownership) bool {
	return volatilePath(v) || longest(v, o.host) >= longest(v, o.own)
}

// treeReal is the file in the tree at root that the virtual path names.
func treeReal(root, vpath string) string { return pathJoin(root, strings.TrimLeft(vpath, "/")) }

// payloadPath is the file a path in the tree stands for: a wrapper's original in .real/ beside it
// when there is one.
func payloadPath(real string) string {
	slash := strings.LastIndexByte(real, '/')
	p := real[:slash+1] + ".real/" + real[slash+1:]
	if _, err := os.Stat(p); err == nil {
		return p
	}
	return real
}

func treePayload(root, vpath string) string { return payloadPath(treeReal(root, vpath)) }

// treeResolve resolves every component of vpath inside the tree, its symlinks too; with
// followLast, the last one's. Returns the canonical virtual path, or "" when a component is
// missing or the links loop (the kernel's 40). links, when given, gains every link met on the way.
func treeResolve(root, vpath string, followLast bool, links *[]string) string {
	cur, rest, pos, hops := "", vpath, 0, 0
	for {
		for pos < len(rest) && rest[pos] == '/' {
			pos++
		}
		if pos == len(rest) {
			if cur == "" {
				return "/"
			}
			return cur
		}
		comp := rest[pos:]
		k := strings.IndexByte(comp, '/')
		if k < 0 {
			k = len(comp)
		}
		comp = comp[:k]
		keep := len(cur)
		pos += k
		if comp == "." {
			continue
		}
		if comp == ".." {
			cur = cur[:max(strings.LastIndexByte(cur, '/'), 0)]
			continue
		}
		cur += "/" + comp
		st, err := lstat(treeReal(root, cur))
		there := err == nil
		for pos < len(rest) && rest[pos] == '/' {
			pos++
		}
		if !there {
			return ""
		}
		if isLnk(&st) && (pos < len(rest) || followLast) {
			target, err := os.Readlink(treeReal(root, cur))
			hops++
			if err != nil || hops > 40 { // the kernel's limit, ELOOP
				return ""
			}
			if links != nil {
				*links = append(*links, cur)
			}
			rest = target + "/" + rest[pos:]
			pos = 0
			if strings.HasPrefix(target, "/") {
				cur = ""
			} else {
				cur = cur[:keep]
			}
		}
	}
}

// ---------------------------------------------------------------- the manifest and ownership (6.2, 8.1)

// manifestOf is the exclave's manifest's records, none when it has no manifest.
func manifestOf(ex string) []record {
	p := pathJoin(ex, ".exclave/manifest")
	if _, err := os.Stat(p); err != nil {
		return nil
	}
	rs, err := grammarParse(readFile(p), kindManifest)
	if err != nil {
		failGrammar(err)
	}
	return rs
}

func valuesOf(rs []record, key string) []string {
	var out []string
	for _, r := range rs {
		if r.key == key {
			out = append(out, r.f[0].v)
		}
	}
	return out
}

func dataPrefixes(ex string) []string { return valuesOf(manifestOf(ex), "data") }

// ownedTop lists the tree's top-level entries the exclave owns by 8.1 rule 1: all but the empty
// directories.
func ownedTop(ex string) []string {
	root := pathJoin(ex, "tree")
	e, err := listDir(root)
	if err != nil {
		failErrno(root, err)
	}
	var out []string
	for i := range e {
		empty := false
		if !isLnk(&e[i].st) && e[i].isDir {
			sub, err := listDir(pathJoin(root, e[i].name))
			empty = err == nil && len(sub) == 0 // one that cannot be listed is not empty
		}
		if !empty {
			out = append(out, "/"+e[i].name)
		}
	}
	return out
}

// The host's directories by default (8.1.5), as the identity files are: SSSD's state, where its
// lookup module finds the daemon (13 item 17). An own record naming one exactly removes it.
var hostDirs = []string{"/var/lib/sss"}

func ownershipOf(ex string) *ownership {
	m := manifestOf(ex)
	o := &ownership{own: valuesOf(m, "own"), host: valuesOf(m, "host")}
	for _, d := range hostDirs {
		if !slices.Contains(o.own, d) {
			o.host = append(o.host, d)
		}
	}
	o.own = append(o.own, ownedTop(ex)...)
	return o
}

// ---------------------------------------------------------------- path spelling, as Python's posixpath

func normpath(p string) string {
	if p == "" {
		return "."
	}
	slashes := 0
	if strings.HasPrefix(p, "/") {
		slashes = 1
		if strings.HasPrefix(p, "//") && !strings.HasPrefix(p, "///") {
			slashes = 2
		}
	}
	var comps []string
	for part := range strings.SplitSeq(p, "/") {
		if part == "" || part == "." {
			continue
		}
		if part != ".." || (slashes == 0 && len(comps) == 0) || (len(comps) > 0 && comps[len(comps)-1] == "..") {
			comps = append(comps, part)
		} else if len(comps) > 0 {
			comps = comps[:len(comps)-1]
		}
	}
	out := "//"[:slashes] + strings.Join(comps, "/")
	if out == "" {
		return "."
	}
	return out
}

func dirnameOf(p string) string {
	n := strings.LastIndexByte(p, '/') + 1
	k := n
	for k > 0 && p[k-1] == '/' {
		k--
	}
	if k > 0 { // trailing slashes go, unless the head is all slashes
		n = k
	}
	return p[:n]
}

func basenameOf(p string) string { return p[strings.LastIndexByte(p, '/')+1:] }

// relpath is path relative to base, both made normal as Python's relpath does.
func relpath(p, base string) string {
	split := func(s string) []string {
		return slices.DeleteFunc(strings.Split(normpath(s), "/"), func(c string) bool { return c == "" })
	}
	pa, pb := split(p), split(base)
	i := 0
	for i < len(pa) && i < len(pb) && pa[i] == pb[i] {
		i++
	}
	var parts []string
	for range pb[i:] {
		parts = append(parts, "..")
	}
	parts = append(parts, pa[i:]...)
	if len(parts) == 0 {
		return "."
	}
	return strings.Join(parts, "/")
}
