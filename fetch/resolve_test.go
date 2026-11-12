package fetch

import (
	"slices"
	"strings"
	"testing"

	"exclave/unpack/reader"
)

// The resolvers' rules (DESIGN.md 10.1), each on an index filled here as loadIndex fills one: what a
// closure holds, which version, alternative or provider is taken, and what is refused and how.

// closure spells a resolver's answer: each package as name=version, in the order of the names.
func closure[P any](selected map[string]P, version func(P) string) string {
	var out []string
	for name, p := range selected {
		out = append(out, name+"="+version(p))
	}
	slices.Sort(out)
	return strings.Join(out, " ")
}

// judge compares one case's answer with what it expects: the closure, or the refusal's text.
func judge(t *testing.T, got string, err error, want, refusal string) {
	t.Helper()
	switch {
	case refusal != "" && err == nil:
		t.Errorf("resolved to %q; expected the refusal %q", got, refusal)
	case refusal != "" && err.Error() != refusal:
		t.Errorf("refused with %q; expected %q", err, refusal)
	case refusal == "" && err != nil:
		t.Errorf("refused with %q; expected %q", err, want)
	case refusal == "" && got != want:
		t.Errorf("resolved to %q; expected %q", got, want)
	}
}

// fields makes a stanza of "Field: value" items.
func fields(items ...string) stanza {
	st := stanza{}
	for _, item := range items {
		k, v, _ := strings.Cut(item, ": ")
		st[k] = v
	}
	return st
}

func TestResolveDebs(t *testing.T) {
	deb := func(name, version string, more ...string) stanza {
		return fields(append([]string{"Package: " + name, "Version: " + version}, more...)...)
	}
	r := &debRepo{index: map[string][]stanza{}, provides: map[string][]provider{}}
	for _, st := range []stanza{
		deb("app", "1.0", "Pre-Depends: base", "Depends: libfoo (>= 2), mta | mailx"),
		deb("base", "1"),
		deb("libfoo", "2.1"), deb("libfoo", "3.0"), deb("libfoo", "1.5"),
		deb("exim", "4", "Provides: mta", "Priority: important"),
		deb("postfix", "3", "Provides: mta", "Priority: optional"),
		deb("mailx", "8"),
		deb("old", "1", "Depends: libfoo (<< 2)"),
		deb("picky", "1", "Depends: libfoo (<< 2) | mailx"),
		deb("writer", "1", "Depends: editor"),
		deb("vim", "9", "Provides: editor"), deb("nano", "7", "Provides: editor"),
		deb("wants-version", "1", "Depends: virt (>= 2)"),
		deb("plain", "1", "Provides: virt"), deb("exact", "1", "Provides: virt (= 3)"),
		deb("wants-newer", "1", "Depends: unversioned (>= 2)"),
		deb("gives-none", "1", "Provides: unversioned"),
		deb("soft", "1", "Recommends: mailx", "Suggests: exim"),
		deb("broken", "1", "Depends: nowhere"),
		deb("too-new", "1", "Depends: libfoo (>= 9) | nowhere"),
		deb("init", "1"), deb("init", "2", "Essential: yes", "Depends: base"),
	} {
		if err := r.add(st); err != nil {
			t.Fatal(err)
		}
	}
	r.sortVersions()
	for _, c := range []struct {
		rule      string
		wanted    []string
		essential bool
		choose    map[string]string
		want      string
		refusal   string
	}{
		{rule: "Depends and Pre-Depends are followed; the highest version that meets a constraint; " +
			"the first alternative the index can meet; of a name's providers the one of highest Priority",
			wanted: []string{"app"}, want: "app=1.0 base=1 exim=4 libfoo=3.0"},
		{rule: "the version that meets the constraint is the one selected, not the name's highest",
			wanted: []string{"old"}, want: "libfoo=1.5 old=1"},
		{rule: "an alternative already selected wins over an earlier one",
			wanted: []string{"mailx", "app"}, want: "app=1.0 base=1 libfoo=3.0 mailx=8"},
		{rule: "a provider already selected wins over one of higher Priority",
			wanted: []string{"postfix", "app"}, want: "app=1.0 base=1 libfoo=3.0 postfix=3"},
		{rule: "the package --choose names for a virtual package is used",
			wanted: []string{"app"}, choose: map[string]string{"mta": "postfix"},
			want: "app=1.0 base=1 libfoo=3.0 postfix=3"},
		{rule: "providers of one Priority are taken by name",
			wanted: []string{"writer"}, want: "nano=7 writer=1"},
		{rule: "a versioned dependency is met only by a provider that provides a version",
			wanted: []string{"wants-version"}, want: "exact=1 wants-version=1"},
		{rule: "an alternative selected at a version that does not meet it is passed over",
			wanted: []string{"libfoo", "picky"}, want: "libfoo=3.0 mailx=8 picky=1"},
		{rule: "Recommends and Suggests are not followed",
			wanted: []string{"soft"}, want: "soft=1"},
		{rule: "the Essential set is added when asked for, by each package's highest version",
			wanted: []string{"mailx"}, essential: true, want: "base=1 init=2 mailx=8"},
		{rule: "a requested package the index lacks is refused",
			wanted: []string{"ghost"}, refusal: "no package provides ghost (needed by requested)"},
		{rule: "a dependency the index lacks is refused, by name",
			wanted: []string{"broken"}, refusal: "cannot satisfy Depends of broken: nowhere (not in the index)"},
		{rule: "a dependency no version meets is refused, with what the index has for each alternative",
			wanted: []string{"too-new"},
			refusal: "cannot satisfy Depends of too-new: libfoo >= 9 (the index has 3.0, 2.1, 1.5) | " +
				"nowhere (not in the index)"},
		{rule: "a versioned dependency on a name provided without a version is refused",
			wanted:  []string{"wants-newer"},
			refusal: "cannot satisfy Depends of wants-newer: unversioned >= 2 (no provider meets the constraint)"},
	} {
		t.Run(c.rule, func(t *testing.T) {
			selected, err := r.resolve(c.wanted, c.essential, c.choose)
			judge(t, closure(selected, func(st stanza) string { return st["Version"] }), err, c.want, c.refusal)
		})
	}
}

func TestResolveApks(t *testing.T) {
	apk := func(name, version string, more ...string) stanza {
		return fields(append([]string{"P: " + name, "V: " + version}, more...)...)
	}
	r := &apkRepo{index: map[string]stanza{}, provides: map[string][]provider{}}
	for _, c := range []struct {
		st    stanza
		added bool
	}{
		{apk("app", "1.0-r0", "D: so:libz.so.1 busybox>=1.30 /bin/sh !conflict cmd:editor"), true},
		{apk("zlib", "1.3-r0", "p: so:libz.so.1=1.3"), true},
		{apk("zlib", "9.9-r0", "p: so:libz.so.1=9.9"), false}, // a later repository's: not the one used
		{apk("busybox", "1.36-r0", "p: cmd:sh=1.36-r0"), true},
		{apk("alpine-baselayout", "3.6-r0"), true},
		{apk("nano", "7-r0", "p: cmd:editor", "k: 10"), true},
		{apk("vim", "9-r0", "p: cmd:editor", "k: 100"), true},
		{apk("lister", "1-r0", "D: cmd:ls"), true},
		{apk("coreutils", "9-r0", "p: cmd:ls"), true}, {apk("busybox-extras", "1-r0", "p: cmd:ls"), true},
		{apk("wants-version", "1-r0", "D: virt>=2"), true},
		{apk("plain", "1-r0", "p: virt"), true}, {apk("exact", "1-r0", "p: virt=3"), true},
		{apk("impostor", "1-r0", "p: zlib=5"), true},
		{apk("wants-zlib", "1-r0", "D: zlib"), true},
		{apk("old", "1-r0", "D: busybox>=2"), true},
		{apk("broken", "1-r0", "D: nowhere"), true},
		{apk("", "1-r0"), false}, {apk("no-version", ""), false},
	} {
		added, err := r.add(c.st)
		if err != nil {
			t.Fatal(err)
		}
		if added != c.added {
			t.Errorf("add(%s %s) answered %v; expected %v", c.st["P"], c.st["V"], added, c.added)
		}
	}
	for _, c := range []struct {
		rule    string
		wanted  []string
		base    bool
		want    string
		refusal string
	}{
		{rule: "D: is followed; a file dependency and a conflict are not; a shared object and a command " +
			"are met by their providers, the one of highest provider priority first; the first " +
			"repository's package is the one used",
			wanted: []string{"app"}, want: "app=1.0-r0 busybox=1.36-r0 vim=9-r0 zlib=1.3-r0"},
		{rule: "a provider already selected wins over one of higher priority",
			wanted: []string{"nano", "app"}, want: "app=1.0-r0 busybox=1.36-r0 nano=7-r0 zlib=1.3-r0"},
		{rule: "providers without a priority are taken by name",
			wanted: []string{"lister"}, want: "busybox-extras=1-r0 lister=1-r0"},
		{rule: "a versioned dependency is met only by a provider that provides a version",
			wanted: []string{"wants-version"}, want: "exact=1-r0 wants-version=1-r0"},
		{rule: "the package of the name wins over a provider of it",
			wanted: []string{"wants-zlib"}, want: "wants-zlib=1-r0 zlib=1.3-r0"},
		{rule: "the base set is added when asked for",
			wanted: []string{"zlib"}, base: true, want: "alpine-baselayout=3.6-r0 busybox=1.36-r0 zlib=1.3-r0"},
		{rule: "a requested package the index lacks is refused",
			wanted: []string{"ghost"}, refusal: "no package provides ghost (needed by requested)"},
		{rule: "a dependency the index lacks is refused, by name",
			wanted: []string{"broken"}, refusal: "cannot satisfy nowhere of broken"},
		{rule: "a dependency the indexed version does not meet is refused, with that version",
			wanted: []string{"old"}, refusal: "cannot satisfy busybox>=2 of old; the index has 1.36-r0"},
	} {
		t.Run(c.rule, func(t *testing.T) {
			selected, err := r.resolve(c.wanted, c.base)
			judge(t, closure(selected, func(st stanza) string { return st["V"] }), err, c.want, c.refusal)
		})
	}
}

func TestResolveRpms(t *testing.T) {
	needs := func(name string, constraint ...string) reader.Dep {
		d := reader.Dep{Name: name}
		if len(constraint) == 2 {
			d.Op, d.Version = constraint[0], constraint[1]
		}
		return d
	}
	r := &rpmRepo{
		index: map[string]*rpmPackage{}, provides: map[string][]rpmProvider{}, files: map[string][]*rpmPackage{},
	}
	for _, pkg := range []*rpmPackage{
		{name: "app", version: "1.0-1", requires: []reader.Dep{
			needs("glibc", ">=", "2.17"), needs("libfoo.so.1()(64bit)"), needs("/usr/bin/perl"),
			needs("rpmlib(CompressedFileNames)", "<=", "3.0.4-1"), needs("(langpacks-en if glibc)"),
			needs("/usr/libexec/unlisted"),
		}},
		{name: "glibc", version: "2.20-1"}, {name: "glibc", version: "2.28-1"}, {name: "glibc", version: "2.17-1"},
		{name: "foo-libs", version: "1-1", provides: []provided{{"libfoo.so.1()(64bit)", ""}}},
		{name: "perl-interpreter", version: "5-1", files: []string{"/usr/bin/perl"}},
		{name: "site", version: "1-1", requires: []reader.Dep{needs("webserver")}},
		{name: "nginx", version: "1-1", provides: []provided{{"webserver", ""}}},
		{name: "httpd", version: "2-1", provides: []provided{{"webserver", ""}}},
		{name: "wants-cap", version: "1-1", requires: []reader.Dep{needs("cap", ">=", "2")}},
		{name: "cap", version: "1-1", provides: []provided{{"cap", "2"}}},
		{name: "aaa", version: "1-1", provides: []provided{{"cap", "3"}}},
		{name: "wants-version", version: "1-1", requires: []reader.Dep{needs("virt", ">=", "2")}},
		{name: "plain", version: "1-1", provides: []provided{{"virt", ""}}},
		{name: "exact", version: "1-1", provides: []provided{{"virt", "3"}}},
		{name: "old", version: "1-1", requires: []reader.Dep{needs("glibc", ">=", "3")}},
		{name: "broken", version: "1-1", requires: []reader.Dep{needs("nowhere")}},
		{name: "setup", version: "1-1"}, {name: "filesystem", version: "1-1"},
		{name: "basesystem", version: "1-1"}, {name: "bash", version: "5-1"},
	} {
		if r.newer(pkg.name, pkg.version) {
			r.add(pkg)
		}
	}
	r.capabilities()
	for _, c := range []struct {
		rule    string
		wanted  []string
		base    bool
		choose  map[string]string
		want    string
		notes   string
		refusal string
	}{
		{rule: "Requires is followed, to the highest version of a name across the repositories, to the " +
			"provider of a capability and to the package that lists a file; rpmlib's own and a rich " +
			"dependency are not; a file no indexed package lists is noted, not refused",
			wanted: []string{"app"}, want: "app=1.0-1 foo-libs=1-1 glibc=2.28-1 perl-interpreter=5-1",
			notes: "app needs /usr/libexec/unlisted, which no indexed package ships"},
		{rule: "providers of a capability are taken by name",
			wanted: []string{"site"}, want: "httpd=2-1 site=1-1"},
		{rule: "a provider already selected wins",
			wanted: []string{"nginx", "site"}, want: "nginx=1-1 site=1-1"},
		{rule: "the package --choose names for a capability is used",
			wanted: []string{"site"}, choose: map[string]string{"webserver": "nginx"}, want: "nginx=1-1 site=1-1"},
		{rule: "a provider named like the dependency wins over one earlier by name",
			wanted: []string{"wants-cap"}, want: "cap=1-1 wants-cap=1-1"},
		{rule: "a versioned dependency is met only by a provider that provides a version",
			wanted: []string{"wants-version"}, want: "exact=1-1 wants-version=1-1"},
		{rule: "the base set is added when asked for",
			wanted: []string{"glibc"}, base: true,
			want: "basesystem=1-1 bash=5-1 filesystem=1-1 glibc=2.28-1 setup=1-1"},
		{rule: "a requested package the index lacks is refused",
			wanted: []string{"ghost"}, refusal: "no package provides ghost (needed by requested)"},
		{rule: "a capability the index lacks is refused, by name",
			wanted: []string{"broken"}, refusal: "cannot satisfy nowhere of broken"},
		{rule: "a dependency the indexed version does not meet is refused, with that version",
			wanted: []string{"old"}, refusal: "cannot satisfy glibc >= 3 of old; the index has 2.28-1"},
	} {
		t.Run(c.rule, func(t *testing.T) {
			selected, notes, err := r.resolve(c.wanted, c.base, c.choose)
			judge(t, closure(selected, func(p *rpmPackage) string { return p.version }), err, c.want, c.refusal)
			if got := strings.Join(notes, "; "); got != c.notes {
				t.Errorf("noted %q; expected %q", got, c.notes)
			}
		})
	}
}
