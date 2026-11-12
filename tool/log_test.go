package main

import "testing"

// TestParseLog: a log's lines as the command reads them, a NUL's rest dropped, a result past the
// range saturated, an unreadable line passed over, and each escape undone once.
func TestParseLog(t *testing.T) {
	lines := parseLog([]byte("launcher 1 cwd /\nopen 3 /srv/liba.so\x00junk\nopen 3 /srv/libb\\\\c.so\n" +
		"open 99999999999999999999 /srv/libbig.so\nopen -2 /srv/libgone.so\nbad line\nopen x /y\n" +
		"open 3 /srv/libz.so\\\nlauncher 2 cwd /a\\x1bb\nopen 3 /srv/e\\x1b[31m\\x7f.so\nopen 3 /srv/\\\\x1b\n" +
		"open 3 /srv/\\xAB\\x4"))
	want := []logLine{{"launcher", "cwd /", 1}, {"open", "/srv/liba.so", 3}, {"open", "/srv/libb\\c.so", 3},
		{"open", "/srv/libbig.so", 1<<63 - 1}, {"open", "/srv/libgone.so", -2}, {"open", "/srv/libz.so\\", 3},
		{"launcher", "cwd /a\x1bb", 2}, {"open", "/srv/e\x1b[31m\x7f.so", 3}, {"open", "/srv/\\x1b", 3},
		{"open", "/srv/\\xAB\\x4", 3}}
	if len(lines) != len(want) {
		t.Fatalf("%+v", lines)
	}
	for i := range want {
		if lines[i] != want[i] {
			t.Errorf("line %d: %+v, wanted %+v", i, lines[i], want[i])
		}
	}
}

func FuzzLog(f *testing.F) {
	f.Add([]byte("open 3 /srv/liba.so\nlauncher 1 cwd given to the host /x\n"))
	f.Fuzz(func(t *testing.T, data []byte) {
		for _, l := range parseLog(data) {
			_ = libraryName(l.path)
		}
	})
}
