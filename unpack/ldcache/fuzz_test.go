package ldcache

import "testing"

// FuzzSharedObject reads any bytes as a shared object: an answer or a skip, never a panic.
func FuzzSharedObject(f *testing.F) {
	f.Add([]byte{}, EMX8664)
	f.Add(append([]byte("\x7fELF\x02\x01\x01"), make([]byte, 60)...), EMX8664)
	f.Add(append([]byte("\x7fELF\x01\x01\x01"), make([]byte, 60)...), EMAarch64)
	f.Fuzz(func(t *testing.T, data []byte, family int) {
		SharedObject(data, family)
		TrustedDirs(data)
		Generator(data)
	})
}

// FuzzVersionCmp holds ldconfig's order to its laws, and Fnmatch to answering every pattern.
func FuzzVersionCmp(f *testing.F) {
	f.Add("libc.so.6", "libc.so.10", "lib*.so.[0-9]")
	f.Fuzz(func(t *testing.T, a, b, pattern string) {
		if VersionCmp(a, a) != 0 {
			t.Errorf("%q differs from itself", a)
		}
		if x, y := VersionCmp(a, b), VersionCmp(b, a); x != -y {
			t.Errorf("%q against %q: %d and %d", a, b, x, y)
		}
		Fnmatch(pattern, a)
		IsDSO(a)
	})
}
