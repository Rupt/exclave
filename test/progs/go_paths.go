// go_paths.go — the Go regression of DESIGN.md 17.4: a static Go program doing path syscalls from goroutines while
// another collects garbage.
// Go issues its syscalls raw, creates threads with clone, installs its own handler for every signal, SIGSYS
// included (7.5.2), and runs goroutines on small stacks with a signal stack per thread. Built by the host's
// go with cgo off, run inside an exclave as a host program.
package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
)

// big reaches past 0x3f0000 when the test links the program from 0x10000, as Go's aarch64 linker does (13 item 24)
var big [8 << 20]byte

func env(name, dflt string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return dflt
}

func main() {
	fails := 0
	fail := func(f string, a ...interface{}) { fails++; fmt.Printf("FAIL "+f+"\n", a...) }
	big[len(big)-1] = 1
	marker := "/usr/share/exclave-test-marker"
	sh, shExe, truep := env("EXCLAVE_TEST_SH", "/usr/bin/sh"), env("EXCLAVE_TEST_SH_EXE", "/usr/bin/dash"), env("EXCLAVE_TEST_TRUE", "/usr/bin/true")

	// path syscalls from goroutines, concurrently with a blocked read
	pr, pw, err := os.Pipe()
	if err != nil {
		fail("pipe: %v", err)
	}
	// a collector beside them, so that Go's preemption signal lands in the launcher's handler mid-trap (7.5.3)
	var collecting atomic.Bool
	collecting.Store(true)
	collected := make(chan struct{})
	go func() {
		for collecting.Load() {
			runtime.GC()
		}
		close(collected)
	}()
	var wg sync.WaitGroup
	errs := make(chan string, 64)
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for k := 0; k < 200; k++ {
				if st, err := os.Stat(marker); err != nil || st.Size() != 7 {
					errs <- fmt.Sprintf("stat marker in goroutine %d: %v", i, err)
					return
				}
				if _, err := os.Lstat(sh); err != nil {
					errs <- fmt.Sprintf("lstat %s: %v", sh, err)
					return
				}
				if k%50 == 0 {
					if ents, err := os.ReadDir("/usr/share"); err != nil || len(ents) == 0 {
						errs <- fmt.Sprintf("readdir /usr/share: %v", err)
						return
					}
				}
			}
		}(i)
	}
	go func() { buf := make([]byte, 4); pr.Read(buf); pr.Close() }()
	wg.Wait()
	collecting.Store(false)
	<-collected
	pw.Write([]byte("done"))
	pw.Close()
	close(errs)
	for e := range errs {
		fail("%s", e)
	}

	// exec: the exclave's true and its shell, by path and by PATH
	if err := exec.Command(truep).Run(); err != nil {
		fail("exec %s: %v", truep, err)
	}
	if err := exec.Command("true").Run(); err != nil {
		fail("exec true by PATH: %v", err)
	}
	if out, err := exec.Command(sh, "-c", "echo spawned $0").Output(); err != nil || strings.TrimSpace(string(out)) != "spawned "+sh {
		fail("exec %s -c: %q %v", sh, out, err)
	}

	// the exclave is read-only, the host is not
	if err := os.WriteFile("/usr/share/exclave-new", []byte("y"), 0644); err == nil || !strings.Contains(err.Error(), syscall.EROFS.Error()) {
		fail("write to the exclave: %v", err)
	}
	if _, err := os.Open("/usr/share/nonexistent"); !os.IsNotExist(err) {
		fail("open of a missing exclave file: %v", err)
	}
	cwd, err := os.Getwd()
	if err != nil {
		fail("getwd: %v", err)
	}
	host := filepath.Join(cwd, "go-host-file")
	if err := os.WriteFile(host, []byte("host"), 0644); err != nil {
		fail("write to the host: %v", err)
	} else if b, err := os.ReadFile(host); err != nil || string(b) != "host" {
		fail("host read back: %q %v", b, err)
	}
	os.Remove(host)

	// identity: the program's own path, links, the working directory inside the exclave
	if exe, err := os.Executable(); err != nil || filepath.Base(exe) != filepath.Base(os.Args[0]) {
		fail("os.Executable: %q %v", exe, err)
	}
	if real, err := filepath.EvalSymlinks(sh); err != nil || real != shExe {
		fail("EvalSymlinks %s: %q %v", sh, real, err)
	}
	if err := os.Chdir("/usr/share"); err != nil {
		fail("chdir /usr/share: %v", err)
	} else {
		if wd, err := os.Getwd(); err != nil || wd != "/usr/share" {
			fail("getwd in the exclave: %q %v", wd, err)
		}
		if _, err := os.Stat("exclave-test-marker"); err != nil {
			fail("relative stat in the exclave: %v", err)
		}
		if _, err := os.Stat("../share/exclave-test-marker"); err != nil {
			fail("relative stat with ..: %v", err)
		}
	}
	os.Chdir(cwd)

	// a signal handler of Go's own, with every path syscall still translated afterwards
	if _, err := os.Stat("/etc/passwd"); err != nil {
		fail("stat an identity file: %v", err)
	}
	fmt.Printf("go: %d failures\n", fails)
	if fails > 0 {
		os.Exit(1)
	}
}
