package fetch

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"io/fs"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

// One fetch of a URL, retried where the failure is the network's rather than the server's
// answer: a connection refused or reset, a timeout, or a 5xx or 429 reply is tried again after a
// wait that doubles, four tries in all, since a mirror answers the same request a moment later;
// a 4xx reply is the answer and returned at once. Each retry is logged.
const (
	tries     = 4
	firstWait = 2 * time.Second
)

// httpError is a server's answer other than the file: its status.
type httpError struct {
	code   int
	reason string
	url    string
}

func (e *httpError) Error() string {
	return fmt.Sprintf("%s: HTTP Error %d: %s", e.url, e.code, e.reason)
}

var unsafeRe = regexp.MustCompile(`[^A-Za-z0-9._-]`)

// cache is the directory a fetcher keeps files in, and how it fetches.
type cache struct {
	dir      string
	timeout  time.Duration
	trim     int  // keep only the last trim characters of a cache name, or every one when 0
	snapshot bool // the mirror never changes, so even a mutable file is kept
	client   *http.Client
}

func newCache(dir string, timeout time.Duration, trim int) (*cache, error) {
	if err := os.MkdirAll(dir, 0o777); err != nil {
		return nil, err
	}
	dialer := &net.Dialer{Timeout: timeout}
	transport := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		// every read of the body has timeout to deliver a byte, as urllib's socket timeout had,
		// so a mirror that stalls is tried again rather than waited on
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			c, err := dialer.DialContext(ctx, network, addr)
			if err != nil {
				return nil, err
			}
			return &idleConn{Conn: c, idle: timeout}, nil
		},
		TLSHandshakeTimeout:   timeout,
		ResponseHeaderTimeout: timeout,
		// the bytes as the server stores them: a .gz an object store labels gzip-encoded would
		// otherwise arrive decompressed and fail its digest
		DisableCompression: true,
	}
	return &cache{dir: dir, timeout: timeout, trim: trim, client: &http.Client{Transport: transport}}, nil
}

// path returns the cache file for url.
func (c *cache) path(u string) string {
	name := unsafeRe.ReplaceAllString(u, "_")
	if c.trim > 0 && len(name) > c.trim {
		name = name[len(name)-c.trim:]
	}
	return filepath.Join(c.dir, name)
}

// fetch returns the body at u, read whole, with the retries the module describes.
func (c *cache) fetch(u string) ([]byte, error) {
	var buf bytes.Buffer
	err := c.fetchInto(u, &buf, func() error { buf.Reset(); return nil })
	return buf.Bytes(), err
}

// fetchInto writes the body at u to w as it arrives, with the retries the module describes;
// reset empties w before each try.
func (c *cache) fetchInto(u string, w io.Writer, reset func() error) error {
	parsed, err := url.Parse(u)
	if err != nil {
		return err
	}
	if parsed.Scheme == "file" {
		f, err := os.Open(parsed.Path)
		if err != nil {
			return err
		}
		defer f.Close()
		_, err = io.Copy(w, f)
		return err
	}
	wait := firstWait
	for attempt := 0; ; attempt++ {
		if err := reset(); err != nil {
			return err
		}
		err := c.once(u, w)
		if err == nil {
			return nil
		}
		if run.Err() != nil { // a signal is ending the fetch: no retry
			return run.Err()
		}
		if he, ok := errors.AsType[*httpError](err); ok {
			if attempt == tries-1 || !(he.code == 429 || he.code >= 500) {
				return err
			}
			log(fmt.Sprintf("retry after %d %s in %.0f s", he.code, he.reason, wait.Seconds()))
		} else {
			if attempt == tries-1 {
				return err
			}
			log(fmt.Sprintf("retry after %s in %.0f s", err, wait.Seconds()))
		}
		select {
		case <-time.After(wait):
		case <-run.Done():
			return run.Err()
		}
		wait *= 2
	}
}

func (c *cache) once(u string, w io.Writer) error {
	req, err := http.NewRequestWithContext(run, "GET", u, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", userAgent())
	resp, err := c.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return &httpError{resp.StatusCode, strings.TrimPrefix(resp.Status, fmt.Sprintf("%d ", resp.StatusCode)), u}
	}
	_, err = io.Copy(w, resp.Body)
	return err
}

// idleConn is a connection whose every read must deliver within idle.
type idleConn struct {
	net.Conn
	idle time.Duration
}

func (c *idleConn) Read(b []byte) (int, error) {
	if err := c.Conn.SetReadDeadline(time.Now().Add(c.idle)); err != nil {
		return 0, err
	}
	return c.Conn.Read(b)
}

func sha256hex(data []byte) string {
	s := sha256.Sum256(data)
	return hex.EncodeToString(s[:])
}

// get returns a mutable file, one whose content can change at the same URL, such as a signed
// index: fetched every time unless the mirror is a snapshot, which never changes, and then kept
// by its URL. A file a signed index names by its digest is getVerified's.
func (c *cache) get(u string) ([]byte, error) {
	path := c.path(u)
	keep := c.snapshot
	if keep {
		if data, err := os.ReadFile(path); err == nil {
			return data, nil
		}
	}
	log("fetch " + u)
	data, err := c.fetch(u)
	if err != nil {
		return nil, err
	}
	if keep {
		tmp := fmt.Sprintf("%s.tmp%d", path, os.Getpid()) // several runs may share the cache
		if err := os.WriteFile(tmp, data, 0o666); err != nil {
			return nil, err
		}
		if err := os.Rename(tmp, path); err != nil {
			return nil, err
		}
	}
	return data, nil
}

// ---------------------------------------------------------------- files kept by their digest

// A file a signed index names by its digest is kept under the cache as KIND/DIGEST, whatever
// mirror, snapshot or URL served it, so that another mirror of the same file is a hit. It is
// streamed to a file as it arrives and hashed, kept only once it is the file the index names, and
// checked again every time it is used, so a file damaged in the cache is fetched again.

var digestRe = regexp.MustCompile(`^[0-9a-f]{32,128}$`)

// keyed is the cache file for the content whose digest under kind is digest, or an error when
// the digest is not one, which a signed index would not hold.
func (c *cache) keyed(kind, digest string) (string, error) {
	if !digestRe.MatchString(digest) {
		return "", fmt.Errorf("the index names a %s digest %q, which is not lowercase hex", kind, digest)
	}
	return filepath.Join(c.dir, kind, digest), nil
}

// mismatch is a file that is not the one its index names: by its digest, or by its size.
type mismatch string

func (m mismatch) Error() string { return string(m) }

const (
	errDigest mismatch = "digest"
	errSize   mismatch = "size"
)

// checkFile reports whether the file at p has the digest want under newHash and, unless size is
// negative, that many bytes; the digest is checked first.
func checkFile(p string, newHash func() hash.Hash, want string, size int64) error {
	f, err := os.Open(p)
	if err != nil {
		return err
	}
	defer f.Close()
	h := newHash()
	n, err := io.Copy(h, f)
	if err != nil {
		return err
	}
	if hex.EncodeToString(h.Sum(nil)) != want {
		return errDigest
	}
	if size >= 0 && n != size {
		return errSize
	}
	return nil
}

// getVerified makes path the file at u, unless the file there already passes verify, and
// returns verify's refusal of what u served. The download goes to a file of its own beside path,
// renamed over it only once it passes, so that runs sharing the cache never see half a file.
func (c *cache) getVerified(u, path string, verify func(string) error) error {
	if verify(path) == nil {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o777); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".tmp*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name()) // gone once renamed
	log("fetch " + u)
	err = c.fetchInto(u, tmp, func() error {
		if err := tmp.Truncate(0); err != nil {
			return err
		}
		_, err := tmp.Seek(0, io.SeekStart)
		return err
	})
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	if err := verify(tmp.Name()); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

// downloads is how many packages a fetcher fetches, or checks in its cache, at once: enough to
// overlap a mirror's latency and the hashing, few enough to load neither a mirror nor the machine.
const downloads = 4

// eachAtOnce runs job(i) for every i below n, downloads at a time, and returns each one's error
// by its i, so that the caller reports the first failure in its own order, as one job after
// another would.
func eachAtOnce(n int, job func(int) error) []error {
	errs := make([]error, n)
	var next atomic.Int64
	var wg sync.WaitGroup
	for range min(downloads, n) {
		wg.Go(func() {
			for {
				i := int(next.Add(1) - 1)
				if i >= n {
					return
				}
				if errs[i] = run.Err(); errs[i] == nil { // a signal is ending the fetch: no job started
					errs[i] = job(i)
				}
			}
		})
	}
	wg.Wait()
	return errs
}

// place puts the cache's file src at dst, a hard link where the filesystem allows it; a copy is
// checked again by verify, since it is not the file verified.
func place(src, dst string, verify func(string) error) error {
	if err := linkOrCopy(src, dst); err != nil {
		return err
	}
	if a, err := os.Stat(src); err == nil {
		if b, err := os.Stat(dst); err == nil && os.SameFile(a, b) {
			return nil
		}
	}
	if err := verify(dst); err != nil {
		os.Remove(dst)
		return fmt.Errorf("%s: the cache's file changed while it was copied: %w", dst, err)
	}
	return nil
}

// reject removes u's file from the cache, so that the next run fetches it again, and returns
// the refusal.
func (c *cache) reject(u, msg string) error {
	path := c.path(u)
	if err := os.Remove(path); err == nil {
		msg += "; removed " + path + " from the cache"
	}
	return errors.New(msg)
}

// missing says whether err is a server's answer that the file is not there: 404, 403 as an
// object-store mirror answers for a missing file, or a file:// repository without it.
func missing(err error) bool {
	if he, ok := errors.AsType[*httpError](err); ok {
		return he.code == 403 || he.code == 404
	}
	return errors.Is(err, fs.ErrNotExist)
}

// linkOrCopy puts src at dst, as a hard link where the filesystem allows it, else a copy the
// kernel makes (copy_file_range), which a filesystem with block cloning clones.
func linkOrCopy(src, dst string) error {
	os.Remove(dst)
	if err := os.Link(src, dst); err == nil {
		return nil
	}
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o666)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}

// cacheIn is the directory a fetcher keeps files in: dir when one is given, else a directory of its
// own inside out, removed by done, so that a fetch without --cache keeps nothing outside out and its
// packages are still hard-linked into place. An out the fetch made and left empty, as a refusal
// leaves it, is removed too. A signal ends the fetch through run, so done runs then as well.
func cacheIn(dir, out string) (string, func(), error) {
	if dir != "" {
		return dir, func() {}, nil
	}
	made := !lexists(out)
	if err := os.MkdirAll(out, 0o777); err != nil {
		return "", nil, err
	}
	tmp, err := os.MkdirTemp(out, ".exclave-fetch-")
	if err != nil {
		return "", nil, err
	}
	return tmp, func() {
		os.RemoveAll(tmp)
		if made {
			os.Remove(out) // only when empty
		}
	}, nil
}

// lexists reports whether anything is at path, a dangling link included.
func lexists(path string) bool {
	_, err := os.Lstat(path)
	return err == nil
}

// ---------------------------------------------------------------- ending by a signal

// run is the fetch's context, cancelled by a signal that ends it: downloads in flight stop, no
// retry waits and no job starts, and the fetch returns through its own cleanup before the signal
// ends the process (watchSignals).
var run = context.Background()

// watchSignals cancels run on SIGINT, SIGTERM or SIGHUP, but for those the process was started
// ignoring, which stay ignored. Its result, called once the fetch has returned, ends the process by
// the signal that came, if one did, with the signal's default action, so that the exit says what
// ended it.
func watchSignals() func() {
	ctx, cancel := context.WithCancel(context.Background())
	run = ctx
	var ending []os.Signal
	for _, s := range []os.Signal{syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP} {
		if !signal.Ignored(s) {
			ending = append(ending, s)
		}
	}
	signals := make(chan os.Signal, 1)
	if len(ending) > 0 {
		signal.Notify(signals, ending...)
	}
	var came atomic.Value
	go func() {
		if s, ok := <-signals; ok {
			came.Store(s)
			cancel()
		}
	}()
	return func() {
		signal.Stop(signals)
		close(signals)
		if s, ok := came.Load().(os.Signal); ok {
			signal.Reset(s)
			syscall.Kill(os.Getpid(), s.(syscall.Signal))
			time.Sleep(time.Second) // the default action ends the process first
			os.Exit(128 + int(s.(syscall.Signal)))
		}
		cancel()
	}
}
