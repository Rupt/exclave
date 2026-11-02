package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
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
	parsed, err := url.Parse(u)
	if err != nil {
		return nil, err
	}
	if parsed.Scheme == "file" {
		data, err := os.ReadFile(parsed.Path)
		if err != nil {
			return nil, err
		}
		return data, nil
	}
	wait := firstWait
	for attempt := 0; ; attempt++ {
		data, err := c.once(u)
		if err == nil {
			return data, nil
		}
		if he, ok := errors.AsType[*httpError](err); ok {
			if attempt == tries-1 || !(he.code == 429 || he.code >= 500) {
				return nil, err
			}
			log(fmt.Sprintf("retry after %d %s in %.0f s", he.code, he.reason, wait.Seconds()))
		} else {
			if attempt == tries-1 {
				return nil, err
			}
			log(fmt.Sprintf("retry after %s in %.0f s", err, wait.Seconds()))
		}
		time.Sleep(wait)
		wait *= 2
	}
}

func (c *cache) once(u string) ([]byte, error) {
	req, err := http.NewRequest("GET", u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", userAgent())
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, &httpError{resp.StatusCode, strings.TrimPrefix(resp.Status, fmt.Sprintf("%d ", resp.StatusCode)), u}
	}
	return io.ReadAll(resp.Body)
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

// get returns the file at u, read from the cache when it can be kept there. A file whose URL
// names its content is cached. A mutable file, whose content can change at the same URL, is
// fetched every time unless the mirror is a snapshot.
func (c *cache) get(u string, mutable bool) ([]byte, error) {
	path := c.path(u)
	keep := c.snapshot || !mutable
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

// linkOrCopy puts src at dst, as a hard link where the filesystem allows it.
func linkOrCopy(src, dst string) error {
	os.Remove(dst)
	if err := os.Link(src, dst); err == nil {
		return nil
	}
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, data, 0o666)
}
