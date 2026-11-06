// Package root is the tree being made, with every path in it resolved as if the tree were /
// (DESIGN.md 10.1).
//
// A package installs into a root, and its symlinks mean what they mean there: an absolute target
// starts at the root, and `..` stops at it. dpkg resolves them in the system it installs into;
// unpack resolves them in the tree, so no member, link or synthesised file reaches past it,
// whatever the packages ship. A virtual path is walked one component at a time from a descriptor
// of the tree: each directory opened with O_PATH and O_NOFOLLOW relative to the one before, each
// symlink read and its target walked in turn, at most 40 of them as the kernel allows. Every read
// and write then happens relative to a directory descriptor, on a name that is no longer a path.
package root

import (
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"unicode/utf8"

	"golang.org/x/sys/unix"
)

// maxLinks is the kernel's limit on symlinks followed in one resolution (ELOOP).
const maxLinks = 40

// Margin is what a write leaves free on the tree's filesystem, at the least: a payload that
// decompresses without end is refused rather than filling the disk.
const Margin = 256 << 20

// Error is a path in the tree that cannot be resolved or written as asked.
type Error struct {
	Msg string
}

func (e *Error) Error() string { return e.Msg }

func errorf(format string, a ...any) error {
	return &Error{Msg: fmt.Sprintf(format, a...)}
}

// ErrMissing is a path, or a directory on the way to one, that does not exist; an error that
// carries it names the path.
var ErrMissing = errors.New("no such path in the tree")

func missing(vpath string) error {
	return &os.PathError{Op: "resolve", Path: vpath, Err: ErrMissing}
}

const dirFlags = unix.O_PATH | unix.O_DIRECTORY | unix.O_NOFOLLOW | unix.O_CLOEXEC

// the descriptors of directories walked recently that a Root keeps open
const kept = 64

func parts(path string) []string {
	var out []string
	for p := range strings.SplitSeq(path, "/") {
		if p != "" && p != "." {
			out = append(out, p)
		}
	}
	return out
}

// Root is the tree at Path, open from Open until Close.
type Root struct {
	Path string
	fd   int
	// descriptors of directories walked recently, by their components from the root, oldest
	// first; any removal or replacement forgets them all
	dirs  map[string]int
	order []string
}

// Open opens the tree at path.
func Open(path string) (*Root, error) {
	fd, err := unix.Open(path, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}
	return &Root{Path: path, fd: fd, dirs: map[string]int{}}, nil
}

// Close closes the tree and every descriptor kept.
func (r *Root) Close() error {
	r.forget()
	return unix.Close(r.fd)
}

func (r *Root) forget() {
	for _, fd := range r.dirs {
		unix.Close(fd)
	}
	r.dirs = map[string]int{}
	r.order = nil
}

// openDir returns a descriptor of the directory at comps, every component a directory, none
// followed.
func (r *Root) openDir(comps []string) (int, error) {
	if len(comps) == 0 {
		return r.fd, nil
	}
	key := strings.Join(comps, "/")
	if fd, ok := r.dirs[key]; ok {
		for i, k := range r.order {
			if k == key {
				r.order = append(append(r.order[:i:i], r.order[i+1:]...), key)
				break
			}
		}
		return fd, nil
	}
	parent, err := r.openDir(comps[:len(comps)-1])
	if err != nil {
		return 0, err
	}
	fd, err := unix.Openat(parent, comps[len(comps)-1], dirFlags, 0)
	if err != nil {
		// ENOTDIR also when the component became a symlink since it was walked, which O_NOFOLLOW
		// with O_DIRECTORY refuses as not a directory
		if err == unix.ENOENT || err == unix.ENOTDIR {
			return 0, missing("/" + key)
		}
		return 0, errorf("/%s: %s", key, errno(err))
	}
	r.dirs[key] = fd
	r.order = append(r.order, key)
	if len(r.order) > kept {
		oldest := r.order[0]
		r.order = r.order[1:]
		unix.Close(r.dirs[oldest])
		delete(r.dirs, oldest)
	}
	return fd, nil
}

// errno spells an errno as strerror does, with its first letter capitalised as Python prints it.
func errno(err error) string {
	s := err.Error()
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

// walk returns the directory holding vpath's last component, from the root, and its name.
//
// Every directory on the way is resolved in the tree; with follow, the last component is too,
// when it is a symlink. With create, a directory missing on the way is made. ErrMissing is a
// directory on the way that does not exist when create is false; an Error one that is not a
// directory, or links that go round more than MaxLinks times.
func (r *Root) walk(vpath string, follow, create bool) ([]string, string, error) {
	todo := parts(vpath)
	var comps []string
	links := 0
	for len(todo) > 0 {
		name := todo[0]
		todo = todo[1:]
		if name == ".." {
			if len(comps) > 0 {
				comps = comps[:len(comps)-1]
			}
			continue
		}
		last := len(todo) == 0
		dfd, err := r.openDir(comps)
		if err != nil {
			return nil, "", err
		}
		if last && !follow {
			return comps, name, nil
		}
		var st unix.Stat_t
		if err := unix.Fstatat(dfd, name, &st, unix.AT_SYMLINK_NOFOLLOW); err != nil {
			if err != unix.ENOENT && err != unix.ENOTDIR {
				return nil, "", errorf("%s: %s", vpath, errno(err))
			}
			if last {
				return comps, name, nil
			}
			if !create {
				return nil, "", missing(vpath)
			}
			if err := unix.Mkdirat(dfd, name, 0o777); err != nil {
				made := strings.Join(append(comps, name), "/")
				return nil, "", errorf("%s: cannot make /%s: %s", vpath, made, errno(err))
			}
			comps = append(comps, name)
			continue
		}
		if st.Mode&unix.S_IFMT == unix.S_IFLNK {
			links++
			if links > maxLinks {
				return nil, "", errorf("%s: more than %d symlinks on the way (ELOOP)", vpath, maxLinks)
			}
			target, err := readlinkat(dfd, name)
			if err != nil {
				return nil, "", errorf("%s: %s", vpath, errno(err))
			}
			if strings.HasPrefix(target, "/") {
				comps = nil
			}
			todo = append(parts(target), todo...)
			continue
		}
		if last {
			return comps, name, nil
		}
		if st.Mode&unix.S_IFMT != unix.S_IFDIR {
			return nil, "", errorf("%s: /%s is not a directory", vpath, strings.Join(append(comps, name), "/"))
		}
		comps = append(comps, name)
	}
	// the path, or a link at its end, names a directory already walked: the tree's root, or one of
	// its directories, which is then the last component
	if len(comps) == 0 {
		return nil, "", errorf("%s resolves to the tree's root", vpath)
	}
	return comps[:len(comps)-1], comps[len(comps)-1], nil
}

func readlinkat(dfd int, name string) (string, error) {
	for size := 256; ; size *= 2 {
		buf := make([]byte, size)
		n, err := unix.Readlinkat(dfd, name, buf)
		if err != nil {
			return "", err
		}
		if n < size {
			return string(buf[:n]), nil
		}
	}
}

// at returns a descriptor of the directory holding vpath's last component, and its name.
func (r *Root) at(vpath string, follow, create bool) (int, string, error) {
	comps, name, err := r.walk(vpath, follow, create)
	if err != nil {
		return 0, "", err
	}
	dfd, err := r.openDir(comps)
	return dfd, name, err
}

func (r *Root) lstat(vpath string, follow bool) (*unix.Stat_t, bool) {
	dfd, name, err := r.at(vpath, follow, false)
	if err != nil {
		return nil, false
	}
	var st unix.Stat_t
	if err := unix.Fstatat(dfd, name, &st, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return nil, false
	}
	return &st, true
}

// ------------------------------------------------------------ questions, as os.path asks them

// Lexists says whether vpath names something, a symlink at its end not followed.
func (r *Root) Lexists(vpath string) bool {
	_, ok := r.lstat(vpath, false)
	return ok
}

// Exists says whether vpath names something, a symlink at its end followed.
func (r *Root) Exists(vpath string) bool {
	_, ok := r.lstat(vpath, true)
	return ok
}

// IsLink says whether vpath names a symlink.
func (r *Root) IsLink(vpath string) bool {
	st, ok := r.lstat(vpath, false)
	return ok && st.Mode&unix.S_IFMT == unix.S_IFLNK
}

// IsDir says whether vpath names a directory, a symlink at its end followed.
func (r *Root) IsDir(vpath string) bool {
	st, ok := r.lstat(vpath, true)
	return ok && st.Mode&unix.S_IFMT == unix.S_IFDIR
}

// IsFile says whether vpath names a regular file, a symlink at its end followed.
func (r *Root) IsFile(vpath string) bool {
	st, ok := r.lstat(vpath, true)
	return ok && st.Mode&unix.S_IFMT == unix.S_IFREG
}

// Readlink returns the target of the symlink at vpath.
func (r *Root) Readlink(vpath string) (string, error) {
	dfd, name, err := r.at(vpath, false, false)
	if err != nil {
		return "", err
	}
	return readlinkat(dfd, name)
}

// Stat returns what vpath names, resolved in the tree, or false when nothing does.
func (r *Root) Stat(vpath string, follow bool) (*unix.Stat_t, bool) {
	return r.lstat(vpath, follow)
}

// ------------------------------------------------------------ reading

// open opens what vpath names with flags, a symlink at its end followed in the tree.
func (r *Root) open(vpath string, flags int) (int, error) {
	dfd, name, err := r.at(vpath, true, false)
	if err != nil {
		return 0, err
	}
	fd, err := unix.Openat(dfd, name, flags|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		if err == unix.ENOENT || err == unix.ENOTDIR {
			return 0, missing(vpath)
		}
		return 0, &os.PathError{Op: "open", Path: vpath, Err: err}
	}
	return fd, nil
}

// ReadBytes returns the file at vpath, whole.
func (r *Root) ReadBytes(vpath string) ([]byte, error) {
	return r.ReadBytesN(vpath, -1)
}

// ReadBytesN returns the first limit bytes of the file at vpath, or all of it when limit is
// negative.
func (r *Root) ReadBytesN(vpath string, limit int64) ([]byte, error) {
	fd, err := r.open(vpath, unix.O_RDONLY)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), vpath)
	defer f.Close()
	if limit < 0 {
		return io.ReadAll(f)
	}
	return io.ReadAll(io.LimitReader(f, limit))
}

// ReadText returns the file's text as a decode with "replace" reads it, every line end a newline.
func (r *Root) ReadText(vpath string) (string, error) {
	data, err := r.ReadBytes(vpath)
	if err != nil {
		return "", err
	}
	text := decode(data)
	return strings.ReplaceAll(strings.ReplaceAll(text, "\r\n", "\n"), "\r", "\n"), nil
}

// decode decodes UTF-8 as Python's "replace" does: each maximal subpart of an ill-formed
// sequence, a lead byte with the continuation bytes that could have followed it, becomes one
// U+FFFD.
func decode(data []byte) string {
	if utf8.Valid(data) {
		return string(data)
	}
	var b strings.Builder
	for len(data) > 0 {
		c, size := utf8.DecodeRune(data)
		if c == utf8.RuneError && size == 1 {
			size = subpart(data)
			b.WriteRune(utf8.RuneError)
		} else {
			b.Write(data[:size])
		}
		data = data[size:]
	}
	return b.String()
}

// subpart returns the length of the maximal subpart of the ill-formed sequence at the start of
// data: its lead byte, and each continuation byte in the range the lead and the bytes before it
// allow (Unicode 3.9, table 3-7).
func subpart(data []byte) int {
	lead := data[0]
	var need int
	lo, hi := byte(0x80), byte(0xBF)
	switch {
	case lead >= 0xC2 && lead <= 0xDF:
		need = 1
	case lead == 0xE0:
		need, lo = 2, 0xA0
	case lead == 0xED:
		need, hi = 2, 0x9F
	case lead >= 0xE1 && lead <= 0xEF:
		need = 2
	case lead == 0xF0:
		need, lo = 3, 0x90
	case lead == 0xF4:
		need, hi = 3, 0x8F
	case lead >= 0xF1 && lead <= 0xF3:
		need = 3
	default:
		return 1
	}
	n := 1
	for ; n <= need && n < len(data); n++ {
		if data[n] < lo || data[n] > hi {
			break
		}
		lo, hi = 0x80, 0xBF
	}
	return n
}

// Listdir returns the names in the directory at vpath, sorted; none when it is no directory.
// The empty path, which no virtual path names, is the tree's root.
func (r *Root) Listdir(vpath string) []string {
	var fd int
	var err error
	if len(parts(vpath)) == 0 {
		fd, err = unix.Openat(r.fd, ".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	} else {
		fd, err = r.open(vpath, unix.O_RDONLY|unix.O_DIRECTORY)
	}
	if err != nil {
		return nil
	}
	f := os.NewFile(uintptr(fd), vpath)
	defer f.Close()
	names, err := f.Readdirnames(-1)
	if err != nil {
		return nil
	}
	sort.Strings(names)
	return names
}

// ------------------------------------------------------------ writing

// Makedirs makes the directory at vpath and those on the way, as os.makedirs with exist_ok.
func (r *Root) Makedirs(vpath string) error {
	dfd, name, err := r.at(vpath, true, true)
	if err != nil {
		return err
	}
	if err := unix.Mkdirat(dfd, name, 0o777); err != nil {
		if err == unix.EEXIST {
			if !r.IsDir(vpath) {
				return errorf("%s: something other than a directory stands there", vpath)
			}
			return nil
		}
		return &os.PathError{Op: "mkdir", Path: vpath, Err: err}
	}
	return nil
}

// parent returns the directory holding vpath's last component, made where missing, and its name.
func (r *Root) parent(vpath string) (int, string, error) {
	return r.at(vpath, false, true)
}

// Symlink makes a symlink at vpath to target, as a package's would be made there.
func (r *Root) Symlink(target, vpath string) error {
	dfd, name, err := r.parent(vpath)
	if err != nil {
		return err
	}
	if err := unix.Symlinkat(target, dfd, name); err != nil {
		return &os.PathError{Op: "symlink", Path: vpath, Err: err}
	}
	return nil
}

// Link makes a hard link at dst to the entry src names, which is not followed.
func (r *Root) Link(src, dst string) error {
	notHeld := errorf("the hard link /%s names %s, which the tree does not hold", strings.TrimLeft(dst, "/"), src)
	cached, sname, err := r.at(src, false, false)
	if err != nil {
		if errors.Is(err, ErrMissing) {
			return notHeld
		}
		return err
	}
	sfd, err := unix.Dup(cached) // the walk to dst may evict the cached descriptor and close it
	if err != nil {
		return err
	}
	defer unix.Close(sfd)
	dfd, dname, err := r.parent(dst)
	if err != nil {
		return err
	}
	if err := unix.Linkat(sfd, sname, dfd, dname, 0); err != nil {
		if err == unix.ENOENT {
			return notHeld
		}
		return &os.PathError{Op: "link", Path: dst, Err: err}
	}
	return nil
}

// Remove unlinks what vpath names, a symlink at its end not followed.
func (r *Root) Remove(vpath string) error {
	r.forget() // before the walk, whose descriptor the call uses
	dfd, name, err := r.at(vpath, false, false)
	if err != nil {
		return err
	}
	if err := unix.Unlinkat(dfd, name, 0); err != nil {
		return &os.PathError{Op: "unlink", Path: vpath, Err: err}
	}
	return nil
}

// Rmdir removes the empty directory at vpath.
func (r *Root) Rmdir(vpath string) error {
	r.forget() // before the walk, whose descriptor the call uses
	dfd, name, err := r.at(vpath, false, false)
	if err != nil {
		return err
	}
	if err := unix.Unlinkat(dfd, name, unix.AT_REMOVEDIR); err != nil {
		return &os.PathError{Op: "rmdir", Path: vpath, Err: err}
	}
	return nil
}

// Rmtree removes the directory at vpath and everything in it, following no symlink.
func (r *Root) Rmtree(vpath string) error {
	r.forget() // before the walk, whose descriptor the call uses
	dfd, name, err := r.at(vpath, false, false)
	if err != nil {
		return err
	}
	var st unix.Stat_t
	if err := unix.Fstatat(dfd, name, &st, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return &os.PathError{Op: "lstat", Path: vpath, Err: err}
	}
	if st.Mode&unix.S_IFMT == unix.S_IFLNK {
		return errorf("%s is a symlink, not a directory to remove", vpath)
	}
	return rmtreeAt(dfd, name, vpath)
}

// rmtreeAt removes the directory name in dfd and everything in it, every step relative to a
// descriptor, as shutil.rmtree with dir_fd does.
func rmtreeAt(dfd int, name, vpath string) error {
	fd, err := unix.Openat(dfd, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return &os.PathError{Op: "open", Path: vpath, Err: err}
	}
	f := os.NewFile(uintptr(fd), vpath)
	names, err := f.Readdirnames(-1)
	if err != nil {
		f.Close()
		return &os.PathError{Op: "readdir", Path: vpath, Err: err}
	}
	for _, n := range names {
		var st unix.Stat_t
		if err := unix.Fstatat(fd, n, &st, unix.AT_SYMLINK_NOFOLLOW); err != nil {
			f.Close()
			return &os.PathError{Op: "lstat", Path: vpath + "/" + n, Err: err}
		}
		if st.Mode&unix.S_IFMT == unix.S_IFDIR {
			if err := rmtreeAt(fd, n, vpath+"/"+n); err != nil {
				f.Close()
				return err
			}
		} else if err := unix.Unlinkat(fd, n, 0); err != nil {
			f.Close()
			return &os.PathError{Op: "unlink", Path: vpath + "/" + n, Err: err}
		}
	}
	f.Close()
	if err := unix.Unlinkat(dfd, name, unix.AT_REMOVEDIR); err != nil {
		return &os.PathError{Op: "rmdir", Path: vpath, Err: err}
	}
	return nil
}

// ChmodDir sets the mode of the directory at vpath.
func (r *Root) ChmodDir(vpath string, mode uint32) error {
	fd, err := r.open(vpath, unix.O_RDONLY|unix.O_DIRECTORY)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	return unix.Fchmod(fd, mode)
}

// Chmod sets the mode of the file at vpath, exactly, whatever the umask.
func (r *Root) Chmod(vpath string, mode uint32) error {
	fd, err := r.open(vpath, unix.O_RDONLY)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	return unix.Fchmod(fd, mode)
}

// Room refuses size bytes more in the tree that would leave less than Margin free beside it.
func (r *Root) Room(size int64, what string) error {
	var st unix.Statfs_t
	if err := unix.Fstatfs(r.fd, &st); err != nil {
		return &os.PathError{Op: "statfs", Path: r.Path, Err: err}
	}
	free := int64(st.Bavail) * int64(st.Frsize)
	if size > free-Margin {
		return errorf("%s %d bytes, which would leave less than %d MiB free on the output's filesystem (%d MiB free)",
			what, size, Margin>>20, free>>20)
	}
	return nil
}

// Create makes a new file at vpath for size bytes, open for writing, mode 0600 until set.
func (r *Root) Create(vpath string, size int64) (*os.File, error) {
	if err := r.Room(size, fmt.Sprintf("/%s declares", strings.TrimLeft(vpath, "/"))); err != nil {
		return nil, err
	}
	dfd, name, err := r.parent(vpath)
	if err != nil {
		return nil, err
	}
	fd, err := unix.Openat(dfd, name, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
	if err != nil {
		return nil, &os.PathError{Op: "create", Path: vpath, Err: err}
	}
	return os.NewFile(uintptr(fd), vpath), nil
}

// WriteBytes writes data as the whole file at vpath, following a link there as open(path, "w")
// does, with mode under the umask.
func (r *Root) WriteBytes(vpath string, data []byte, mode uint32) error {
	if err := r.Room(int64(len(data)), fmt.Sprintf("/%s would hold", strings.TrimLeft(vpath, "/"))); err != nil {
		return err
	}
	dfd, name, err := r.at(vpath, true, true)
	if err != nil {
		return err
	}
	fd, err := unix.Openat(dfd, name, unix.O_WRONLY|unix.O_CREAT|unix.O_TRUNC|unix.O_NOFOLLOW|unix.O_CLOEXEC, mode)
	if err != nil {
		return &os.PathError{Op: "open", Path: vpath, Err: err}
	}
	f := os.NewFile(uintptr(fd), vpath)
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

// Realpath is vpath with every link on the way resolved in the tree, as dpkg-realpath --root
// gives it, for a path that does not resolve to the tree's root itself; "/" is "/". A directory
// missing on the way is ErrMissing, and the last component need not exist.
func (r *Root) Realpath(vpath string) (string, error) {
	if len(parts(vpath)) == 0 {
		return "/", nil
	}
	comps, name, err := r.walk(vpath, true, false)
	if err != nil {
		return "", err
	}
	return "/" + strings.Join(append(comps, name), "/"), nil
}
