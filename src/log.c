/* log.c — EXCLAVE_LOG (6.2) and fatal messages. */
#include "common.h"

struct exclave C;

static unsigned long log_dev, log_ino;

/* Whether descriptor fd's file lies in the exclave's directory, by the real path /proc gives it. */
static int in_exclave(long fd)
{
    static char real[PATH_MAX];
    /* a pipe or a socket has no path, so is not the exclave's */
    return fd_real_path((int)fd, real) >= 0 && starts_dir(real, C.dir);
}

/* Make the log at path, an absolute path the launcher has found no file at. It is made new (O_EXCL), so a symlink
 * there is never followed to make its target, and only in a directory outside the exclave; when another launcher of
 * the run makes it first, it is opened as theirs. Returns the descriptor or -errno. */
static long log_create(const char *path)
{
    static char dir[PATH_MAX];
    scpy(dir, path, PATH_MAX);
    char *slash = xstrrchr(dir, '/');
    if (!slash) return -ENOENT;
    const char *base = path + (slash - dir) + 1;
    if (slash == dir) slash[1] = 0;                            /* the root directory */
    else slash[0] = 0;
    long dfd = sys_open(dir, O_PATH | O_DIRECTORY | O_CLOEXEC, 0);
    if (dfd < 0) return dfd;
    if (in_exclave(dfd)) die("EXCLAVE_LOG is inside the exclave", path, 0);
    long fd = sys_openat((int)dfd, base, O_WRONLY | O_APPEND | O_CREAT | O_EXCL | O_CLOEXEC, 0644);
    if (fd == -EEXIST) fd = sys_openat((int)dfd, base, O_WRONLY | O_APPEND | O_CLOEXEC, 0);
    sys_close((int)dfd);
    return fd;
}

/* EXCLAVE_LOG names a host file by its absolute path, the one file every launcher of a run appends to (6.2). The
 * launcher opens it itself, untranslated, so a relative value would be read against the program's working directory,
 * often inside the tree: it is refused by name, and so is a log in the exclave, which the log must leave unchanged.
 * A log that cannot be opened is not kept, and the run goes on. Called once the exclave is found. */
void log_open(char **envp)
{
    C.logfd = -1;
    const char *path = 0;
    for (char **e = envp; *e; e++)
        if (xstarts(*e, "EXCLAVE_LOG=")) path = *e + 12;
    if (!path || !*path) return;
    if (path[0] != '/') die("EXCLAVE_LOG must be an absolute path", path, 0);
    long fd = sys_open(path, O_WRONLY | O_APPEND | O_CLOEXEC, 0);
    if (fd == -ENOENT) fd = log_create(path);
    if (fd < 0) return;
    if (in_exclave(fd)) die("EXCLAVE_LOG is inside the exclave", path, 0);
    /* out of the way of the program's own descriptors */
    long hi = sys_fcntl((int)fd, 1030 /* F_DUPFD_CLOEXEC */, 900);
    if (hi >= 0) {
        sys_close((int)fd);
        fd = hi;
    }
    struct kstat st;
    if (SC2(NR_fstat, fd, &st) == 0) {
        log_dev = st.st_dev;
        log_ino = st.st_ino;
    }
    C.logfd = (int)fd;
}

/* the descriptor is inherited by the program, which may close it and reuse the number:
 * a line is written only when the descriptor still names the log file */
static int log_ok(void)
{
    if (C.logfd < 0) return 0;
    struct kstat st;
    if (SC2(NR_fstat, C.logfd, &st) < 0 || st.st_dev != log_dev || st.st_ino != log_ino) {
        C.logfd = -1;
        return 0;
    }
    return 1;
}

/* one line, one write: "<what> <result> <path>\n"; atomic under O_APPEND. A path may hold any byte: a newline is
 * written as \n and a backslash as \\, the two escapes the tool undoes when it reads a log; the
 * escaped pieces go out as iovecs, no buffer, since this runs on the handler's stack */
static struct iovec iov(const void *p, size_t n) { return (struct iovec){unconst(p), n}; }

void log_line(const char *what, long result, const char *path)
{
    if (!log_ok()) return;
    char n[24];
    ltoa_(result, n);
    if (!path) path = "-";
    struct iovec io[12];
    int k = 0;
    io[k++] = iov(what, xstrlen(what));
    io[k++] = iov(" ", 1);
    io[k++] = iov(n, xstrlen(n));
    io[k++] = iov(" ", 1);
    const char *seg = path;
    for (const char *p = path;; p++) {
        if (*p && *p != '\n' && *p != '\\') continue;
        if (p > seg) io[k++] = iov(seg, (size_t)(p - seg));
        if (!*p) break;
        io[k++] = iov(*p == '\n' ? "\\n" : "\\\\", 2);
        seg = p + 1;
        /* a pathological path costs a second write */
        if (k >= 10) {
            SC3(NR_writev, C.logfd, io, k);
            k = 0;
        }
    }
    io[k++] = iov("\n", 1);
    SC3(NR_writev, C.logfd, io, k);
}
void log_msg(const char *a, const char *b)
{
    if (!log_ok()) return;
    struct iovec io[5] = {iov("launcher 0 ", 11), iov(a, xstrlen(a)), iov(" ", b ? 1 : 0),
                          iov(b ? b : "", b ? xstrlen(b) : 0), iov("\n", 1)};
    /* one write, no buffer: this runs on the handler's stack too */
    SC3(NR_writev, C.logfd, io, 5);
}

void die_status(int status, const char *what, const char *detail, long err)
{
    outs(2, "launcher: ");
    outs(2, what);
    if (detail) {
        outs(2, ": ");
        outs(2, detail);
    }
    if (err) {
        outs(2, ": ");
        outs(2, strerr(err));
    }
    outs(2, "\n");
    log_msg("fatal", what);
    sys_exit(status);
}
void die(const char *what, const char *detail, long err) { die_status(127, what, detail, err); }
