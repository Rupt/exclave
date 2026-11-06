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
    long hi = sys_fcntl((int)fd, F_DUPFD_CLOEXEC, 900);
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

/* the descriptor is inherited by the program, which may close it and reuse the number: a line is written only when
 * the descriptor still names the log file */
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

static struct iovec iov(const void *p, size_t n) { return (struct iovec){unconst(p), n}; }

/* Ends a line whose first k pieces are in io (k at most 4) with path, escaped, and a newline, in one write unless the
 * path needs more than two escapes, atomic under O_APPEND. A path may hold any byte: a newline is written as \n, a
 * backslash as \\ and every other control byte, below 0x20 or 0x7f, as \x and two hex digits, the escapes the tool
 * undoes when it reads a log (6.2), so that no byte of a name can end a line, move the cursor or recolour a terminal.
 * The escaped pieces go out as iovecs and their few bytes, no buffer, since this runs on the handler's stack. */
static void log_end(struct iovec *io, int k, const char *path)
{
    char hex[6][4];
    int nh = 0;
    const char *seg = path;
    for (const char *p = path;; p++) {
        unsigned char c = (unsigned char)*p;
        if (c && c != '\\' && c >= 0x20 && c != 0x7f) continue;
        if (p > seg) io[k++] = iov(seg, (size_t)(p - seg));
        if (!c) break;
        if (c == '\n' || c == '\\') io[k++] = iov(c == '\n' ? "\\n" : "\\\\", 2);
        else {
            char *h = hex[nh++];
            h[0] = '\\';
            h[1] = 'x';
            h[2] = "0123456789abcdef"[c >> 4];
            h[3] = "0123456789abcdef"[c & 15];
            io[k++] = iov(h, 4);
        }
        seg = p + 1;
        /* a pathological path costs a second write */
        if (k >= 10 || nh == 6) {
            SC3(NR_writev, C.logfd, io, k);
            k = nh = 0;
        }
    }
    io[k++] = iov("\n", 1);
    SC3(NR_writev, C.logfd, io, k);
}

/* one line: "<what> <result> <path>" */
void log_line(const char *what, long result, const char *path)
{
    if (!log_ok()) return;
    char n[24];
    ltoa_(result, n);
    struct iovec io[12] = {iov(what, xstrlen(what)), iov(" ", 1), iov(n, xstrlen(n)), iov(" ", 1)};
    log_end(io, 4, path ? path : "-");
}
/* one of the launcher's own lines: "launcher <version> <a> <b>", b escaped as a path is */
void log_msg(const char *a, const char *b)
{
    if (!log_ok()) return;
    /* the number where other lines carry a result is the log format's version (6.2) */
    struct iovec io[12] = {iov("launcher " LOG_VERSION " ", 11), iov(a, xstrlen(a)), iov(" ", b ? 1 : 0)};
    log_end(io, 3, b ? b : "");
}

/* the message the C library would give for errno e, for the errors the launcher reports */
static const char *strerr(long e)
{
    switch (e < 0 ? -e : e) {
    case EPERM: return "Operation not permitted";
    case ENOENT: return "No such file or directory";
    case EACCES: return "Permission denied";
    case ENOEXEC: return "Exec format error";
    case EEXIST: return "File exists";
    case ENOTDIR: return "Not a directory";
    case EINVAL: return "Invalid argument";
    case EROFS: return "Read-only file system";
    case ENOSYS: return "Function not implemented";
    case ENAMETOOLONG: return "File name too long";
    case ENOMEM: return "Cannot allocate memory";
    case EBUSY: return "Device or resource busy";
    case EISDIR: return "Is a directory";
    case EMFILE: return "Too many open files";
    case ELOOP: return "Too many levels of symbolic links";
    case EIO: return "Input/output error";
    case ELIBBAD: return "Accessing a corrupted shared library";
    default: return "error";
    }
}

static void say(const char *what, const char *detail, long err)
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
}
void die_status(int status, const char *what, const char *detail, long err)
{
    say(what, detail, err);
    sys_exit(status);
}
void die_signal(int sig, const char *what, const char *detail, long err)
{
    say(what, detail, err);
    struct {
        void *h;
        unsigned long flags;
        void *restorer;
        unsigned long mask;
    } dfl = {0, 0, 0, 0};
    sys_rt_sigaction(sig, &dfl, 0, 8);
    unsigned long m = 1UL << (sig - 1);
    sys_rt_sigprocmask(SIG_UNBLOCK, &m, 0, 8);
    sys_tgkill((pid_t)sys_getpid(), (pid_t)sys_gettid(), sig);
    sys_exit(128 + sig); /* a disposition the signal could not reach */
}
void die(const char *what, const char *detail, long err) { die_status(127, what, detail, err); }
