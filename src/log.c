/* log.c — EXCLAVE_LOG (6.2) and fatal messages. */
#include "common.h"

struct exclave C;

static unsigned long log_dev, log_ino;

void log_open(char **envp)
{
    C.logfd = -1;
    for (char **e = envp; *e; e++)
        if (xstarts(*e, "EXCLAVE_LOG=") && (*e)[12]) {
            long fd = sys_open(*e + 12, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0644);
            if (fd < 0) return;
            long hi = sys_fcntl((int)fd, 1030 /* F_DUPFD_CLOEXEC */, 900);   /* out of the way of the program's own descriptors */
            if (hi >= 0) { sys_close((int)fd); fd = hi; }
            struct kstat st; if (SC2(NR_fstat, fd, &st) == 0) { log_dev = st.st_dev; log_ino = st.st_ino; }
            C.logfd = (int)fd;
            return;
        }
}

/* the descriptor is inherited by the program, which may close it and reuse the number (review F3-18):
 * a line is written only when the descriptor still names the log file */
static int log_ok(void)
{
    if (C.logfd < 0) return 0;
    struct kstat st;
    if (SC2(NR_fstat, C.logfd, &st) < 0 || st.st_dev != log_dev || st.st_ino != log_ino) { C.logfd = -1; return 0; }
    return 1;
}

/* one line, one write: "<what> <result> <path>\n"; atomic under O_APPEND. A path may hold any byte: a newline is
 * written as \n and a backslash as \\, the two escapes the cannery undoes when it reads a log (review O4-5); the
 * escaped pieces go out as iovecs, no buffer, since this runs on the handler's stack */
void log_line(const char *what, long result, const char *path)
{
    if (!log_ok()) return;
    char n[24]; ltoa_(result, n);
    if (!path) path = "-";
    struct iovec io[12]; int k = 0;
    io[k++] = (struct iovec){ (void *)what, xstrlen(what) }; io[k++] = (struct iovec){ " ", 1 };
    io[k++] = (struct iovec){ n, xstrlen(n) }; io[k++] = (struct iovec){ " ", 1 };
    const char *seg = path;
    for (const char *p = path;; p++) {
        if (*p && *p != '\n' && *p != '\\') continue;
        if (p > seg) io[k++] = (struct iovec){ (void *)seg, (size_t)(p - seg) };
        if (!*p) break;
        io[k++] = (struct iovec){ (void *)(*p == '\n' ? "\\n" : "\\\\"), 2 };
        seg = p + 1;
        if (k >= 10) { SC3(NR_writev, C.logfd, io, k); k = 0; }   /* a pathological path costs a second write */
    }
    io[k++] = (struct iovec){ "\n", 1 };
    SC3(NR_writev, C.logfd, io, k);
}
void log_msg(const char *a, const char *b)
{
    if (!log_ok()) return;
    struct iovec io[5] = { { "launcher 0 ", 11 }, { (void *)a, xstrlen(a) }, { " ", b ? 1 : 0 }, { (void *)(b ? b : ""), b ? xstrlen(b) : 0 }, { "\n", 1 } };
    SC3(NR_writev, C.logfd, io, 5);                          /* one write, no buffer: this runs on the handler's stack too */
}

void die_status(int status, const char *what, const char *detail, long err)
{
    outs(2, "launcher: "); outs(2, what);
    if (detail) { outs(2, ": "); outs(2, detail); }
    if (err) { outs(2, ": "); outs(2, strerr(err)); }
    outs(2, "\n");
    log_msg("fatal", what);
    sys_exit(status);
}
void die(const char *what, const char *detail, long err) { die_status(127, what, detail, err); }
