/* log.c — CAN_LOG (6.2) and fatal messages. */
#include "common.h"

struct can C;

static unsigned long log_dev, log_ino;

void log_open(char **envp)
{
    C.logfd = -1;
    for (char **e = envp; *e; e++)
        if (xstarts(*e, "CAN_LOG=") && (*e)[8]) {
            long fd = sys_open(*e + 8, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0644);
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

/* one line, one write: "<what> <result> <path>\n"; atomic under O_APPEND */
void log_line(const char *what, long result, const char *path)
{
    if (!log_ok()) return;
    char n[24]; ltoa_(result, n);
    if (!path) path = "-";
    struct iovec io[6] = { { (void *)what, xstrlen(what) }, { " ", 1 }, { n, xstrlen(n) }, { " ", 1 }, { (void *)path, xstrlen(path) }, { "\n", 1 } };
    SC3(NR_writev, C.logfd, io, 6);
}
void log_msg(const char *a, const char *b)
{
    if (!log_ok()) return;
    struct iovec io[5] = { { "opener 0 ", 9 }, { (void *)a, xstrlen(a) }, { " ", b ? 1 : 0 }, { (void *)(b ? b : ""), b ? xstrlen(b) : 0 }, { "\n", 1 } };
    SC3(NR_writev, C.logfd, io, 5);                          /* one write, no buffer: this runs on the handler's stack too */
}

void die(const char *what, const char *detail, long err)
{
    outs(2, "opener: "); outs(2, what);
    if (detail) { outs(2, ": "); outs(2, detail); }
    if (err) { outs(2, ": "); outs(2, strerr(err)); }
    outs(2, "\n");
    log_msg("fatal", what);
    sys_exit(127);
}
