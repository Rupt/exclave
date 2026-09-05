/* log.c — CAN_LOG (6.2) and fatal messages. */
#include "common.h"

struct can C;

void log_open(char **envp)
{
    C.logfd = -1;
    for (char **e = envp; *e; e++)
        if (xstarts(*e, "CAN_LOG=") && (*e)[8]) {
            long fd = sys_open(*e + 8, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0644);
            if (fd >= 0) C.logfd = (int)fd;
            return;
        }
}

/* one line, one write: "<what> <result> <path>\n"; atomic under O_APPEND */
void log_line(const char *what, long result, const char *path)
{
    if (C.logfd < 0) return;
    char n[24]; ltoa_(result, n);
    if (!path) path = "-";
    struct iovec io[6] = { { (void *)what, xstrlen(what) }, { " ", 1 }, { n, xstrlen(n) }, { " ", 1 }, { (void *)path, xstrlen(path) }, { "\n", 1 } };
    SC3(NR_writev, C.logfd, io, 6);
}
void log_msg(const char *a, const char *b)
{
    if (C.logfd < 0) return;
    char l[PATH_MAX]; scpy(l, "opener 0 ", sizeof l); scat(l, a, sizeof l);
    if (b) { scat(l, " ", sizeof l); scat(l, b, sizeof l); }
    scat(l, "\n", sizeof l); sys_write(C.logfd, l, xstrlen(l));
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
