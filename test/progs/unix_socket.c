/* unix_socket.c — sockaddr_un paths under the visibility rule (PROPOSAL.md 13 item 31, 17.4): bind, connect and sendto
 * with a path of every class. usage: unix_socket HOSTDIR [CANDIR CANFILE CANSOCK]. Prints one line per case,
 * "<case>: ret=<r> errno=<e>", the same in every world, so that the kernel under bwrap is the oracle for the opener.
 * CANDIR: a can-owned directory (default /usr/share); CANFILE: a can-owned regular file (default $CONT_TRUE); CANSOCK: a
 * socket file in the tree, if the maker put one there. Exit 0 always: the driver compares. */
#define _GNU_SOURCE
#include <errno.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

static void show(const char *name, long r) { printf("%s: ret=%ld errno=%d\n", name, r < 0 ? -1L : r, r < 0 ? errno : 0); }
static struct sockaddr_un addr(const char *path, socklen_t *len)
{
    struct sockaddr_un a; memset(&a, 0, sizeof a); a.sun_family = AF_UNIX;
    size_t n = strlen(path); if (n > sizeof a.sun_path) n = sizeof a.sun_path;
    memcpy(a.sun_path, path, n);
    *len = (socklen_t)(offsetof(struct sockaddr_un, sun_path) + n + (n < sizeof a.sun_path ? 1 : 0));
    return a;
}
static void bind_at(const char *name, const char *path, int type)
{
    int s = socket(AF_UNIX, type, 0); socklen_t l; struct sockaddr_un a = addr(path, &l);
    long r = bind(s, (struct sockaddr *)&a, l); show(name, r);
    if (r == 0 && path[0]) unlink(path);
    close(s);
}
static void connect_to(const char *name, const char *path, int type)
{
    int s = socket(AF_UNIX, type, 0); socklen_t l; struct sockaddr_un a = addr(path, &l);
    show(name, connect(s, (struct sockaddr *)&a, l)); close(s);
}
static void sendto_at(const char *name, const char *path)
{
    int s = socket(AF_UNIX, SOCK_DGRAM, 0); socklen_t l; struct sockaddr_un a = addr(path, &l);
    show(name, sendto(s, "x", 1, 0, (struct sockaddr *)&a, l)); close(s);
}

int main(int argc, char **argv)
{
    if (argc < 2) { fprintf(stderr, "usage: unix_socket HOSTDIR [CANDIR CANFILE CANSOCK]\n"); return 2; }
    const char *host = argv[1];
    const char *candir = argc > 2 ? argv[2] : "/usr/share";
    const char *canfile = argc > 3 ? argv[3] : getenv("CONT_TRUE") ? getenv("CONT_TRUE") : "/usr/bin/true";
    const char *cansock = argc > 4 ? argv[4] : "";
    char p[4096], q[4096];
    /* bind: host paths, can paths, an abstract name, relative paths from two working directories */
    snprintf(p, sizeof p, "%s/sock-host", host); bind_at("bind host dir", p, SOCK_STREAM);
    snprintf(p, sizeof p, "/tmp/cont-sock-%d", (int)getpid()); bind_at("bind /tmp", p, SOCK_STREAM);
    snprintf(p, sizeof p, "%s/cont-sock", candir); bind_at("bind can dir", p, SOCK_STREAM);
    bind_at("bind existing can file", canfile, SOCK_STREAM);
    if (cansock[0]) bind_at("bind existing can socket", cansock, SOCK_STREAM);
    bind_at("bind missing can parent", "/usr/nonexistent/sock", SOCK_STREAM);
    snprintf(p, sizeof p, "%s/sock", canfile); bind_at("bind under a can file", p, SOCK_STREAM);
    snprintf(p, sizeof p, "%s/", candir); bind_at("bind can dir itself", p, SOCK_STREAM);
    bind_at("bind can dir trailing slash name", "/usr/share/cont-sock/", SOCK_STREAM);
    { int s = socket(AF_UNIX, SOCK_STREAM, 0); struct sockaddr_un a; memset(&a, 0, sizeof a); a.sun_family = AF_UNIX;
      int n = snprintf(a.sun_path + 1, sizeof a.sun_path - 1, "cont-abstract-%d", (int)getpid());        /* one name per process: suites run side by side */
      show("bind abstract", bind(s, (struct sockaddr *)&a, (socklen_t)(offsetof(struct sockaddr_un, sun_path) + 1 + n))); close(s); }
    if (chdir(host) == 0) bind_at("bind relative in host cwd", "sock-rel", SOCK_STREAM);
    if (chdir(candir) == 0) bind_at("bind relative in can cwd", "sock-rel", SOCK_STREAM);
    chdir(host);
    /* connect: a listener on the host, a host socket file without one, can files, a can socket, a missing name */
    snprintf(p, sizeof p, "%s/sock-listen", host);
    { int s = socket(AF_UNIX, SOCK_STREAM, 0); socklen_t l; struct sockaddr_un a = addr(p, &l); unlink(p);
      if (bind(s, (struct sockaddr *)&a, l) == 0 && listen(s, 1) == 0) connect_to("connect host listener", p, SOCK_STREAM);
      close(s); }
    connect_to("connect host socket no listener", p, SOCK_STREAM); unlink(p);
    connect_to("connect can file", canfile, SOCK_STREAM);
    if (cansock[0]) connect_to("connect can socket", cansock, SOCK_STREAM);
    connect_to("connect missing can path", "/usr/share/nonexistent-sock", SOCK_STREAM);
    connect_to("connect can dir", candir, SOCK_STREAM);
    snprintf(p, sizeof p, "%s/sock", canfile); connect_to("connect under a can file", p, SOCK_STREAM);
    snprintf(p, sizeof p, "%s/missing-host", host); connect_to("connect missing host path", p, SOCK_STREAM);
    /* datagram destinations */
    snprintf(q, sizeof q, "%s/sock-dgram", host);
    { int s = socket(AF_UNIX, SOCK_DGRAM, 0); socklen_t l; struct sockaddr_un a = addr(q, &l); unlink(q);
      if (bind(s, (struct sockaddr *)&a, l) == 0) sendto_at("sendto host dgram", q);
      close(s); unlink(q); }
    sendto_at("sendto missing can path", "/usr/share/nonexistent-dgram");
    sendto_at("sendto can file", canfile);
    /* the structure's own limits: a length past the structure, a family that is not AF_UNIX with a path */
    { int s = socket(AF_UNIX, SOCK_STREAM, 0); socklen_t l; struct sockaddr_un a = addr("/usr/share/x", &l);
      show("bind addrlen too long", bind(s, (struct sockaddr *)&a, sizeof a + 1));
      show("bind addrlen too short", bind(s, (struct sockaddr *)&a, 1));
      a.sun_family = AF_INET; show("bind wrong family", bind(s, (struct sockaddr *)&a, l)); close(s); }
    { char longp[120]; memset(longp, 'a', sizeof longp); memcpy(longp, "/usr/share/", 11); longp[107] = 0;
      bind_at("bind can path of 107 bytes", longp, SOCK_STREAM); connect_to("connect can path of 107 bytes", longp, SOCK_STREAM); }
    return 0;
}
