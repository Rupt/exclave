/* ro_matrix.c — the read-only matrix of PROPOSAL.md 8.2 plus path-argument fidelity.
 * usage: ro_matrix HOSTDIR   (HOSTDIR: a writable host directory). Prints FAIL lines; exit 1 on any. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/xattr.h>
#include <unistd.h>
#include <utime.h>
#include <linux/fs.h>

static int fails;
#define CHECK(expr, want) do { errno = 0; long r_ = (long)(expr); int e_ = errno; \
    if ((want) == 0 ? r_ < 0 : !(r_ < 0 && e_ == (want))) { fails++; printf("FAIL %s: got %ld errno %d (%s), wanted %s\n", #expr, r_, e_, strerror(e_), (want) == 0 ? "success" : strerror(want)); } \
    else if (r_ >= 0 && strncmp(#expr, "open", 4) == 0) close((int)r_); } while (0)

int main(int argc, char **argv)
{
    if (argc < 2) { fprintf(stderr, "usage: ro_matrix HOSTDIR\n"); return 2; }
    const char *host = argv[1];
    const char *marker = "/usr/share/cont-test-marker", *missing = "/usr/share/cont-missing", *dir = "/usr/share";
    char hfile[4096], hnew[4096], hdir[4096];
    snprintf(hfile, sizeof hfile, "%s/hfile", host); snprintf(hnew, sizeof hnew, "%s/hnew", host); snprintf(hdir, sizeof hdir, "%s/hdir", host);
    unlink(hnew); rmdir(hdir); int hf = open(hfile, O_WRONLY | O_CREAT | O_TRUNC, 0644); if (hf < 0) { perror("hfile"); return 2; } close(hf);

    /* opens */
    CHECK(open(marker, O_RDONLY), 0);
    CHECK(open(marker, O_WRONLY), EROFS);
    CHECK(open(marker, O_RDWR), EROFS);
    CHECK(open(marker, O_RDONLY | O_TRUNC), EROFS);
    CHECK(open(missing, O_WRONLY), ENOENT);
    CHECK(open(missing, O_WRONLY | O_CREAT, 0644), EROFS);
    CHECK(open(marker, O_RDONLY | O_CREAT, 0644), 0);
    CHECK(open(marker, O_WRONLY | O_CREAT | O_EXCL, 0644), EEXIST);
    CHECK(open(dir, O_WRONLY), EISDIR);
    CHECK(open(dir, O_RDONLY), 0);
    CHECK(open(dir, O_RDWR | O_TMPFILE, 0600), EROFS);
    CHECK(open(missing, O_RDONLY), ENOENT);
    /* deletes: EROFS regardless of existence */
    CHECK(unlink(marker), EROFS);
    CHECK(unlink(missing), EROFS);
    CHECK(rmdir(dir), EROFS);
    CHECK(rmdir(missing), EROFS);
    /* creates: EEXIST wins over EROFS */
    CHECK(mkdir(dir, 0755), EEXIST);
    CHECK(mkdir("/usr/share/", 0755), EEXIST);
    CHECK(mkdir(missing, 0755), EROFS);
    CHECK(mknod(missing, S_IFIFO | 0644, 0), EROFS);
    CHECK(symlink("x", missing), EROFS);
    CHECK(symlink("x", marker), EEXIST);
    /* across the boundary */
    CHECK(link(marker, hnew), EXDEV);
    CHECK(link(hfile, missing), EROFS);
    CHECK(rename(marker, missing), EROFS);
    CHECK(rename(marker, hnew), EXDEV);
    CHECK(rename(hfile, missing), EXDEV);
    CHECK(rename(missing, hnew), EXDEV);
    CHECK(rename(missing, "/usr/share/cont-missing2"), EROFS);
    CHECK(link(missing, hnew), ENOENT);
    /* attributes */
    CHECK(truncate(marker, 0), EROFS);
    CHECK(truncate(missing, 0), ENOENT);
    CHECK(chmod(marker, 0644), EROFS);
    CHECK(chmod(missing, 0644), ENOENT);
    CHECK(chown(marker, getuid(), getgid()), EROFS);
    CHECK(utime(marker, 0), EROFS);
    CHECK(utimensat(AT_FDCWD, marker, 0, 0), EROFS);
    CHECK(setxattr(marker, "user.x", "y", 1, 0), EROFS);
    CHECK(removexattr(marker, "user.x"), EROFS);
    CHECK(access(marker, W_OK), EROFS);
    CHECK(access(marker, R_OK), 0);
    CHECK(access(missing, W_OK), ENOENT);
    /* descriptors that name can files */
    int fd = open(marker, O_RDONLY); if (fd < 0) { printf("FAIL open marker: %s\n", strerror(errno)); return 1; }
    CHECK(fchmod(fd, 0644), EROFS);
    CHECK(fchown(fd, getuid(), getgid()), EROFS);
    CHECK(futimens(fd, 0), EROFS);
    CHECK(fsetxattr(fd, "user.x", "y", 1, 0), EROFS);
    { int fl = 0; CHECK(ioctl(fd, FS_IOC_SETFLAGS, &fl), EROFS); }
    { struct stat a, b; CHECK(fstatat(fd, "", &a, AT_EMPTY_PATH), 0); stat(marker, &b); if (a.st_ino != b.st_ino) { fails++; printf("FAIL fstatat AT_EMPTY_PATH inode\n"); } }
    { struct statvfs v; CHECK(fstatvfs(fd, &v), 0); if (!(v.f_flag & ST_RDONLY)) { fails++; printf("FAIL fstatvfs lacks ST_RDONLY\n"); } }
    close(fd);
    { struct statvfs v; CHECK(statvfs("/usr", &v), 0); if (!(v.f_flag & ST_RDONLY)) { fails++; printf("FAIL statvfs /usr lacks ST_RDONLY\n"); }
      CHECK(statvfs(host, &v), 0); if (v.f_flag & ST_RDONLY) { fails++; printf("FAIL statvfs host has ST_RDONLY\n"); } }
    /* trailing slash and bad pointers */
    { struct stat st; CHECK(stat("/usr/share/cont-test-marker/", &st), ENOTDIR); CHECK(stat("/usr/share/", &st), 0); CHECK(lstat("/usr/share/", &st), 0);
      CHECK(stat((const char *)8, &st), EFAULT); CHECK(open((const char *)8, O_RDONLY), EFAULT); CHECK(access((const char *)8, R_OK), EFAULT); }
    { char b[16]; CHECK(readlink((const char *)8, b, 16), EFAULT); }
    /* the host stays writable */
    CHECK(open(hnew, O_WRONLY | O_CREAT | O_EXCL, 0644), 0);
    CHECK(mkdir(hdir, 0755), 0);
    CHECK(rename(hnew, hfile), 0);
    CHECK(unlink(hfile), 0);
    CHECK(rmdir(hdir), 0);
    /* wrapper redirect: opening a wrapper reads the payload */
    { const char *w = argv[2] ? argv[2] : "/usr/bin/x86_64-linux-gnu-gcc-13"; char p[4096]; const char *b = strrchr(w, '/');
      snprintf(p, sizeof p, "%.*s/.real%s", (int)(b - w), w, b);
      struct stat a, c; int f = open(w, O_RDONLY); unsigned char h[4] = {0};
      if (f < 0 || read(f, h, 4) != 4 || memcmp(h, "\177ELF", 4) || fstat(f, &a) || stat(p, &c) || a.st_ino != c.st_ino || a.st_size != c.st_size)
          { fails++; printf("FAIL wrapper redirect for %s\n", w); }
      if (f >= 0) close(f);
      if (stat(w, &a) || a.st_ino != c.st_ino) { fails++; printf("FAIL stat of wrapper reports the opener\n"); } }
    printf("ro_matrix: %d failures\n", fails);
    return fails ? 1 : 0;
}
