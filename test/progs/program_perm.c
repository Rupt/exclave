/* program_perm.c — a write-open or truncate of the running program's own file, on a host path, when its mode forbids
 * writing (DESIGN.md 7.4.3, 13 item 29): may_open's permission check, EACCES (inode_permission, with O_TRUNC wanting
 * write access whatever the access mode: build_open_flags), comes before the ETXTBSY of do_dentry_open and
 * handle_truncate, and vfs_truncate's permission before its own ETXTBSY. Makes its own file unwritable and puts it
 * back. usage: program_perm. Prints one line per case: the case and the errno text, or ok (test/kernel_answers.py
 * has the kernel's answers). */
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static void try(const char *what, int flags)
{
    int fd = open("/proc/self/exe", flags, 0644);
    printf("%s: %s\n", what, fd >= 0 ? "ok" : strerror(errno));
    if (fd >= 0) close(fd);
}

int main(void)
{
    char self[4096];
    ssize_t n = readlink("/proc/self/exe", self, sizeof self - 1);
    if (n < 0) return 2;
    self[n] = 0;
    try("O_WRONLY on the writable program", O_WRONLY);
    try("O_WRONLY|O_TRUNC on the writable program", O_WRONLY | O_TRUNC);
    try("O_RDONLY|O_TRUNC on the writable program", O_RDONLY | O_TRUNC);
    try("O_RDWR on the writable program", O_RDWR);
    printf("truncate of the writable program: %s\n", truncate(self, 0) == 0 ? "ok" : strerror(errno));
    printf("chmod 0555: %s\n", chmod(self, 0555) == 0 ? "ok" : strerror(errno));
    try("O_WRONLY on the unwritable program", O_WRONLY);
    try("O_WRONLY|O_TRUNC on the unwritable program", O_WRONLY | O_TRUNC);
    try("O_RDONLY|O_TRUNC on the unwritable program", O_RDONLY | O_TRUNC);
    try("O_RDWR on the unwritable program", O_RDWR);
    try("O_RDONLY on the unwritable program", O_RDONLY);
    printf("truncate of the unwritable program: %s\n", truncate(self, 0) == 0 ? "ok" : strerror(errno));
    printf("chmod 0755: %s\n", chmod(self, 0755) == 0 ? "ok" : strerror(errno));
    return 0;
}
