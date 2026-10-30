/* creat_slash.c — open with O_CREAT through a final symlink whose text ends in a slash (DESIGN.md 8.1, 17.4). The
 * kernel walks the link's text as the rest of the path, so the slash is the path's trailing slash: open_last_lookups
 * answers EISDIR for O_CREAT before any lookup, whether the target exists or not, and a plain open follows the link
 * to its missing target, ENOENT. Makes its links in argv[1], a writable host directory, and prints one line per case:
 * the case and the errno text, or ok. */
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static void try(const char *what, const char *path, int flags)
{
    int fd = open(path, flags, 0644);
    printf("%s: %s\n", what, fd >= 0 ? "ok" : strerror(errno));
    if (fd >= 0) close(fd);
}

static void link_to(const char *text, const char *name)
{
    unlink(name);
    if (symlink(text, name) != 0) {
        printf("symlink %s: %s\n", name, strerror(errno));
        _exit(2);
    }
}

int main(int argc, char **argv)
{
    if (argc != 2 || chdir(argv[1]) != 0) {
        fprintf(stderr, "usage: creat_slash DIR\n");
        return 2;
    }
    link_to("/usr/nonexistent/", "l_absent_slash");
    link_to("/usr/share/", "l_dir_slash");
    link_to("/etc/../usr/nonexistent/", "l_dotdot_slash");
    try("creat through a link to a missing name with a slash", "l_absent_slash", O_RDONLY | O_CREAT);
    try("creat for writing through the same link", "l_absent_slash", O_WRONLY | O_CREAT);
    try("creat through a link to a directory with a slash", "l_dir_slash", O_RDONLY | O_CREAT);
    try("creat through a link whose text has .. and a slash", "l_dotdot_slash", O_RDONLY | O_CREAT);
    try("open through a link to a missing name with a slash", "l_absent_slash", O_RDONLY);
    try("creat with O_EXCL through the link", "l_absent_slash", O_WRONLY | O_CREAT | O_EXCL);
    return 0;
}
