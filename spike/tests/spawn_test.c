#include <spawn.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <unistd.h>
extern char **environ;
int main(void) {
  pid_t pid; char *argv[] = {"/bin/sh", "-c", "echo spawned: $(ls /usr/libexec/gcc/x86_64-linux-gnu/13 | head -3 | tr '\\n' ' '); exit 7", 0};
  int r = posix_spawn(&pid, "/bin/sh", 0, 0, argv, environ); if (r) { printf("posix_spawn failed %d\n", r); return 1; }
  int st; waitpid(pid, &st, 0); printf("posix_spawn child exit=%d\n", WEXITSTATUS(st));
  r = system("echo system: $(cat /etc/os-release 2>/dev/null | head -1 || echo no-os-release); /usr/bin/gcc-13 --version | head -1");
  printf("system() -> %d\n", r);
  return 0;
}
