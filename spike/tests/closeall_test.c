#include <unistd.h>
#include <stdio.h>
#include <fcntl.h>
#include <sys/syscall.h>
int main(void){ int r = syscall(436 /*close_range*/, 3, ~0U, 0); printf("close_range(3,~0) -> %d; fd999 still valid: %d\n", r, fcntl(999, F_GETFD) >= 0); fflush(stdout);
  execl("/bin/echo", "echo", "exec after close_range: ok", (char*)0); perror("execl"); return 1; }
