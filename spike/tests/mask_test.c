#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
int main(void){ sigset_t s, o; sigemptyset(&s); sigaddset(&s, SIGUSR1); sigaddset(&s, SIGSYS);
  sigprocmask(SIG_BLOCK, &s, &o); FILE *f = fopen("/proc/self/status","r"); char l[256];
  while (fgets(l, 256, f)) if (!strncmp(l, "SigBlk:", 7)) printf("after block USR1+SYS: %s", l);
  fclose(f); printf("oldset had SIGSYS: %d, had USR1: %d\n", sigismember(&o, SIGSYS), sigismember(&o, SIGUSR1));
  sigprocmask(SIG_SETMASK, &o, NULL); f = fopen("/proc/self/status","r");
  while (fgets(l, 256, f)) if (!strncmp(l, "SigBlk:", 7)) printf("after restore: %s", l);
  return 0; }
