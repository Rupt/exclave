#include <spawn.h>
#include <stdio.h>
#include <sys/wait.h>
#include <pthread.h>
extern char **environ;
static void *w(void *a){ for(int i=0;i<25;i++){ pid_t p; char *av[]={"/bin/true",0}; if(posix_spawn(&p,"/bin/true",0,0,av,environ)) return (void*)1; int st; waitpid(p,&st,0); if(st) return (void*)2;} return 0; }
int main(void){ pthread_t t[8]; void *r; int bad=0; for(int i=0;i<8;i++) pthread_create(&t[i],0,w,0); for(int i=0;i<8;i++){ pthread_join(t[i],&r); if(r) bad++; } printf("8 threads x 25 spawns: %s\n", bad?"FAILED":"ok"); return bad; }
