// go_fwd.go — Go forwarding a signal to a handler C installed before the runtime started (DESIGN.md 7.5.7, 13
// item 20): the runtime queries the action at its start, keeps what it finds, installs its own handler, and on a
// fault in C code calls the kept handler as a function with the signal, its siginfo and its context. Under the
// launcher the query answers the stub, which, called rather than delivered to, runs the C handler with the
// arguments as given. The C handler makes the faulting page writable, and the store is retried. Built static with
// cgo by its test, run inside an exclave as a host program.
package main

/*
#include <signal.h>
#include <string.h>
#include <sys/mman.h>
static char *page;
static volatile int got_sig, got_addr;
static void h(int sig, siginfo_t *si, void *uc)
{
	(void)uc;
	got_sig = sig;
	got_addr = si != 0 && si->si_addr == page;
	mprotect(page, 4096, PROT_READ | PROT_WRITE);
}
__attribute__((constructor)) static void install(void)
{
	struct sigaction sa;
	memset(&sa, 0, sizeof sa);
	sa.sa_sigaction = h;
	sa.sa_flags = SA_SIGINFO | SA_ONSTACK | SA_RESTART;
	sigaction(SIGSEGV, &sa, 0);
}
static int fault(void)
{
	page = mmap(0, 4096, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (page == MAP_FAILED) return -1;
	*(volatile char *)page = 1;
	return page[0];
}
static int sig_seen(void) { return got_sig; }
static int addr_seen(void) { return got_addr; }
*/
import "C"

import "fmt"

func main() {
	r := C.fault()
	switch {
	case C.sig_seen() == 0 || r != 1:
		fmt.Println("the C handler Go forwards to: did not run")
	case C.addr_seen() == 0:
		fmt.Println("the C handler Go forwards to: ran without its siginfo")
	default:
		fmt.Println("the C handler Go forwards to: ran with its signal and siginfo")
	}
}
