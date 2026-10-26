/* execstack.c — a nested function whose address is taken puts a trampoline on the stack; the program's
 * PT_GNU_STACK asks for an executable stack, which the loader must honour. */
#include <stdio.h>
static int apply(int (*f)(int), int x) { return f(x); }
int main(int argc, char **argv)
{
    int k = argc + 6;
    int add(int x) { return x + k; }
    printf("result %d\n", apply(add, 5));
    return 0;
}
