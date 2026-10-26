#include <stdio.h>
int origin_value(void);
int main(void)
{
    printf("origin %d\n", origin_value());
    return origin_value() == 42 ? 0 : 1;
}
