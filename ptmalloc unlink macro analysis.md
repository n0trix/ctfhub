# ptmalloc unlink macro analysis

source(glibc2.23):

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

+ 在从bin中解链的时候首先会检查与victim相邻的下一个堆块的preszie位是否与victim本身的size相等
+ 双向链表完整性检查，即前一个堆块的bk是不是victim，后一个堆块的fd是不是victim
+ 如果是largebin的unlink，还会检查nextsize构成的双向链表完整性

利用姿势：

+ unsafe unlink

+ largebin attack
+ 存在tcache机制时，tcache stashing unlink

largebin：

+ 对于存在多个满足空间的堆块来说，申请出来的是堆头的下一个结点，它的`fd_nextsize`和`bk_nextsize`为空。也就是说即使它是largebin chunk，但是它的`fd_nextsize`也为空，即不满足条件`__builtin_expect (P->fd_nextsize != NULL, 0)`，对于此类chunk的unlink，只会像smallbin的unlink一样检查`fd`与`bk`，而不会对`fd_nextsize`与`bk_nextsize`进行检查与操作