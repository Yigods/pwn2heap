# applepie

定位：glibc 2.39 用户态堆利用收官题。预期链：

```text
UAF show/edit
  -> unsorted bin libc leak
  -> tcache safe-linking heap leak
  -> tcache poisoning to _IO_list_all
  -> fake FILE / House of Apple 2
  -> _IO_wfile_jumps -> setcontext
  -> SROP ORW: openat/read/write /flag
```

保护：PIE、Full RELRO、Canary、NX、seccomp。没有 win，不能 execve/system 拿 shell。

本地：

```bash
python3 solve.py L
```

Docker：

```bash
docker compose up -d applepie
python3 applepie/solve.py
```

修补说明：`resize` 已同步更新逻辑 size；show/edit/delete 会用当前真实栈指针拒绝靠近 stack 的目标，压低直接 environ→stack ROP 以及改写 environ 绕 guard 的捷径，保留 `_IO_list_all` / FSOP 预期链。
