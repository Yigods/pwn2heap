# darklamp

glibc 2.39 pwn. 极简灯盏接口，没有用户可控 free，也没有传统 show/edit；`light` 的堆溢出先伪造 lens，`pray` 的状态机制造 unsorted libc leak，`look` 是 byte oracle，`aim/whisper` 在 lens 被伪造后升级成受限 AAR/AAW。

预期链：

```text
tcache residue byte oracle
-> light overflow corrupt lens
-> pray allocator state machine creates/frees large moon chunk
-> byte oracle leaks libc from unsorted bin
-> scan heap page to locate forged lens
-> write fake ucontext + SROP ORW to libc .bss
-> arm lens dream trigger with setcontext
-> sleep calls setcontext(ctx) and reads /flag
```

修补说明：seccomp 已提前安装，`aim` 增加 canonical userland 过滤，`whisper` 单次写入限制收窄，并拒绝写当前 stack 附近；目标改为 byte oracle + 状态机 + setcontext 到 libc .bss SROP ORW，而不是 stack ROP 或 seccomp 前 execve。
