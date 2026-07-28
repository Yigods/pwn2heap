# notezpz1 classic

这是 `notezpz1` 的 classic 版本：i386 + glibc 2.27。

预期链：

```text
stale questions[] UAF
→ 0x20 tcache overlap
→ leak heap chunk pointer
→ poison tcache fd
→ leak PIE print_question
→ leak libc puts@GOT
→ q3->text 指向 __free_hook
→ __free_hook = system
→ free("/bin//sh")
```

本地：

```bash
python3 solve.py L
```

Docker：

```bash
docker compose up -d notezpz1
python3 notezpz1/solve.py
```
