# ezpz1 解题说明

## 漏洞

`create_question()` 分配两个 0x10 chunk：`struct question` 与 `text`。`delete_question()` 释放后没有清空 `questions[id]`，形成 UAF。再次创建会复用刚释放的 tcache chunk，使旧问题的 `struct` 与新问题的 `text` 重叠。

`ask_question()` 会调用 `q->print(q)`，因此通过 UAF 把旧问题结构体里的函数指针覆盖成 `win()` 即可执行 `/bin/sh`。

## 利用流程

1. 创建 question 0、1。
2. 删除 0、1，留下悬挂指针。
3. 再创建 question 2，复用 question 1 的 chunk。
4. `set_question(2, p64(win))` 覆盖 question 1 的函数指针。
5. `ask_question(1)` 触发 `win()`。

本目录 `solve.py` 已适配重新编译后的符号地址：`win_addr = exe.sym["win"]`。
