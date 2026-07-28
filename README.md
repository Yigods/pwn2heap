# hn2026 Pwn Challenges

7 道可独立构建、Docker 部署并适配 GZ::CTF `GZCTF_FLAG` 动态 flag 的 Pwn 题目。题目统一包含源码、发布附件、对应 glibc/loader、Docker 部署文件及出题人验证脚本。

> 本仓库包含官方解题脚本（`solve.py` / `notezpz*.py`），适合作为**出题人私有仓库**。若需赛前公开源码，请在发布前删除各题的官方解题脚本。

## 题目与难度

| 境界 | 目录 | 运行环境 | 核心考点 |
|---|---|---|---|
| 炼气 | `ezpz1` | amd64 / glibc 2.39 | UAF、chunk overlap、函数指针劫持到 `win()` |
| 筑基 | `ezpz2` | amd64 / glibc 2.39 | heap overflow、libc 泄漏、控制流劫持 |
| 筑基 | `notezpz1` | i386 / glibc 2.27 | tcache poisoning、PIE/libc leak、`__free_hook` |
| 金丹 | `notezpz1-plus` | amd64 / glibc 2.39 | 现代堆利用、泄漏与 `setcontext` 利用链 |
| 金丹 | `notezpz2` | amd64 / glibc 2.39 | UAF、largebin、任意读写、栈 ROP |
| 元婴 | `applepie` | amd64 / glibc 2.39 | House of Apple 2 / FSOP → `setcontext` → SROP ORW |
| 元婴 | `darklamp` | amd64 / glibc 2.39 | byte oracle、状态机堆利用、受限 AAR/AAW、`setcontext` → SROP ORW |

## 快速开始

### Docker：完整构建与验证

```bash
docker compose build
docker compose up -d
./test_all_docker.sh
```

所有服务在容器内监听 `9999`，本地映射如下：

| 题目 | 本地端口 |
|---|---:|
| ezpz1 | 8002 |
| ezpz2 | 8003 |
| notezpz1 | 8004 |
| notezpz2 | 8005 |
| applepie | 8006 |
| notezpz1-plus | 8007 |
| darklamp | 8008 |

停止环境：

```bash
docker compose down
```

### 从源码重新构建

```bash
./build_all.sh
```

- `notezpz1` 在 `ubuntu:18.04` 中按 i386 / glibc 2.27 构建；
- 其余题目在 `ubuntu:24.04` 中按 glibc 2.39 构建；
- 需要 Docker、`make` 与网络镜像源访问。

## GZ::CTF 部署

每题 Docker 镜像通过启动脚本读取 `GZCTF_FLAG` 并写入 chroot 中的 `/flag`。在 GZ::CTF 后台：

```text
Container Image: <你的镜像地址>
Container Port: 9999
Challenge Type: Dynamic Container
```

不要在镜像中写入真实 flag。仓库的 `flag.example` 仅供本地非 Docker 调试参考，实际 `/flag` 在容器启动时生成。

管理员“测试容器”出现 `flag{GZCTF_dynamic_flag_test}` 是 GZ::CTF 的预期测试 flag；选手实例会注入各队独立的 `GZCTF_FLAG`。

## 推送镜像

构建后可推送全部镜像：

```bash
./push_all.sh docker.io/<username>/hn2026
```

Docker Hub 会推送为：

```text
docker.io/<username>/hn2026-ezpz1:latest
docker.io/<username>/hn2026-ezpz2:latest
...
```

通用私有仓库（例如阿里云）则保留层级路径：

```bash
./push_all.sh registry.example.com/hn2026
```

## 发布附件

每个题目目录中的 `*_patched`、`libc.so.6` 和对应 `ld-linux*` 是选手运行所需的发布附件；源码可通过 `build_all.sh` 重建。
