# Safe-Linking 配套原语

## 结论

- 适用范围：**glibc 2.32～2.43**。
- 原语效果：恢复受保护的 heap 指针，或通过 double-protect 无泄露地重新链接。
- 前置能力：至少泄露编码指针；double-protect 还需要控制 tcache 元数据/链表。

<!-- PRIMITIVE_REQUIREMENTS:START -->
## 原语要求与版本边界

| 项目 | 本手法要求 |
|---|---|
| 最小输入原语 / 信息 | 泄露 encoded next；double-protect 需控制两层链/metadata |
| 关键环境与不变量 | 已知存储槽地址或可构造两次 XOR |
| 最终输出原语 | 恢复 heap pointer；生成合法 encoded pointer；无泄露重链接 |
| 版本边界应如何理解 | 2.32 前不是“失效”，而是没有这项缓解、也不需要解码；2.42/2.43 只改具体 metadata/链位置。 |
<!-- PRIMITIVE_REQUIREMENTS:END -->

<!-- CHUNK_SIZE_REQUIREMENTS:START -->
## Chunk size 要求

- **safe-linking 解码/编码本身不绑定一个固定尺寸**；它适用于使用受保护单链指针的 tcache class，以及 2.32～2.42 的 fastbin class。
- decrypt 至少要有两个同尺寸链节点；double-protect 需要两条可控 tcache 链/槽，PoC 使用物理 `0x20/0x30/0x40` 等 small classes。换 class 时只要仍在启用的 tcache/fastbin 范围，并同步更换所有请求和索引即可。
<!-- CHUNK_SIZE_REQUIREMENTS:END -->

## 版本变化

- 2.32 将 `(pos >> 12) ^ ptr` 用于 fastbin/tcache 单链，并检查 0x10 对齐。
- 2.42 引入 `tcache_put_n/get_n` 和 large tcache 后，`entries[idx]` 头指针还是明文；只有 chunk `next` 链中间槽按存储地址保护。double-protect 的 metadata 索引改变。
- 2.43 tcache TLS 哨兵/布局再变，使用独立 PoC。

## 从源码看

`PROTECT_PTR` 与 `REVEAL_PTR` 宏，以及 `tcache_put_n/get_n`。本目录判断以 GNU glibc 对应 tag/提交为准：[safe-linking 提交](https://sourceware.org/git/?p=glibc.git;a=commit;h=a1a486d70ebcc47a686ff5846875eacad0940e41)、[2.43 开发分支 malloc.c](https://github.com/bminor/glibc/blob/master/malloc/malloc.c)。

版本号只代表上游基线；发行版可能回移检查。实战请按附件 Build ID 对照源码。

## PoC

- [`poc_decrypt_2.32_2.43.c`](./poc_decrypt_2.32_2.43.c)：验证 decrypt–2.32–2.43 分支；成功判据见源码头部。
- [`poc_double_protect_2.32_2.41.c`](./poc_double_protect_2.32_2.41.c)：验证 double–protect–2.32–2.41 分支；成功判据见源码头部。
- [`poc_double_protect_2.42.c`](./poc_double_protect_2.42.c)：验证 double–protect–2.42 分支；成功判据见源码头部。
- [`poc_double_protect_2.43.c`](./poc_double_protect_2.43.c)：验证 double–protect–2.43 分支；成功判据见源码头部。

PoC 为 x86-64 教学程序，故意包含 UAF、越界或 double free。快速验证：

```bash
# 在目录根运行；把版本和文件替换为要测的分支
./tools/run_in_docker.sh 2.39 safe_linking/poc_double_protect_2.43.c
```

迁移时保留堆排布和检查绕过，只把漏洞模拟替换为题目的 edit/UAF/overflow；固定地址和最终目标必须重算。

## 调试

通用断点和排查顺序见 [根目录调试顺序](../README.md#调试顺序)。
