# Safe-Linking 配套原语

## 结论

- 适用范围：**glibc 2.32～2.43**。
- 原语效果：恢复被 safe-linking 保护过的 heap 指针，或者通过 double-protect 手法在不依赖任何泄露的情况下重新完成链接。
- 前置能力：至少要能泄露一次编码后的指针；double-protect 还额外需要控制 tcache 的元数据或链表结构。

<!-- PRIMITIVE_REQUIREMENTS:START -->
## 原语要求与版本边界

| 项目 | 本手法要求 |
|---|---|
| 最小输入原语 / 信息 | 泄露 encoded next；double-protect 需控制两层链/metadata |
| 关键环境与不变量 | 已知存储槽地址或可构造两次 XOR |
| 最终输出原语 | 恢复 heap pointer；生成合法 encoded pointer；无泄露重链接 |
| 版本边界应如何理解 | 2.32 前不是“失效”，而是没有这项缓解、也不需要解码；2.42/2.43 只改具体 metadata/链位置。 |
<!-- PRIMITIVE_REQUIREMENTS:END -->

## 版本变化

- 2.32 开始对 fastbin/tcache 的单链使用 `(pos >> 12) ^ ptr` 编码，并检查 0x10 对齐。
- 2.42 引入 `tcache_put_n/get_n` 和 large tcache 之后，`entries[idx]` 这个头指针仍然是明文存放的，只有 chunk 的 `next` 链中间那些槽位是按存储地址保护的。这也让 double-protect 用到的 metadata 索引发生了变化。
- 2.43 tcache 的 TLS 哨兵和布局又有变动，因此需要单独的 PoC 来适配。

## 从源码角度理解

关键在于 `PROTECT_PTR` 与 `REVEAL_PTR` 这两个宏，以及 `tcache_put_n/get_n` 的实现。本目录的版本判断以 GNU glibc 对应的 tag/提交为准：[safe-linking 提交](https://sourceware.org/git/?p=glibc.git;a=commit;h=a1a486d70ebcc47a686ff5846875eacad0940e41)、[2.43 开发分支 malloc.c](https://github.com/bminor/glibc/blob/master/malloc/malloc.c)。

这里的版本号只代表上游基线，发行版可能会把某些检查回移到更早的版本里。实战中还是要按附件的 Build ID 去对照源码确认。

## PoC

- [`poc_decrypt_2.32_2.43.c`](./poc_decrypt_2.32_2.43.c)：验证 decrypt–2.32–2.43 分支；成功判据见源码头部。
- [`poc_double_protect_2.32_2.41.c`](./poc_double_protect_2.32_2.41.c)：验证 double–protect–2.32–2.41 分支；成功判据见源码头部。
- [`poc_double_protect_2.42.c`](./poc_double_protect_2.42.c)：验证 double–protect–2.42 分支；成功判据见源码头部。
- [`poc_double_protect_2.43.c`](./poc_double_protect_2.43.c)：验证 double–protect–2.43 分支；成功判据见源码头部。

这些 PoC 是 x86-64 上的教学程序，故意包含 UAF、越界或 double free。快速验证方式：

```bash
# 在目录根运行；把版本和文件替换为要测的分支
./tools/run_in_docker.sh 2.39 safe_linking/poc_double_protect_2.43.c
```

迁移到实际题目时，保留堆排布和检查绕过的思路，只把其中的漏洞模拟替换成题目里实际的 edit/UAF/overflow 操作；固定地址和最终目标都需要重新计算。

## 调试

通用断点和排查顺序见 [根目录调试顺序](../README.md#调试顺序)。
