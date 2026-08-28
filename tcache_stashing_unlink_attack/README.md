# Tcache Stashing Unlink Attack（Smallbin Attack）

## 结论

- 适用范围：**glibc 2.26～2.40；2.41 起这套 PoC 失效**。
- 原语效果：任意地址写 main_arena 指针，还能把假节点 stash 到 tcache 后分配。
- 前置能力：控制 smallbin 的 `bk`；目标附近可写；对应 tcache 为空；常用 calloc 触发。

<!-- PRIMITIVE_REQUIREMENTS:START -->
## 原语要求与版本边界

| 项目 | 本手法要求 |
|---|---|
| 最小输入原语 / 信息 | UAF 改 smallbin victim `bk` |
| 关键环境与不变量 | 目标附近可写/对齐；目标 tcache 有空位；通常 calloc 触发 |
| 最终输出原语 | main_arena 指针写 + fake 节点进 tcache/AAF |
| 版本边界应如何理解 | 2.41 删除旧 exact-smallbin stashing 循环，形成消费路径硬边界；Lore 直接 smallbin unlink 仍活，但不是 TSU。 |
<!-- PRIMITIVE_REQUIREMENTS:END -->

<!-- CHUNK_SIZE_REQUIREMENTS:START -->
## Chunk size 要求

- victim 必须处于一个物理 `chunksize < 0x400` 的 smallbin class，且同一 class 的 tcache 还要有空槽；真实节点、`calloc` 触发与最终 `malloc` 必须精确同尺寸。
- PoC 用 `malloc(0x90) -> chunksize 0xa0`。通常选择高于 `get_max_fast()` 的 class 以便直接走 smallbin；换值时要重做 tcache 填充与 smallbin 排序。
- 旧 stashing 循环不会单独验证被 `bk` 引入的 fake 节点 `size`；fake 区域的硬要求是对应 `bk/fd` 槽可写以及最终 user 地址 0x10 对齐。
<!-- CHUNK_SIZE_REQUIREMENTS:END -->

## 版本变化

- 2.26～2.39/2.40 利用 smallbin→tcache 预填充循环。
- 2.32+ 目标必须对齐，但 smallbin 双链本身不使用 safe-linking。
- 2.41 提交 `e2436d6` 重构释放小块/预填充流程，how2heap 不再提供这套 PoC。

## 从源码看

smallbin 精确大小分支中的 tcache stashing 循环及 `bck->fd` 更新。本目录判断以 GNU glibc 对应 tag/提交为准：[2.40 malloc.c](https://github.com/bminor/glibc/blob/glibc-2.40/malloc/malloc.c)、[2.41 smallbin 重构](https://sourceware.org/git/?p=glibc.git;a=commit;h=e2436d6f5aa47ce8da80c2ba0f59dfb9ffde08f3)。

版本号只代表上游基线；发行版可能回移检查。实战请按附件 Build ID 对照源码。

## PoC

- [`poc_2.26_2.40.c`](./poc_2.26_2.40.c)：验证 2.26–2.40 分支；成功判据见源码头部。

PoC 为 x86-64 教学程序，故意包含 UAF、越界或 double free。快速验证：

```bash
# 在目录根运行；把版本和文件替换为要测的分支
./tools/run_in_docker.sh 2.39 tcache_stashing_unlink_attack/poc_2.26_2.40.c
```

迁移时保留堆排布和检查绕过，只把漏洞模拟替换为题目的 edit/UAF/overflow；固定地址和最终目标必须重算。

## 调试

通用断点和排查顺序见 [根目录调试顺序](../README.md#调试顺序)。
