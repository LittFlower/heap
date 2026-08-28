# House of Einherjar

## 结论

- 适用范围：**glibc 2.23～2.43**。
- 原语效果：off-by-null 触发伪造后向合并，做出 chunk overlap/任意分配。
- 前置能力：off-by-null、堆地址泄露、可伪造前块双向链；高版本还需 tcache 链投毒。

<!-- PRIMITIVE_REQUIREMENTS:START -->
## 原语要求与版本边界

| 项目 | 本手法要求 |
|---|---|
| 最小输入原语 / 信息 | off-by-null/overflow 改 `prev_size` 与 `PREV_INUSE`；堆地址泄露 |
| 关键环境与不变量 | fake 前块的双向链完整，且 size/prev_size 一致；现代版本还需处理 tcache |
| 最终输出原语 | 后向合并产生 overlap/AAF |
| 版本边界应如何理解 | 2.26、2.29、2.32、2.43 都只是检查或路由适配；fake 前块后向合并的核心思想到 2.43 仍可满足。 |
<!-- PRIMITIVE_REQUIREMENTS:END -->

<!-- CHUNK_SIZE_REQUIREMENTS:START -->
## Chunk size 要求

- 被 free 的 victim 必须最终走**普通向后合并**，不能停在 tcache/fastbin；可选 `chunksize > get_max_fast()` 并填满对应 tcache，或直接选高于 tcache 上限的 class。
- fake previous chunk 的物理 `size` 必须按 `0x10` 对齐、不小于 `MINSIZE`，并精确等于 victim 的 `prev_size`；2.29+ 这是硬检查。现代 PoC 常用 `malloc(0xf8)`（物理 `0x100`）并填 tcache，旧分支也用过物理 `0x500`，都不是唯一值。
<!-- CHUNK_SIZE_REQUIREMENTS:END -->

## 版本变化

- 2.23～2.28 主要绕过 unlink 双链检查。
- 2.29 起还要满足 fake chunk size 等于后一块 prev_size。
- 2.32 起 tcache poisoning 需要 safe-linking 编码。
- 2.43 因 tcache 元数据布局变化调整布局，但原理还成立。

## 从源码看

`_int_free_merge_chunk` 的 PREV_INUSE 分支与 `unlink_chunk`。本目录判断以 GNU glibc 对应 tag/提交为准：[2.29 null-byte 加固](https://sourceware.org/git/?p=glibc.git;a=commit;h=d6db68e66dff25d12c3bc5641b60cbd7fb6ab44f)、[2.43 malloc.c](https://github.com/bminor/glibc/blob/master/malloc/malloc.c)。

版本号只代表上游基线；发行版可能回移检查。实战请按附件 Build ID 对照源码。

## PoC

- [`poc_2.23_2.25.c`](./poc_2.23_2.25.c)：验证 2.23–2.25 分支；成功判据见源码头部。
- [`poc_2.26_2.29.c`](./poc_2.26_2.29.c)：验证 2.26–2.29 分支；成功判据见源码头部。
- [`poc_2.30_2.31.c`](./poc_2.30_2.31.c)：验证 2.30–2.31 分支；成功判据见源码头部。
- [`poc_2.32_2.42.c`](./poc_2.32_2.42.c)：验证 2.32–2.42 分支；成功判据见源码头部。
- [`poc_2.43.c`](./poc_2.43.c)：验证 2.43 分支；成功判据见源码头部。

PoC 为 x86-64 教学程序，故意包含 UAF、越界或 double free。快速验证：

```bash
# 在目录根运行；把版本和文件替换为要测的分支
./tools/run_in_docker.sh 2.39 house_of_einherjar/poc_2.43.c
```

迁移时保留堆排布和检查绕过，只把漏洞模拟替换为题目的 edit/UAF/overflow；固定地址和最终目标必须重算。

## 调试

通用断点和排查顺序见 [根目录调试顺序](../README.md#调试顺序)。
