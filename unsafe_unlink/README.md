# Unsafe Unlink（现代约束版）

## 结论

- 适用范围：**glibc 2.23～2.43**。
- 原语效果：借后向合并改写一个受害者指针，进而形成可控写。
- 前置能力：溢出伪造 free chunk、清 PREV_INUSE，并满足 `fd->bk == P && bk->fd == P`。

<!-- PRIMITIVE_REQUIREMENTS:START -->
## 原语要求与版本边界

| 项目 | 本手法要求 |
|---|---|
| 最小输入原语 / 信息 | heap overflow 伪造 free chunk 并清 `PREV_INUSE` |
| 关键环境与不变量 | `fd->bk==P && bk->fd==P`；2.26+/2.29+ size/prev_size 一致 |
| 最终输出原语 | 改写受害者指针，升级为受约束 AAW |
| 版本边界应如何理解 | 本范围没有删除 unlink 消费路径；2.26、2.29 是必须补齐的不变量，属于适配。若题目只有单字段写而不能建双链，则从一开始就不满足前置。 |
<!-- PRIMITIVE_REQUIREMENTS:END -->

<!-- CHUNK_SIZE_REQUIREMENTS:START -->
## Chunk size 要求

- 被 free 的 victim 必须进入会执行向后合并/`unlink_chunk` 的普通 free 路径，不能被 tcache 或 fastbin 截走；可选 `chunksize > tcache_max`，或选 `chunksize > get_max_fast()` 并先填满对应 tcache。
- fake previous chunk 的 `size` 必须按 `0x10` 对齐、`>= MINSIZE`，并精确等于 victim 的 `prev_size`。PoC 在无 tcache 的旧版用 `malloc(0x80) -> 0x90`，现代版用 `malloc(0x420) -> 0x430`。
<!-- CHUNK_SIZE_REQUIREMENTS:END -->

## 版本变化

- 现代 glibc 都有双向链检查，所以不再是古早任意 `FD/BK` 的无条件两次写。
- 2.29 增加 `chunksize(p) == prev_size(next_chunk(p))`，off-by-null 链需额外伪造/合并。
- 这套双链 unlink 本身不走 safe-linking，所以 2.32 不会直接封堵它。

## 从源码看

`unlink_chunk` 的 size/prev_size 与 fd/bk 两组一致性检查。本目录判断以 GNU glibc 对应 tag/提交为准：[2.43 开发分支 unlink_chunk](https://github.com/bminor/glibc/blob/master/malloc/malloc.c)、[2.29 null-byte 加固](https://sourceware.org/git/?p=glibc.git;a=commit;h=d6db68e66dff25d12c3bc5641b60cbd7fb6ab44f)。

版本号只代表上游基线；发行版可能回移检查。实战请按附件 Build ID 对照源码。

## PoC

- [`poc_2.23_2.25.c`](./poc_2.23_2.25.c)：验证 2.23–2.25 分支；成功判据见源码头部。
- [`poc_2.26_2.28.c`](./poc_2.26_2.28.c)：验证 2.26–2.28 分支；成功判据见源码头部。
- [`poc_2.29_2.43.c`](./poc_2.29_2.43.c)：验证 2.29–2.43 分支；成功判据见源码头部。

PoC 为 x86-64 教学程序，故意包含 UAF、越界或 double free。快速验证：

```bash
# 在目录根运行；把版本和文件替换为要测的分支
./tools/run_in_docker.sh 2.39 unsafe_unlink/poc_2.29_2.43.c
```

迁移时保留堆排布和检查绕过，只把漏洞模拟替换为题目的 edit/UAF/overflow；固定地址和最终目标必须重算。

## 调试

通用断点和排查顺序见 [根目录调试顺序](../README.md#调试顺序)。
