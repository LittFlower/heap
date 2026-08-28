# Fastbin Dup

## 结论

- 适用范围：**glibc 2.23～2.42；2.43 失效**。
- 原语效果：通过 A→B→A 的 double free 环，让两个活动指针别名到同一 chunk。
- 前置能力：double free；2.26+ 还要能避开或耗尽 tcache；2.32+ 的后续链投毒需要堆地址泄露。

<!-- PRIMITIVE_REQUIREMENTS:START -->
## 原语要求与版本边界

| 项目 | 本手法要求 |
|---|---|
| 最小输入原语 / 信息 | A-B-A double free；2.26+ 可绕/耗尽 tcache |
| 关键环境与不变量 | 同尺寸；2.32+ 后续 poisoning 需 heap page |
| 最终输出原语 | 重复活动指针/别名 chunk |
| 版本边界应如何理解 | 2.26～2.42 是 tcache 路由与 safe-linking **适配**；2.43 删除 fastbin，形成消费路径硬边界。Botcake/tcache dup 能给相似输出，但属于另一条路径。 |
<!-- PRIMITIVE_REQUIREMENTS:END -->

<!-- CHUNK_SIZE_REQUIREMENTS:START -->
## Chunk size 要求

- A、B 和后续取回请求必须属于**同一个 fastbin size class**：物理 `chunksize` 按 `0x10` 对齐，且 `MINSIZE <= chunksize <= get_max_fast()`。
- 没有某个唯一必选尺寸；PoC 的 `malloc(8)`/`malloc(0x18)` 都得到物理 `0x20`。换成其他 fastbin class 时，填充 tcache、guard 和所有消费请求也要一起换成同一 class。
<!-- CHUNK_SIZE_REQUIREMENTS:END -->

## 版本变化

- 2.26 引入 tcache：free 默认先进入 tcache，PoC 用填满 tcache 与 `calloc` 绕到 fastbin。
- 2.41 的 `calloc` 也走 tcache 快路径，必须在取 fastbin 前显式耗尽 tcache。
- 2.43 开发分支提交 `bf1015f` 删除 fastbin 的分配与释放路径，A→B→A 不再可消费。

## 从源码看

`_int_free_chunk` 的 fastbin 入链、`_int_malloc` 的 fastbin 出链，以及 2.43 删除它们的提交。本目录判断以 GNU glibc 对应 tag/提交为准：[glibc 2.42 malloc.c](https://github.com/bminor/glibc/blob/glibc-2.42/malloc/malloc.c)、[2.43 fastbin 删除](https://sourceware.org/git/?p=glibc.git;a=commit;h=bf1015fb2d7e4057925481960626533f8571a2fb)。

版本号只代表上游基线；发行版可能回移检查。实战请按附件 Build ID 对照源码。

## PoC

- [`poc_2.23_2.25.c`](./poc_2.23_2.25.c)：验证 2.23–2.25 分支；成功判据见源码头部。
- [`poc_2.26_2.40.c`](./poc_2.26_2.40.c)：验证 2.26–2.40 分支；成功判据见源码头部。
- [`poc_2.41_2.42.c`](./poc_2.41_2.42.c)：验证 2.41–2.42 分支；成功判据见源码头部。
- [`poc_tcache_stash_2.26_2.42.c`](./poc_tcache_stash_2.26_2.42.c)：验证 tcache–stash–2.26–2.42 分支；成功判据见源码头部。

PoC 为 x86-64 教学程序，故意包含 UAF、越界或 double free。快速验证：

```bash
# 在目录根运行；把版本和文件替换为要测的分支
./tools/run_in_docker.sh 2.39 fastbin_dup/poc_tcache_stash_2.26_2.42.c
```

迁移时保留堆排布和检查绕过，只把漏洞模拟替换为题目的 edit/UAF/overflow；固定地址和最终目标必须重算。

## 调试

通用断点和排查顺序见 [根目录调试顺序](../README.md#调试顺序)。
