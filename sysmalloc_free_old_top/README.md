# Sysmalloc Free Old Top（缩小 top 后由 malloc 间接 free）

## 结论

- 适用范围：**glibc 2.23～2.43，x86-64**。
- 前置能力：能够减小 top chunk 的 size，同时保留合法对齐、`PREV_INUSE` 和最低大小；随后能够申请超过伪 top 剩余空间的 chunk。
- 效果：不直接调用 `free(old_top)`，而是让 `sysmalloc` 扩展 heap、建立 fencepost，并把旧 top 的可用部分交给 `_int_free`。它可制造指定大小的 unsorted/small/tcache chunk，也是 House of Orange 与 House of Tangerine 的底层步骤。
- 与 House of Force 不同：这里不是把 top size 改成 `-1` 后计算超大 malloc。2.29 的 `top size > system_mem` 检查封住 Force，但没有删除 `sysmalloc` 合法释放旧 top 的机制。

<!-- PRIMITIVE_REQUIREMENTS:START -->
## 原语要求与版本边界

| 项目 | 本手法要求 |
|---|---|
| 最小输入原语 / 信息 | 缩小 top size，并触发超过伪 top 的申请 |
| 关键环境与不变量 | top size 合法对齐、`PREV_INUSE`、最低尺寸；sysmalloc 能扩展 |
| 最终输出原语 | 无显式 free 地制造 old-top unsorted/small/tcache chunk |
| 版本边界应如何理解 | 2.29 封的是 Force 的超大 top，不是合法缩小 top；2.43 fastbin 删除也不删 old-top 回收。属于持续适配。 |
<!-- PRIMITIVE_REQUIREMENTS:END -->

## 从源码看

当 `_int_malloc` 发现 top 不够满足请求时进入 `sysmalloc`。若 heap 扩展后的新区域不能直接与旧 top 连续合并，`sysmalloc` 会：

1. 从旧 top 尾部扣掉两份 chunk header 作为 fencepost；
2. 把剩余的 `old_size` 向下对齐；
3. 若该剩余大小至少为 `MINSIZE`，调用 `_int_free(av, old_top, 1)`。

PoC 让旧 top 的末端仍落在 page 边界，并把它的物理大小精确缩成：

```text
CHUNK_HDR_SZ + MALLOC_ALIGNMENT + wanted_freed_chunk
```

其中在 x86-64 上 header 为 `0x10`、alignment 为 `0x10`，所以物理大小是 `0x170`，size 字段含 `PREV_INUSE` 时为 `0x171`。扣除 `0x20` fencepost 后得到 `wanted_freed_chunk=0x150`，接着 `malloc(0x140)` 会重新取回这段低地址旧 top。

## 版本变化

| 版本 | 与本原语相关的变化 |
|---|---|
| 2.23～2.25 | 无 tcache；旧 top 通常先进入 unsorted bin |
| 2.26～2.28 | 引入 tcache，但 sysmalloc 释放旧 top 的步骤仍在 |
| 2.29 | top size 加入 `system_mem` 上界检查，House of Force 失效；本 PoC 使用缩小后的合法 top size，仍可用 |
| 2.32 | safe-linking 只影响后续单链指针编码，不影响制造 free chunk |
| 2.42 | large tcache/元数据重构改变后续投递选择，不改变 sysmalloc 的 fencepost/old-top free |
| 2.43 | fastbin 路径删除；本 PoC 的 `0x150` chunk 可进入其他正常回收路径，原语仍可用 |

这条链非常依赖 page 边界与当前 top 大小。PoC 先进行一次小分配，从紧邻的 top header 读出真实 size，再动态计算 padding；不能把其中的 `allocated_size` 当成所有题目的常数。

## PoC

- [`poc_2.23_2.43.c`](./poc_2.23_2.43.c)：动态探测 top，在保持 top 末端 page-aligned 的前提下把物理大小缩为 `0x170`，用更大 malloc 触发 `sysmalloc`，最后断言旧 top 已能被重新分配。

运行：

```bash
./tools/run_in_docker.sh 2.23 sysmalloc_free_old_top/poc_2.23_2.43.c
./tools/run_in_docker.sh 2.43 sysmalloc_free_old_top/poc_2.23_2.43.c
```

## CTF 迁移提示

1. 泄露或预测 heap/top，计算页面低 12 位；ASLR 不会改变同一 page 内的低位。
2. 保证伪 top 末端仍 page-aligned，这是 `sysmalloc` 内部断言的重要条件。
3. `new_top_size` 必须保留 `PREV_INUSE`，并满足 `MINSIZE`；不要照搬 House of Force 的 `-1`。
4. old top 被 `_int_free` 后去了哪个 bin 取决于大小、tcache 状态和版本；制造原语与最终投递要分开设计。

## 源码与补充资料

- [glibc 2.23 `sysmalloc`](https://github.com/bminor/glibc/blob/glibc-2.23/malloc/malloc.c)
- [glibc 当前 `malloc.c`](https://github.com/bminor/glibc/blob/master/malloc/malloc.c)
- [how2heap `sysmalloc_int_free.c`](https://github.com/shellphish/how2heap/blob/master/glibc_2.43/sysmalloc_int_free.c)
- [看雪《CTF 中 glibc 堆利用及 IO_FILE 总结》离线存档](/Users/flower/Zotero/storage/QPI8VQE6/thread-272098-1.html)
