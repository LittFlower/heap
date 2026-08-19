# Sysmalloc Free Old Top（缩小 top 后由 malloc 间接 free）

## 结论

- 适用范围：**glibc 2.23～2.43，x86-64**。
- 前置能力：能够减小 top chunk 的 size，同时仍保持合法对齐、`PREV_INUSE` 标记和最低尺寸；之后能够申请一个超过伪 top 剩余空间的 chunk。
- 效果：不直接调用 `free(old_top)`，而是让 `sysmalloc` 去扩展 heap、建立 fencepost，再把旧 top 里可用的部分交给 `_int_free` 处理。这样就能制造出指定大小的 unsorted/small/tcache chunk，也是 House of Orange 与 House of Tangerine 底层依赖的一步。
- 与 House of Force 的区别：这里不是把 top size 改成 `-1` 再申请一个超大 chunk。2.29 加入的 `top size > system_mem` 检查封住了 Force 的路子，但并没有删除 `sysmalloc` 合法释放旧 top 的机制，所以这条手法依然可用。

<!-- PRIMITIVE_REQUIREMENTS:START -->
## 原语要求与版本边界

| 项目 | 本手法要求 |
|---|---|
| 最小输入原语 / 信息 | 缩小 top size，并触发超过伪 top 的申请 |
| 关键环境与不变量 | top size 合法对齐、`PREV_INUSE`、最低尺寸；sysmalloc 能扩展 |
| 最终输出原语 | 无显式 free 地制造 old-top unsorted/small/tcache chunk |
| 版本边界应如何理解 | 2.29 封的是 Force 的超大 top，不是合法缩小 top；2.43 fastbin 删除也不删 old-top 回收。属于持续适配。 |
<!-- PRIMITIVE_REQUIREMENTS:END -->

## 从源码角度理解

当 `_int_malloc` 发现 top 不够满足请求时，会进入 `sysmalloc`。如果 heap 扩展后的新区域不能直接与旧 top 连续合并，`sysmalloc` 会依次做这几件事：

1. 从旧 top 的尾部扣掉两份 chunk header，用作 fencepost；
2. 把剩下的 `old_size` 向下对齐；
3. 如果这个剩余大小至少达到 `MINSIZE`，就调用 `_int_free(av, old_top, 1)` 把它释放掉。

PoC 让旧 top 的末端仍然落在 page 边界上，并把它的物理大小精确地缩成：

```text
CHUNK_HDR_SZ + MALLOC_ALIGNMENT + wanted_freed_chunk
```

在 x86-64 上 header 是 `0x10`、alignment 是 `0x10`，所以物理大小算出来是 `0x170`，size 字段带上 `PREV_INUSE` 后就是 `0x171`。扣掉 `0x20` 的 fencepost 之后得到 `wanted_freed_chunk=0x150`，接下来 `malloc(0x140)` 就会重新取回这段位于低地址的旧 top。

## 版本变化

| 版本 | 与本原语相关的变化 |
|---|---|
| 2.23～2.25 | 没有 tcache，旧 top 通常会先落进 unsorted bin |
| 2.26～2.28 | 引入了 tcache，但 sysmalloc 释放旧 top 的这一步依然保留 |
| 2.29 | top size 加入了 `system_mem` 的上界检查，House of Force 因此失效；但本 PoC 用的是缩小后仍合法的 top size，所以不受影响，照样可用 |
| 2.32 | safe-linking 只影响后续单链指针的编码方式，不影响制造 free chunk 这一步 |
| 2.42 | large tcache 和元数据的重构改变了后续的投递选择，但不影响 sysmalloc 的 fencepost 处理和 old-top 释放 |
| 2.43 | fastbin 路径被删除；本 PoC 中 `0x150` 大小的 chunk 会走其他正常的回收路径，原语依然可用 |

这条链非常依赖 page 边界和当前 top 的实际大小。PoC 会先做一次小分配，从紧邻的 top header 里读出真实的 size，再动态计算 padding；不要把其中的 `allocated_size` 当成所有题目通用的常数。

## PoC

- [`poc_2.23_2.43.c`](./poc_2.23_2.43.c)：动态探测 top 的实际状态，在保持 top 末端 page-aligned 的前提下把它的物理大小缩为 `0x170`，再用一次更大的 malloc 触发 `sysmalloc`，最后断言旧 top 确实已经能被重新分配出来。

运行：

```bash
./tools/run_in_docker.sh 2.23 sysmalloc_free_old_top/poc_2.23_2.43.c
./tools/run_in_docker.sh 2.43 sysmalloc_free_old_top/poc_2.23_2.43.c
```

## 迁移到实际 CTF 题目时的提示

1. 先泄露或预测出 heap/top 地址，算出页面低 12 位；ASLR 不会改变同一 page 内的低位部分。
2. 要确保伪 top 的末端仍然是 page-aligned 的，这是 `sysmalloc` 内部断言会检查的关键条件。
3. `new_top_size` 必须保留 `PREV_INUSE` 标记，并且满足 `MINSIZE`；不要照搬 House of Force 里用的 `-1`。
4. old top 被 `_int_free` 释放后具体去哪个 bin，取决于大小、tcache 状态和 glibc 版本；建议把“制造原语”和“最终投递到哪个 bin”分开设计，不要混在一起考虑。

## 源码与补充资料

- [glibc 2.23 `sysmalloc`](https://github.com/bminor/glibc/blob/glibc-2.23/malloc/malloc.c)
- [glibc 当前 `malloc.c`](https://github.com/bminor/glibc/blob/master/malloc/malloc.c)
- [how2heap `sysmalloc_int_free.c`](https://github.com/shellphish/how2heap/blob/master/glibc_2.43/sysmalloc_int_free.c)
- [看雪《CTF 中 glibc 堆利用及 IO_FILE 总结》离线存档](/Users/flower/Zotero/storage/QPI8VQE6/thread-272098-1.html)
