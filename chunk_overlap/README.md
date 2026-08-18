# Chunk Overlap（堆块重叠原语）

## 结论

“chunk overlap”描述的是结果，不是一条永远相同的链。本目录把补充资料中最容易混淆的两个 size overwrite 变体拆开：

| 子型 | 上游版本 | 核心区别 |
|---|---|---|
| free 后篡改 unsorted chunk size | **2.23～2.28** | victim 已在 unsorted bin；2.29 新增 unsorted next-chunk 完整性检查后失效 |
| free 前篡改 in-use chunk size | **2.23～2.43** | 伪 size 正好跨过中间 chunk 到达 top，随后 free 与 top 合并；不走被 2.29 封住的旧 unsorted 取出条件 |

另有两类相邻技术不重复收录：off-by-null 向后合并见 [House of Einherjar](../house_of_einherjar/README.md)，mmap chunk 重叠见 [House of Muney](../house_of_muney/README.md)。

<!-- PRIMITIVE_REQUIREMENTS:START -->
## 原语要求与版本边界

| 项目 | 本手法要求 |
|---|---|
| 最小输入原语 / 信息 | 相邻 heap overflow/UAF，可改 chunk `size` |
| 关键环境与不变量 | 伪边界最终必须落到合法 next/top，并满足 `prev_size`/`system_mem` |
| 最终输出原语 | 两个活动指针覆盖同一物理区域，继而改对象字段 |
| 版本边界应如何理解 | freed-unsorted 子型 2.29 被完整性检查封住；这是该弱布局的硬边界。free 前改 in-use size→真实 top 的同一“重叠目标”仍到 2.43，属于换布局而非只改偏移。 |
<!-- PRIMITIVE_REQUIREMENTS:END -->

## 旧式 freed-unsorted size overwrite

布局如下：

```text
p1 | p2(size=0x500, freed to unsorted) | p3(size=0x80) | top
         \-- UAF/overflow: size 0x500 -> 0x580 --/
```

再次申请 `0x578` 时，malloc 把伪装成 `0x580` 的 p2 整块返回，于是新 p4 覆盖仍在使用的 p3。

glibc 2.29 合入提交 `b90ddd`。`_int_malloc` 从 unsorted bin 取 victim 时新增两项关键检查：

```c
if (chunksize_nomask(next) < CHUNK_HDR_SZ
    || chunksize_nomask(next) > av->system_mem)
  malloc_printerr("malloc(): invalid next size (unsorted)");
if ((prev_size(next) & ~(SIZE_BITS)) != size)
  malloc_printerr("malloc(): mismatching next->prev_size (unsorted)");
```

旧 PoC 改大 p2.size 后，伪造的 `next` 和真实物理边界不再一致，因而从 2.29 起中止。

## 现代 in-use size overwrite

布局改成：

```text
p1 | p2(size=0x500, still in use) | p3(size=0x80) | top
         \-- overflow: size 0x500 -> 0x580 --/
```

这里先改 p2.size，再 `free(p2)`；伪造后的 next 恰好是真实 top。`free` 认为 p2 与 top 相邻并把它们合并，新分配从 p2 起返回，覆盖中间仍在使用的 p3。它规避的是特定的 2.29 unsorted 取出检查，并不意味着任意伪 size 都能通过现代 `_int_free_merge_chunk` 的 size、`prev_inuse`、top 与 system_mem 检查。

## PoC

- [`poc_freed_unsorted_size_2.23_2.28.c`](./poc_freed_unsorted_size_2.23_2.28.c)：旧式 UAF/overflow 修改已释放 p2.size；2.29 起应报 unsorted 完整性错误。
- [`poc_inuse_size_2.23_2.43.c`](./poc_inuse_size_2.23_2.43.c)：free 之前改大 p2.size，跨过 p3 与 top 合并；两个同时存活的指针覆盖同一内存。

运行：

```bash
./tools/run_in_docker.sh 2.23 chunk_overlap/poc_freed_unsorted_size_2.23_2.28.c
./tools/run_in_docker.sh 2.43 chunk_overlap/poc_inuse_size_2.23_2.43.c
```

## CTF 迁移提示

1. 用 chunk size（不是用户请求值）画物理边界；x86-64 默认按 `0x10` 对齐。
2. 确认目标 size 不会落入 tcache：本 PoC 使用 `0x500` 级 chunk。
3. 把 p3 当作目标对象：从重叠的大 chunk 改 p3 的指针、长度或 vtable。
4. 在 `free`、`_int_free_merge_chunk`、`_int_malloc` 下断点，逐项核对伪 next、top、`prev_inuse` 与 `system_mem`。

## 源码与补充资料

- [glibc 提交 b90ddd：unsorted bin integrity checks](https://sourceware.org/git/?p=glibc.git;a=commitdiff;h=b90ddd08f6dd688e651df9ee89ca3a69ff88cd0c)
- [glibc 2.29 `malloc.c`](https://github.com/bminor/glibc/blob/glibc-2.29/malloc/malloc.c)
- [how2heap `overlapping_chunks.c`](https://github.com/shellphish/how2heap/blob/master/glibc_2.43/overlapping_chunks.c)
- [ALateFall Heap 目录](https://github.com/ALateFall/blogs/tree/main/system/Heap)
- [看雪《CTF 中 glibc 堆利用及 IO_FILE 总结》离线存档](/Users/flower/Zotero/storage/QPI8VQE6/thread-272098-1.html)
