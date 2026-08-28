# House of Rabbit

## 结论

**一句话**：能让 fastbin 里的小 victim 指向大 fake chunk，再触发 `malloc_consolidate`，fake chunk 就被转入 unsorted/largebin；2.27 起经典跨尺寸链失效。

| 版本 | 你能拿到什么 | 备注 |
|---|---|---|
| 2.23～2.25 | consolidate 把大 fake chunk 转入 unsorted/largebin，取得大范围 overlap | 无 tcache |
| **2.26** | 同上 | 引入 tcache，须先填满 |
| 2.27～2.42 | 经典跨尺寸链失效 | `malloc_consolidate` 增加 `fastbin_index(chunksize(p))` 一致性检查；2.43 删除 fastbin |

<!-- PRIMITIVE_REQUIREMENTS:START -->
## 原语要求与版本边界

| 项目 | 本手法要求 |
|---|---|
| 最小输入原语 / 信息 | fastbin UAF 把小 victim 指向大 fake chunk，可触发 consolidate |
| 关键环境与不变量 | 跨 size fastbin 链在 consolidate 时不被 index/size 拒绝 |
| 最终输出原语 | 把大 fake chunk 转入 unsorted/largebin，取得大范围 overlap |
| 版本边界应如何理解 | 2.27 fastbin size/index 一致性检查硬封经典跨尺寸链。改用真实同尺寸节点再造 overlap 是另一实现，不能只改偏移。 |
<!-- PRIMITIVE_REQUIREMENTS:END -->

<!-- CHUNK_SIZE_REQUIREMENTS:START -->
## Chunk size 要求

- 必须同时控制两个不同范围：一个真实 **fastbin** victim，以及一个伪造的 **large chunk**。PoC 分别用 `malloc(0x18) -> chunksize 0x20` 和 fake `chunksize=0x420`。
- 还需一次 large request 触发 `malloc_consolidate`（PoC 为 `0x1000`），随后用与 fake large chunk 精确匹配的请求取回它（`malloc(0x410) -> 0x420`）。不能只控制单一 request 大小。
<!-- CHUNK_SIZE_REQUIREMENTS:END -->

## 从源码看

malloc/malloc.c 的 malloc_consolidate，对比 glibc-2.26 与 glibc-2.27。

源码与背景：

- [glibc 2.26 `malloc_consolidate`](https://github.com/bminor/glibc/blob/glibc-2.26/malloc/malloc.c)
- [glibc 2.27 `malloc_consolidate`](https://github.com/bminor/glibc/blob/glibc-2.27/malloc/malloc.c)
- [GNU glibc 当前开发分支](https://github.com/bminor/glibc/tree/master)
- [House of all 综述](https://roderickchan.github.io/zh-cn/2023-02-27-house-of-all-about-glibc-heap-exploitation/)
- [高版本 heap exploitation](https://roderickchan.github.io/zh-cn/2023-03-01-analysis-of-glibc-heap-exploitation-in-high-version/)

## PoC

- [`poc_2.23_2.25.c`](./poc_2.23_2.25.c)：无 tcache
- [`poc_2.26.c`](./poc_2.26.c)：填满 tcache

C 文件验证的是真实堆管理器路径；要迁到题目专属布局，就按 PoC 末尾的中文注释来。局部原语跑通了，不等于脱离题目就有 RCE。

## 迁移与调试

1. 先确认投递路径和最终触发点在目标 Build ID 中都存在。
2. 把占位地址和 add/edit/free 顺序替换成题目能力。
3. 在消费函数下断点，逐字段核对 size、对齐、safe-linking、FILE/link_map 私有布局。
