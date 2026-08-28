# House of Fun

## 结论

**一句话**：House of Fun 只是早期 Large Bin Attack 的历史名称——旧 largebin 插入直接信任 `fd/bk/fd_nextsize/bk_nextsize` 四个指针；2.30 起这套写法失效。

| 版本 | 你能拿到什么 | 备注 |
|---|---|---|
| **2.23～2.29** | 旧四指针 largebin 写，多个 heap/libc 指针写，本目录默认指这条 | 依赖 2.23～2.29 旧插入逻辑 |
| 2.30～2.41 | 迁移到"更小 victim"现代 Large Bin Attack | 2.30 新增 nextsize 链完整性检查；这是家族换实现，不是旧 Fun 延续 |
| 2.42+ | 无经典 largebin 任意目标写 | 2.42 连改进版打法也一并封堵 |

前置能力：旧 largebin UAF，能控制 victim 的 `fd/bk/fd_nextsize/bk_nextsize`。

<!-- PRIMITIVE_REQUIREMENTS:START -->
## 原语要求与版本边界

| 项目 | 本手法要求 |
|---|---|
| 最小输入原语 / 信息 | 旧 largebin UAF 控制 `fd/bk/fd_nextsize/bk_nextsize` |
| 关键环境与不变量 | 2.23～2.29 旧插入逻辑 |
| 最终输出原语 | 多个 heap/libc 指针写 |
| 版本边界应如何理解 | 2.30 硬封旧四指针形式，但 2.30～2.41 可迁移到现代“更小 victim”Large Bin Attack；这是家族换实现。2.42 再封经典任意目标写。 |
<!-- PRIMITIVE_REQUIREMENTS:END -->

<!-- CHUNK_SIZE_REQUIREMENTS:START -->
## Chunk size 要求

- 所有被当作 largebin 节点消费的 chunk 都必须有物理 `chunksize >= MIN_LARGE_SIZE (0x400)`，并按旧四指针插入分支所需的大小顺序布置；这不是 smallbin/tcache 尺寸上的攻击。
- 目录 PoC 使用 request `0x420`（物理 `0x430`）和 `0x500`（物理 `0x510`）等多种 large size。迁移时可换数值，但每个节点所在 largebin、比较顺序和触发 request 必须一起重算。
<!-- CHUNK_SIZE_REQUIREMENTS:END -->

## 从源码看

关键是 malloc.c 里 largebin 的排序插入逻辑，以及 2.30 和 2.42 各自新增的完整性检查。

最终触发点还在，不代表旧链成立：投递方式（怎么把伪造数据送到目标位置）、私有结构和控制流终点，都要按附件 libc/ld 的 Build ID 重新核对。

源码与背景：

- [glibc 2.29 `malloc.c`：旧 largebin 插入](https://github.com/bminor/glibc/blob/glibc-2.29/malloc/malloc.c)
- [glibc 2.30 `malloc.c`：现代较小 victim 分支](https://github.com/bminor/glibc/blob/glibc-2.30/malloc/malloc.c)
- [glibc 2.42 largebin nextsize 加固](https://sourceware.org/git/?p=glibc.git;a=commit;h=4cf2d869367e3813c6c8f662915dedb1f3830c53)
- [GNU glibc 当前开发分支](https://github.com/bminor/glibc/tree/master)
- [House of all 综述](https://roderickchan.github.io/zh-cn/2023-02-27-house-of-all-about-glibc-heap-exploitation/)
- [高版本 heap exploitation](https://roderickchan.github.io/zh-cn/2023-03-01-analysis-of-glibc-heap-exploitation-in-high-version/)

## PoC

- [`poc_2.23_2.29.c`](./poc_2.23_2.29.c)：可直接执行的旧版 largebin attack PoC。

这个 C 文件走真实堆管理器的代码路径；题目有专属堆布局时，参考 PoC 末尾的中文注释迁移就行。注意：这里验证的局部原语成功，不等于脱离题目就能直接 RCE。

## 迁移与调试

1. 先确认投递路径和最终触发点在目标程序的 Build ID 中都确实存在。
2. 把占位地址，以及 add/edit/free 的调用顺序，替换成题目实际提供的能力。
3. 在读取这些字段的消费函数处下断点，逐字段核对 size、对齐、safe-linking 编码、FILE/link_map 私有结构布局。
