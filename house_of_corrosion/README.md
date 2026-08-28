# House of Corrosion

## 结论

**一句话**：能放大 `global_max_fast`，就能把 `main_arena.fastbinsY` 当成 libc 内部的相对读写/指针搬运数组；2.37 起这个放大本身被堵死。

| 版本 | 你能拿到什么 | 备注 |
|---|---|---|
| 2.27 原版 | 完整链：unsortedbin attack 放大 `global_max_fast` → 搬运 stderr → `_IO_strfile._allocate_buffer` 回调 + one_gadget | 绑定 Ubuntu 18.04 特定构建（Build ID 强相关），不外推；2.28 加固 unsorted removal 并删除旧 `_IO_strfile` 回调，这条链到此结束 |
| 2.29 Addendum A | 完整链：WAF + tcache poison 搬运 → `_rtld_global/link_map` 非默认命名空间绕过 `_IO_vtable_check` → 堆上伪造 vtable | 绑定 Ubuntu 19.04 特定构建；这个构建的 IO vtable 段权限异常，结论不可外推 |
| **2.27～2.36**（原语窗口） | 超大 fastbin 越界索引 → libc 内相对读写 + "源槽→中转区→目标槽"指针搬运 | 2.32～2.36 需另处理 safe-linking（要提前知道堆页地址）；作者未发布这些版本的端到端链 |
| 2.37～2.43 | 无 | `global_max_fast` 缩为 `uint8_t`，远端 fastbin 指针搬运结束；2.43 删除 fastbin 是更晚的变化，不是失效的第一个边界 |

前置能力：能写大 `global_max_fast`、fastbin UAF/double free、libc 地址泄露；完整链与 Build ID 强相关。

<!-- PRIMITIVE_REQUIREMENTS:START -->
## 原语要求与版本边界

| 项目 | 本手法要求 |
|---|---|
| 最小输入原语 / 信息 | 能写大 `global_max_fast`；fastbin UAF/double free；libc 地址泄露/相对布局 |
| 关键环境与不变量 | 目标必须落在可由超大尺寸 fastbin 越界索引覆盖的 libc/ld 区域；与 Build ID 强相关 |
| 最终输出原语 | 在 libc 内按相对偏移写入堆指针，以及“源槽→可编辑中转区→目标槽”的指针搬运 |
| 版本边界应如何理解 | 2.32 的 safe-linking 只是额外适配；2.37 将 `global_max_fast` 缩为 `uint8_t`，无法再用远端 fastbin 索引越过 `main_arena`，核心投递就此失效。2.27/2.29 完整链仍只对作者的构建负责。 |
<!-- PRIMITIVE_REQUIREMENTS:END -->

<!-- CHUNK_SIZE_REQUIREMENTS:START -->
## Chunk size 要求

- **要求能制造并 free 目标地址反算出的精确超大物理尺寸**，不是只要“有一个 fastbin 小块”。x86-64 上 `chunksize = 2 * (target - fastbinsY) + 0x20`，再由该物理尺寸反算 request；每个源槽、中转槽和目标槽都可能对应不同尺寸。
- 在扩大 `global_max_fast` 前通常要先申请好承载 victim 的正常 chunk，再用 WAF/overlap 改其 header size；否则直接申请超大反算值可能先走 largebin/sysmalloc，无法建立预期状态。
- `global_max_fast` 必须至少覆盖最大的伪 `chunksize`。2.37 起它只能表示很小范围，因此无法满足远端目标所需的尺寸。
<!-- CHUNK_SIZE_REQUIREMENTS:END -->

## 从源码看

### 共同堆管理器原语

在 x86-64 上：

```c
fastbin_index(size) = (size >> 4) - 2;
target - &fastbinsY[0] = fastbin_index(size) * 8;
size = 2 * (target - &fastbinsY[0]) + 0x20;
```

把 `global_max_fast` 放大到足够大，再 free 一个带这个伪造 size 的 victim，`fastbinsY[index]` 这个“数组槽”就会落在任意后续的 libc/ld 地址上。之后靠 WAF 反复改写 victim 的 size 字段，可把某槽旧值带入 `victim->fd`，再搬到另一个槽。

2.32 起只有 fastbin 头槽还保存原始 chunk 指针，chunk 内部的 `fd` 变成 `raw ^ (&fd >> 12)`，2.27/2.29 直接搬运明文指针的写法不能原样延续。2.37 起 `global_max_fast` 变成 `uint8_t`，最大 0xff；代回公式后覆盖范围只到 `fastbinsY` 后约 0x6f 字节，到不了 stderr、rtld 或一般 libc 目标。这才是本原语真正的硬性终点。

### 两条已发布完整链

- **2.27 原版**：原文固定在 Ubuntu 18.04 的 Build ID `b417c0ba7cc5cf06d1d1bed6652cedb9253c60d0` 上。先用 unsortedbin attack 放大 `global_max_fast`，再搬运 stderr 字段，最后利用 2.27 还会消费的 `_IO_strfile._allocate_buffer` 回调和构建相关的 one_gadget 完成利用。
- **2.29 Addendum A**：固定在 Ubuntu 19.04 的 Build ID `d561ec515222887a1e004555981169199d841024` 上。这一版改用 WAF 配合 tcache poison 取代原来的 unsorted 写；再搬运 `_rtld_global/link_map` 字段，造出非默认命名空间，绕过 `_IO_vtable_check` 后就能使用堆上伪造 vtable。原作者特别说明，这个 Ubuntu 构建的 IO vtable 段权限存在异常，结论不能外推到其他构建。

原语本身可以改造，不等于完整链能跨版本使用。2.30/2.31 需重新设计投递方式和最终 gadget，2.32～2.36 还得额外解决 safe-linking。本项目未找到作者针对这些版本发布的端到端链，因此不再把 2.29～2.33 笼统标成统一可用。

源码里还能走到最终触发点，不代表旧利用链还成立。投递方式、私有结构和控制流终点都要按附件 libc/ld 的 Build ID 复核。

源码与背景：

- [House of Corrosion 原始仓库](https://github.com/CptGibbon/House-of-Corrosion)
- [ptr-yudai 的 2.27 sample challenge/exploit](https://github.com/ptr-yudai/House-of-Corrosion)
- [glibc 2.36 `malloc.c`：fastbinsY/global_max_fast](https://github.com/bminor/glibc/blob/glibc-2.36/malloc/malloc.c)
- [glibc 2.37：`global_max_fast` 改为 `uint8_t`](https://sourceware.org/git/?p=glibc.git;a=commit;h=15a94e6668a6d7c5697e805d8d67f1d102d0d52e)
- [glibc 2.43：删除 fastbin 基础设施](https://sourceware.org/git/?p=glibc.git;a=commit;h=bf1015fb2d7e4057925481960626533f8571a2fb)
- [GNU glibc 当前开发分支](https://github.com/bminor/glibc/tree/master)
- [House of all 综述](https://roderickchan.github.io/zh-cn/2023-02-27-house-of-all-about-glibc-heap-exploitation/)
- [高版本 heap exploitation](https://roderickchan.github.io/zh-cn/2023-03-01-analysis-of-glibc-heap-exploitation-in-high-version/)

## PoC

- [`poc_fastbin_pointer_move_2.27_2.36.c`](./poc_fastbin_pointer_move_2.27_2.36.c)：一个线性 `main` 同时演示 2.27～2.31 的明文 fd 和 2.32～2.36 的 safe-linking 搬运；严格断言 size 反算和“源槽→中转区→目标槽”。

原版 2.27、Addendum 2.29 的完整阶段清单和 2.37 硬边界说明，都放在这个 C 文件末尾的中文伪代码中。它保留各自构建的专属条件，不冒充通用的端到端 RCE。

## 迁移与调试

1. 先确认投递路径和最终触发点在目标 Build ID 上确实都存在。
2. 把占位地址和 add/edit/free 的调用顺序替换成题目实际提供的能力。
3. 在消费函数处下断点，逐个字段核对 size、对齐、safe-linking 编码，以及 FILE/link_map 的私有布局。
