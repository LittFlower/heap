# House of Husk

## 结论

- 适用范围：**printf handler 这个最终触发点从 2.23 到 2.43 一直存在；本目录用 largebin 投递的完整 PoC 覆盖到 2.41**。
- 原语/效果：改写 `__printf_function_table` 和 `__printf_arginfo_table`，让 printf 解析格式串时间接调用我们控制的函数。
- 版本变化：2.23～2.41 都可以用 largebin attack 投递。
- 2.42 加固了 `nextsize` 检查，这条投递路径失效。
- 2.43 的 `reg-printf.c`/`vfprintf-internal.c` 还是会读这两张表；只要题目另外提供任意写，最终触发点还是能打通。

<!-- PRIMITIVE_REQUIREMENTS:START -->
## 原语要求与版本边界

| 项目 | 本手法要求 |
|---|---|
| 最小输入原语 / 信息 | 能写两张隐藏 printf 表；有可控格式串触发 |
| 关键环境与不变量 | `__printf_function_table/__printf_arginfo_table` 真实偏移、表项与参数 ABI |
| 最终输出原语 | printf 解析时受控回调/CF |
| 版本边界应如何理解 | 最终触发点到 2.43 仍在；2.42 只封常用的经典 largebin 投递。隐藏偏移是 Build-ID 条件，局部写到“某个可写地址”不算成功。 |
<!-- PRIMITIVE_REQUIREMENTS:END -->

<!-- CHUNK_SIZE_REQUIREMENTS:START -->
## Chunk size 要求

- **printf handler 最终触发点本身不要求某个 chunk size**；只要能写两张表并触发格式串即可。
- 2.27 的超大 fastbin 投递要为两张表分别反算精确 request；该 PoC 使用 `request = 2*(target-main_arena)-0x10` 的 `offset2size` 宏，并先放大 `global_max_fast`。它不是任意 large request，换 Build ID 后须从实际 `fastbinsY` 写入槽重新验算。
- 现代 largebin 投递必须能准备两组物理 large chunks。PoC 分别使用 request `0x418/0x428`（物理 `0x420/0x430`）与 `0x478/0x488`（物理 `0x480/0x490`）；换值时要保证每组的 largebin 归属和“新 victim 更小”顺序仍正确。
<!-- CHUNK_SIZE_REQUIREMENTS:END -->

## 从源码看

涉及三处源码：`stdio-common/reg-printf.c`、`vfprintf-internal.c`，以及 `malloc.c` 里 largebin 的插入逻辑。

最终触发点还在，不代表旧的完整链成立：投递方式、私有结构和控制流终点都要按附件 libc/ld 的 Build ID 逐一复核。

源码与背景：

- [glibc 2.43 `stdio-common/reg-printf.c`](https://sourceware.org/cgit/glibc/tree/stdio-common/reg-printf.c?h=release/2.43/master)
- [glibc 2.43 `vfprintf-internal.c`](https://sourceware.org/cgit/glibc/tree/stdio-common/vfprintf-internal.c?h=release/2.43/master)
- [glibc 2.41 `malloc.c`：经典 largebin 投递末版](https://github.com/bminor/glibc/blob/glibc-2.41/malloc/malloc.c)
- [GNU glibc 当前开发分支](https://github.com/bminor/glibc/tree/master)
- [House of all 综述](https://roderickchan.github.io/zh-cn/2023-02-27-house-of-all-about-glibc-heap-exploitation/)
- [高版本 heap exploitation](https://roderickchan.github.io/zh-cn/2023-03-01-analysis-of-glibc-heap-exploitation-in-high-version/)

## PoC

- [`poc_printf_handler_sink_2.23_2.43.c`](./poc_printf_handler_sink_2.23_2.43.c)：通过官方注册 API 初始化同一组内部 handler 表，真实触发 arginfo/handler。用于验证跨版本都存在的最终触发点，不把这个 API 本身伪装成漏洞。
- [`poc_2.27.c`](./poc_2.27.c)
- [`poc_2.35.c`](./poc_2.35.c)
- [`poc_2.37.c`](./poc_2.37.c)
- [`poc_2.39.c`](./poc_2.39.c)
- [`poc_2.41.c`](./poc_2.41.c)：这 5 个都绑定各自构建的实际偏移，只有走到 `HUSK_<version>_CALLBACK` 才算通过，不用 one-gadget 或非交互 shell 返回码这类模糊判据。

[`poc_2.41.c`](./poc_2.41.c) 里的偏移对应当前验证镜像 Ubuntu 25.04 `GLIBC 2.41-6ubuntu1.2`：`main_arena=0x210ac0`、`__printf_function_table=0x212700`、`__printf_arginfo_table=0x212708`，来自 `libc6-dbg` Build ID `ae7440bbdce614e0e79280c3b2e45b1df44e639c`。题目附件不同就必须重算，不要把这三个数当成整个 2.41 分支的 ABI。

上面 5 个完整投递 PoC 都用 largebin attack 先后改写两张表，不靠官方注册 API；通用最终触发点 PoC 则故意用官方 API，单独证明 2.42/2.43 还有消费路径。

## 迁移与调试

1. 先确认投递路径和最终触发点在目标 Build ID 中是否都存在。
2. 把占位地址和 add/edit/free 的调用顺序换成题目实际提供的能力。
3. 在消费函数处下断点，逐字段核对 size、对齐、safe-linking，以及 FILE/link_map 的私有布局。
