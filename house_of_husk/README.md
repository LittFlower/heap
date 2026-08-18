# House of Husk

## 结论

- 适用范围：**printf handler 最终触发点在 2.23～2.43 仍存在；本目录 largebin 投递 PoC 到 2.41**。
- 原语/效果：改写 __printf_function_table 与 __printf_arginfo_table，让格式串解析间接调用受控函数。
- 版本变化：2.23～2.41 可用 largebin 投递；2.42 加固 nextsize 后该投递失效；2.43 的 reg-printf.c/vfprintf-internal.c 仍消费两张表，若另有任意写则最终触发点尚在。

<!-- PRIMITIVE_REQUIREMENTS:START -->
## 原语要求与版本边界

| 项目 | 本手法要求 |
|---|---|
| 最小输入原语 / 信息 | 能写两张隐藏 printf 表；有可控格式串触发 |
| 关键环境与不变量 | `__printf_function_table/__printf_arginfo_table` 真实偏移、表项与参数 ABI |
| 最终输出原语 | printf 解析时受控回调/CF |
| 版本边界应如何理解 | 最终触发点到 2.43 仍在；2.42 只封常用的经典 largebin 投递。隐藏偏移是 Build-ID 条件，局部写到“某个可写地址”不算成功。 |
<!-- PRIMITIVE_REQUIREMENTS:END -->

## 从源码看

stdio-common/reg-printf.c、vfprintf-internal.c 与 malloc.c largebin 插入。

源码中仍能走到最终触发点，不等于旧利用链仍成立：投递方式、私有结构和控制流终点都要按附件 libc/ld 的 Build ID 复核。

源码与背景：

- [glibc 2.43 `stdio-common/reg-printf.c`](https://sourceware.org/cgit/glibc/tree/stdio-common/reg-printf.c?h=release/2.43/master)
- [glibc 2.43 `vfprintf-internal.c`](https://sourceware.org/cgit/glibc/tree/stdio-common/vfprintf-internal.c?h=release/2.43/master)
- [glibc 2.41 `malloc.c`：经典 largebin 投递末版](https://github.com/bminor/glibc/blob/glibc-2.41/malloc/malloc.c)
- [GNU glibc 当前开发分支](https://github.com/bminor/glibc/tree/master)
- [House of all 综述](https://roderickchan.github.io/zh-cn/2023-02-27-house-of-all-about-glibc-heap-exploitation/)
- [高版本 heap exploitation](https://roderickchan.github.io/zh-cn/2023-03-01-analysis-of-glibc-heap-exploitation-in-high-version/)

## PoC

- [`poc_printf_handler_sink_2.23_2.43.c`](./poc_printf_handler_sink_2.23_2.43.c)：通过官方注册 API 初始化同一组内部 handler 表，真实触发 arginfo/handler；用于验证跨版本最终触发点，不把 API 本身伪装成漏洞。
- [`poc_2.27.c`](./poc_2.27.c)
- [`poc_2.35.c`](./poc_2.35.c)
- [`poc_2.37.c`](./poc_2.37.c)
- [`poc_2.39.c`](./poc_2.39.c)
- [`poc_2.41.c`](./poc_2.41.c)：均绑定各自构建偏移，已改为只有真实进入 `HUSK_<version>_CALLBACK` 才通过。不再使用 one-gadget/非交互 shell 的返回码作模糊判据。

[`poc_2.41.c`](./poc_2.41.c) 中的偏移对应当前验证镜像 Ubuntu 25.04 `GLIBC 2.41-6ubuntu1.2`：`main_arena=0x210ac0`、`__printf_function_table=0x212700`、`__printf_arginfo_table=0x212708`；来自 `libc6-dbg` Build ID `ae7440bbdce614e0e79280c3b2e45b1df44e639c`。题目附件不同时必须重算，不得把这三个数当作 2.41 ABI。

上述 5 个完整投递 PoC 都用 largebin 先后改写两张表，不是官方注册 API 演示；通用最终触发点 PoC 则故意使用 API 来隔离证明 2.42/2.43 仍有消费路径。

## 迁移与调试

1. 先确认投递路径和最终触发点在目标 Build ID 中都存在。
2. 把占位地址和 add/edit/free 顺序替换成题目能力。
3. 在消费函数下断点，逐字段核对 size、对齐、safe-linking、FILE/link_map 私有布局。
