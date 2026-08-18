# House of Emma

## 结论

- 适用范围：**IO cookie 最终触发点 2.23～2.43；原始 largebin 投递止于 2.41**。
- 原语/效果：让合法 vtable 落到 _IO_cookie_jumps，通过 cookie 回调间接调用。
- 版本变化：2.23 回调为明文；2.24 的 `983fd5c` 引入 cookie 回调 PTR_MANGLE，同时合法 `_IO_cookie_jumps` 可通过 vtable validation；2.42 largebin 投递失效，但 cookie 最终触发点在 2.43 仍在。

<!-- PRIMITIVE_REQUIREMENTS:START -->
## 原语要求与版本边界

| 项目 | 本手法要求 |
|---|---|
| 最小输入原语 / 信息 | 控制 cookie FILE/回调表并投递/触发；2.24+需 pointer_guard |
| 关键环境与不变量 | 合法 `_IO_cookie_jumps`；回调参数与 mangle 正确 |
| 最终输出原语 | cookie read/write/seek/close 间接调用 |
| 版本边界应如何理解 | 2.24 PTR_MANGLE 只是新增信息/编码前置；2.42 只切断经典 largebin 投递，cookie 最终触发点到 2.43 仍在。 |
<!-- PRIMITIVE_REQUIREMENTS:END -->

## 从源码看

`libio/iofopncook.c` 与 x86-64 `pointer_guard.h`。2.23 直接从
`cfile->__io_functions.write` 调用；[`983fd5c`](https://sourceware.org/git/?p=glibc.git;a=commit;h=983fd5c41ab7e5a5c33922259ca1ac99b3b413f8)
进入 2.24 后，保存时 `PTR_MANGLE`、消费时 `PTR_DEMANGLE`。这和
[`db3476a`](https://sourceware.org/git/?p=glibc.git;a=commit;h=db3476aff19b75c4fdefbe65fcd5f0a90588ba51)
的 primary vtable 白名单是两个独立检查，不应合写成“2.23～latest 都需要 guard”。

源码中仍能走到最终触发点，不等于旧利用链仍成立：投递方式、私有结构和控制流终点都要按附件 libc/ld 的 Build ID 复核。

源码与背景：

- [glibc 2.43 `libio/iofopncook.c`](https://sourceware.org/cgit/glibc/tree/libio/iofopncook.c?h=release/2.43/master)
- [glibc 2.43 x86-64 `pointer_guard.h`](https://sourceware.org/cgit/glibc/tree/sysdeps/unix/sysv/linux/x86_64/pointer_guard.h?h=release/2.43/master)
- [glibc 2.43 `libio/vtables.c`](https://sourceware.org/cgit/glibc/tree/libio/vtables.c?h=release/2.43/master)
- [GNU glibc 当前开发分支](https://github.com/bminor/glibc/tree/master)
- [House of all 综述](https://roderickchan.github.io/zh-cn/2023-02-27-house-of-all-about-glibc-heap-exploitation/)
- [高版本 heap exploitation](https://roderickchan.github.io/zh-cn/2023-03-01-analysis-of-glibc-heap-exploitation-in-high-version/)

## PoC

- [`poc_cookie_callback_2.23.c`](./poc_cookie_callback_2.23.c)：真实覆盖 fopencookie 对象的明文 write 回调。
- [`poc_cookie_callback_2.24_2.43.c`](./poc_cookie_callback_2.24_2.43.c)：从已知回调密文反推 pointer_guard，重新编码攻击回调；2.24/2.31/2.43 已实跑。

fake `_IO_cookie_file` 的字段偏移、四个回调槽和 `rol64(pointer ^ guard, 17)` 关系已写在现代 C PoC 末尾。

## 迁移与调试

1. 先确认投递路径和最终触发点在目标 Build ID 中都存在。
2. 把占位地址和 add/edit/free 顺序替换成题目能力。
3. 在消费函数下断点，逐字段核对 size、对齐、safe-linking、FILE/link_map 私有布局。
