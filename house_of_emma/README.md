# House of Emma

## 结论

**一句话**：让合法 vtable 落在 `_IO_cookie_jumps` 上，就能借 cookie 回调间接完成调用；这个最终触发点 2.23～2.43 都在。

| 版本 | 你能拿到什么 | 备注 |
|---|---|---|
| 2.23 | 明文 cookie 回调，直接覆盖 | 无需 pointer_guard |
| **2.24～2.43** | cookie read/write/seek/close 间接调用，本目录默认指这条 | `983fd5c` 起回调存取加 PTR_MANGLE，需先拿到 pointer_guard；`_IO_cookie_jumps` 本身能过 vtable validation |
| 2.42～2.43 | 仅剩最终触发点本身 | 原来的 largebin 投递方式失效，需另一投递原语 |

前置能力：控制 cookie FILE/回调表，完成投递和触发；2.24+ 需 pointer_guard。

<!-- PRIMITIVE_REQUIREMENTS:START -->
## 原语要求与版本边界

| 项目 | 本手法要求 |
|---|---|
| 最小输入原语 / 信息 | 控制 cookie FILE/回调表并投递/触发；2.24+需 pointer_guard |
| 关键环境与不变量 | 合法 `_IO_cookie_jumps`；回调参数与 mangle 正确 |
| 最终输出原语 | cookie read/write/seek/close 间接调用 |
| 版本边界应如何理解 | 2.24 PTR_MANGLE 只是新增信息/编码前置；2.42 只切断经典 largebin 投递，cookie 最终触发点到 2.43 仍在。 |
<!-- PRIMITIVE_REQUIREMENTS:END -->

<!-- CHUNK_SIZE_REQUIREMENTS:START -->
## Chunk size 要求

- **IO cookie 回调消费端不要求特定 chunk size。** fake cookie FILE 及其 cookie 数据只需位于足够大、可写、对齐的区域。
- 若使用经典 largebin attack 写入 FILE/链指针，则另需物理 `chunksize >= 0x400` 的有序 largebin 节点；2.42+ 改用其他投递后，尺寸约束随投递原语改变。
<!-- CHUNK_SIZE_REQUIREMENTS:END -->

## 从源码看

关键代码在 `libio/iofopncook.c` 和 x86-64 的 `pointer_guard.h` 里。2.23 直接从
`cfile->__io_functions.write` 调用；进入 2.24 后，
[`983fd5c`](https://sourceware.org/git/?p=glibc.git;a=commit;h=983fd5c41ab7e5a5c33922259ca1ac99b3b413f8)
让保存时做 `PTR_MANGLE`、消费时做 `PTR_DEMANGLE`。这一步加密和
[`db3476a`](https://sourceware.org/git/?p=glibc.git;a=commit;h=db3476aff19b75c4fdefbe65fcd5f0a90588ba51)
引入的 primary vtable 白名单是两个独立检查，别笼统当成"2.23 到最新版本都需要 guard"。

最终触发点还在，不代表旧链成立：投递方式、私有结构和控制流终点都要按附件 libc/ld 的 Build ID 重新核实。

源码与背景：

- [glibc 2.43 `libio/iofopncook.c`](https://sourceware.org/cgit/glibc/tree/libio/iofopncook.c?h=release/2.43/master)
- [glibc 2.43 x86-64 `pointer_guard.h`](https://sourceware.org/cgit/glibc/tree/sysdeps/unix/sysv/linux/x86_64/pointer_guard.h?h=release/2.43/master)
- [glibc 2.43 `libio/vtables.c`](https://sourceware.org/cgit/glibc/tree/libio/vtables.c?h=release/2.43/master)
- [GNU glibc 当前开发分支](https://github.com/bminor/glibc/tree/master)
- [House of all 综述](https://roderickchan.github.io/zh-cn/2023-02-27-house-of-all-about-glibc-heap-exploitation/)
- [高版本 heap exploitation](https://roderickchan.github.io/zh-cn/2023-03-01-analysis-of-glibc-heap-exploitation-in-high-version/)

## PoC

- [`poc_cookie_callback_2.23.c`](./poc_cookie_callback_2.23.c)：在真实 fopencookie 对象上覆盖明文的 write 回调。
- [`poc_cookie_callback_2.24_2.43.c`](./poc_cookie_callback_2.24_2.43.c)：从已知回调的密文反推出 pointer_guard，再重新编码出攻击用的回调；已在 2.24/2.31/2.43 上实际跑通。

fake `_IO_cookie_file` 的字段偏移、四个回调槽位置，以及 `rol64(pointer ^ guard, 17)` 的编码关系都写在这份较新的 C PoC 末尾。

## 迁移与调试

1. 先确认投递路径和最终触发点在目标 Build ID 上都真实存在。
2. 把占位地址和 add/edit/free 的顺序换成题目实际给出的能力。
3. 在消费函数处下断点，逐字段核对 size、对齐、safe-linking，以及 FILE/link_map 的私有布局。
