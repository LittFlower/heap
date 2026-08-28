# House of Lys

## 结论

**一句话**：把 FILE 的 primary vtable 错位指到 `_IO_obstack_jumps+0x20`，本该调用的 overflow 槽就错位到 xsputn，最终间接调用 fake obstack 里的 `chunkfun`。

- 适用范围：**glibc 2.23～2.36**，可沿 exit→`_IO_cleanup`→`_IO_flush_all_lockp`→`_IO_obstack_xsputn` 这条路径走通。
- 版本边界：2.37 起这条路径被删掉，exit→`_IO_obstack_xsputn` 调用链不复存在，需改用 House of Snake 的新链路。

<!-- PRIMITIVE_REQUIREMENTS:START -->
## 原语要求与版本边界

| 项目 | 本手法要求 |
|---|---|
| 最小输入原语 / 信息 | fake FILE + fake obstack；能挂到 exit/flush 链 |
| 关键环境与不变量 | `_IO_obstack_jumps+0x20` 错位；残留 `rdx` 是可用长度 |
| 最终输出原语 | `chunkfun(extra_arg,size)` 间接调用 |
| 版本边界应如何理解 | 2.37 删除旧 `_IO_obstack_xsputn` 消费路径，Lys 硬失效；2.37+ 可迁移到 Snake 的新 printf_buffer 消费路径，但应改名且前置不同。 |
<!-- PRIMITIVE_REQUIREMENTS:END -->

<!-- CHUNK_SIZE_REQUIREMENTS:START -->
## Chunk size 要求

- **exit→obstack FILE 最终触发链没有 bin/chunk size 前提。** fake FILE、obstack 和 shifted vtable 只需足够的连续可写空间与正确对齐。
- `_obstack_newchunk` 计算出的扩容长度是回调参数，不等于利用前必须能从题目菜单申请某个固定 size；前置投递若使用 heap attack，再按该原语另算。
<!-- CHUNK_SIZE_REQUIREMENTS:END -->

## 从源码看

关键代码在 `stdlib/exit.c`、`libio/genops.c`、`libio/obprintf.c`，以及 2.37 的 printf 重构。源码中 `_IO_obstack_file` 是 `FILE_plus` 紧跟一个 `struct obstack *`：x86-64 上 `FILE+0xe0` 存的是 fake obstack 的地址，不是把整个 obstack 结构体内嵌在这个偏移处。

exit 触发的 flush 本来会调用 vtable 里 overflow 槽（`+0x18`）指向的函数。如果直接把 primary vtable 设成 `_IO_obstack_jumps`，就会走进 `_IO_obstack_overflow(fp, EOF)`，撞上里面的 `assert(c != EOF)` 而失败。Lys 的解法是把 vtable 错位一个槛位：

```text
primary vtable = _IO_obstack_jumps + 0x20
primary overflow(+0x18) = 原表 xsputn(+0x38)
```

`+0x20` 还落在 `__libc_IO_vtables` section 内，所以能通过 2.24 起加入的 vtable validation 检查。错位后，原本 overflow 的第二个参数 `EOF` 会被当成 xsputn 的 `data`，调用点残留的 `rdx` 会被当成 `n`。要走通完整 exit 链，需按附件反汇编确认此时 `rdx` 是可用的正长度——这取决于具体构建和触发点，C 函数原型本身不保证。

源码能走到最终触发点，不代表旧链在具体题目里还成立；投递方式、私有结构布局和控制流终点都要按附件 Build ID 复核。

源码与背景：

- [glibc 2.36 `libio/obprintf.c`](https://github.com/bminor/glibc/blob/glibc-2.36/libio/obprintf.c)
- [glibc 2.36 `libio/genops.c`：cleanup/flush](https://github.com/bminor/glibc/blob/glibc-2.36/libio/genops.c)
- [glibc 2.37 `printf_buffer_flush.c`](https://github.com/bminor/glibc/blob/glibc-2.37/stdio-common/printf_buffer_flush.c)
- [SECCON 2022 babyfile 原始 writeup](https://nasm.re/posts/babyfile/)
- [GNU glibc 当前开发分支](https://github.com/bminor/glibc/tree/master)
- [House of all 综述](https://roderickchan.github.io/zh-cn/2023-02-27-house-of-all-about-glibc-heap-exploitation/)
- [高版本 heap exploitation](https://roderickchan.github.io/zh-cn/2023-03-01-analysis-of-glibc-heap-exploitation-in-high-version/)

## PoC

- [`poc_shifted_obstack_sink_2.23.c`](./poc_shifted_obstack_sink_2.23.c)：线性 PoC，直接用本项目这个构建下的 `_IO_wfile_jumps-0x1120`。
- [`poc_shifted_obstack_sink_2.24_2.36.c`](./poc_shifted_obstack_sink_2.24_2.36.c)：线性 PoC，直接用对应构建下的 `_IO_wfile_jumps+0x300`。

两个 C PoC 都只保留 fake FILE、fake obstack 和一次错位调用；2.24～2.36 的文件末尾另附 exit/flush 布局伪代码。要凑成完整攻击链，还得把 fake FILE 投递到 `_IO_list_all` 或某个标准流，并确认 exit 调用点当时的 `rdx` 值可用。

## 迁移与调试

1. `FILE+0xe0` 写的是 fake obstack 的指针，不要把整个 obstack 结构体内嵌在这个偏移。
2. primary vtable 写成 `_IO_obstack_jumps+0x20`，并结合 `IO_validate_vtable`、`_IO_obstack_xsputn` 源码确认错位正确。
3. 需同时满足 `write_ptr+n > write_end`、`next_free+n > chunk_limit`、`use_extra_arg=1`。
4. 在具体 exit/fflush 调用点检查 `rdx`；不可用时，可改走 babyfile 文中的 `_IO_obstack_overflow` 入口，或换一个能控制第三个参数的触发点。
5. 2.37 起旧 jump table 已删除，转看 House of Snake。
