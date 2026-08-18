# House of Lys

## 结论

- 适用范围：**2.23～2.36；2.37 起 exit→_IO_obstack_xsputn 链消失**。
- 原语/效果：把 primary vtable 指到合法 `_IO_obstack_jumps+0x20`，使 overflow 槽错位到 xsputn，最终调用 fake obstack.chunkfun。
- 版本变化：2.23～2.36 可沿 exit→_IO_cleanup→_IO_flush_all_lockp→_IO_obstack_xsputn；2.37 后应改用 Snake 新链。

<!-- PRIMITIVE_REQUIREMENTS:START -->
## 原语要求与版本边界

| 项目 | 本手法要求 |
|---|---|
| 最小输入原语 / 信息 | fake FILE + fake obstack；能挂到 exit/flush 链 |
| 关键环境与不变量 | `_IO_obstack_jumps+0x20` 错位；残留 `rdx` 是可用长度 |
| 最终输出原语 | `chunkfun(extra_arg,size)` 间接调用 |
| 版本边界应如何理解 | 2.37 删除旧 `_IO_obstack_xsputn` 消费路径，Lys 硬失效；2.37+ 可迁移到 Snake 的新 printf_buffer 消费路径，但应改名且前置不同。 |
<!-- PRIMITIVE_REQUIREMENTS:END -->

## 从源码看

`stdlib/exit.c`、`libio/genops.c`、`libio/obprintf.c` 与 2.37 printf 重构。源码中的 `_IO_obstack_file` 是 `FILE_plus` 后接一个 `struct obstack *`：x86-64 的 `FILE+0xe0` 必须存 fake obstack 的地址，不是把 obstack 本体内嵌在该偏移。

exit flush 原本调用 vtable 的 overflow 槽（`+0x18`）。如果 primary vtable 直接等于 `_IO_obstack_jumps`，会进入 `_IO_obstack_overflow(fp, EOF)` 并撞上 `assert(c != EOF)`。Lys 因此使用：

```text
primary vtable = _IO_obstack_jumps + 0x20
primary overflow(+0x18) = 原表 xsputn(+0x38)
```

`+0x20` 仍在 `__libc_IO_vtables` section 内，可以通过 2.24 起的 vtable validation。错位调用把原 overflow 的第二参数 `EOF` 当作 xsputn 的 `data`，还会把调用点残留的 `rdx` 当作 `n`；所以完整 exit 链需要按附件反汇编确认 `rdx` 是可用的正长度。这是构建/触发点条件，不是 C 函数原型保证。

源码中仍能走到最终触发点，不等于旧利用链仍成立：投递方式、私有结构和控制流终点都要按附件 libc/ld 的 Build ID 复核。

源码与背景：

- [glibc 2.36 `libio/obprintf.c`](https://github.com/bminor/glibc/blob/glibc-2.36/libio/obprintf.c)
- [glibc 2.36 `libio/genops.c`：cleanup/flush](https://github.com/bminor/glibc/blob/glibc-2.36/libio/genops.c)
- [glibc 2.37 `printf_buffer_flush.c`](https://github.com/bminor/glibc/blob/glibc-2.37/stdio-common/printf_buffer_flush.c)
- [SECCON 2022 babyfile 原始 writeup](https://nasm.re/posts/babyfile/)
- [GNU glibc 当前开发分支](https://github.com/bminor/glibc/tree/master)
- [House of all 综述](https://roderickchan.github.io/zh-cn/2023-02-27-house-of-all-about-glibc-heap-exploitation/)
- [高版本 heap exploitation](https://roderickchan.github.io/zh-cn/2023-03-01-analysis-of-glibc-heap-exploitation-in-high-version/)

## PoC

- [`poc_shifted_obstack_sink_2.23.c`](./poc_shifted_obstack_sink_2.23.c)：线性 PoC，直接使用该构建的 `_IO_wfile_jumps-0x1120`。
- [`poc_shifted_obstack_sink_2.24_2.36.c`](./poc_shifted_obstack_sink_2.24_2.36.c)：线性 PoC，直接使用对应构建的 `_IO_wfile_jumps+0x300`。

C PoC 保留 fake FILE、fake obstack 和一次错位调用；2.24～2.36 文件末尾补齐 exit/flush 布局伪代码。完整链还需要投递到 `_IO_list_all`/标准流，并验证 exit 调用点的 `rdx`。

## 迁移与调试

1. `FILE+0xe0` 写 fake obstack 指针；不要把 obstack 结构直接内嵌在那里。
2. primary vtable 写 `_IO_obstack_jumps+0x20`，并在 `IO_validate_vtable`、`_IO_obstack_xsputn` 下确认错位正确。
3. 满足 `write_ptr+n > write_end`、`next_free+n > chunk_limit`、`use_extra_arg=1`。
4. 在具体 exit/fflush 调用点看 `rdx`；若不可用，改走 babyfile 的 `_IO_obstack_overflow` 入口或选择另一个能控制第三参数的触发点。
5. 2.37+ 旧 jump table 已删除，改看 House of Snake。
