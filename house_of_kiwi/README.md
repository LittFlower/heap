# House of Kiwi

## 结论

- 适用范围：**2.23～2.35；2.36 起专属触发器失效**。
- 原语/效果：故意触发 malloc assert，以 stderr 的 IO 刷新触发 fake FILE/FSOP。
- 版本变化：2.35 及以前 `__malloc_assert` 会输出并刷新 stdio；2.36 重写后移除该 IO 操作。fake wide FILE 还要按 2.23～2.29 / 2.30 / 2.31+ 的 `0x130 / 0xf0 / 0xe0` 三种 `_wide_vtable` 字段偏移分开。

<!-- PRIMITIVE_REQUIREMENTS:START -->
## 原语要求与版本边界

| 项目 | 本手法要求 |
|---|---|
| 最小输入原语 / 信息 | 能伪造/覆盖 stderr FILE；能破坏 top 触发 malloc assert |
| 关键环境与不变量 | 旧 `__malloc_assert→__fxprintf/fflush(stderr)`；wide 布局正确 |
| 最终输出原语 | 借错误路径触发 FSOP/CF |
| 版本边界应如何理解 | 2.36 assert 改走 `__libc_message`，Kiwi 专属消费路径硬失效；Apple/Cat 等正常 IO 最终触发点仍在，但不是 Kiwi 触发器。 |
<!-- PRIMITIVE_REQUIREMENTS:END -->

## 从源码看

对比 glibc-2.35/2.36 `malloc/malloc.c` 的 `__malloc_assert`，并读取 `libio/libio.h` 的 `_IO_wide_data`。提交 [`ac8047c`](https://sourceware.org/git/?p=glibc.git;a=commit;h=ac8047cdf326504f652f7db97ec96c0e0cee052f) 进入 2.36，用 `__libc_message` 代替复杂的 `__fxprintf + fflush(stderr)`，这是 Kiwi 触发器的硬边界。2.30 的 [`09e1b0e`](https://sourceware.org/git/?p=glibc.git;a=commit;h=09e1b0e3f6facc1af2dbcfef204f0aaa8718772b) 与 2.31 的 [`70c6e15`](https://sourceware.org/git/?p=glibc.git;a=commit;h=70c6e15654928c603c6d24bd01cf62e7a8e2ce9b) 分别造成两个 wide-data 布局边界。

源码中仍能走到最终触发点，不等于旧利用链仍成立：投递方式、私有结构和控制流终点都要按附件 libc/ld 的 Build ID 复核。

源码与背景：

- [glibc 2.35 `__malloc_assert`](https://github.com/bminor/glibc/blob/glibc-2.35/malloc/malloc.c)
- [glibc 2.36 `__malloc_assert`](https://github.com/bminor/glibc/blob/glibc-2.36/malloc/malloc.c)
- [glibc 2.35 `libio/wfileops.c`](https://github.com/bminor/glibc/blob/glibc-2.35/libio/wfileops.c)
- [GNU glibc 当前开发分支](https://github.com/bminor/glibc/tree/master)
- [House of all 综述](https://roderickchan.github.io/zh-cn/2023-02-27-house-of-all-about-glibc-heap-exploitation/)
- [高版本 heap exploitation](https://roderickchan.github.io/zh-cn/2023-03-01-analysis-of-glibc-heap-exploitation-in-high-version/)

## PoC

- [`poc_malloc_assert_trigger_2.23_2.35.c`](./poc_malloc_assert_trigger_2.23_2.35.c)：真实覆盖 top size，触发 sysmalloc 断言，并用缓冲 fopencookie 严格观察源码中的 `fflush(stderr)`；已实测 2.23/2.35，同一程序在 2.36 不进回调并退出 134。

C 文件末尾列出三段 wide-data 偏移和 stderr fake FILE 伪代码。可执行主体隔离验证 Kiwi 专属触发器；最终回调、ROP 与投递仍按题目替换。

## 迁移与调试

1. 覆盖 top size 后让 sysmalloc 的 old-top invariant 失败；仅制造普通 `malloc_printerr` 不等价于进入 `__malloc_assert`。
2. 控制的是 `stderr` 指向的 FILE；`__fxprintf(NULL,...)` 会选择 stderr，随后旧源码显式 `fflush(stderr)`。
3. 按 2.23～2.29 / 2.30 / 2.31～2.35 选择 wide-data ABI，并确保 primary vtable 合法。
4. 2.36+ 即使 Apple2/Apple3 最终触发点仍存在，也不能再靠 Kiwi 的 malloc assert 触发它们。
