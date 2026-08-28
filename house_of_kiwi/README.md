# House of Kiwi

## 结论

**一句话**：能伪造 stderr 的 FILE 并触发 malloc 内部 assert，旧版 `__malloc_assert` 对 stderr 的那次 IO 刷新就会把 fake FILE 拉进 FSOP 触发链；2.36 起这个专属触发器被删掉。

| 版本 | 你能拿到什么 | 备注 |
|---|---|---|
| **2.23～2.35** | `__malloc_assert` 报错时输出信息并刷新 stdio，借这次 IO 触发 FSOP | 伪造 wide FILE 的 `_wide_vtable` 字段偏移按 2.23～2.29 / 2.30 / 2.31+ 分别用 `0x130 / 0xf0 / 0xe0`，不能混用 |
| 2.36+ | Kiwi 专属触发器失效 | `__malloc_assert` 重写，去掉了这次 IO 操作 |

<!-- PRIMITIVE_REQUIREMENTS:START -->
## 原语要求与版本边界

| 项目 | 本手法要求 |
|---|---|
| 最小输入原语 / 信息 | 能伪造/覆盖 stderr FILE；能破坏 top 触发 malloc assert |
| 关键环境与不变量 | 旧 `__malloc_assert→__fxprintf/fflush(stderr)`；wide 布局正确 |
| 最终输出原语 | 借错误路径触发 FSOP/CF |
| 版本边界应如何理解 | 2.36 assert 改走 `__libc_message`，Kiwi 专属消费路径硬失效；Apple/Cat 等正常 IO 最终触发点仍在，但不是 Kiwi 触发器。 |
<!-- PRIMITIVE_REQUIREMENTS:END -->

<!-- CHUNK_SIZE_REQUIREMENTS:START -->
## Chunk size 要求

- **没有固定 bin size。** 触发 malloc 只需大于被破坏后 top 的可用空间，使执行进入 `sysmalloc` 并命中 old-top 断言；PoC 用 `malloc(0x1000)`，该常量不是通用下限。
- fake stderr/FILE 布局只要求足够可写空间；wide-data 的 `0x130/0xf0/0xe0` 是字段偏移，不是 chunk size。
<!-- CHUNK_SIZE_REQUIREMENTS:END -->

## 从源码看

对比 glibc 2.35 和 2.36 的 `malloc/malloc.c` 里的 `__malloc_assert`，并结合 `libio/libio.h` 中 `_IO_wide_data` 的定义一起看。2.36 合入 [`ac8047c`](https://sourceware.org/git/?p=glibc.git;a=commit;h=ac8047cdf326504f652f7db97ec96c0e0cee052f) 后，改用 `__libc_message` 代替原来的 `__fxprintf + fflush(stderr)`，这就是 Kiwi 触发器失效的硬边界。另外，2.30 的 [`09e1b0e`](https://sourceware.org/git/?p=glibc.git;a=commit;h=09e1b0e3f6facc1af2dbcfef204f0aaa8718772b) 和 2.31 的 [`70c6e15`](https://sourceware.org/git/?p=glibc.git;a=commit;h=70c6e15654928c603c6d24bd01cf62e7a8e2ce9b) 各带来一次 wide-data 布局变化，即前面两个版本边界的来源。

最终触发点还在，不代表旧链成立：投递方式、私有结构和控制流终点都要按附件 libc/ld 的 Build ID 复核。

源码与背景：

- [glibc 2.35 `__malloc_assert`](https://github.com/bminor/glibc/blob/glibc-2.35/malloc/malloc.c)
- [glibc 2.36 `__malloc_assert`](https://github.com/bminor/glibc/blob/glibc-2.36/malloc/malloc.c)
- [glibc 2.35 `libio/wfileops.c`](https://github.com/bminor/glibc/blob/glibc-2.35/libio/wfileops.c)
- [GNU glibc 当前开发分支](https://github.com/bminor/glibc/tree/master)
- [House of all 综述](https://roderickchan.github.io/zh-cn/2023-02-27-house-of-all-about-glibc-heap-exploitation/)
- [高版本 heap exploitation](https://roderickchan.github.io/zh-cn/2023-03-01-analysis-of-glibc-heap-exploitation-in-high-version/)

## PoC

- [`poc_malloc_assert_trigger_2.23_2.35.c`](./poc_malloc_assert_trigger_2.23_2.35.c)：真实覆盖 top size，触发 sysmalloc 断言，并用带缓冲的 fopencookie 严格观察源码里的那次 `fflush(stderr)`；已在 2.23 和 2.35 实测通过，同一份程序在 2.36 不进入回调，以退出码 134 结束。

C 文件末尾列出了三段 wide-data 偏移和 stderr fake FILE 的伪代码。这个可执行主体只用于隔离验证 Kiwi 专属触发器；最终的回调、ROP 链和投递方式还要按题目替换。

## 迁移与调试

1. 覆盖 top size，让 sysmalloc 的 old-top 不变量检查失败；只触发一次普通的 `malloc_printerr` 不等于真正进入 `__malloc_assert`。
2. 这里控制的是 `stderr` 指向的 FILE；`__fxprintf(NULL,...)` 会选中 stderr，随后旧版源码显式调用 `fflush(stderr)`。
3. 按 2.23～2.29 / 2.30 / 2.31～2.35 三个区间选用对应的 wide-data ABI，并确保 primary vtable 本身合法。
4. 2.36 及以后，即使 Apple2/Apple3 用到的最终触发点还在，也不能再靠 Kiwi 的 malloc assert 触发。
