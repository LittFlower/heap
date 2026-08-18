# House of Snake

## 结论

- 适用范围：**2.37～2.43**。
- 原语/效果：利用 __printf_buffer_flush_obstack→__obstack_newchunk→chunkfun 间接调用。
- 版本变化：2.37 新增 printf_buffer obstack 实现；到 2.43 的 printf_buffer_flush.c 仍调用 __obstack_newchunk。

<!-- PRIMITIVE_REQUIREMENTS:START -->
## 原语要求与版本边界

| 项目 | 本手法要求 |
|---|---|
| 最小输入原语 / 信息 | 能影响 `__printf_buffer_obstack` 所持 obstack 并触发 printf flush |
| 关键环境与不变量 | 2.37+ 新 printf_buffer 后端；chunkfun ABI 正确 |
| 最终输出原语 | `_obstack_newchunk→chunkfun` 间接调用 |
| 版本边界应如何理解 | 2.37 才引入该消费路径；更早版本应使用 Obstack/Lys。到 2.43 最终触发点仍在，投递方式取决于题目。 |
<!-- PRIMITIVE_REQUIREMENTS:END -->

## 从源码看

stdio-common/printf_buffer_flush.c 与 malloc/obstack.c。

源码中仍能走到最终触发点，不等于旧利用链仍成立：投递方式、私有结构和控制流终点都要按附件 libc/ld 的 Build ID 复核。

源码与背景：

- [glibc 2.37 `printf_buffer_flush.c`](https://github.com/bminor/glibc/blob/glibc-2.37/stdio-common/printf_buffer_flush.c)
- [glibc 2.43 `printf_buffer_flush.c`](https://sourceware.org/cgit/glibc/tree/stdio-common/printf_buffer_flush.c?h=release/2.43/master)
- [glibc 2.43 `malloc/obstack.c`](https://sourceware.org/cgit/glibc/tree/malloc/obstack.c?h=release/2.43/master)
- [提交 `5365acc`：新增 printf_buffer obstack 后端](https://sourceware.org/git/?p=glibc.git;a=commit;h=5365acc567a49270b4341b9d325794ec554258d9)
- [GNU glibc 当前开发分支](https://github.com/bminor/glibc/tree/master)
- [House of all 综述](https://roderickchan.github.io/zh-cn/2023-02-27-house-of-all-about-glibc-heap-exploitation/)
- [高版本 heap exploitation](https://roderickchan.github.io/zh-cn/2023-03-01-analysis-of-glibc-heap-exploitation-in-high-version/)

## PoC

- [`poc_chunkfun_sink_2.37_2.43.c`](./poc_chunkfun_sink_2.37_2.43.c)：公开 API 建立真实 obstack 并强制 printf_buffer 多次 flush，严格验证 `chunkfun(extra_arg,size)`；已实测 2.37/2.43。

C PoC 使用合法 API 设置回调，所以 API 本身不是漏洞；文件末尾的中文伪代码负责题目侧 `__printf_buffer_obstack` 与 obstack 字段。

## 迁移与调试

1. 确认题目能影响 `__printf_buffer_obstack` 持有的 obstack 指针或其指向对象；存在公开回调 API 不等于自动存在覆盖能力。
2. 让 `next_free == chunk_limit`，并制造仍需写出的格式化数据，进入 `__printf_buffer_flush_obstack`。
3. 在 `_obstack_newchunk` 下断点确认 `chunkfun(extra_arg,new_size)` 的参数顺序；不要把 `extra_arg` 错写成第二参数。
4. 2.36 及以前走的是 `_IO_obstack_jumps`，应使用 House of Obstack 文件。
