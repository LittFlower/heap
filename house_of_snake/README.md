# House of Snake

## 结论

- 适用范围：**2.37～2.43**。
- 原语/效果：借助 `__printf_buffer_flush_obstack → __obstack_newchunk → chunkfun` 这条调用链，把执行流间接导向题目可控的回调函数。
- 版本变化：2.37 引入了新的 printf_buffer obstack 实现；一直到 2.43，`printf_buffer_flush.c` 依然会调用 `__obstack_newchunk`，这条链没有被替换掉。

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

源码里仍能走到最终触发点，不代表旧的利用链原样成立：具体怎么把数据送到这个位置、内部私有结构长什么样、控制流最终落在哪里，都要按附件 libc/ld 对应的 Build ID 逐一复核。

源码与背景：

- [glibc 2.37 `printf_buffer_flush.c`](https://github.com/bminor/glibc/blob/glibc-2.37/stdio-common/printf_buffer_flush.c)
- [glibc 2.43 `printf_buffer_flush.c`](https://sourceware.org/cgit/glibc/tree/stdio-common/printf_buffer_flush.c?h=release/2.43/master)
- [glibc 2.43 `malloc/obstack.c`](https://sourceware.org/cgit/glibc/tree/malloc/obstack.c?h=release/2.43/master)
- [提交 `5365acc`：新增 printf_buffer obstack 后端](https://sourceware.org/git/?p=glibc.git;a=commit;h=5365acc567a49270b4341b9d325794ec554258d9)
- [GNU glibc 当前开发分支](https://github.com/bminor/glibc/tree/master)
- [House of all 综述](https://roderickchan.github.io/zh-cn/2023-02-27-house-of-all-about-glibc-heap-exploitation/)
- [高版本 heap exploitation](https://roderickchan.github.io/zh-cn/2023-03-01-analysis-of-glibc-heap-exploitation-in-high-version/)

## PoC

- [`poc_chunkfun_sink_2.37_2.43.c`](./poc_chunkfun_sink_2.37_2.43.c)：用公开 API 建立一个真实的 obstack，强制 printf_buffer 多次 flush，严格验证最终调用形态是 `chunkfun(extra_arg,size)`；已在 2.37 和 2.43 上实测通过。

C 语言 PoC 用的是官方合法 API 来设置回调，所以 API 本身不是漏洞；文件末尾附的中文伪代码，负责说明题目侧要怎样伪造 `__printf_buffer_obstack` 和 obstack 结构的字段。

## 迁移与调试

1. 先确认题目能不能影响到 `__printf_buffer_obstack` 持有的 obstack 指针，或者能影响该指针指向的对象；光是存在这个公开的回调设置 API，不代表题目自动具备覆盖它的能力。
2. 想办法让 `next_free == chunk_limit`，同时还有格式化数据要写出去，这样才能进入 `__printf_buffer_flush_obstack`。
3. 在 `_obstack_newchunk` 处下断点，确认最终调用的参数顺序确实是 `chunkfun(extra_arg,new_size)`；别把 `extra_arg` 误写成第二个参数。
4. 如果目标是 2.36 及更早的版本，走的是 `_IO_obstack_jumps` 这条旧路径，应该用 House of Obstack 那份文件。
