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

<!-- CHUNK_SIZE_REQUIREMENTS:START -->
## Chunk size 要求

- **printf-buffer/obstack 消费端没有固定 heap size class。** 只要伪造的 obstack 满足 `next_free == chunk_limit`，后续数据会让 `_obstack_newchunk` 自行计算 `new_size` 并调用 `chunkfun`。
- 该 `new_size` 是受布局影响的回调参数，不是题目必须提供的某个 malloc 菜单尺寸；fake buffer/obstack 只需足够大、可写、对齐。
<!-- CHUNK_SIZE_REQUIREMENTS:END -->

## 从源码看

stdio-common/printf_buffer_flush.c 与 malloc/obstack.c。

源码与背景：

- [glibc 2.37 `printf_buffer_flush.c`](https://github.com/bminor/glibc/blob/glibc-2.37/stdio-common/printf_buffer_flush.c)
- [glibc 2.43 `printf_buffer_flush.c`](https://sourceware.org/cgit/glibc/tree/stdio-common/printf_buffer_flush.c?h=release/2.43/master)
- [glibc 2.43 `malloc/obstack.c`](https://sourceware.org/cgit/glibc/tree/malloc/obstack.c?h=release/2.43/master)
- [提交 `5365acc`：新增 printf_buffer obstack 后端](https://sourceware.org/git/?p=glibc.git;a=commit;h=5365acc567a49270b4341b9d325794ec554258d9)
- [GNU glibc 当前开发分支](https://github.com/bminor/glibc/tree/master)
- [House of all 综述](https://roderickchan.github.io/zh-cn/2023-02-27-house-of-all-about-glibc-heap-exploitation/)
- [高版本 heap exploitation](https://roderickchan.github.io/zh-cn/2023-03-01-analysis-of-glibc-heap-exploitation-in-high-version/)

## PoC

- [`poc_chunkfun_sink_2.37_2.43.c`](./poc_chunkfun_sink_2.37_2.43.c)：用公开 API 建立真实 obstack，强制 printf_buffer 多次 flush，严格验证最终调用形态是 `chunkfun(extra_arg,size)`；已在 2.37 和 2.43 实测通过。

C PoC 用官方合法 API 设置回调，API 本身不是漏洞；文件末尾的中文伪代码说明题目侧如何伪造 `__printf_buffer_obstack` 和 obstack 字段。

## 迁移与调试

1. 先确认题目能影响 `__printf_buffer_obstack` 持有的 obstack 指针或它指向的对象；公开回调 API 存在，不代表题目就能覆盖它。
2. 让 `next_free == chunk_limit`，并且还有格式化数据要写，才能进入 `__printf_buffer_flush_obstack`。
3. 在 `_obstack_newchunk` 处下断点，确认最终调用参数顺序是 `chunkfun(extra_arg,new_size)`；别把 `extra_arg` 误写成第二个参数。
4. 目标是 2.36 或更早版本的话，走 `_IO_obstack_jumps` 旧路径，看 House of Obstack。
