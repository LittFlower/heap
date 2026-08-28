# House of Apple 1

## 结论

**一句话**：能用 fake `_IO_wstrnfile` 触发 `_IO_wstrn_overflow`，就把 `overflow_buf` 的已知地址写进攻击者指定的 `_IO_wide_data`，一次触发产生 8 个相关指针写。

- 适用范围：**glibc 2.23～2.36；2.37 删除了该函数和 jump table，硬失效**。
- 2.23 可使用任意 fake primary vtable；2.24～2.36 必须让 primary vtable 指向合法的隐藏 `_IO_wstrn_jumps`。
- 注意区分两个名字相近的函数：原始 Apple1 用的是 `libio/vswprintf.c` 的 `_IO_wstrn_overflow`，不是 `libio/wstrops.c` 中负责可扩容宽字符串流的 `_IO_wstr_overflow`。旧文章 2022 年写的“所有版本”不能外推到 2.37～2.43。

<!-- PRIMITIVE_REQUIREMENTS:START -->
## 原语要求与版本边界

| 项目 | 本手法要求 |
|---|---|
| 最小输入原语 / 信息 | 可控 FILE、wide data、`_IO_wstrnfile` 尾部；可触发对应宽输出 |
| 关键环境与不变量 | libc leak；primary vtable/字段满足宽流检查 |
| 最终输出原语 | 一次产生 8 个互相关联的已知地址指针写 |
| 版本边界应如何理解 | 2.37 删除 `_IO_wstrn_overflow/_IO_wstrn_jumps`，形成消费路径硬边界；其他已知值写不等于 Apple1 存活。 |
<!-- PRIMITIVE_REQUIREMENTS:END -->

<!-- CHUNK_SIZE_REQUIREMENTS:START -->
## Chunk size 要求

- **最终 FILE 消费链不要求某个 malloc size class。** fake FILE、`_IO_wide_data` 与 `_IO_wstrnfile` 尾部只需位于足够大、可写且满足指针对齐的区域；它们可以在 heap、BSS 或其他已知可写区。
- 若用 largebin/tcache/overlap 把这些结构投递到目标，尺寸限制属于所选投递原语，应另外按对应 README 检查，不能把其 PoC 尺寸当成 Apple1 本身的要求。
<!-- CHUNK_SIZE_REQUIREMENTS:END -->

## 从源码看

在 glibc 2.36 中，`_IO_wstrn_overflow(fp, c)` 将 `fp` 转为 `_IO_wstrnfile *snf`。如果 `wide->_IO_buf_base != snf->overflow_buf`，它先调用：

```c
_IO_wsetb(fp, snf->overflow_buf, snf->overflow_buf + 64, 0);
```

然后写以下 x86-64 字段。设 `K = fake_file + 0xf0`，也就是 `snf->overflow_buf`：

| fake `_IO_wide_data` 偏移 | 字段 | 写入值 |
|---:|---|---:|
| `+0x00` | `_IO_read_ptr` | `K` |
| `+0x08` | `_IO_read_end` | `K + 0x100` |
| `+0x10` | `_IO_read_base` | `K` |
| `+0x18` | `_IO_write_base` | `K` |
| `+0x20` | `_IO_write_ptr` | `K` |
| `+0x28` | `_IO_write_end` | `K` |
| `+0x30` | `_IO_buf_base` | `K` |
| `+0x38` | `_IO_buf_end` | `K + 0x100` |

`K + 0x100` 来自 `wchar_t overflow_buf[64]`。进入 `_IO_wsetb` 前应让旧 `wide->_IO_buf_base` 为 0，或按附件确认 `_IO_FLAGS2_USER_WBUF`，否则它可能先 `free` 旧指针。

关键硬边界是提交 [`118816de3383`](https://sourceware.org/git/?p=glibc.git;a=commit;h=118816de3383ff12769349784689141355cc787c)：它进入 glibc 2.37，把 `__vswprintf_internal` 改为 `printf_buffer`，同时删除 `_IO_wstrn_overflow` 和 `_IO_wstrn_jumps`。

源码与背景：

- [glibc 2.36 `libio/vswprintf.c`](https://github.com/bminor/glibc/blob/glibc-2.36/libio/vswprintf.c)
- [glibc 2.37 `libio/vswprintf.c`](https://github.com/bminor/glibc/blob/glibc-2.37/libio/vswprintf.c)
- [House of Apple 1 原始文章](https://roderickchan.github.io/zh-cn/house-of-apple-%E4%B8%80%E7%A7%8D%E6%96%B0%E7%9A%84glibc%E4%B8%ADio%E6%94%BB%E5%87%BB%E6%96%B9%E6%B3%95-1/)

## PoC

- [`poc_known_write_2.23_2.36.c`](./poc_known_write_2.23_2.36.c)：在真实 glibc 中经 `__overflow → _IO_wstrn_overflow`，严格验证 8 个字段的写入；已实测 2.23、2.24、2.35、2.36。

fake `_IO_wstrnfile` 的完整字段关系和写入结果位于 C 文件末尾的“题目布局伪代码”，无需额外生成二进制布局文件。

C PoC 为跨发行版运行，使用上游 x86-64 本范围内 `_IO_wstrn_jumps = _IO_wfile_jumps - 0x300` 的关系。迁移到题目时必须从附件 libc 的隐藏 symbol/反汇编重新取偏移。

## 迁移与调试

1. 准备 fake `_IO_wstrnfile`，`_wide_data` 指向想修改的目标结构起点。
2. 2.24～2.36 的 primary vtable 必须是 `__libc_IO_vtables` 内的 `_IO_wstrn_jumps`；不要把 `_IO_wstr_jumps` 当成同一个表。
3. 若用 `exit` flush 触发，还得控制 `_IO_list_all`/链表，满足 `write_ptr > write_base` 等筛选条件。经典 largebin 投递自身只到 2.41，但 Apple1 最终触发点已先在 2.37 消失。
4. 在 `_IO_wstrn_overflow` 与 `_IO_wsetb` 下断点，先确认不会错误 `free(target+0x30)`，再接 tcache、`mp_` 或 pointer_guard 等后续链。
