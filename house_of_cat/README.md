# House of Cat

## 结论

- `_IO_wfile_seekoff -> _IO_switch_to_wget_mode -> _IO_WOVERFLOW` 最终触发点：**glibc 2.24～2.43** 可用合法偏移 primary vtable 到达；内部 wide vtable 未经过 `IO_validate_vtable`。
- “House of Cat”命名来自 2022 强网杯同名题，原题完整链基于 **glibc 2.35**。
- 原题/常见完整链用 largebin attack 覆盖 `stderr`，再用旧 `__malloc_assert` 触发；因此原投递只到 2.41、原触发只到 2.35。2.36+ 需正常 IO/exit 等别的消费点，2.42+ 还需替代 largebin 任意写。
- 原语效果：最终 `fake_wide_vtable->__overflow(fp, WEOF)` 可调用不受 primary vtable whitelist 约束的目标函数；实际 RCE/ORW 仍需满足调用约定、参数与 CET/构建条件。

<!-- PRIMITIVE_REQUIREMENTS:START -->
## 原语要求与版本边界

| 项目 | 本手法要求 |
|---|---|
| 最小输入原语 / 信息 | fake FILE/wide data，能投递到可调用 `seekoff` 的流 |
| 关键环境与不变量 | 合法偏移 primary vtable；wide vtable 不单独验证；调用约定可用 |
| 最终输出原语 | 未检查 wide vtable 的 `__overflow(fp,WEOF)` 间接调用 |
| 版本边界应如何理解 | 三代 wide ABI 是适配；原题只验证 2.35，不代表最终触发点仅存在于 2.35。当前上游到 2.43 仍存活。 |
<!-- PRIMITIVE_REQUIREMENTS:END -->

## 调用链

常见 exit/flush 变体让 primary `overflow` 槽落到 `_IO_wfile_seekoff`：

```text
fake FILE primary vtable = _IO_wfile_jumps + (seekoff - overflow)
                         = _IO_wfile_jumps + (0x48 - 0x18)
                         = _IO_wfile_jumps + 0x30

_IO_OVERFLOW(fake, EOF)
  -> _IO_wfile_seekoff(fake, ...)
  -> _IO_switch_to_wget_mode(fake)
  -> _IO_WOVERFLOW(fake, WEOF)
  -> fake->_wide_data->_wide_vtable->__overflow(fake, WEOF)
```

`_IO_wfile_jumps + 0x30` 仍在 `__libc_IO_vtables` section 内，primary 校验会放行；`_IO_WIDE_JUMPS_FUNC` 只是读取 `_wide_data->_wide_vtable`，没有调用 `IO_validate_vtable`。

## 关键字段

以 x86-64 常见 ABI 为例：

- `FILE->_wide_data`：`FILE+0xa0`；
- `FILE->_mode`：`FILE+0xc0`，应让 wide 路径成立；
- primary vtable：`FILE+0xd8`；
- `_wide_data->_IO_write_base`：`wide+0x18`；
- `_wide_data->_IO_write_ptr`：`wide+0x20`，必须大于 `write_base`；
- `_wide_data->_wide_vtable`：2.24～2.29 为 `wide+0x130`，2.30 为 `wide+0xf0`，2.31～2.43 为 `wide+0xe0`；
- fake wide vtable 的 `overflow`：`fake_wide_vtable+0x18`。

如果回调返回 `WEOF`，`_IO_switch_to_wget_mode` 会立即失败并让 `_IO_wfile_seekoff` 返回，可把微型 PoC 限定在回调最终触发点，不必继续满足 seek 的 codecvt/buffer/file-descriptor 分支。

## 从源码看

- [`_IO_wfile_seekoff`](https://github.com/bminor/glibc/blob/master/libio/wfileops.c)
- [`_IO_switch_to_wget_mode`](https://github.com/bminor/glibc/blob/master/libio/wgenops.c)
- [`_IO_WIDE_JUMPS_FUNC` 不做 whitelist](https://github.com/bminor/glibc/blob/master/libio/libioP.h)
- [2.24 primary vtable validation](https://sourceware.org/git/?p=glibc.git;a=commit;h=db3476aff19b75c4fdefbe65fcd5f0a90588ba51)
- [2.30 删除 legacy codecvt 函数表](https://sourceware.org/git/?p=glibc.git;a=commit;h=09e1b0e3f6facc1af2dbcfef204f0aaa8718772b)
- [强网杯 2022 house_of_cat 题目 writeup/附件语境](https://4f-kira.github.io/2022/08/07/qwb2022/)

上述最终触发点与字段数据流在 2.24、2.35、2.43 端点都由本目录 PoC 实跑。**这不等于原题 2.35 的 largebin + assert 完整链自动延伸到 2.43。**

## PoC

- [`poc_wide_seekoff_2.24_2.29.c`](./poc_wide_seekoff_2.24_2.29.c)：legacy codecvt 布局，`_wide_vtable=wide+0x130`。
- [`poc_wide_seekoff_2.30.c`](./poc_wide_seekoff_2.30.c)：codecvt 函数表刚删除、但 `_IO_iconv_t` 尚未缩小的单版本布局，`_wide_vtable=wide+0xf0`。
- [`poc_wide_seekoff_2.31_2.43.c`](./poc_wide_seekoff_2.31_2.43.c)：现代 `_IO_iconv_t` 布局，`_wide_vtable=wide+0xe0`。

三个 PoC 都使用真实 `_IO_wfile_jumps`、合法 `+0x30` primary vtable，并调用 glibc 的 `__overflow` 经过 primary whitelist；marker 回调返回 `WEOF`，assert 验证 wide 回调被执行。

```bash
./tools/run_in_docker.sh 2.24 house_of_cat/poc_wide_seekoff_2.24_2.29.c
./tools/run_in_docker.sh 2.30 house_of_cat/poc_wide_seekoff_2.30.c
./tools/run_in_docker.sh 2.43 house_of_cat/poc_wide_seekoff_2.31_2.43.c
```

## 迁移到题目

1. 先选 primary 消费槽：exit/flush 常见是 `overflow`，其他触发要用 `seekoff_offset - called_slot_offset` 重算。
2. 确认 shifted primary vtable 的整个指针仍落在 `__libc_IO_vtables`，且被调用槽确实是 `_IO_wfile_seekoff`。
3. 令两处 `write_ptr > write_base` 条件和 `_mode` 满足目标源码分支；为 `_lock`、buffer、codecvt 准备可读写对象。
4. 回调的第一个参数是 fake `FILE *`，第二个是 `WEOF`；`system(fp)` 变体要求 `FILE` 开头可解释为命令字符串，ORW/setcontext 变体则按附件 gadget 重做。
