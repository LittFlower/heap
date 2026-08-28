# House of Cat

## 结论

**一句话**：`_IO_wfile_seekoff→_IO_switch_to_wget_mode→_IO_WOVERFLOW` 链路内部的 wide vtable 从未被 `IO_validate_vtable` 校验，用合法偏移后的 primary vtable 就能在 2.24～2.43 到达最终触发点。

| 版本 | 你能拿到什么 | 备注 |
|---|---|---|
| **2.24～2.43** | 不受 primary vtable 白名单约束的 `fake_wide_vtable->__overflow(fp, WEOF)` 间接调用 | `_wide_vtable` 偏移 2.24～2.29 / 2.30 / 2.31+ 分别为 `wide+0x130 / +0xf0 / +0xe0` |
| 2.35 | 原题完整链：largebin attack 覆盖 `stderr` + 旧版 `__malloc_assert` 触发 | “House of Cat”来自 2022 年强网杯同名题，完整链只在 2.35 上验证过 |
| 2.36～2.41 | 触发点还在，largebin 投递也还在 | 要换成正常的 IO/exit 等其他消费点触发 |
| 2.42～2.43 | 仅剩最终触发点 | 得另找任意写手法替代 largebin attack |

要变成真正的 RCE 或 ORW，还得满足调用约定、参数布局以及 CET 等构建限制。

<!-- PRIMITIVE_REQUIREMENTS:START -->
## 原语要求与版本边界

| 项目 | 本手法要求 |
|---|---|
| 最小输入原语 / 信息 | fake FILE/wide data，能投递到可调用 `seekoff` 的流 |
| 关键环境与不变量 | 合法偏移 primary vtable；wide vtable 不单独验证；调用约定可用 |
| 最终输出原语 | 未检查 wide vtable 的 `__overflow(fp,WEOF)` 间接调用 |
| 版本边界应如何理解 | 三代 wide ABI 是适配；原题只验证 2.35，不代表最终触发点仅存在于 2.35。当前上游到 2.43 仍存活。 |
<!-- PRIMITIVE_REQUIREMENTS:END -->

<!-- CHUNK_SIZE_REQUIREMENTS:START -->
## Chunk size 要求

- **`_IO_wfile_seekoff` 最终消费链不要求特定 chunk size。** fake FILE、wide data 与 shifted wide vtable 只需有足够可写空间和正确对齐，可位于 heap 以外。
- 结构字段偏移随 ABI 变化，但那不是 request 范围；采用 largebin、tcache 或 overlap 投递时，另按对应手法满足尺寸要求。
<!-- CHUNK_SIZE_REQUIREMENTS:END -->

## 调用链

常见的 exit/flush 变体会把 primary vtable 里的 `overflow` 槽偏移到 `_IO_wfile_seekoff` 上：

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

`_IO_wfile_jumps + 0x30` 还落在 `__libc_IO_vtables` section 内，primary 校验会放行。而 `_IO_WIDE_JUMPS_FUNC` 只是直接读取 `_wide_data->_wide_vtable`，不调用 `IO_validate_vtable`，这正是本手法绕过检查的关键。

## 关键字段

以 x86-64 常见 ABI 为例：

- `FILE->_wide_data`：`FILE+0xa0`；
- `FILE->_mode`：`FILE+0xc0`，得让 wide 路径成立；
- primary vtable：`FILE+0xd8`；
- `_wide_data->_IO_write_base`：`wide+0x18`；
- `_wide_data->_IO_write_ptr`：`wide+0x20`，必须大于 `write_base`；
- `_wide_data->_wide_vtable`：2.24～2.29 为 `wide+0x130`，2.30 为 `wide+0xf0`，2.31～2.43 为 `wide+0xe0`；
- fake wide vtable 的 `overflow`：`fake_wide_vtable+0x18`。

只要回调返回 `WEOF`，`_IO_switch_to_wget_mode` 就立即失败，`_IO_wfile_seekoff` 随之直接返回。这样微型 PoC 只需验证回调这一个最终触发点，不必再满足 seek 操作里 codecvt、buffer、file-descriptor 那几条分支的条件。

## 从源码看

- [`_IO_wfile_seekoff`](https://github.com/bminor/glibc/blob/master/libio/wfileops.c)
- [`_IO_switch_to_wget_mode`](https://github.com/bminor/glibc/blob/master/libio/wgenops.c)
- [`_IO_WIDE_JUMPS_FUNC` 不做 whitelist](https://github.com/bminor/glibc/blob/master/libio/libioP.h)
- [2.24 primary vtable validation](https://sourceware.org/git/?p=glibc.git;a=commit;h=db3476aff19b75c4fdefbe65fcd5f0a90588ba51)
- [2.30 删除 legacy codecvt 函数表](https://sourceware.org/git/?p=glibc.git;a=commit;h=09e1b0e3f6facc1af2dbcfef204f0aaa8718772b)
- [强网杯 2022 house_of_cat 题目 writeup/附件语境](https://4f-kira.github.io/2022/08/07/qwb2022/)

这些最终触发点和字段数据流，本目录的 PoC 分别在 2.24、2.35、2.43 三个端点上都实际跑通过。**但这不代表原题在 2.35 上验证的 largebin + assert 完整链能自动延伸到 2.43。**

## PoC

- [`poc_wide_seekoff_2.24_2.29.c`](./poc_wide_seekoff_2.24_2.29.c)：legacy codecvt 布局，`_wide_vtable=wide+0x130`。
- [`poc_wide_seekoff_2.30.c`](./poc_wide_seekoff_2.30.c)：codecvt 函数表刚删除、但 `_IO_iconv_t` 尚未缩小的单版本布局，`_wide_vtable=wide+0xf0`。
- [`poc_wide_seekoff_2.31_2.43.c`](./poc_wide_seekoff_2.31_2.43.c)：现代 `_IO_iconv_t` 布局，`_wide_vtable=wide+0xe0`。

三个 PoC 都使用真实的 `_IO_wfile_jumps`，把 primary vtable 偏移合法的 `+0x30`，再调用 glibc 自带的 `__overflow` 走一遍 primary whitelist 校验。marker 回调返回 `WEOF`，最后用 assert 验证 wide 回调确实被执行。

```bash
./tools/run_in_docker.sh 2.24 house_of_cat/poc_wide_seekoff_2.24_2.29.c
./tools/run_in_docker.sh 2.30 house_of_cat/poc_wide_seekoff_2.30.c
./tools/run_in_docker.sh 2.43 house_of_cat/poc_wide_seekoff_2.31_2.43.c
```

## 迁移到题目

1. 先确定 primary 消费槽用哪个：exit/flush 常见走的是 `overflow`，如果换成其他触发路径，就要用 `seekoff_offset - called_slot_offset` 重新计算偏移。
2. 确认偏移后的 primary vtable 指针整体还落在 `__libc_IO_vtables` 区域内，并且被调用的槽位确实是 `_IO_wfile_seekoff`。
3. 让 `write_ptr > write_base` 这两处条件和 `_mode` 都满足目标源码分支的要求；同时为 `_lock`、buffer、codecvt 准备好可读写的对象。
4. 回调第一个参数是伪造的 `FILE *`，第二个是 `WEOF`。做 `system(fp)` 变体时，`FILE` 开头必须能被解释成命令字符串；ORW 或 setcontext 变体需按附件实际 gadget 重新构造。
