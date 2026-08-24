# House of Cat

## 结论

- `_IO_wfile_seekoff -> _IO_switch_to_wget_mode -> _IO_WOVERFLOW` 这条调用链的最终触发点在 **glibc 2.24～2.43** 都能用合法偏移后的 primary vtable 到达，原因是链路内部的 wide vtable 从未被 `IO_validate_vtable` 校验过。
- “House of Cat”这个名字来自 2022 年强网杯的同名题目，原题给出的完整链是在 **glibc 2.35** 上验证的。
- 原题及常见的完整链都是先用 largebin attack 覆盖 `stderr`，再靠旧版 `__malloc_assert` 触发，所以这条投递路径最多能延续到 2.41，触发点则只在 2.35 上被验证过。2.36 及之后的版本需要换成正常的 IO/exit 等其他消费点才能触发；2.42 及之后还得再找别的任意写手法替代 largebin attack。
- 原语最终能做到的事：让 `fake_wide_vtable->__overflow(fp, WEOF)` 调用一个不受 primary vtable 白名单约束的目标函数；但要把它变成真正的 RCE 或 ORW，仍然要满足调用约定、参数布局，以及 CET 等构建相关的限制条件。

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

`_IO_wfile_jumps + 0x30` 这个地址仍然落在 `__libc_IO_vtables` section 内，所以 primary 校验会放行；而 `_IO_WIDE_JUMPS_FUNC` 只是直接读取 `_wide_data->_wide_vtable`，并不会调用 `IO_validate_vtable` 做校验，这正是本手法能绕过检查的关键。

## 关键字段

以 x86-64 常见 ABI 为例：

- `FILE->_wide_data`：`FILE+0xa0`；
- `FILE->_mode`：`FILE+0xc0`，应让 wide 路径成立；
- primary vtable：`FILE+0xd8`；
- `_wide_data->_IO_write_base`：`wide+0x18`；
- `_wide_data->_IO_write_ptr`：`wide+0x20`，必须大于 `write_base`；
- `_wide_data->_wide_vtable`：2.24～2.29 为 `wide+0x130`，2.30 为 `wide+0xf0`，2.31～2.43 为 `wide+0xe0`；
- fake wide vtable 的 `overflow`：`fake_wide_vtable+0x18`。

只要回调返回 `WEOF`，`_IO_switch_to_wget_mode` 就会立即失败，进而让 `_IO_wfile_seekoff` 直接返回。这样一来，微型 PoC 就可以只验证回调这一个最终触发点，不必再去满足 seek 操作里 codecvt、buffer、file-descriptor 那几条分支的条件。

## 从源码看

- [`_IO_wfile_seekoff`](https://github.com/bminor/glibc/blob/master/libio/wfileops.c)
- [`_IO_switch_to_wget_mode`](https://github.com/bminor/glibc/blob/master/libio/wgenops.c)
- [`_IO_WIDE_JUMPS_FUNC` 不做 whitelist](https://github.com/bminor/glibc/blob/master/libio/libioP.h)
- [2.24 primary vtable validation](https://sourceware.org/git/?p=glibc.git;a=commit;h=db3476aff19b75c4fdefbe65fcd5f0a90588ba51)
- [2.30 删除 legacy codecvt 函数表](https://sourceware.org/git/?p=glibc.git;a=commit;h=09e1b0e3f6facc1af2dbcfef204f0aaa8718772b)
- [强网杯 2022 house_of_cat 题目 writeup/附件语境](https://4f-kira.github.io/2022/08/07/qwb2022/)

上述最终触发点和字段数据流，本目录的 PoC 分别在 2.24、2.35、2.43 三个端点上都实际跑通过。**但这不代表原题在 2.35 上验证的 largebin + assert 完整链能够自动延伸到 2.43。**

## PoC

- [`poc_wide_seekoff_2.24_2.29.c`](./poc_wide_seekoff_2.24_2.29.c)：legacy codecvt 布局，`_wide_vtable=wide+0x130`。
- [`poc_wide_seekoff_2.30.c`](./poc_wide_seekoff_2.30.c)：codecvt 函数表刚删除、但 `_IO_iconv_t` 尚未缩小的单版本布局，`_wide_vtable=wide+0xf0`。
- [`poc_wide_seekoff_2.31_2.43.c`](./poc_wide_seekoff_2.31_2.43.c)：现代 `_IO_iconv_t` 布局，`_wide_vtable=wide+0xe0`。

三个 PoC 都使用真实的 `_IO_wfile_jumps`，把 primary vtable 偏移合法的 `+0x30`，再调用 glibc 自带的 `__overflow` 走一遍 primary whitelist 校验；marker 回调返回 `WEOF`，最后用 assert 验证 wide 回调确实被执行了。

## Python 离线板子

[`cat.py`](./cat.py) 生成三段 ABI 对应的 fake FILE、fake wide data 和 fake wide vtable。

```python
from cat import build_house_of_cat

writes = build_house_of_cat(
    "2.43",
    file_addr=fake_file,
    fake_wide_data_addr=wide_data,
    fake_wide_vtable_addr=wide_vtable,
    callback_addr=callback,
    wfile_jumps_addr=libc_base + io_wfile_jumps_offset,
)
```

| 参数 | 含义 |
|---|---|
| `version` | 目标 glibc 版本；决定 `_wide_vtable` 为 `+0x130`、`+0xf0` 或 `+0xe0`。 |
| `file_addr` | fake FILE 地址。 |
| `fake_wide_data_addr` | fake `_IO_wide_data` 地址，写入 `FILE + 0xa0`。 |
| `fake_wide_vtable_addr` | fake wide vtable 地址。 |
| `callback_addr` | fake wide vtable `__overflow` 槽地址，固定写入 vtable `+0x18`。 |
| `wfile_jumps_addr` | 目标 libc 的合法 `_IO_wfile_jumps` 地址；函数写入偏移后的 primary vtable `+0x30`。 |

返回 `MemoryWrite` 元组，包含绝对地址、对象镜像和标签。函数不负责 `_IO_list_all` 投递、`__overflow` 触发或 callback 的调用约定。

```bash
./tools/run_in_docker.sh 2.24 house_of_cat/poc_wide_seekoff_2.24_2.29.c
./tools/run_in_docker.sh 2.30 house_of_cat/poc_wide_seekoff_2.30.c
./tools/run_in_docker.sh 2.43 house_of_cat/poc_wide_seekoff_2.31_2.43.c
```

## 迁移到题目

1. 先确定 primary 消费槽用哪个：exit/flush 常见走的是 `overflow`，如果换成其他触发路径，就要用 `seekoff_offset - called_slot_offset` 重新计算偏移。
2. 确认偏移后的 primary vtable 指针整体仍落在 `__libc_IO_vtables` 区域内，并且被调用的槽位确实是 `_IO_wfile_seekoff`。
3. 让 `write_ptr > write_base` 这两处条件和 `_mode` 都满足目标源码分支的要求；同时为 `_lock`、buffer、codecvt 准备好可读写的对象。
4. 回调函数的第一个参数是伪造的 `FILE *`，第二个是 `WEOF`；如果要做 `system(fp)` 这类变体，`FILE` 结构体开头必须能被解释成命令字符串，ORW 或 setcontext 变体则需要按附件里实际的 gadget 重新构造。
