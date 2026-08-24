# House of Apple 2

## 结论

- 适用范围：**2.24～2.43（最终触发点）；投递原语需另选**。
- 原语/效果：保留合法的主 vtable，利用未被单独校验的 `_wide_data->_wide_vtable`，经 `_IO_wfile_overflow→_IO_wdoallocbuf` 调用受控 `doallocate`。
- 版本变化：2.24 起使用合法 `_IO_wfile_jumps`；`_wide_vtable` 字段偏移在 2.24～2.29 / 2.30 / 2.31+ 分别是 `0x130 / 0xf0 / 0xe0`；2.34 hooks 删除不影响最终触发点；2.42/2.43 仍从 fake wide vtable 取 doallocate，但经典 largebin 投递已失效。

<!-- PRIMITIVE_REQUIREMENTS:START -->
## 原语要求与版本边界

| 项目 | 本手法要求 |
|---|---|
| 最小输入原语 / 信息 | 能覆盖/投递 fake FILE 与 wide data；能触发 wide overflow |
| 关键环境与不变量 | 合法 `_IO_wfile_jumps`；可控 fake wide vtable；x86-64 wide ABI |
| 最终输出原语 | `doallocate(fp)` 间接调用/CF |
| 版本边界应如何理解 | 2.30、2.31 只改 `_wide_vtable` 偏移，属于适配；2.42 切断经典 largebin 投递，但最终触发点到 2.43 仍在。 |
<!-- PRIMITIVE_REQUIREMENTS:END -->

## 从源码看

`libio/libioP.h` 的 WJUMP、`libio/wfileops.c`，以及 `libio/libio.h` 中 `_IO_wide_data/_IO_iconv_t` 的布局。2.30 的 [`09e1b0e`](https://sourceware.org/git/?p=glibc.git;a=commit;h=09e1b0e3f6facc1af2dbcfef204f0aaa8718772b) 删除 legacy codecvt 函数表；2.31 的 [`70c6e15`](https://sourceware.org/git/?p=glibc.git;a=commit;h=70c6e15654928c603c6d24bd01cf62e7a8e2ce9b) 又缩小 `_IO_iconv_t`。

源码中仍能走到最终触发点，不等于旧利用链仍成立：投递方式、私有结构和控制流终点都要按附件 libc/ld 的 Build ID 复核。

源码与背景：

- [glibc 2.43 `libio/wfileops.c`](https://sourceware.org/cgit/glibc/tree/libio/wfileops.c?h=release/2.43/master)
- [glibc 2.43 `_IO_wide_data` 定义](https://sourceware.org/cgit/glibc/tree/libio/libio.h?h=release/2.43/master)
- [House of Apple 2 原始文章](https://roderickchan.github.io/zh-cn/house-of-apple-%E4%B8%80%E7%A7%8D%E6%96%B0%E7%9A%84glibc%E4%B8%ADio%E6%94%BB%E5%87%BB%E6%96%B9%E6%B3%95-2/)
- [GNU glibc 当前开发分支](https://github.com/bminor/glibc/tree/master)
- [House of all 综述](https://roderickchan.github.io/zh-cn/2023-02-27-house-of-all-about-glibc-heap-exploitation/)
- [高版本 heap exploitation](https://roderickchan.github.io/zh-cn/2023-03-01-analysis-of-glibc-heap-exploitation-in-high-version/)

## PoC

- [`poc_sink_2.24_2.29.c`](./poc_sink_2.24_2.29.c)：可执行最终触发点；真实经过合法 primary vtable，使用 `wide->_wide_vtable=wide+0x130` 调用 fake doallocate。
- [`poc_sink_2.30.c`](./poc_sink_2.30.c)：可执行 2.30 过渡 ABI，偏移 `+0xf0`。
- [`poc_sink_2.31_2.43.c`](./poc_sink_2.31_2.43.c)：可执行现代 ABI，偏移 `+0xe0`；2.43 端点已实跑。

三份 C 文件已经直接写出各自 ABI 的 fake FILE、wide data 和 fake wide vtable 字段，不再另存重复的布局生成器。2.42～2.43 继续使用 `+0xe0`，但投递原语必须另选。

## Python 离线板子

[`apple2.py`](./apple2.py) 按目标 glibc 版本生成 Apple2 **最终消费点**所需的写入计划。它严格对应三份 C PoC：

```python
from apple2 import build_house_of_apple2

writes = build_house_of_apple2(
    "2.35",                         # 2.31～2.43 使用 wide_data + 0xe0
    file_addr=fake_file,
    fake_wide_data_addr=fake_wide_data,
    fake_wide_vtable_addr=fake_wide_vtable,
    callback_addr=callback,
    wfile_jumps_addr=libc_base + io_wfile_jumps_offset,
    narrow_buffer_addr=controlled_buffer,
    current_flags=known_file_flags,  # 不知道时省略，保留原 flags
)

for write in writes:
    write_primitive(write.address, write.data)
```

### `build_house_of_apple2` 参数

| 参数 | 含义 |
|---|---|
| `version` | 目标 glibc 版本字符串。支持 `2.24`～`2.43`；根据此选择 `_wide_vtable` 的 `0x130`、`0xf0` 或 `0xe0` 偏移。 |
| `file_addr` | fake FILE 或被覆盖的现有 FILE 地址；函数会在这个地址生成 `FILE` 字段写入。 |
| `fake_wide_data_addr` | fake `_IO_wide_data` 地址；`FILE + 0xa0` 会指向这里。该地址必须可写并满足题目布局要求。 |
| `fake_wide_vtable_addr` | fake wide vtable 地址；fake wide data 的版本对应槽位会指向这里。 |
| `callback_addr` | fake wide vtable 的 `__doallocate` 回调地址，固定写在 vtable `+0x68`；实际回调用途由题目决定。 |
| `wfile_jumps_addr` | 目标 libc 中合法 `_IO_wfile_jumps` 地址，写入 `FILE + 0xd8` 以通过 primary vtable 检查。 |
| `narrow_buffer_addr` | fake FILE 使用的窄字符缓冲区地址；对应 PoC 中的 `narrow_buffer`，函数按固定 `0x20` 字节生成结束地址。 |
| `current_flags` | 当前 `_flags` 值；已知时传入，函数清除 `NO_WRITES`、`UNBUFFERED`、`CURRENTLY_PUTTING`，未知时省略以保留原字段。 |

返回值是 `MemoryWrite` 元组。每项包含 `address`、`data` 和 `label`，可直接交给题目的任意写、堆对象编辑或分段写入函数。函数不负责 fake FILE 的投递、libc 地址解析、`__woverflow` 触发或 callback 后续控制流。

版本对应关系：

```text
2.24～2.29: fake_wide_data + 0x130 -> fake_wide_vtable
2.30:       fake_wide_data + 0x0f0 -> fake_wide_vtable
2.31～2.43: fake_wide_data + 0x0e0 -> fake_wide_vtable
所有版本:   fake_wide_vtable + 0x068 -> callback
```

返回的 `MemoryWrite` 包含绝对地址、零填充对象镜像和标签。函数只负责消费点布局；`wfile_jumps_addr`、fake FILE 的投递、`__woverflow`/等价 wide overflow 触发和 callback 的实际语义由题目 exploit 提供。它不假设 largebin、stderr 覆盖或任何 hook 终点。

## 迁移与调试

1. 先确认投递路径和最终触发点在目标 Build ID 中都存在。
2. 把占位地址和 add/edit/free 顺序替换成题目能力。
3. 在消费函数下断点，逐字段核对 size、对齐、safe-linking、FILE/link_map 私有布局。
