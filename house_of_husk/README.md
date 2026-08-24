# House of Husk

## 结论

- 适用范围：**printf handler 这个最终触发点从 2.23 到 2.43 一直存在；本目录用 largebin 投递的完整 PoC 覆盖到 2.41**。
- 原语/效果：改写 `__printf_function_table` 和 `__printf_arginfo_table`，让 printf 解析格式串时间接调用我们控制的函数。
- 版本变化：2.23～2.41 都可以用 largebin attack 投递；2.42 加固了 `nextsize` 检查，这条投递路径失效；2.43 的 `reg-printf.c`/`vfprintf-internal.c` 仍然会读这两张表，只要题目另外提供任意写，最终触发点依然可以打通。

<!-- PRIMITIVE_REQUIREMENTS:START -->
## 原语要求与版本边界

| 项目 | 本手法要求 |
|---|---|
| 最小输入原语 / 信息 | 能写两张隐藏 printf 表；有可控格式串触发 |
| 关键环境与不变量 | `__printf_function_table/__printf_arginfo_table` 真实偏移、表项与参数 ABI |
| 最终输出原语 | printf 解析时受控回调/CF |
| 版本边界应如何理解 | 最终触发点到 2.43 仍在；2.42 只封常用的经典 largebin 投递。隐藏偏移是 Build-ID 条件，局部写到“某个可写地址”不算成功。 |
<!-- PRIMITIVE_REQUIREMENTS:END -->

## 从源码看

涉及三处源码：`stdio-common/reg-printf.c`、`vfprintf-internal.c`，以及 `malloc.c` 里 largebin 的插入逻辑。

源码里仍能走到最终触发点，不代表旧的完整利用链还成立：投递方式、私有结构和控制流终点都需要按附件 libc/ld 的 Build ID 逐一复核。

源码与背景：

- [glibc 2.43 `stdio-common/reg-printf.c`](https://sourceware.org/cgit/glibc/tree/stdio-common/reg-printf.c?h=release/2.43/master)
- [glibc 2.43 `vfprintf-internal.c`](https://sourceware.org/cgit/glibc/tree/stdio-common/vfprintf-internal.c?h=release/2.43/master)
- [glibc 2.41 `malloc.c`：经典 largebin 投递末版](https://github.com/bminor/glibc/blob/glibc-2.41/malloc/malloc.c)
- [GNU glibc 当前开发分支](https://github.com/bminor/glibc/tree/master)
- [House of all 综述](https://roderickchan.github.io/zh-cn/2023-02-27-house-of-all-about-glibc-heap-exploitation/)
- [高版本 heap exploitation](https://roderickchan.github.io/zh-cn/2023-03-01-analysis-of-glibc-heap-exploitation-in-high-version/)

## PoC

- [`poc_printf_handler_sink_2.23_2.43.c`](./poc_printf_handler_sink_2.23_2.43.c)：通过官方注册 API 初始化同一组内部 handler 表，真实触发 arginfo/handler。用于验证跨版本都存在的最终触发点，不把这个 API 本身伪装成漏洞。
- [`poc_2.27.c`](./poc_2.27.c)
- [`poc_2.35.c`](./poc_2.35.c)
- [`poc_2.37.c`](./poc_2.37.c)
- [`poc_2.39.c`](./poc_2.39.c)
- [`poc_2.41.c`](./poc_2.41.c)：这 5 个都绑定各自构建的实际偏移，只有真的走到 `HUSK_<version>_CALLBACK` 才算通过，不再用 one-gadget 或非交互 shell 的返回码这类模糊判据。

[`poc_2.41.c`](./poc_2.41.c) 里的偏移对应当前验证镜像 Ubuntu 25.04 `GLIBC 2.41-6ubuntu1.2`：`main_arena=0x210ac0`、`__printf_function_table=0x212700`、`__printf_arginfo_table=0x212708`，来自 `libc6-dbg` Build ID `ae7440bbdce614e0e79280c3b2e45b1df44e639c`。题目附件不同的话必须重新计算，不要把这三个数直接当成整个 2.41 分支的 ABI。

上面 5 个完整投递 PoC 都是用 largebin attack 先后改写两张表，不是靠官方注册 API；通用最终触发点 PoC 则反过来故意用官方 API，单独证明 2.42/2.43 仍然存在消费路径。

## Python 离线板子

[`husk.py`](./husk.py) 提供 `build_house_of_husk`，生成两张 printf handler 表的目标写入计划。

### 函数用途

构造 printf 解析 `format_char` 时读取的 handler 表关系：

```text
printf("%X")
  -> __printf_arginfo_table[X - 2] -> arginfo 回调
  -> __printf_function_table[X - 2] -> handler 回调
```

### 对应 PoC

- [`poc_printf_handler_sink_2.23_2.43.c`](./poc_printf_handler_sink_2.23_2.43.c)：官方 API 隔离验证最终触发点；
- [`poc_2.27.c`](./poc_2.27.c) 等版本文件：真实 largebin 投递完整链，偏移绑定各自构建。

### 表索引

glibc 的 handler 表按 `specifier - 2` 索引：

```text
slot = format_char - slot_bias
默认 slot_bias = 2
```

因此 `%X`（ASCII 0x58）使用 `0x58 - 2 = 0x56` 号槽，即 `table + 0x56 * 8`。

### 最小使用示例

```python
from husk import build_house_of_husk

writes = build_house_of_husk(
    printf_function_table_addr=0x7fff1000,   # libc 隐藏表指针
    printf_arginfo_table_addr=0x7fff1008,    # libc 隐藏表指针
    function_table_data_addr=0x400000,       # 伪 function 表
    arginfo_table_data_addr=0x401000,        # 伪 arginfo 表
    format_char=ord("X"),
    handler_addr=0x402000,                   # 回调
)

# 三个 MemoryWrite：
# 1. __printf_function_table 指针
# 2. __printf_arginfo_table 指针
# 3. arginfo 表槽位
for w in writes:
    print(w.label, hex(w.address), w.data.hex())
```

### 参数

| 参数 | 含义 |
|---|---|
| `printf_function_table_addr` | libc 中 `__printf_function_table` 全局指针地址，必须按目标 Build ID 解析。 |
| `printf_arginfo_table_addr` | libc 中 `__printf_arginfo_table` 全局指针地址，必须按目标 Build ID 解析。 |
| `function_table_data_addr` | 伪 `__printf_function_table` 表的实际可写地址。 |
| `arginfo_table_data_addr` | 伪 `__printf_arginfo_table` 表的实际可写地址。 |
| `format_char` | 触发 handler 的格式字符 ASCII 值，例如 `ord('X')`。 |
| `handler_addr` | 伪 arginfo 表对应槽位的回调地址。 |
| `slot_bias` | 表索引偏移，PoC 默认值为 2；目标源码/构建不同时显式修改。 |

### 返回对象

返回三个 `MemoryWrite`。`MemoryWrite` 每个成员含义：

| 成员 | 含义 |
|---|---|
| `address` | 要写入的绝对地址。 |
| `data` | 要写入的小端字节串（`bytes`）。 |
| `label` | 该写入的用途标签，用于调试和识别。 |

各写入内容：

```text
1. printf_function_table_addr -> function_table_data_addr
2. printf_arginfo_table_addr -> arginfo_table_data_addr
3. arginfo_table_data_addr + slot * 8 -> handler_addr
```

注意：两张伪表是不同对象，不能共用一个 `table_addr`。

### 调用者必须提供

```text
libc 基址和两张隐藏表指针的真实地址（Build ID 相关）
可写的两张伪表区
能触发含 format_char 的 printf 的入口
```

### 函数不负责

```text
不负责 largebin 投递
不负责隐藏符号偏移解析
不触发 printf
不处理 handler 的参数 ABI 和最终控制流
```

## 迁移与调试

1. 先确认投递路径和最终触发点在目标 Build ID 中是否都存在。
2. 把占位地址和 add/edit/free 的调用顺序换成题目实际提供的能力。
3. 在消费函数处下断点，逐字段核对 size、对齐、safe-linking，以及 FILE/link_map 的私有布局。
