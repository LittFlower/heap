# House of Lys

## 结论

- 适用范围：**glibc 2.23～2.36；2.37 起 exit→_IO_obstack_xsputn 这条调用链就没有了**。
- 原语/效果：把 FILE 的 primary vtable 指向合法的 `_IO_obstack_jumps+0x20`，让本该调用的 overflow 槽错位指到 xsputn，最终间接调用到 fake obstack 里的 chunkfun。
- 版本变化：2.23～2.36 可以沿着 exit→_IO_cleanup→_IO_flush_all_lockp→_IO_obstack_xsputn 这条路径走通；2.37 之后这条路径被删掉了，需要改用 House of Snake 的新链路。

<!-- PRIMITIVE_REQUIREMENTS:START -->
## 原语要求与版本边界

| 项目 | 本手法要求 |
|---|---|
| 最小输入原语 / 信息 | fake FILE + fake obstack；能挂到 exit/flush 链 |
| 关键环境与不变量 | `_IO_obstack_jumps+0x20` 错位；残留 `rdx` 是可用长度 |
| 最终输出原语 | `chunkfun(extra_arg,size)` 间接调用 |
| 版本边界应如何理解 | 2.37 删除旧 `_IO_obstack_xsputn` 消费路径，Lys 硬失效；2.37+ 可迁移到 Snake 的新 printf_buffer 消费路径，但应改名且前置不同。 |
<!-- PRIMITIVE_REQUIREMENTS:END -->

## 从源码看

关键代码在 `stdlib/exit.c`、`libio/genops.c`、`libio/obprintf.c`，以及 2.37 的 printf 重构。源码里的 `_IO_obstack_file` 结构是 `FILE_plus` 后面紧跟一个 `struct obstack *`：在 x86-64 上，`FILE+0xe0` 这个位置必须存的是 fake obstack 的地址，而不是把整个 obstack 结构体直接内嵌在这个偏移处。

exit 触发的 flush 本来会调用 vtable 里 overflow 槽（`+0x18`）指向的函数。如果直接把 primary vtable 设成 `_IO_obstack_jumps`，就会走进 `_IO_obstack_overflow(fp, EOF)`，撞上里面的 `assert(c != EOF)` 而失败。Lys 的解法是把 vtable 错位一个槛位：

```text
primary vtable = _IO_obstack_jumps + 0x20
primary overflow(+0x18) = 原表 xsputn(+0x38)
```

`+0x20` 这个位置仍然落在 `__libc_IO_vtables` 这个 section 内，所以能通过 2.24 起加入的 vtable validation 检查。错位之后的调用会把原本 overflow 的第二个参数 `EOF` 当成 xsputn 的 `data`，还会把调用点残留在寄存器里的 `rdx` 当成 `n`；所以要走通完整的 exit 链，还得按附件的反汇编确认 `rdx` 此时确实是一个可用的正长度。这属于具体构建和触发点的条件，C 函数原型本身并不保证。

能在源码里走到最终的触发点，不代表旧的利用链在具体题目里就一定成立：实际投递方式、私有结构布局和控制流终点，都要按附件 libc/ld 的 Build ID 重新核对。

源码与背景：

- [glibc 2.36 `libio/obprintf.c`](https://github.com/bminor/glibc/blob/glibc-2.36/libio/obprintf.c)
- [glibc 2.36 `libio/genops.c`：cleanup/flush](https://github.com/bminor/glibc/blob/glibc-2.36/libio/genops.c)
- [glibc 2.37 `printf_buffer_flush.c`](https://github.com/bminor/glibc/blob/glibc-2.37/stdio-common/printf_buffer_flush.c)
- [SECCON 2022 babyfile 原始 writeup](https://nasm.re/posts/babyfile/)
- [GNU glibc 当前开发分支](https://github.com/bminor/glibc/tree/master)
- [House of all 综述](https://roderickchan.github.io/zh-cn/2023-02-27-house-of-all-about-glibc-heap-exploitation/)
- [高版本 heap exploitation](https://roderickchan.github.io/zh-cn/2023-03-01-analysis-of-glibc-heap-exploitation-in-high-version/)

## PoC

- [`poc_shifted_obstack_sink_2.23.c`](./poc_shifted_obstack_sink_2.23.c)：线性 PoC，直接用本项目该构建下的 `_IO_wfile_jumps-0x1120`。
- [`poc_shifted_obstack_sink_2.24_2.36.c`](./poc_shifted_obstack_sink_2.24_2.36.c)：线性 PoC，直接用对应构建下的 `_IO_wfile_jumps+0x300`。

两个 C PoC 都只保留了 fake FILE、fake obstack 和一次错位调用；2.24～2.36 那个文件末尾还补了一段 exit/flush 布局的伪代码。要形成完整的攻击链，还需要把 fake FILE 投递到 `_IO_list_all` 或某个标准流上，并确认 exit 调用点当时的 `rdx` 值可用。

## Python 离线板子

[`lys.py`](./lys.py) 提供两个函数：

```text
build_house_of_lys         -> 返回 LysPlan
build_house_of_lys_payload -> 返回 FILE 字段镜像 + fake obstack 镜像
```

### 函数用途

构造以下调用链所需的对象：

```text
__overflow(fp, EOF)
  -> primary vtable = _IO_obstack_jumps + 0x20
  -> _IO_obstack_xsputn
  -> _obstack_newchunk
  -> chunkfun(extra_arg, size)
```

### 对应 PoC

- [`poc_shifted_obstack_sink_2.23.c`](./poc_shifted_obstack_sink_2.23.c)：`_IO_obstack_jumps = _IO_wfile_jumps - 0x1120`；
- [`poc_shifted_obstack_sink_2.24_2.36.c`](./poc_shifted_obstack_sink_2.24_2.36.c)：`_IO_obstack_jumps = _IO_wfile_jumps + 0x300`。

primary vtable 统一再加 `+0x20`，让 overflow 槽落到 xsputn。

### 最小使用示例

```python
from lys import build_house_of_lys, build_house_of_lys_payload

plan = build_house_of_lys(
    version="2.24",
    wfile_jumps_addr=0x7fff0000,  # _IO_wfile_jumps
    obstack_addr=0x200000,        # fake obstack（写 FILE+0xe0）
    chunkfun_addr=0x401234,       # 分配回调
    extra_arg=0x500000,           # callback 第一个参数
)

# 返回 LysPlan；primary_vtable_addr 是 _IO_obstack_jumps+0x20
print(hex(plan.primary_vtable_addr), hex(plan.obstack_addr),
      hex(plan.chunkfun_addr), hex(plan.extra_arg))

writes = build_house_of_lys_payload(
    version="2.24",
    file_addr=0x100000,
    wfile_jumps_addr=0x7fff0000,
    obstack_addr=0x200000,
    chunkfun_addr=0x401234,
    extra_arg=0x500000,
)
for w in writes:
    print(w.label, hex(w.address), w.data.hex())
```

### 参数

| 参数 | 含义 |
|---|---|
| `version` | 目标 glibc 版本，支持 `2.23`～`2.36`。 |
| `wfile_jumps_addr` | 目标 libc 的 `_IO_wfile_jumps` 地址。 |
| `obstack_addr` | fake obstack 地址，将写入 `FILE+0xe0`。 |
| `chunkfun_addr` | `_obstack_newchunk` 间接调用的分配回调。 |
| `extra_arg` | callback 第一个参数。 |
| `object_base` / `next_free` / `chunk_limit` | obstack 当前 chunk 边界；默认 `0/1/0` 让扩容立即发生。 |

### 返回对象 `LysPlan`

| 字段 | 含义 |
|---|---|
| `version` | 目标版本。 |
| `primary_vtable_addr` | `_IO_obstack_jumps + 0x20` 的最终 vtable 地址。 |
| `obstack_addr` | fake obstack 地址。 |
| `object_base` / `next_free` / `chunk_limit` | obstack 当前 chunk 边界。 |
| `chunkfun_addr` | 分配回调地址。 |
| `extra_arg` | callback 第一个参数。 |

### 返回对象 `MemoryWrite`

`build_house_of_lys_payload` 返回两项写入：

```text
1. file_addr -> 0xe8 字节 FILE 字段镜像
       +0xd8  primary vtable = _IO_obstack_jumps + 0x20
       +0xe0  obstack 指针 = obstack_addr

2. obstack_addr -> 0x70 字节 fake obstack 镜像
       +0x38  chunkfun
       +0x40  extra_arg
       +0x50  use_extra_arg = 1
       +0x58/+0x60/+0x68  object_base / next_free / chunk_limit
```

### 调用者必须提供

```text
libc 基址和 _IO_wfile_jumps 地址
能投递 fake FILE 到 _IO_list_all 或标准流的能力
调用点残留的 rdx 可用作 xsputn 长度（或等价触发）
```

### 函数不负责

```text
不生成 fake FILE 完整镜像
不把 fake FILE 挂到 _IO_list_all
不处理 2.37+（旧 _IO_obstack_xsputn 已删除）
```

## 迁移与调试

1. `FILE+0xe0` 处要写的是 fake obstack 的指针，不要把整个 obstack 结构体直接内嵌在这个偏移。
2. primary vtable 写成 `_IO_obstack_jumps+0x20`，并结合 `IO_validate_vtable`、`_IO_obstack_xsputn` 的源码确认这个错位是对的。
3. 需要同时满足 `write_ptr+n > write_end`、`next_free+n > chunk_limit`、`use_extra_arg=1` 这几个条件。
4. 在具体的 exit/fflush 调用点检查 `rdx` 的值；如果它不可用，可以改走 babyfile 那篇文章里的 `_IO_obstack_overflow` 入口，或者换一个能控制第三个参数的触发点。
5. 2.37 及以后旧的 jump table 已经被删除，需要转去看 House of Snake。
