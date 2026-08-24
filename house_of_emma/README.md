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

[`emma.py`](./emma.py) 生成 `_IO_cookie_file` 的 cookie 和四个 callback 槽，并提供 pointer_guard 的恢复/编码辅助函数。

```python
from emma import build_house_of_emma

writes = build_house_of_emma(
    version="2.35",
    file_addr=fake_file,
    cookie_addr=controlled_cookie,
    callback_addr=callback,
    pointer_guard=guard,
)
```

| 参数 | 含义 |
|---|---|
| `version` | 2.23 使用明文 callback；2.24～2.43 使用 PTR_MANGLE。 |
| `file_addr` | fake `_IO_cookie_file` 起点。 |
| `cookie_addr` | 写入 `FILE + 0xe0` 的 cookie 参数。 |
| `callback_addr` | write callback 明文地址；函数按版本编码。 |
| `pointer_guard` | 2.24+ 的 pointer guard；未知时拒绝生成密文。 |
| `read_addr` / `seek_addr` / `close_addr` | 其余三个 cookie callback 槽，默认 0，按题目实际触发路径补充。 |

`recover_pointer_guard(known_callback_addr, encoded_callback)` 可由已知明文 callback 和泄露的密文恢复 guard；函数不负责 FILE 投递、flags 或触发条件。

## 迁移与调试

1. 先确认投递路径和最终触发点在目标 Build ID 上都真实存在。
2. 把占位地址和 add/edit/free 的顺序换成题目实际给出的能力。
3. 在消费函数处下断点，逐字段核对 size、对齐、safe-linking，以及 FILE/link_map 的私有布局。
