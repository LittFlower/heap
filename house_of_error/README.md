# House of Error

## 结论

**一句话**：fake memstream 配合 `__libc_IO_vtables` 段内偏移 vtable，一次 `_IO_mem_sync` 拿到两个相关 qword 写；这个触发点 2.24～2.43 都在。

| 版本 | 你能拿到什么 | 备注 |
|---|---|---|
| **2.24～2.43** | `_IO_mem_sync` 双写，本目录默认指这条 | 2.23 已经有这个函数，但当时还没有 vtable whitelist，用不上这条绕法；第二次写受差值约束，不是两次独立 AAW |
| 2.35 原始链 | largebin 覆盖 `stderr` + `__malloc_assert→fflush(stderr)` 端到端 | 原作者完整 exploit 绑定 2.35 特定构建；专用 assert 触发方式只到 2.35 |
| 2.36～2.41 | 双写还在，可保留 largebin 投递 | 2.36 切断旧 assert 触发，要另外找标准流消费点 |
| 2.42～2.43 | 仅剩 `_IO_mem_sync` 双写本身 | largebin 投递失效，任意写投递与触发都要重新想办法 |

前置能力：libc 地址泄露、一个可控的 fake FILE、把标准流指针或链条指向它的手段；是否需要堆地址泄露取决于触发方式。

<!-- PRIMITIVE_REQUIREMENTS:START -->
## 原语要求与版本边界

| 项目 | 本手法要求 |
|---|---|
| 最小输入原语 / 信息 | libc leak、fake memstream、能把流指针/链投向它 |
| 关键环境与不变量 | 合法 section 内错位 vtable；`write_ptr!=write_end`；两目标可写 |
| 最终输出原语 | 一次触发两个相关 qword 写 |
| 版本边界应如何理解 | `_IO_mem_sync` 最终触发点到 2.43 仍在；2.36 切断旧 assert 触发，2.42 切断 largebin 投递。第二次写受差值约束，不是两次独立 AAW。 |
<!-- PRIMITIVE_REQUIREMENTS:END -->

<!-- CHUNK_SIZE_REQUIREMENTS:START -->
## Chunk size 要求

- **`_IO_mem_sync` 双写消费端没有 bin/chunk size 前提。** fake FILE 与附属缓冲字段只需要足够的连续可写空间和正确对齐，不要求来自 malloc chunk。
- 用何种 heap attack 覆盖 FILE 或把它挂入链表是独立投递阶段；该阶段的 request 范围应按所选原语另算。
<!-- CHUNK_SIZE_REQUIREMENTS:END -->

## 核心原语

`struct _IO_FILE_memstream` 在 `_IO_strfile` 后追加 `bufloc` 和 `sizeloc`。`_IO_mem_sync` 最后执行：

```c
*mp->bufloc = fp->_IO_write_base;
*mp->sizeloc = fp->_IO_write_ptr - fp->_IO_write_base;
```

所以只要控制好 fake FILE，就能同时拿到两次写：

- `where1 = bufloc`，写入的内容是 `what1 = _IO_write_base`；
- `where2 = sizeloc`，写入的内容是受减法约束的 `what2 = _IO_write_ptr - _IO_write_base`。

注意第二次写并不是完全独立的 8 字节任意写。另外还要保证 `_IO_write_ptr != _IO_write_end`，否则函数会先走进 `_IO_str_overflow`，带来额外的字段和分配约束。

## 合法偏移 vtable

x86-64 `_IO_jump_t` 里几个常用槽位相对表首地址的偏移分别是：`overflow=0x18`、`uflow=0x28`、`xsputn=0x38`、`sync=0x60`。如果消费点调用的是 `uflow`，想让它落到 `_IO_mem_sync`，可以这样算：

```text
fake_vtable = _IO_mem_jumps + (0x60 - 0x28)
            = _IO_mem_jumps + 0x38
```

这个地址还落在 glibc 的合法 vtable section 内，能通过 2.24 引入的 `IO_validate_vtable` 校验。换成其他消费点时要按“目标槽位 - 被调用槽位”重新算一遍，不能照抄这里的 `+0x38`。

## 从源码看

- [FSOPAgain / House of Error 原始仓库](https://github.com/un1c0rn-the-pwnie/FSOPAgain)
- [glibc 2.35 `libio/memstream.c`](https://github.com/bminor/glibc/blob/glibc-2.35/libio/memstream.c)
- [glibc 当前 `libio/memstream.c`](https://github.com/bminor/glibc/blob/master/libio/memstream.c)
- [2.24 vtable validation 提交](https://sourceware.org/git/?p=glibc.git;a=commit;h=db3476aff19b75c4fdefbe65fcd5f0a90588ba51)
- [2.36 简化 `__malloc_assert`、删除旧 stdio 路径](https://sourceware.org/git/?p=glibc.git;a=commit;h=ac8047cdf326504f652f7db97ec96c0e0cee052f)

2.43 把 `_IO_mem_jumps` 收进了 `libio/vtables.c` 的表数组里，但 `sync` 槽和这两次写依然存在。**最终触发点存在，不代表原始 2.35 那条完整链路还可用**。

## PoC

- [`poc_mem_sync_2.24_2.43.c`](./poc_mem_sync_2.24_2.43.c)：可执行的微型 PoC。它从真实的 `open_memstream` 取得 `_IO_mem_jumps`，把 vtable 合法偏移到 `sync-uflow`，再调用 `__uflow`，最后用 assert 验证这两次写是否成功。

这份 PoC 借用真实 memstream 的扩展对象，只为单独隔离最终触发点，不虚构题目级的 largebin/标准流投递能力；原始 2.35 端到端菜单 exploit 和附件在 FSOPAgain 仓库的 `poc3/` 目录下。

```bash
./tools/run_in_docker.sh 2.35 house_of_error/poc_mem_sync_2.24_2.43.c
./tools/run_in_docker.sh 2.43 house_of_error/poc_mem_sync_2.24_2.43.c
```

## 迁移到题目

1. 按题目的 Build ID 确认 `_IO_mem_jumps`、`FILE` 和 `_IO_strfile` 的实际布局；x86-64 上常见的 `bufloc/sizeloc` 偏移是 `0xf0/0xf8`。
2. 先确定实际触发的是 `overflow/uflow/xsputn/...` 中的哪一个槽，再照它算 vtable 偏移。
3. 投递和触发要分开选择：2.35 可以参考原始的 `stderr + __malloc_assert`；2.36～2.41 可以保留 largebin 投递，但要换成正常的 IO 触发方式；2.42～2.43 这两部分都需要替换。
4. 在 `_IO_mem_sync` 处下断点，逐项核对 `write_base/write_ptr/write_end/bufloc/sizeloc`，再接上 exit handler、cookie、GOT 或题目自身回调等最终目标。
