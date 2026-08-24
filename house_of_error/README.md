# House of Error

## 结论

- `_IO_mem_sync` 双写：**glibc 2.24～2.43** 都能从合法 `__libc_IO_vtables` 段内的偏移 vtable 到达；这个函数在 2.23 也存在，但当时还没有 vtable whitelist，通常用不上这条绕法。
- 原作者发布的完整 House of Error exploit 针对的是：**glibc 2.35 特定构建**。
- 原始的投递链是用当时的 largebin attack 覆盖 `stderr`，再通过 `__malloc_assert→fflush(stderr)` 触发。这条 largebin 投递路径只延续到 2.41，专用的 assert 触发方式只延续到 2.35；2.36 之后要另外找标准流消费点，2.42 之后连任意写投递也得重新想办法。
- 前置能力：需要 libc 地址泄露、一个可控的 fake FILE，以及能把标准流指针或链条指向这个 fake FILE 的手段；是否还需要堆地址泄露，取决于具体用哪种方式触发。

<!-- PRIMITIVE_REQUIREMENTS:START -->
## 原语要求与版本边界

| 项目 | 本手法要求 |
|---|---|
| 最小输入原语 / 信息 | libc leak、fake memstream、能把流指针/链投向它 |
| 关键环境与不变量 | 合法 section 内错位 vtable；`write_ptr!=write_end`；两目标可写 |
| 最终输出原语 | 一次触发两个相关 qword 写 |
| 版本边界应如何理解 | `_IO_mem_sync` 最终触发点到 2.43 仍在；2.36 切断旧 assert 触发，2.42 切断 largebin 投递。第二次写受差值约束，不是两次独立 AAW。 |
<!-- PRIMITIVE_REQUIREMENTS:END -->

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

这个地址仍然落在 glibc 的合法 vtable section 内，能通过 2.24 引入的 `IO_validate_vtable` 校验。换成其他消费点时要按“目标槽位 - 被调用槽位”重新算一遍，不能照抄这里的 `+0x38`。

## 从源码看

- [FSOPAgain / House of Error 原始仓库](https://github.com/un1c0rn-the-pwnie/FSOPAgain)
- [glibc 2.35 `libio/memstream.c`](https://github.com/bminor/glibc/blob/glibc-2.35/libio/memstream.c)
- [glibc 当前 `libio/memstream.c`](https://github.com/bminor/glibc/blob/master/libio/memstream.c)
- [2.24 vtable validation 提交](https://sourceware.org/git/?p=glibc.git;a=commit;h=db3476aff19b75c4fdefbe65fcd5f0a90588ba51)
- [2.36 简化 `__malloc_assert`、删除旧 stdio 路径](https://sourceware.org/git/?p=glibc.git;a=commit;h=ac8047cdf326504f652f7db97ec96c0e0cee052f)

2.43 把 `_IO_mem_jumps` 收进了 `libio/vtables.c` 的表数组里，但 `sync` 槽和上述两次写依然存在。**最终触发点存在，不代表原始 2.35 那条完整链路仍然可用**。

## PoC

- [`poc_mem_sync_2.24_2.43.c`](./poc_mem_sync_2.24_2.43.c)：可执行的微型 PoC。它从真实的 `open_memstream` 取得 `_IO_mem_jumps`，把 vtable 合法偏移到 `sync-uflow`，再调用 `__uflow`，最后用 assert 验证这两次写是否成功。

这份 PoC 直接借用真实 memstream 的扩展对象，只为了单独隔离出最终触发点，并不虚构题目级别的 largebin/标准流投递能力；原始 2.35 那套端到端菜单 exploit 和附件在 FSOPAgain 仓库的 `poc3/` 目录下。

## Python 离线板子

```python
from error import build_house_of_error

writes = build_house_of_error(
    file_addr=fake_file,
    mem_jumps_addr=libc_base + mem_jumps_offset,
    bufloc_addr=target_pointer_slot,
    sizeloc_addr=target_size_slot,
    write_base_addr=controlled_buffer,
    write_length=0x123,
)
```

| 参数 | 含义 |
|---|---|
| `file_addr` | fake/被覆盖 memstream FILE 地址。 |
| `mem_jumps_addr` | `_IO_mem_jumps` 地址；函数按 `sync(0x60)-uflow(0x28)=+0x38` 生成合法偏移 vtable。 |
| `bufloc_addr` / `sizeloc_addr` | `_IO_mem_sync` 两次写入的目标地址。 |
| `write_base_addr` | 第一次写入的值，即 `_IO_write_base`。 |
| `write_length` | `_IO_write_ptr - _IO_write_base`，第二次写入的 size 值；不是独立任意 qword。 |

返回一个 memstream FILE 镜像，函数不负责投递、触发或修复 Build ID 私有布局。

```bash
./tools/run_in_docker.sh 2.35 house_of_error/poc_mem_sync_2.24_2.43.c
./tools/run_in_docker.sh 2.43 house_of_error/poc_mem_sync_2.24_2.43.c
```

## 迁移到题目

1. 按题目的 Build ID 确认 `_IO_mem_jumps`、`FILE` 和 `_IO_strfile` 的实际布局；x86-64 上常见的 `bufloc/sizeloc` 偏移是 `0xf0/0xf8`。
2. 先确定实际触发的是 `overflow/uflow/xsputn/...` 中的哪一个槽，再据此计算 vtable 偏移。
3. 投递和触发要分开选择：2.35 可以参考原始的 `stderr + __malloc_assert`；2.36～2.41 可以保留 largebin 投递，但要换成正常的 IO 触发方式；2.42～2.43 这两部分都需要替换。
4. 在 `_IO_mem_sync` 处下断点，逐项核对 `write_base/write_ptr/write_end/bufloc/sizeloc` 的值，再接上 exit handler、cookie、GOT 或题目自身回调等最终目标。
