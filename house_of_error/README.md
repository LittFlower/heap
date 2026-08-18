# House of Error

## 结论

- `_IO_mem_sync` 双写：**glibc 2.24～2.43** 可从合法 `__libc_IO_vtables` 内的偏移 vtable 到达；函数本身在 2.23 也存在，但 2.23 尚无 vtable whitelist，通常不必使用这条绕法。
- 原作者发布的完整 House of Error exploit：**glibc 2.35 特定构建**。
- 原始投递链用现代 largebin attack 覆盖 `stderr`，再经 `__malloc_assert→fflush(stderr)` 触发。largebin 投递只到 2.41，专用 assert 触发只到 2.35；2.36+ 必须另找标准流消费点，2.42+ 还必须另找任意写投递。
- 前置能力：libc 地址泄露、可控 fake FILE、能把标准流指针或链投向 fake FILE；是否需要堆地址泄露取决于具体触发方式。

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

所以 fake FILE 可同时得到：

- `where1 = bufloc`，写入 `what1 = _IO_write_base`；
- `where2 = sizeloc`，写入受减法约束的 `what2 = _IO_write_ptr - _IO_write_base`。

第二次写不是完全独立的 8-byte arbitrary write。还要令 `_IO_write_ptr != _IO_write_end`，否则函数会先进入 `_IO_str_overflow`，带来额外字段和分配约束。

## 合法偏移 vtable

x86-64 `_IO_jump_t` 中常用槽位相对表首地址为：`overflow=0x18`、`uflow=0x28`、`xsputn=0x38`、`sync=0x60`。若消费点调用 `uflow`，让它落到 `_IO_mem_sync`：

```text
fake_vtable = _IO_mem_jumps + (0x60 - 0x28)
            = _IO_mem_jumps + 0x38
```

这个地址仍位于 glibc 的合法 vtable section，能通过 2.24 引入的 `IO_validate_vtable`。不同消费点要用“目标槽位 - 被调用槽位”重新计算，不能照抄 `+0x38`。

## 从源码看

- [FSOPAgain / House of Error 原始仓库](https://github.com/un1c0rn-the-pwnie/FSOPAgain)
- [glibc 2.35 `libio/memstream.c`](https://github.com/bminor/glibc/blob/glibc-2.35/libio/memstream.c)
- [glibc 当前 `libio/memstream.c`](https://github.com/bminor/glibc/blob/master/libio/memstream.c)
- [2.24 vtable validation 提交](https://sourceware.org/git/?p=glibc.git;a=commit;h=db3476aff19b75c4fdefbe65fcd5f0a90588ba51)
- [2.36 简化 `__malloc_assert`、删除旧 stdio 路径](https://sourceware.org/git/?p=glibc.git;a=commit;h=ac8047cdf326504f652f7db97ec96c0e0cee052f)

2.43 把 `_IO_mem_jumps` 收进 `libio/vtables.c` 的表数组，但 `sync` 槽及上述两次写仍在。**最终触发点存在不代表原始 2.35 完整链仍存在**。

## PoC

- [`poc_mem_sync_2.24_2.43.c`](./poc_mem_sync_2.24_2.43.c)：可执行微型 PoC。它从真实 `open_memstream` 取得 `_IO_mem_jumps`，把 vtable 合法偏移到 `sync-uflow`，再调用 `__uflow`，用 assert 验证两次写。

PoC 直接使用真实 memstream 的扩展对象以隔离最终触发点，不虚构题目级 largebin/标准流投递能力；原始 2.35 端到端菜单 exploit 与附件在 FSOPAgain 仓库 `poc3/`。

```bash
./tools/run_in_docker.sh 2.35 house_of_error/poc_mem_sync_2.24_2.43.c
./tools/run_in_docker.sh 2.43 house_of_error/poc_mem_sync_2.24_2.43.c
```

## 迁移到题目

1. 按 Build ID 确认 `_IO_mem_jumps`、`FILE` 和 `_IO_strfile` 布局；x86-64 常见 `bufloc/sizeloc` 偏移是 `0xf0/0xf8`。
2. 先确定实际触发的是 `overflow/uflow/xsputn/...` 哪个槽，再计算 vtable 偏移。
3. 分开选择投递与触发：2.35 可参考原始 `stderr + __malloc_assert`；2.36～2.41 可保留 largebin 投递但需换正常 IO 触发；2.42～2.43 两者都要替换。
4. 下断点到 `_IO_mem_sync`，逐项确认 `write_base/write_ptr/write_end/bufloc/sizeloc`，再接 exit handler、cookie、GOT 或题目自身回调等终点。
