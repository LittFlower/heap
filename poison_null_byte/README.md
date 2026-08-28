# Poison Null Byte

## 结论

**一句话**：off-by-null 缩小相邻 chunk，做出 overlap；四个版本区间要四条不同的链，别指望一份 PoC 通吃。

| 版本 | 你能拿到什么 | 备注 |
|---|---|---|
| 2.23～2.25 | 旧 stale-`prev_size` overlap | `unlink` 还不检查 `chunksize(P) == prev_size(next_chunk(P))` |
| 2.26～2.28 | 在缩小后的边界伪造一个一致的 `prev_size` | `17f487b` 给 unlink 加了 size/prev_size 检查 |
| **2.29～2.42** | largebin residual-pointer fake chunk，给它补一套能过 unlink 的双链 | `d6db68e` 又在向后合并前直接比较 `chunksize(prev) == prev_size(victim)`，旧链到此为止；本仓库主力分支 |
| 2.43 | 同一条 residual-pointer 链 | 新 tcache/TLS 初始化布局会影响 0x10000 低位对齐，得先初始化 tcache metadata 再算 padding |

漏洞模型：能把相邻 chunk 的 `size` 低字节清零成 `\x00`——清掉 `PREV_INUSE`，或者干脆缩小这个空闲 chunk，两条路都能做出 overlap。前置能力：一次 off-by-null；现代分支还得能布置 large chunk，并能改动重新取出来的 chunk 的低两字节。

跟 House of Einherjar 的区别：Einherjar 是直接伪造一整套 `prev_size + fake prev chunk`；这里靠一个空字节缩小 free chunk，留下的是一段"过期"边界，不是凭空伪造出来的。

<!-- PRIMITIVE_REQUIREMENTS:START -->
## 原语要求与版本边界

| 项目 | 本手法要求 |
|---|---|
| 最小输入原语 / 信息 | 对相邻 `size` 的单 NUL；现代链还需 large chunk 排布和低字节改写 |
| 关键环境与不变量 | fake previous chunk 的 size/prev_size 与 fd/bk 自洽 |
| 最终输出原语 | 后向合并造成 overlap |
| 版本边界应如何理解 | 2.26、2.29、2.43 都改变实现不变量，但 off-by-null→合并的思想未消失；四套 PoC 是适配，不应写成中间版本“不可用”。 |
<!-- PRIMITIVE_REQUIREMENTS:END -->

<!-- CHUNK_SIZE_REQUIREMENTS:START -->
## Chunk size 要求

- NUL 清零 `size` 低字节后，`new_chunksize = old_size & ~0xff` 得继续满足 `0x10` 对齐、不小于 `MINSIZE`，还要真的产生缩小/清 `PREV_INUSE` 的效果——所以至少要挑百字节级、跨得过 `0x100` 边界的 chunk，最小 fastbin 不够用。
- 旧 PoC 用一组 `malloc(0x100)`；现代 residual-pointer 分支用 `malloc(0x500)`/`malloc(0x4f0)` 这类 large request。数值可以换，但换了就要重新算缩小前后的边界、fake `prev_size`、largebin 残留指针和 tcache 绕过。
<!-- CHUNK_SIZE_REQUIREMENTS:END -->

## 版本变化

| 版本 | PoC 分支 | 变化原因 |
|---|---|---|
| 2.23～2.25 | 旧 stale-`prev_size` overlap | `unlink` 尚不检查 `chunksize(P) == prev_size(next_chunk(P))` |
| 2.26～2.28 | 在缩小后边界伪造一致 `prev_size` | [17f487b](https://sourceware.org/git/?p=glibc.git;a=commit;h=17f487b7afa7cd6c316040f3e6c86dc96b2eec30) 加入 unlink size/prev_size 检查 |
| 2.29～2.42 | largebin residual-pointer fake chunk | [d6db68e](https://sourceware.org/git/?p=glibc.git;a=commit;h=d6db68e66dff25d12c3bc5641b60cbd7fb6ab44f) 又在 `_int_free` 向后合并前直接比较 `chunksize(prev) == prev_size(victim)`，旧链终止 |
| 2.43 | 同一 residual-pointer 链，先初始化 tcache metadata | 新 tcache/TLS 初始化布局会影响 0x10000 低位对齐；先初始化再算 padding |

现代分支的 PoC 要把 fake chunk 地址低两字节对齐到 `0x0010`：保持 libc/heap 高字节不变，只改 `\x10\x00` 两字节，就能让 `a->bk` 与 `b->fd` 回指到它。演示里用 padding 省掉了低半字节的爆破；真实题目堆形状是固定的，直接按实际地址重算就行。

## 从源码看

关键路径是 `unlink_chunk`（旧版本是 `unlink` 宏），以及 `_int_free` 处理 `!prev_inuse(p)` 时的 backward consolidation：

1. 空字节把 victim 的 `PREV_INUSE` 位清零；
2. 通过 `prev_size(victim)` 定位 fake previous chunk；
3. 2.29 起先校验 fake chunk 的 `chunksize` 与 victim 的 `prev_size` 是否一致；
4. `unlink_chunk` 再校验 `fd->bk == p && bk->fd == p`；
5. 合并后的块进入 unsorted bin，再次申请即拿到与在用 chunk 重叠的内存。

源码/基线：

- [shellphish/how2heap `poison_null_byte.c`](https://github.com/shellphish/how2heap/blob/master/glibc_2.43/poison_null_byte.c)
- [2.26 unlink consistency check](https://sourceware.org/git/?p=glibc.git;a=commit;h=17f487b7afa7cd6c316040f3e6c86dc96b2eec30)
- [2.29 backward-consolidation check](https://sourceware.org/git/?p=glibc.git;a=commit;h=d6db68e66dff25d12c3bc5641b60cbd7fb6ab44f)
- [glibc 当前 `unlink_chunk/_int_free`](https://github.com/bminor/glibc/blob/master/malloc/malloc.c)

## PoC

- [`poc_2.23_2.25.c`](./poc_2.23_2.25.c)：无 size/prev_size 检查的旧链。
- [`poc_2.26_2.28.c`](./poc_2.26_2.28.c)：补齐 unlink 边界校验。
- [`poc_2.29_2.42.c`](./poc_2.29_2.42.c)：用 largebin residual pointers 构造可 unlink fake chunk。
- [`poc_2.43.c`](./poc_2.43.c)：先初始化 tcache metadata，再做现代链的地址对齐。

```bash
./tools/run_in_docker.sh 2.23 poison_null_byte/poc_2.23_2.25.c
./tools/run_in_docker.sh 2.27 poison_null_byte/poc_2.26_2.28.c
./tools/run_in_docker.sh 2.42 poison_null_byte/poc_2.29_2.42.c
./tools/run_in_docker.sh 2.43 poison_null_byte/poc_2.43.c
```

## 调试观察点

1. 在 off-by-null 前后分别确认被缩小 chunk 的物理 size 和下一个边界位置。
2. 2.26 起 `unlink_chunk` 会检查 fake chunk 末尾的 `next->prev_size`。
3. 2.29 起同时检查 victim 的 `prev_size`、fake chunk 的 `size` 以及 `a->bk`、`b->fd` 四者是否自洽。
4. tcache 要提前用尺寸绕开；free 若落进 tcache，就不会走到预期的 backward consolidation。
