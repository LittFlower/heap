# Poison Null Byte

## 结论

- 适用范围：**glibc 2.23～2.43**，但不是同一条 PoC 就能横跨所有版本。
- 漏洞模型：只能把相邻 chunk 的 `size` 最低字节写成 `\x00`；借助清除 `PREV_INUSE` 或缩小空闲 chunk，最终制造出 overlap。
- 与 House of Einherjar 的区别：Einherjar 通常是直接伪造出 `prev_size + fake prev chunk` 再向后合并；而 Poison Null Byte 的经典链路强调的是“用一个空字节缩小 free chunk，让它留下一段陈旧边界”，2.29 之后的版本又借助 largebin 残留的指针，给 fake chunk 补上一套能通过 unlink 检查的双链。
- 前置能力：需要一次 off-by-null；现代分支还需要能布置 large chunk，并允许对重新取出的 chunk 做低两字节的修改。

<!-- PRIMITIVE_REQUIREMENTS:START -->
## 原语要求与版本边界

| 项目 | 本手法要求 |
|---|---|
| 最小输入原语 / 信息 | 对相邻 `size` 的单 NUL；现代链还需 large chunk 排布和低字节改写 |
| 关键环境与不变量 | fake previous chunk 的 size/prev_size 与 fd/bk 自洽 |
| 最终输出原语 | 后向合并造成 overlap |
| 版本边界应如何理解 | 2.26、2.29、2.43 都改变实现不变量，但 off-by-null→合并的思想未消失；四套 PoC 是适配，不应写成中间版本“不可用”。 |
<!-- PRIMITIVE_REQUIREMENTS:END -->

## 版本变化

| 版本 | PoC 分支 | 变化原因 |
|---|---|---|
| 2.23～2.25 | 旧 stale-`prev_size` overlap | `unlink` 尚不检查 `chunksize(P) == prev_size(next_chunk(P))` |
| 2.26～2.28 | 在缩小后边界伪造一致 `prev_size` | [17f487b](https://sourceware.org/git/?p=glibc.git;a=commit;h=17f487b7afa7cd6c316040f3e6c86dc96b2eec30) 加入 unlink size/prev_size 检查 |
| 2.29～2.42 | largebin residual-pointer fake chunk | [d6db68e](https://sourceware.org/git/?p=glibc.git;a=commit;h=d6db68e66dff25d12c3bc5641b60cbd7fb6ab44f) 又在 `_int_free` 向后合并前直接比较 `chunksize(prev) == prev_size(victim)`，旧链终止 |
| 2.43 | 同一 residual-pointer 链，先初始化 tcache metadata | 新 tcache/TLS 初始化布局会影响 0x10000 低位对齐；先初始化再算 padding |

现代分支的 PoC 要把 fake chunk 地址的低两字节对齐到 `0x0010`，这样只要保持 libc/heap 的高字节不变，只改 `\x10\x00` 这两个字节，就能让 `a->bk` 与 `b->fd` 回指到它。演示中通过 padding 消除了低半字节需要爆破的部分；真实题目里如果堆形状是固定的，可以按实际地址重新计算。

## 从源码角度理解

关键路径是 `unlink_chunk`（旧版本里是 `unlink` 宏），以及 `_int_free` 中处理 `!prev_inuse(p)` 时的 backward consolidation：

1. 那个空字节把 victim 的 `PREV_INUSE` 位清零了；
2. 通过 `prev_size(victim)` 就能定位到 fake previous chunk；
3. 2.29 及之后的版本会先校验 fake chunk 的 `chunksize` 是否与 victim 的 `prev_size` 一致；
4. `unlink_chunk` 接着还会校验 `fd->bk == p && bk->fd == p` 是否成立；
5. 合并后的块会进入 unsorted bin，之后再次申请就能拿到一段与仍在使用的 chunk 重叠的内存。

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

1. 在 off-by-null 前后分别检查一下被缩小 chunk 的物理 size，以及下一个边界所在的位置。
2. 2.26 及之后的版本会在 `unlink_chunk` 里检查 fake chunk 末尾的 `next->prev_size`。
3. 2.29 及之后的版本还会同时检查 victim 的 `prev_size`、fake chunk 的 `size`，以及 `a->bk` 和 `b->fd` 这四者是否自洽。
4. tcache 必须提前用尺寸绕开，或者做好相应的预处理；如果 free 之后意外落进了 tcache，就不会走到预期的 backward consolidation 逻辑。
