# Poison Null Byte

## 结论

- 适用范围：**glibc 2.23～2.43**，但不是同一条 PoC 横跨全部版本。
- 漏洞模型：相邻 chunk 的 `size` 最低字节只能被写成 `\x00`；通过清 `PREV_INUSE` 或缩小空闲 chunk，最终制造 overlap。
- 与 House of Einherjar 的区别：Einherjar 通常直接伪造 `prev_size + fake prev chunk` 后向后合并；Poison Null Byte 的经典链强调“单 NUL 缩小 free chunk 后留下陈旧边界”，2.29 后版本又借 largebin 残留指针为 fake chunk 补齐 unlink 双链。
- 前置能力：off-by-null；现代分支还需要能布置 large chunks，并允许对重新取出的 chunk 做低两字节修改。

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

现代 PoC 要把 fake chunk 地址的低两字节对齐到 `0x0010`，使残留的 libc/heap 高字节不变、只改 `\x10\x00` 就能让 `a->bk` 与 `b->fd` 回指它。演示通过 padding 消除低半字节爆破；真实题目若 heap 形状固定，可按实际地址重算。

## 从源码看

关键路径是 `unlink_chunk`（旧版为 `unlink` 宏）以及 `_int_free` 中 `!prev_inuse(p)` 的 backward consolidation：

1. NUL 把 victim 的 `PREV_INUSE` 清零；
2. `prev_size(victim)` 定位 fake previous chunk；
3. 2.29+ 先校验 fake chunk 的 `chunksize` 与 victim 的 `prev_size` 相等；
4. `unlink_chunk` 再校验 `fd->bk == p && bk->fd == p`；
5. 合并块进入 unsorted bin，之后申请得到与仍在用 chunk 重叠的区域。

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

1. off-by-null 前后检查被缩小 chunk 的物理 size 和下一边界位置。
2. 2.26+ 在 `unlink_chunk` 检查 fake chunk 末尾的 `next->prev_size`。
3. 2.29+ 同时检查 victim 的 `prev_size`、fake chunk 的 `size`、`a->bk` 和 `b->fd` 四个关系。
4. tcache 必须被尺寸绕开或预先处理；若 free 后意外进入 tcache，就不会走预期的 backward consolidation。
