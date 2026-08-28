# Fastbin Reverse Into Tcache

## 结论

- 适用范围：**glibc 2.26～2.42；2.43 失效**。
- 原语效果：借 fastbin→tcache stash 产生受控元数据写，并把目标地址放进 tcache。
- 前置能力：UAF 修改 fastbin `fd`、堆地址泄露（2.32+）、可填满并耗尽 tcache。

<!-- PRIMITIVE_REQUIREMENTS:START -->
## 原语要求与版本边界

| 项目 | 本手法要求 |
|---|---|
| 最小输入原语 / 信息 | UAF 改 fastbin `fd`；堆地址泄露；可填满/耗尽 tcache |
| 关键环境与不变量 | fake 节点同尺寸，2.42 通过 refill size 检查 |
| 最终输出原语 | 目标进入 tcache，并产生受控元数据写/AAF |
| 版本边界应如何理解 | 2.42 只是额外 size 适配；2.43 删除 fastbin→tcache refill 来源，消费路径硬失效。 |
<!-- PRIMITIVE_REQUIREMENTS:END -->

<!-- CHUNK_SIZE_REQUIREMENTS:START -->
## Chunk size 要求

- 所有真实节点、fake 节点和触发请求必须是同一个、同时可由 fastbin 与 small tcache 表示的 size class；正常 fastbin 尺寸天然满足后一点。
- PoC 用 `malloc(0x40)`，其物理 `chunksize=0x50`；可以换 class，但填满/耗尽 tcache 的请求也必须同步更换。
- glibc 2.42 stash/refill 会核对节点的物理 size，fake 节点不能只伪造 `next` 而漏掉与请求精确匹配的 `size`。
<!-- CHUNK_SIZE_REQUIREMENTS:END -->

## 版本变化

- 2.26～2.31 是明文 fd。
- 2.32～2.41 fastbin fd 使用 safe-linking。
- 2.42 large-tcache 链中间 next 槽会被 mangling（metadata 头还是明文），stash 时还加了 chunk-size 一致性检查。
- 2.43 `_int_malloc` 不再从 fastbin 分配。

## 从源码看

`_int_malloc` 的 fastbin 分支在返回 victim 前将剩余同尺寸节点 `tcache_put`。本目录判断以 GNU glibc 对应 tag/提交为准：[2.42 malloc.c](https://github.com/bminor/glibc/blob/glibc-2.42/malloc/malloc.c)、[2.42 前置 size 检查](https://sourceware.org/git/?p=glibc.git;a=commit;h=d10176c0ffeadbc0bcd443741f53ebd85e70db44)。

版本号只代表上游基线；发行版可能回移检查。实战请按附件 Build ID 对照源码。

## PoC

- [`poc_2.26_2.31.c`](./poc_2.26_2.31.c)：验证 2.26–2.31 分支；成功判据见源码头部。
- [`poc_2.32_2.41.c`](./poc_2.32_2.41.c)：验证 2.32–2.41 分支；成功判据见源码头部。
- [`poc_2.42.c`](./poc_2.42.c)：验证 2.42 分支；成功判据见源码头部。

PoC 为 x86-64 教学程序，故意包含 UAF、越界或 double free。快速验证：

```bash
# 在目录根运行；把版本和文件替换为要测的分支
./tools/run_in_docker.sh 2.39 fastbin_reverse_into_tcache/poc_2.42.c
```

迁移时保留堆排布和检查绕过，只把漏洞模拟替换为题目的 edit/UAF/overflow；固定地址和最终目标必须重算。

## 调试

通用断点和排查顺序见 [根目录调试顺序](../README.md#调试顺序)。
