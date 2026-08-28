# Tcache Metadata Hijacking（延迟初始化）

## 结论

- 适用范围：**glibc 2.42～2.43**。
- 原语效果：把 tcache_perthread_struct 放到攻击者大块之后，再用顺向溢出改 entries。
- 前置能力：tcache 初始化前先走非 tcache 大块分配；可溢出到后续元数据。

<!-- PRIMITIVE_REQUIREMENTS:START -->
## 原语要求与版本边界

| 项目 | 本手法要求 |
|---|---|
| 最小输入原语 / 信息 | tcache 初始化前的大块顺向溢出 |
| 关键环境与不变量 | 2.42+ 延迟/邻接初始化布局；能控制紧邻 metadata |
| 最终输出原语 | 覆盖 `entries`，得到 AAF |
| 版本边界应如何理解 | 这是 2.42 新布局产生的手法；更早版本可做普通 metadata poisoning，但不存在同一个“延迟初始化后相邻落位”消费路径。 |
<!-- PRIMITIVE_REQUIREMENTS:END -->

<!-- CHUNK_SIZE_REQUIREMENTS:START -->
## Chunk size 要求

- 第一次、tcache 尚未初始化时的来源申请必须**不进入 tcache但仍来自 arena**：物理 `chunksize` 高于当前 `tcache_max`，同时低于/避开 `mmap_threshold`。PoC 用 `malloc(0x420) -> chunksize 0x430`；若启动时提高了 `tcache_max`，这个示例就必须改大。
- 随后还要申请一个启用的 tcache class 来触发 metadata 初始化并验证劫持；PoC 用 `malloc(0x10) -> 0x20`。大块与小块两种尺寸能力缺一不可。
<!-- CHUNK_SIZE_REQUIREMENTS:END -->

## 版本变化

- 2.42 重构取消部分非 tcache 路径中的 `MAYBE_INIT_TCACHE`，tcache 不再必定位于 heap 顶部。
- 2.43 tcache 结构/TLS 哨兵让目标 entry 的相对偏移从示例的 21 个 qword 变成 25 个 qword。

## 从源码看

`tcache_init` 调用时机与 `tcache_perthread_struct` 的 2.42/2.43 布局。本目录判断以 GNU glibc 对应 tag/提交为准：[2.42 large tcache/初始化重构](https://sourceware.org/git/?p=glibc.git;a=commit;h=cbfd7988107b27b9ff1d0b57fa2c8f13a932e508)、[2.42 malloc.c](https://github.com/bminor/glibc/blob/glibc-2.42/malloc/malloc.c)。

版本号只代表上游基线；发行版可能回移检查。实战请按附件 Build ID 对照源码。

## PoC

- [`poc_2.42.c`](./poc_2.42.c)：验证 2.42 分支；成功判据见源码头部。
- [`poc_2.43.c`](./poc_2.43.c)：验证 2.43 分支；成功判据见源码头部。

PoC 为 x86-64 教学程序，故意包含 UAF、越界或 double free。快速验证：

```bash
# 在目录根运行；把版本和文件替换为要测的分支
./tools/run_in_docker.sh 2.39 tcache_metadata_hijacking/poc_2.43.c
```

迁移时保留堆排布和检查绕过，只把漏洞模拟替换为题目的 edit/UAF/overflow；固定地址和最终目标必须重算。

## 调试

通用断点和排查顺序见 [根目录调试顺序](../README.md#调试顺序)。
