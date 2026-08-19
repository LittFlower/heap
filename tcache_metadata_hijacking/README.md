# Tcache Metadata Hijacking（延迟初始化）

## 结论

- 适用范围：**glibc 2.42～2.43**。
- 原语效果：把 tcache_perthread_struct 挤到攻击者控制的大块之后，再用向后溢出改写 entries。
- 前置能力：在 tcache 初始化之前先完成一次非 tcache 的大块分配；并具备溢出到随后才创建出来的元数据的能力。

<!-- PRIMITIVE_REQUIREMENTS:START -->
## 原语要求与版本边界

| 项目 | 本手法要求 |
|---|---|
| 最小输入原语 / 信息 | tcache 初始化前的大块顺向溢出 |
| 关键环境与不变量 | 2.42+ 延迟/邻接初始化布局；能控制紧邻 metadata |
| 最终输出原语 | 覆盖 `entries`，得到 AAF |
| 版本边界应如何理解 | 这是 2.42 新布局产生的手法；更早版本可做普通 metadata poisoning，但不存在同一个“延迟初始化后相邻落位”消费路径。 |
<!-- PRIMITIVE_REQUIREMENTS:END -->

## 版本变化

- 2.42 的重构去掉了部分非 tcache 路径里的 `MAYBE_INIT_TCACHE` 调用，tcache 因此不再必然位于堆顶。
- 2.43 因 tcache 结构和 TLS 哨兵的变化，目标 entry 的相对偏移从示例中的 21 个 qword 变成了 25 个 qword。

## 从源码看

关键看点是 `tcache_init` 的调用时机，以及 `tcache_perthread_struct` 在 2.42/2.43 两个版本里各自的布局。本目录的判断以 GNU glibc 对应 tag/提交为准：[2.42 large tcache/初始化重构](https://sourceware.org/git/?p=glibc.git;a=commit;h=cbfd7988107b27b9ff1d0b57fa2c8f13a932e508)、[2.42 malloc.c](https://github.com/bminor/glibc/blob/glibc-2.42/malloc/malloc.c)。

版本号只代表上游基线；发行版可能回移检查，实战时请按附件的 Build ID 对照源码确认。

## PoC

- [`poc_2.42.c`](./poc_2.42.c)：验证 2.42 分支，成功判据见源码头部。
- [`poc_2.43.c`](./poc_2.43.c)：验证 2.43 分支，成功判据见源码头部。

下面的 PoC 都是 x86-64 教学程序，其中的 UAF、越界或 double free 都是特意模拟出来的漏洞行为。快速验证：

```bash
# 在目录根运行；把版本和文件替换为要测的分支
./tools/run_in_docker.sh 2.39 tcache_metadata_hijacking/poc_2.43.c
```

迁移到具体题目时，堆排布和检查绕过的思路不用改，只需要把漏洞模拟部分换成题目实际提供的 edit/UAF/overflow 原语；写死的地址和最终目标都要按题目重新计算。

## 调试

通用的断点位置和排查顺序见[根目录调试顺序](../README.md#调试顺序)。
