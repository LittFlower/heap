# Tcache Stashing Unlink Attack（Smallbin Attack）

## 结论

- 适用范围：**glibc 2.26～2.40；2.41 起该 PoC 失效**。
- 原语效果：往任意地址写入一个 main_arena 指针，同时能把一个伪造节点 stash 进 tcache，随后被分配出来。
- 前置能力：能控制 smallbin 中某个 chunk 的 `bk`；目标地址附近可写；对应尺寸的 tcache 已经清空；通常用 calloc 触发。

<!-- PRIMITIVE_REQUIREMENTS:START -->
## 原语要求与版本边界

| 项目 | 本手法要求 |
|---|---|
| 最小输入原语 / 信息 | UAF 改 smallbin victim `bk` |
| 关键环境与不变量 | 目标附近可写/对齐；目标 tcache 有空位；通常 calloc 触发 |
| 最终输出原语 | main_arena 指针写 + fake 节点进 tcache/AAF |
| 版本边界应如何理解 | 2.41 删除旧 exact-smallbin stashing 循环，形成消费路径硬边界；Lore 直接 smallbin unlink 仍活，但不是 TSU。 |
<!-- PRIMITIVE_REQUIREMENTS:END -->

## 版本变化

- 2.26～2.39/2.40：利用的是 smallbin 向 tcache 预填充的那个循环。
- 2.32 起：目标地址必须对齐，但 smallbin 的双向链表本身并不使用 safe-linking 编码。
- 2.41：提交 `e2436d6` 重构了释放小块/预填充的流程，how2heap 也不再提供这个 PoC 了。

## 从源码看

关键在于 smallbin 精确大小匹配分支里的 tcache stashing 循环，以及其中对 `bck->fd` 的更新。本目录的版本结论以 GNU glibc 对应 tag/提交为准，参考：[2.40 malloc.c](https://github.com/bminor/glibc/blob/glibc-2.40/malloc/malloc.c)、[2.41 smallbin 重构](https://sourceware.org/git/?p=glibc.git;a=commit;h=e2436d6f5aa47ce8da80c2ba0f59dfb9ffde08f3)。

版本号只代表上游基线；发行版可能回移检查，实战时请按附件的 Build ID 对照源码确认。

## PoC

- [`poc_2.26_2.40.c`](./poc_2.26_2.40.c)：验证 2.26–2.40 分支，成功判据见源码头部。

下面的 PoC 都是 x86-64 教学程序，其中的 UAF、越界或 double free 都是特意模拟出来的漏洞行为。快速验证：

```bash
# 在目录根运行；把版本和文件替换为要测的分支
./tools/run_in_docker.sh 2.39 tcache_stashing_unlink_attack/poc_2.26_2.40.c
```

迁移到具体题目时，堆排布和检查绕过的思路不用改，只需要把漏洞模拟部分换成题目实际提供的 edit/UAF/overflow 原语；写死的地址和最终目标都要按题目重新计算。

## 调试

通用的断点位置和排查顺序见[根目录调试顺序](../README.md#调试顺序)。
