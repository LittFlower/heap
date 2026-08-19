# House of Muney / Mmap Overlap

## 结论

- 适用范围：**glibc mmap overlap 原语，2.23～2.43**。
- 原语效果：扩大 mmapped chunk 的 size，munmap 掉多出来的区域后再重新映射，制造出跨映射的重叠区域。
- 前置能力：能申请超过 mmap 阈值的 chunk；能改动它的 size 同时保留 IS_MMAPPED 标志；映射的位置要满足相邻关系。

<!-- PRIMITIVE_REQUIREMENTS:START -->
## 原语要求与版本边界

| 项目 | 本手法要求 |
|---|---|
| 最小输入原语 / 信息 | 可申请 mmap 阈值以上 chunk 并改其 size/flags |
| 关键环境与不变量 | 相邻映射、页对齐、`IS_MMAPPED`；重新映射地址受 ASLR |
| 最终输出原语 | 跨 mmap 区域 overlap |
| 版本边界应如何理解 | 2.43 mmap header/layout 重写需要适配，但 munmap 过量区域→重映射思想仍成立。映射邻接是环境概率，不是版本保证。 |
<!-- PRIMITIVE_REQUIREMENTS:END -->

## 版本变化

- 2.29 前后 ptmalloc 主链的一系列加固，和这个原语关系不大。
- 2.43 里 `munmap_chunk` 的页对齐和映射检查，依然允许 PoC 构造出的这种合法扩大范围。
- 完整地"偷到" libc 的映射高度依赖 ASLR、内核的 mmap 布局和目标 ELF 本身，本目录的 PoC 只把稳定可复现的 overlap 原语作为成功判据。

## 从源码看

`munmap_chunk` 是用 chunk 的 `prev_size/size` 来计算要解除的映射区间的。本目录的版本结论以 GNU glibc 对应的 tag/提交为准：[2.43 malloc.c](https://github.com/bminor/glibc/blob/master/malloc/malloc.c)。

版本号只代表上游基线；发行版可能会把某些检查往回移植，实战时还是要按附件的 Build ID 对照源码确认。

## PoC

- [`poc_2.23_2.42.c`](./poc_2.23_2.42.c)：验证 2.23–2.42 分支，成功判据见源码头部。
- [`poc_2.43.c`](./poc_2.43.c)：验证 2.43 分支，成功判据见源码头部。

下面的 PoC 都是 x86-64 教学程序，其中故意包含的 UAF、越界或 double free 都是漏洞模拟。快速验证：

```bash
# 在目录根运行；把版本和文件替换为要测的分支
./tools/run_in_docker.sh 2.39 house_of_muney/poc_2.43.c
```

迁移到具体题目时，保留堆排布和检查绕过的思路，只需要把漏洞模拟部分换成题目的 edit/UAF/overflow 原语；写死的地址和最终目标都要重新计算。

## 调试

通用的断点位置和排查顺序见 [根目录调试顺序](../README.md#调试顺序)。
