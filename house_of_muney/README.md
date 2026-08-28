# House of Muney / Mmap Overlap

## 结论

- 适用范围：**glibc mmap overlap 原语 2.23～2.43**。
- 原语效果：扩大 mmapped chunk 的 size，munmap 掉超额区域再重新映射，做出跨映射的 overlap。
- 前置能力：申请 mmap 阈值以上 chunk；能改它的 size 并保留 IS_MMAPPED；映射位置满足相邻关系。

<!-- PRIMITIVE_REQUIREMENTS:START -->
## 原语要求与版本边界

| 项目 | 本手法要求 |
|---|---|
| 最小输入原语 / 信息 | 可申请 mmap 阈值以上 chunk 并改其 size/flags |
| 关键环境与不变量 | 相邻映射、页对齐、`IS_MMAPPED`；重新映射地址受 ASLR |
| 最终输出原语 | 跨 mmap 区域 overlap |
| 版本边界应如何理解 | 2.43 mmap header/layout 重写需要适配，但 munmap 过量区域→重映射思想仍成立。映射邻接是环境概率，不是版本保证。 |
<!-- PRIMITIVE_REQUIREMENTS:END -->

<!-- CHUNK_SIZE_REQUIREMENTS:START -->
## Chunk size 要求

- 受害块必须由 `mmap` 分配，而不是来自 brk arena：request 要高于运行时 `mmap_threshold`，并且题目必须允许连续申请多个这种大块。阈值会自适应，不能把一个固定常量当成所有环境的下限。
- 在常见 glibc 动态阈值路径中，释放一个比当前阈值更大、但不超过实现上限的 mmapped chunk，可能把 `mp_.mmap_threshold` 提高到该块尺寸，并同步调整 trim threshold；随后相同 request 便可能改从 arena/top 分配。显式 tunable/`mallopt`、`no_dyn_threshold`、版本上限和既有映射计数都会改变这一步，必须在目标 `_int_malloc/munmap_chunk` 验证。
- 覆盖后的 mmapped `size` 以及最终 overlap request 必须按页对齐并覆盖预期的连续映射范围。PoC 用三个 `malloc(0x100000)`，再用 `malloc(0x300000)` 取回重叠区；这些是稳定演示值，不是算法唯一值。
<!-- CHUNK_SIZE_REQUIREMENTS:END -->

## 版本变化

- 2.29 前后 ptmalloc 主链加固和这个原语关系不大。
- 2.43 `munmap_chunk` 的页对齐/映射检查仍允许 PoC 构造的合法扩大范围。
- 完整“steal libc mapping”高度依赖 ASLR、内核 mmap 布局和目标 ELF，目录 PoC 只把稳定的 overlap 原语作为成功判据。

## 从源码看

`munmap_chunk` 使用 chunk 的 `prev_size/size` 计算要解除的映射区间。本目录判断以 GNU glibc 对应 tag/提交为准：[2.43 malloc.c](https://github.com/bminor/glibc/blob/master/malloc/malloc.c)。

[Ltfall 的 mmap threshold 题目笔记](https://ltfa1l.top/2023/12/28/system/tricks/tricks/)可用于理解“free 后同尺寸申请换来源”的现象；这里不沿用里面的固定 request/阈值，而是按运行时 `mp_` 状态描述。

版本号只代表上游基线；发行版可能回移检查。实战请按附件 Build ID 对照源码。

## PoC

- [`poc_2.23_2.42.c`](./poc_2.23_2.42.c)：验证 2.23–2.42 分支；成功判据见源码头部。
- [`poc_2.43.c`](./poc_2.43.c)：验证 2.43 分支；成功判据见源码头部。

PoC 为 x86-64 教学程序，故意包含 UAF、越界或 double free。快速验证：

```bash
# 在目录根运行；把版本和文件替换为要测的分支
./tools/run_in_docker.sh 2.39 house_of_muney/poc_2.43.c
```

迁移时保留堆排布和检查绕过，只把漏洞模拟替换为题目的 edit/UAF/overflow；固定地址和最终目标必须重算。

## 调试

通用断点和排查顺序见 [根目录调试顺序](../README.md#调试顺序)。
