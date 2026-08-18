# House of Muney / Mmap Overlap

## 结论

- 适用范围：**glibc mmap overlap 原语 2.23～2.43**。
- 原语效果：扩大 mmapped chunk 的 size，munmap 超额区域后重新映射，制造跨映射重叠。
- 前置能力：申请 mmap 阈值以上 chunk；能改其 size 且保留 IS_MMAPPED；映射位置满足相邻关系。

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

- 2.29 前后 ptmalloc 主链加固与该原语关系不大。
- 2.43 `munmap_chunk` 的页对齐/映射检查仍允许 PoC 构造的合法扩大范围。
- 完整“steal libc mapping”高度依赖 ASLR、内核 mmap 布局和目标 ELF，目录 PoC 只把稳定的 overlap 原语作为成功判据。

## 从源码看

`munmap_chunk` 使用 chunk 的 `prev_size/size` 计算要解除的映射区间。本目录判断以 GNU glibc 对应 tag/提交为准：[2.43 malloc.c](https://github.com/bminor/glibc/blob/master/malloc/malloc.c)。

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
