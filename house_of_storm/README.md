# House of Storm

## 结论

- 适用范围：**glibc 2.23～2.27；2.28 起失效**。
- 原语效果：组合 unsorted 与 largebin 元数据，在目标附近生成可分配 fake chunk。
- 前置能力：同时 UAF 控制一个 unsorted chunk 与一个 largebin chunk。

<!-- PRIMITIVE_REQUIREMENTS:START -->
## 原语要求与版本边界

| 项目 | 本手法要求 |
|---|---|
| 最小输入原语 / 信息 | 同时 UAF 控制 unsorted 与 largebin 节点 |
| 关键环境与不变量 | 交叉 fd/bk/nextsize 链、目标附近 fake size；旧 unsorted 无需反向预置 |
| 最终输出原语 | 在目标附近生成可分配 fake chunk/AAF |
| 版本边界应如何理解 | 2.28 首道 `bck->fd==victim` 使第二轮 fake-victim 摘链不自洽，经典弱前置链硬失效。用额外 AAW 补整套反向关系会变成更强 Lore/largebin 组合。 |
<!-- PRIMITIVE_REQUIREMENTS:END -->

<!-- CHUNK_SIZE_REQUIREMENTS:START -->
## Chunk size 要求

- 必须能同时制造一个 unsorted 节点和一个 largebin 节点；PoC 使用 request `0x4e8`（物理 `0x4f0`）与 `0x4d8`（物理 `0x4e0`），两者均处于 large-size 范围且顺序不可互换。
- 最终 fake chunk 的 size 来自写入目标附近的 heap 指针高位，必须清除非法标志、满足 `MINSIZE`/对齐并落在可承受范围；因此还要能发出按运行时地址计算出的精确 `calloc(size,1)`，不存在一个通用固定 request。
<!-- CHUNK_SIZE_REQUIREMENTS:END -->

## 版本变化

- 2.26～2.27 得填满对应 tcache，再用 calloc 绕过前端快速路径。
- 2.28 的 bdc3009 让第二次 fake-victim 摘链过不了 bck->fd==victim。
- 别和 2.30+ 的单独 largebin attack 搞混。

## 从源码看

unsorted 摘链写与 largebin nextsize 插入写的交叉结果。本目录判断以 GNU glibc 对应 tag/提交为准：[2.28 首次 unsorted 加固](https://sourceware.org/git/?p=glibc.git;a=commit;h=bdc3009b8ff0effdbbfb05eb6b10966753cbf9b8)、[2.28 malloc.c](https://github.com/bminor/glibc/blob/glibc-2.28/malloc/malloc.c)。

版本号只代表上游基线；发行版可能回移检查。实战按附件 Build ID 对照源码。

## PoC

- [`poc_2.23_2.27.c`](./poc_2.23_2.27.c)：验证 2.23–2.27 分支；成功判据见源码头部。

PoC 为 x86-64 教学程序，故意包含 UAF、越界或 double free。快速验证：

```bash
# 在目录根运行；把版本和文件替换为要测的分支
./tools/run_in_docker.sh 2.39 house_of_storm/poc_2.23_2.27.c
```

迁移时保留堆排布和检查绕过，只把漏洞模拟换成题目的 edit/UAF/overflow；固定地址和最终目标得重算。

## 调试

通用断点和排查顺序见 [根目录调试顺序](../README.md#调试顺序)。
