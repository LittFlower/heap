# House of Storm

## 结论

- 适用范围：**glibc 2.23～2.27；2.28 起失效**。
- 原语效果：把 unsorted 和 largebin 的元数据组合起来利用，在目标地址附近伪造出一个可以被分配到的 fake chunk。
- 前置能力：需要能同时用 UAF 控制一个 unsorted chunk 和一个 largebin chunk。

<!-- PRIMITIVE_REQUIREMENTS:START -->
## 原语要求与版本边界

| 项目 | 本手法要求 |
|---|---|
| 最小输入原语 / 信息 | 同时 UAF 控制 unsorted 与 largebin 节点 |
| 关键环境与不变量 | 交叉 fd/bk/nextsize 链、目标附近 fake size；旧 unsorted 无需反向预置 |
| 最终输出原语 | 在目标附近生成可分配 fake chunk/AAF |
| 版本边界应如何理解 | 2.28 首道 `bck->fd==victim` 使第二轮 fake-victim 摘链不自洽，经典弱前置链硬失效。用额外 AAW 补整套反向关系会变成更强 Lore/largebin 组合。 |
<!-- PRIMITIVE_REQUIREMENTS:END -->

## 版本变化

- 2.26～2.27 需要先填满对应的 tcache，并用 calloc 绕开分配器的前端快速路径。
- 2.28 引入的 bdc3009 补丁让第二次对 fake-victim 摘链时无法满足 bck->fd==victim 的检查，手法因此失效。
- 注意不要和 2.30+ 单独的 largebin attack 搞混。

## 从源码看

本手法是 unsorted 摘链写与 largebin nextsize 插入写交叉作用的结果。本目录的判断以 GNU glibc 对应 tag/提交为准：[2.28 首次 unsorted 加固](https://sourceware.org/git/?p=glibc.git;a=commit;h=bdc3009b8ff0effdbbfb05eb6b10966753cbf9b8)、[2.28 malloc.c](https://github.com/bminor/glibc/blob/glibc-2.28/malloc/malloc.c)。

版本号只代表上游基线，发行版可能会回移相关检查；实战时请按附件的 Build ID 对照源码确认。

## PoC

- [`poc_2.23_2.27.c`](./poc_2.23_2.27.c)：验证 2.23–2.27 分支；成功判据见源码头部。

下面的 PoC 是 x86-64 教学程序，其中的 UAF、越界或 double free 都是故意模拟出来的漏洞行为。快速验证：

```bash
# 在目录根运行；把版本和文件替换为要测的分支
./tools/run_in_docker.sh 2.39 house_of_storm/poc_2.23_2.27.c
```

迁移到具体题目时，堆排布和检查绕过的思路不用改，只需要把漏洞模拟部分换成题目实际提供的 edit/UAF/overflow 原语；写死的地址和最终目标都要按题目重新计算。

## 调试

通用的断点位置和排查顺序见 [根目录调试顺序](../README.md#调试顺序)。
