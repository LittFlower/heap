# Unsorted Bin Into Stack

## 结论

- 适用范围：**glibc 2.23～2.27；2.28 起失效**。
- 原语效果：让 malloc 从伪造在栈上或全局区的 unsorted 节点返回地址。
- 前置能力：需要一次 UAF 来改写 `bk` 指针，并在目标附近布置一个能通过 size 检查的 fake chunk。

<!-- PRIMITIVE_REQUIREMENTS:START -->
## 原语要求与版本边界

| 项目 | 本手法要求 |
|---|---|
| 最小输入原语 / 信息 | UAF 改 `bk`；目标区 fake size |
| 关键环境与不变量 | 经典单 fake node，不预建完整反向关系 |
| 最终输出原语 | malloc 返回栈/全局地址 |
| 版本边界应如何理解 | 2.28 `bck->fd==victim` 封住单 fake-node 最小链。若先能写出完整自洽链，可转 Lore/受约束 unsorted，但那增加了接近 AAW 的前置。 |
<!-- PRIMITIVE_REQUIREMENTS:END -->

## 版本变化

- 2.28：新增了 `bck->fd == victim` 的检查，经典的单 fake node 写法从此无法通过；2.29 又补上了 next-size 等一系列检查。

## 从源码看

unsorted 的 first-fit 分支在精确匹配到大小之后，会把 `chunk2mem(victim)` 作为结果返回。本目录的判断以 GNU glibc 对应的 tag/提交为准，参考：[2.28 malloc.c](https://github.com/bminor/glibc/blob/glibc-2.28/malloc/malloc.c)、[2.29 加固](https://sourceware.org/git/?p=glibc.git;a=commit;h=b90ddd08f6dd688e651df9ee89ca3a69ff88cd0c)。

版本号只代表上游基线，发行版可能会把检查回移到更早的版本；实战时请按附件的 Build ID 对照源码确认。

## PoC

- [`poc_2.23_2.27.c`](./poc_2.23_2.27.c)：验证 2.23–2.27 分支，成功判据见源码头部。

下面的 PoC 都是 x86-64 教学程序，其中的 UAF、越界或 double free 都是特意模拟出来的漏洞行为。快速验证：

```bash
# 在目录根运行；把版本和文件替换为要测的分支
./tools/run_in_docker.sh 2.39 unsorted_bin_into_stack/poc_2.23_2.27.c
```

迁移到具体题目时，堆排布和检查绕过的思路不用改，只需要把漏洞模拟部分换成题目实际提供的 edit/UAF/overflow 原语；写死的地址和最终目标都要按题目重新计算。

## 调试

通用的断点位置和排查顺序见 [根目录调试顺序](../README.md#调试顺序)。
