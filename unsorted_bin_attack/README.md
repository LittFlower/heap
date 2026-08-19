# Unsorted Bin Attack

## 结论

- 适用范围：**glibc 2.23～2.27；2.28 起经典形式失效**。
- 原语效果：把 `unsorted_chunks(av)` 的地址写入目标位置；2.23～2.27 对目标的初始值没有任何要求，而 2.28 及之后的版本则要求目标提前被设置成等于 victim。
- 前置能力：需要一次 UAF 来改写 unsorted victim 的 `bk` 指针；2.28 及之后的版本还需要额外构造出 `target == victim_chunk` 这个前置关系。

<!-- PRIMITIVE_REQUIREMENTS:START -->
## 原语要求与版本边界

| 项目 | 本手法要求 |
|---|---|
| 最小输入原语 / 信息 | UAF 改 victim `bk` |
| 关键环境与不变量 | 经典版目标任意初值；2.28+ 目标必须预先等于 victim |
| 最终输出原语 | 向目标写 unsorted head/libc 指针 |
| 版本边界应如何理解 | 2.28 硬封“只改 `bk`、目标任意初值”的弱前置；赋值语句仍在，预置 `target==victim` 可到 2.43，但这应标**强约束残余**，不能冒充经典 AAW。 |
<!-- PRIMITIVE_REQUIREMENTS:END -->

## 版本变化

- 2.23～2.27：摘链过程会直接信任 `victim->bk` 的值，因此可以让 `bck->fd` 指向任意初始值的 target。
- 2.28：提交 `bdc3009` 引入了 `bck->fd == victim` 的一致性检查，经典的无条件单指针写就此终结；2.29 又补上了 next-size 等一系列检查。

## 从源码看

unsorted 遍历过程中会执行 `bck = victim->bk; if (bck->fd != victim) ...; bck->fd = unsorted_chunks(av)`。本目录的判断以 GNU glibc 对应的 tag/提交为准，参考：[2.28 首次 harden removal](https://sourceware.org/git/?p=glibc.git;a=commit;h=bdc3009b8ff0effdbbfb05eb6b10966753cbf9b8)、[2.29 后续加固](https://sourceware.org/git/?p=glibc.git;a=commit;h=b90ddd08f6dd688e651df9ee89ca3a69ff88cd0c)。

版本号只代表上游基线，发行版可能会把检查回移到更早的版本；实战时请按附件的 Build ID 对照源码确认。

## PoC

- [`poc_2.23_2.27.c`](./poc_2.23_2.27.c)：验证 2.23–2.27 分支；成功判据见源码头部。
- [`poc_constrained_2.28_2.43.c`](./poc_constrained_2.28_2.43.c)：验证 constrained–2.28–2.43 分支；成功判据见源码头部。

下面的 PoC 都是 x86-64 教学程序，其中的 UAF、越界或 double free 都是特意模拟出来的漏洞行为。快速验证：

```bash
# 在目录根运行；把版本和文件替换为要测的分支
./tools/run_in_docker.sh 2.39 unsorted_bin_attack/poc_constrained_2.28_2.43.c
```

迁移到具体题目时，堆排布和检查绕过的思路不用改，只需要把漏洞模拟部分换成题目实际提供的 edit/UAF/overflow 原语；写死的地址和最终目标都要按题目重新计算。

## 调试

通用的断点位置和排查顺序见 [根目录调试顺序](../README.md#调试顺序)。
