# Unsorted Bin Into Stack

## 结论

- 适用范围：**glibc 2.23～2.27；2.28 起失效**。
- 原语效果：让 malloc 从伪造在栈/全局区的 unsorted 节点返回地址。
- 前置能力：UAF 改 `bk`，并在目标附近布置可通过 size 判断的 fake chunk。

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

- 2.28 新增 `bck->fd == victim`，经典单 fake node 无法通过；2.29 再加入 next-size 等检查。

## 从源码看

unsorted first-fit 分支在精确大小匹配后将 `chunk2mem(victim)` 返回。本目录判断以 GNU glibc 对应 tag/提交为准：[2.28 malloc.c](https://github.com/bminor/glibc/blob/glibc-2.28/malloc/malloc.c)、[2.29 加固](https://sourceware.org/git/?p=glibc.git;a=commit;h=b90ddd08f6dd688e651df9ee89ca3a69ff88cd0c)。

版本号只代表上游基线；发行版可能回移检查。实战请按附件 Build ID 对照源码。

## PoC

- [`poc_2.23_2.27.c`](./poc_2.23_2.27.c)：验证 2.23–2.27 分支；成功判据见源码头部。

PoC 为 x86-64 教学程序，故意包含 UAF、越界或 double free。快速验证：

```bash
# 在目录根运行；把版本和文件替换为要测的分支
./tools/run_in_docker.sh 2.39 unsorted_bin_into_stack/poc_2.23_2.27.c
```

迁移时保留堆排布和检查绕过，只把漏洞模拟替换为题目的 edit/UAF/overflow；固定地址和最终目标必须重算。

## 调试

通用断点和排查顺序见 [根目录调试顺序](../README.md#调试顺序)。
