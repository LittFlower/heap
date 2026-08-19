# House of Roman

## 结论

- 适用范围：**glibc 2.23～2.27；2.28 起经典链失效**。
- 原语效果：在没有完整地址泄露的情况下，通过相对覆盖把伪造的 fastbin 链导向 hook。
- 前置能力：一次 UAF 或溢出；能做 fastbin attack 和 unsorted-bin attack；还要能对若干低位地址进行猜测。

<!-- PRIMITIVE_REQUIREMENTS:START -->
## 原语要求与版本边界

| 项目 | 本手法要求 |
|---|---|
| 最小输入原语 / 信息 | 无完整泄露；fastbin/tcache 相对覆盖 + unsorted 写 + 低位猜测 |
| 关键环境与不变量 | hook 仍消费；经典 unsorted 目标无需预置；ASLR 低位命中 |
| 最终输出原语 | 无完整 libc 地址下把分配导向 hook 并低字节 CF |
| 版本边界应如何理解 | 2.26/2.27 可通过 tcache 重排，属适配；2.28 硬封经典 unsorted 中段，所以完整 Roman 止于 2.27。额外预置 target/AAW 会破坏其“弱泄露”前提。 |
<!-- PRIMITIVE_REQUIREMENTS:END -->

## 版本变化

- 2.23～2.25 走的是原始的 fastbin 路径。
- 2.26～2.27 改成了 count=3 的 tcache 链，并借助 calloc 跳过 tcache 的快速取块路径，让 exact-size 的 unsorted victim 仍按老路径处理。
- 2.28 引入的 bdc3009 补丁在摘链前检查 `bck->fd==victim`，直接切断了把伪块投递到 hook 的这条路径。
- 2.34 又彻底删除了 malloc/free hooks，这条链原本瞄准的终点也就不存在了。

## 从源码看

本手法的核心是 fastbin freelist、unsorted bin 摘链时对 `bck->fd` 的写入，以及 `__malloc_hook` 调用点三者的组合。本目录的版本结论以 GNU glibc 对应 tag/提交为准，参考：[2.26 tcache](https://sourceware.org/git/?p=glibc.git;a=commit;h=d5c3fafc4307c9b7a4c7d5cb381fcdbfad340bcc)、[2.28 unsorted 加固](https://sourceware.org/git/?p=glibc.git;a=commit;h=bdc3009b8ff0effdbbfb05eb6b10966753cbf9b8)、[2.34 hooks 删除](https://github.com/bminor/glibc/blob/glibc-2.34/malloc/malloc.c)。

版本号只代表上游基线；发行版可能回移检查，实战时请按附件的 Build ID 对照源码确认。

## PoC

- [`poc_2.23_2.27.c`](./poc_2.23_2.27.c)：验证 2.23–2.27 分支；成功判据见源码头部。

下面的 PoC 是 x86-64 教学程序，其中的 UAF、越界或 double free 都是特意模拟出来的漏洞行为。快速验证：

```bash
# 在目录根运行；把版本和文件替换为要测的分支
./tools/run_in_docker.sh 2.39 house_of_roman/poc_2.23_2.27.c
```

迁移到具体题目时，堆排布和检查绕过的思路不用改，只需要把漏洞模拟部分换成题目实际提供的 edit/UAF/overflow 原语；写死的地址和最终目标都要按题目重新计算。

## 调试

通用的断点位置和排查顺序见[根目录调试顺序](../README.md#调试顺序)。
