# House of Spirit

## 结论

- 适用范围：**glibc 整体覆盖 2.23～2.43；其中 fastbin 子型只到 2.42，tcache 子型从 2.26 开始一直可用**。
- 原语效果：free 一个位于非堆区域的伪造 chunk 之后，让接下来的 malloc 返回栈上或全局区的地址。
- 前置能力：能控制被 free 的指针指向哪里，以及伪造 chunk 的 size 字段；目标是 x86-64，需要满足 0x10 对齐。

<!-- PRIMITIVE_REQUIREMENTS:START -->
## 原语要求与版本边界

| 项目 | 本手法要求 |
|---|---|
| 最小输入原语 / 信息 | 控制被 free 的非 heap 指针及 fake size |
| 关键环境与不变量 | 目标 0x10 对齐；fastbin 版需邻接 size/处理 tcache；tcache 版检查更少 |
| 最终输出原语 | malloc 返回栈/全局 fake chunk/AAF |
| 版本边界应如何理解 | fastbin 子型 2.43 随 fastbin 硬删除；tcache 子型 2.26～2.43 持续。因此“Spirit 整体失效”是错误说法。 |
<!-- PRIMITIVE_REQUIREMENTS:END -->

## 版本变化

- 2.23～2.25：使用 fastbin 伪造 chunk，需要提前准备好合法的 next-size。
- 2.26 起：多了检查更少的 tcache 分支可用；fastbin 分支则需要先把 tcache 填满才能触发。
- 2.41：fastbin 分支在取出前需要先耗尽 tcache；2.43：fastbin 分支随 fastbin 一起被删除，但 tcache 分支依然可用。

## 从源码看

本手法主要涉及 `_int_free_check`、tcache 的快速路径判断，以及 fastbin 的 next-size 检查。本目录的版本判断以 GNU glibc 对应 tag/提交为准：[2.42 malloc.c](https://github.com/bminor/glibc/blob/glibc-2.42/malloc/malloc.c)、[2.43 fastbin 删除](https://sourceware.org/git/?p=glibc.git;a=commit;h=bf1015fb2d7e4057925481960626533f8571a2fb)。

版本号只代表上游基线；发行版可能会把检查回移到更早的版本号上，实战时请按附件的 Build ID 对照源码确认。

## PoC

- [`poc_fastbin_2.23_2.25.c`](./poc_fastbin_2.23_2.25.c)：验证 fastbin–2.23–2.25 分支；成功判据见源码头部。
- [`poc_fastbin_2.26_2.40.c`](./poc_fastbin_2.26_2.40.c)：验证 fastbin–2.26–2.40 分支；成功判据见源码头部。
- [`poc_fastbin_2.41_2.42.c`](./poc_fastbin_2.41_2.42.c)：验证 fastbin–2.41–2.42 分支；成功判据见源码头部。
- [`poc_tcache_2.26_2.43.c`](./poc_tcache_2.26_2.43.c)：验证 tcache–2.26–2.43 分支；成功判据见源码头部。

下面的 PoC 都是 x86-64 教学程序，其中的 UAF、越界或 double free 都是故意模拟出来的漏洞行为。快速验证：

```bash
# 在目录根运行；把版本和文件替换为要测的分支
./tools/run_in_docker.sh 2.39 house_of_spirit/poc_tcache_2.26_2.43.c
```

迁移到具体题目时，堆排布和绕过检查的思路不用改，只需要把漏洞模拟部分换成题目实际提供的 edit/UAF/overflow 原语；写死的地址和最终目标都要按题目重新计算。

## 调试

通用的断点位置和排查顺序见 [根目录调试顺序](../README.md#调试顺序)。
