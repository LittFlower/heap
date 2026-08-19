# House of Water

## 结论

- 适用范围：**glibc 2.32～2.43**。
- 原语效果：不需要泄露任何地址，就能控制 tcache 的元数据，并把 libc/unsorted bin 里的指针链接进 tcache。
- 前置能力：一次 UAF 或 double free；能精确控制 tcache_perthread_struct 里 counts（计数数组）和 entries（链表头数组）附近的字节。

<!-- PRIMITIVE_REQUIREMENTS:START -->
## 原语要求与版本边界

| 项目 | 本手法要求 |
|---|---|
| 最小输入原语 / 信息 | tcache UAF/double free；可精确修改 `counts`/`entries` 附近字节 |
| 关键环境与不变量 | 利用元数据自身的值形成 fake chunk，并接入 unsorted/libc 指针；按版本适配布局 |
| 最终输出原语 | 无地址泄露地控制 tcache 元数据，并获得 libc/heap 指针 |
| 版本边界应如何理解 | 2.32 是这套布局和技巧的定义起点；2.42/2.43 需要适配元数据布局，核心思想到 2.43 仍可满足。 |
<!-- PRIMITIVE_REQUIREMENTS:END -->

## 版本变化

- 最低适用版本是 2.32，因为这个手法的目标就是在完全不泄露地址的情况下绕过 safe-linking。
- 2.42 里 tcache 改成了 76 个 bin，num_slots 变成向下计数，并且引入了大块缓存，整体布局和之前不同，所以需要单独的堆风水。
- 2.43 里 TLS 的 inactive/disabled 哨兵值和结构体内部字段的位置都发生了变化，因此再用一份独立的 PoC 来验证。

## 从源码看

这个手法本质上是利用 tcache_perthread_struct 的字节布局，配合对 unsorted bin 链表的写入来实现的。本目录的版本结论以 GNU glibc 对应 tag/提交为准，参考：[2.42 malloc.c](https://github.com/bminor/glibc/blob/glibc-2.42/malloc/malloc.c)、[2.43 malloc.c](https://github.com/bminor/glibc/blob/master/malloc/malloc.c)。

版本号只代表上游基线；发行版可能会回移相关的检查逻辑，实战时请按附件的 Build ID 对照源码确认。

## PoC

- [`poc_2.32_2.41.c`](./poc_2.32_2.41.c)：验证 2.32–2.41 分支，成功判据见源码头部。
- [`poc_2.42.c`](./poc_2.42.c)：验证 2.42 分支，成功判据见源码头部。
- [`poc_2.43.c`](./poc_2.43.c)：验证 2.43 分支，成功判据见源码头部。

下面的 PoC 都是 x86-64 教学程序，其中的 UAF、越界或 double free 都是特意模拟出来的漏洞行为。快速验证：

```bash
# 在目录根运行；把版本和文件替换为要测的分支
./tools/run_in_docker.sh 2.39 house_of_water/poc_2.43.c
```

迁移到具体题目时，堆排布和检查绕过的思路不用改，只需要把漏洞模拟部分换成题目实际提供的 edit/UAF/overflow 原语；写死的地址和最终目标都要按题目重新计算。

## 调试

通用的断点位置和排查顺序见 [根目录调试顺序](../README.md#调试顺序)。
