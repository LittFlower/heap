# Tcache Relative Write

## 结论

- 适用范围：**glibc 2.30～2.41；2.42 元数据重构后失效**。
- 原语效果：把 tcache 计数值或 chunk 指针，作为受限的值写到堆上相邻的目标位置。
- 前置能力：能相对越界访问到 tcache_perthread_struct，并且知道目标与结构体起点的相对偏移。

<!-- PRIMITIVE_REQUIREMENTS:START -->
## 原语要求与版本边界

| 项目 | 本手法要求 |
|---|---|
| 最小输入原语 / 信息 | libc/unsorted leak；能增大 `mp_.tcache_bins`；可申请精确超界 size |
| 关键环境与不变量 | 2.30～2.41 外层用可扩大的 `mp_` 界，metadata 仍固定 64 槽 |
| 最终输出原语 | metadata 后相对位置的半字计数写或 heap-pointer 写 |
| 版本边界应如何理解 | 2.42 把结构扩为 76 bins、改 count-down 并重写 size→idx/边界，原“放大 `mp_.tcache_bins` 让固定数组 OOB”消费路径硬失效；普通 metadata overflow 仍可能，但不是本算法。 |
<!-- PRIMITIVE_REQUIREMENTS:END -->

## 版本变化

- 2.30/2.31 的 counts 字段是 16 位。
- 2.32 引入了 safe-linking。
- 2.35 和 2.38 的 tcache 元数据在初始化和分配的细节上做了一些偏移调整。
- 2.42 把 counts 改成向下计数的 `num_slots`，并将结构体扩展到 76 个 bins，旧版本的原语因此失效。

## 从源码看

关键看点是 tcache 结构体内 counts/entries 两个数组的相邻布局，以及 get/put 操作里的增减逻辑。本目录的判断以 GNU glibc 对应 tag/提交为准：[2.41 malloc.c](https://github.com/bminor/glibc/blob/glibc-2.41/malloc/malloc.c)、[2.42 count-down](https://sourceware.org/git/?p=glibc.git;a=commit;h=7e10e30e64aa2cc8ba50f2f83cb7cc2cdad134ad)。

版本号只代表上游基线；发行版可能回移检查，实战时请按附件的 Build ID 对照源码确认。

## PoC

- [`poc_2.30_2.31.c`](./poc_2.30_2.31.c)：验证 2.30–2.31 分支，成功判据见源码头部。
- [`poc_2.32_2.34.c`](./poc_2.32_2.34.c)：验证 2.32–2.34 分支，成功判据见源码头部。
- [`poc_2.35_2.37.c`](./poc_2.35_2.37.c)：验证 2.35–2.37 分支，成功判据见源码头部。
- [`poc_2.38_2.41.c`](./poc_2.38_2.41.c)：验证 2.38–2.41 分支，成功判据见源码头部。

下面的 PoC 都是 x86-64 教学程序，其中的 UAF、越界或 double free 都是特意模拟出来的漏洞行为。快速验证：

```bash
# 在目录根运行；把版本和文件替换为要测的分支
./tools/run_in_docker.sh 2.39 tcache_relative_write/poc_2.38_2.41.c
```

迁移到具体题目时，堆排布和检查绕过的思路不用改，只需要把漏洞模拟部分换成题目实际提供的 edit/UAF/overflow 原语；写死的地址和最终目标都要按题目重新计算。

## 调试

通用的断点位置和排查顺序见[根目录调试顺序](../README.md#调试顺序)。
