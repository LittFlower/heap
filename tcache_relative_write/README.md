# Tcache Relative Write

## 结论

- 适用范围：**glibc 2.30～2.41；2.42 元数据重构后失效**。
- 原语效果：把 tcache 计数或 chunk 指针作为受限值写到相邻 heap 目标。
- 前置能力：相对越界到 tcache_perthread_struct，且知道目标相对偏移。

<!-- PRIMITIVE_REQUIREMENTS:START -->
## 原语要求与版本边界

| 项目 | 本手法要求 |
|---|---|
| 最小输入原语 / 信息 | libc/unsorted leak；能增大 `mp_.tcache_bins`；可申请精确超界 size |
| 关键环境与不变量 | 2.30～2.41 外层用可扩大的 `mp_` 界，metadata 仍固定 64 槽 |
| 最终输出原语 | metadata 后相对位置的半字计数写或 heap-pointer 写 |
| 版本边界应如何理解 | 2.42 把结构扩为 76 bins、改 count-down 并重写 size→idx/边界，原“放大 `mp_.tcache_bins` 让固定数组 OOB”消费路径硬失效；普通 metadata overflow 仍可能，但不是本算法。 |
<!-- PRIMITIVE_REQUIREMENTS:END -->

<!-- CHUNK_SIZE_REQUIREMENTS:START -->
## Chunk size 要求

- **必须能申请由目标相对 metadata 的距离反算出的精确物理尺寸 `nb`**，不是任选一个 tcache class。PoC 公式为：指针写 `nb = 2*(delta+8)+0x10`，计数写 `nb = 8*(delta+2)+0x10`。
- 对按 `0x10` 对齐的 `nb`，PoC 以 `malloc(nb-0x10)` 得到该物理尺寸；还需先扩大 `mp_.tcache_bins`/上限，使这个越过 64 槽的 size index 真正进入旧 tcache 路径。示例会出现 `0x10100` 级 request，因此菜单上限是实质前置。
<!-- CHUNK_SIZE_REQUIREMENTS:END -->

## 版本变化

- 2.30/2.31 的 counts 为 16 位。
- 2.32 增加 safe-linking。
- 2.35 和 2.38 的 tcache 元数据在初始化/分配细节上有偏移调整。
- 2.42 counts 改为向下计数 `num_slots` 且结构扩成 76 bins，旧原语终止。

## 从源码看

tcache 结构内 counts/entries 的相邻布局和 get/put 的增减操作。本目录判断以 GNU glibc 对应 tag/提交为准：[2.41 malloc.c](https://github.com/bminor/glibc/blob/glibc-2.41/malloc/malloc.c)、[2.42 count-down](https://sourceware.org/git/?p=glibc.git;a=commit;h=7e10e30e64aa2cc8ba50f2f83cb7cc2cdad134ad)。

版本号只代表上游基线；发行版可能回移检查。实战请按附件 Build ID 对照源码。

## PoC

- [`poc_2.30_2.31.c`](./poc_2.30_2.31.c)：验证 2.30–2.31 分支；成功判据见源码头部。
- [`poc_2.32_2.34.c`](./poc_2.32_2.34.c)：验证 2.32–2.34 分支；成功判据见源码头部。
- [`poc_2.35_2.37.c`](./poc_2.35_2.37.c)：验证 2.35–2.37 分支；成功判据见源码头部。
- [`poc_2.38_2.41.c`](./poc_2.38_2.41.c)：验证 2.38–2.41 分支；成功判据见源码头部。

PoC 为 x86-64 教学程序，故意包含 UAF、越界或 double free。快速验证：

```bash
# 在目录根运行；把版本和文件替换为要测的分支
./tools/run_in_docker.sh 2.39 tcache_relative_write/poc_2.38_2.41.c
```

迁移时保留堆排布和检查绕过，只把漏洞模拟替换为题目的 edit/UAF/overflow；固定地址和最终目标必须重算。

## 调试

通用断点和排查顺序见 [根目录调试顺序](../README.md#调试顺序)。
