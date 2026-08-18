# House of Water

## 结论

- 适用范围：**glibc 2.32～2.43**。
- 原语效果：无地址泄露地控制 tcache 元数据，并把 libc/unsorted 指针链入 tcache。
- 前置能力：UAF 或 double free；能精确控制 tcache counts/entries 附近字节。

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

- 最低版本 2.32，因为手法的目标就是 leakless 绕过 safe-linking。
- 2.42 tcache 改为 76 bins、num_slots 向下计数和大块缓存，布局独立。
- 2.43 TLS inactive/disabled 哨兵与结构位置变化，再用独立 PoC。

## 从源码看

tcache_perthread_struct 字节布局与 unsorted 链写入的组合。本目录判断以 GNU glibc 对应 tag/提交为准：[2.42 malloc.c](https://github.com/bminor/glibc/blob/glibc-2.42/malloc/malloc.c)、[2.43 malloc.c](https://github.com/bminor/glibc/blob/master/malloc/malloc.c)。

版本号只代表上游基线；发行版可能回移检查。实战请按附件 Build ID 对照源码。

## PoC

- [`poc_2.32_2.41.c`](./poc_2.32_2.41.c)：验证 2.32–2.41 分支；成功判据见源码头部。
- [`poc_2.42.c`](./poc_2.42.c)：验证 2.42 分支；成功判据见源码头部。
- [`poc_2.43.c`](./poc_2.43.c)：验证 2.43 分支；成功判据见源码头部。

PoC 为 x86-64 教学程序，故意包含 UAF、越界或 double free。快速验证：

```bash
# 在目录根运行；把版本和文件替换为要测的分支
./tools/run_in_docker.sh 2.39 house_of_water/poc_2.43.c
```

迁移时保留堆排布和检查绕过，只把漏洞模拟替换为题目的 edit/UAF/overflow；固定地址和最终目标必须重算。

## 调试

通用断点和排查顺序见 [根目录调试顺序](../README.md#调试顺序)。
