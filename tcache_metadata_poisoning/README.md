# Tcache Metadata Poisoning

## 结论

- 适用范围：**glibc 2.26～2.43；偏移随版本变化**。
- 原语效果：直接篡改 tcache_perthread_struct，控制指定尺寸下一次分配返回的地址。
- 前置能力：能对 tcache 元数据发起堆溢出、重叠写或 UAF。

<!-- PRIMITIVE_REQUIREMENTS:START -->
## 原语要求与版本边界

| 项目 | 本手法要求 |
|---|---|
| 最小输入原语 / 信息 | 能直接覆盖 `tcache_perthread_struct` |
| 关键环境与不变量 | 先泄露/定位 metadata；按版本计算 counts/entries |
| 最终输出原语 | 任意 size class 的下一次返回地址/AAF |
| 版本边界应如何理解 | 2.26～2.43 思想持续；2.30、2.42、2.43 主要是字段宽度、bin 数与语义适配。头指针并未整体 safe-link。 |
<!-- PRIMITIVE_REQUIREMENTS:END -->

## 版本变化

- 2.30 之前 counts 字段是 `char`，2.30 起改为 `uint16_t`。
- 2.42 把 counts 改成向下计数的 `num_slots`，small 和 large 合计共 76 个 bins；entries 表头仍是明文存储。
- 2.43 的 tcache 引入了 TLS inactive/disabled 哨兵，结构体的位置也发生了变化，所以示例用的索引与旧版本不同。

## 从源码看

关键看点是 `tcache_perthread_struct`、`tcache_put_n`、`tcache_get_n` 这几处。本目录的判断以 GNU glibc 对应 tag/提交为准：[2.41 malloc.c](https://github.com/bminor/glibc/blob/glibc-2.41/malloc/malloc.c)、[2.42 count down](https://sourceware.org/git/?p=glibc.git;a=commit;h=7e10e30e64aa2cc8ba50f2f83cb7cc2cdad134ad)、[2.42 large tcache](https://sourceware.org/git/?p=glibc.git;a=commit;h=cbfd7988107b27b9ff1d0b57fa2c8f13a932e508)。

版本号只代表上游基线；发行版可能回移检查，实战时请按附件的 Build ID 对照源码确认。

## PoC

- [`poc_2.26_2.29.c`](./poc_2.26_2.29.c)：验证 2.26–2.29 分支，成功判据见源码头部。
- [`poc_2.30_2.41.c`](./poc_2.30_2.41.c)：验证 2.30–2.41 分支，成功判据见源码头部。
- [`poc_2.42.c`](./poc_2.42.c)：验证 2.42 分支，成功判据见源码头部。
- [`poc_2.43.c`](./poc_2.43.c)：验证 2.43 分支，成功判据见源码头部。

下面的 PoC 都是 x86-64 教学程序，其中的 UAF、越界或 double free 都是特意模拟出来的漏洞行为。快速验证：

```bash
# 在目录根运行；把版本和文件替换为要测的分支
./tools/run_in_docker.sh 2.39 tcache_metadata_poisoning/poc_2.43.c
```

迁移到具体题目时，堆排布和检查绕过的思路不用改，只需要把漏洞模拟部分换成题目实际提供的 edit/UAF/overflow 原语；写死的地址和最终目标都要按题目重新计算。

## 调试

通用的断点位置和排查顺序见[根目录调试顺序](../README.md#调试顺序)。
