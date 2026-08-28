# Tcache Metadata Poisoning

## 结论

- 适用范围：**glibc 2.26～2.43；偏移随版本变化**。
- 原语效果：直接篡改 tcache_perthread_struct，控制某尺寸下一次返回地址。
- 前置能力：对 tcache 元数据的堆溢出、重叠或 UAF。

<!-- PRIMITIVE_REQUIREMENTS:START -->
## 原语要求与版本边界

| 项目 | 本手法要求 |
|---|---|
| 最小输入原语 / 信息 | 能直接覆盖 `tcache_perthread_struct` |
| 关键环境与不变量 | 先泄露/定位 metadata；按版本计算 counts/entries |
| 最终输出原语 | 任意 size class 的下一次返回地址/AAF |
| 版本边界应如何理解 | 2.26～2.43 思想持续；2.30、2.42、2.43 主要是字段宽度、bin 数与语义适配。头指针并未整体 safe-link。 |
<!-- PRIMITIVE_REQUIREMENTS:END -->

<!-- CHUNK_SIZE_REQUIREMENTS:START -->
## Chunk size 要求

- 没有唯一尺寸，但必须选一个**已启用的 tcache class**，把对应 `counts/num_slots` 与 `entries[idx]` 一起伪造成可取状态，然后用同一 class 请求消费。
- PoC 选 `malloc(0x10) -> chunksize 0x20`。若改用其他 small/已启用 large class，必须按该版本的 `csize2tidx/large_csize2tidx` 重算 metadata 索引；不能只改最终 malloc 参数。
<!-- CHUNK_SIZE_REQUIREMENTS:END -->

## 版本变化

- 2.30 前 counts 是 `char`，2.30 起为 `uint16_t`。
- 2.42 counts 改成向下计数的 `num_slots`，small+large 共 76 bins；entries 头为明文。
- 2.43 tcache 使用 TLS inactive/disabled 哨兵且结构位置改变，示例索引不同。

## 从源码看

`tcache_perthread_struct`、`tcache_put_n`、`tcache_get_n`。本目录判断以 GNU glibc 对应 tag/提交为准：[2.41 malloc.c](https://github.com/bminor/glibc/blob/glibc-2.41/malloc/malloc.c)、[2.42 count down](https://sourceware.org/git/?p=glibc.git;a=commit;h=7e10e30e64aa2cc8ba50f2f83cb7cc2cdad134ad)、[2.42 large tcache](https://sourceware.org/git/?p=glibc.git;a=commit;h=cbfd7988107b27b9ff1d0b57fa2c8f13a932e508)。

版本号只代表上游基线；发行版可能回移检查。实战请按附件 Build ID 对照源码。

## PoC

- [`poc_2.26_2.29.c`](./poc_2.26_2.29.c)：验证 2.26–2.29 分支；成功判据见源码头部。
- [`poc_2.30_2.41.c`](./poc_2.30_2.41.c)：验证 2.30–2.41 分支；成功判据见源码头部。
- [`poc_2.42.c`](./poc_2.42.c)：验证 2.42 分支；成功判据见源码头部。
- [`poc_2.43.c`](./poc_2.43.c)：验证 2.43 分支；成功判据见源码头部。

PoC 为 x86-64 教学程序，故意包含 UAF、越界或 double free。快速验证：

```bash
# 在目录根运行；把版本和文件替换为要测的分支
./tools/run_in_docker.sh 2.39 tcache_metadata_poisoning/poc_2.43.c
```

迁移时保留堆排布和检查绕过，只把漏洞模拟替换为题目的 edit/UAF/overflow；固定地址和最终目标必须重算。

## 调试

通用断点和排查顺序见 [根目录调试顺序](../README.md#调试顺序)。
