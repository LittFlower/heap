# House of Einherjar

## 结论

- 适用范围：**glibc 2.23～2.43**。
- 原语效果：用 off-by-null 触发一次伪造的后向合并，制造出 chunk overlap 或任意地址分配。
- 前置能力：一个 off-by-null、堆地址泄露、能伪造前块的双向链；高版本还需要配合 tcache 链投毒。

<!-- PRIMITIVE_REQUIREMENTS:START -->
## 原语要求与版本边界

| 项目 | 本手法要求 |
|---|---|
| 最小输入原语 / 信息 | off-by-null/overflow 改 `prev_size` 与 `PREV_INUSE`；堆地址泄露 |
| 关键环境与不变量 | fake 前块的双向链完整，且 size/prev_size 一致；现代版本还需处理 tcache |
| 最终输出原语 | 后向合并产生 overlap/AAF |
| 版本边界应如何理解 | 2.26、2.29、2.32、2.43 都只是检查或路由适配；fake 前块后向合并的核心思想到 2.43 仍可满足。 |
<!-- PRIMITIVE_REQUIREMENTS:END -->

## 版本变化

- 2.23～2.28：主要要绕过的是 unlink 的双链检查。
- 2.29 起：还要让 fake chunk 的 size 等于后一块的 prev_size 才能通过检查。
- 2.32 起：tcache poisoning 需要按 safe-linking 编码。
- 2.43：因为 tcache 元数据布局变了要相应调整，但整体原理不受影响。

## 从源码看

关键在 `_int_free_merge_chunk` 里判断 PREV_INUSE 的分支，以及 `unlink_chunk`。本目录的版本结论以 GNU glibc 对应 tag/提交为准，参考：[2.29 null-byte 加固](https://sourceware.org/git/?p=glibc.git;a=commit;h=d6db68e66dff25d12c3bc5641b60cbd7fb6ab44f)、[2.43 malloc.c](https://github.com/bminor/glibc/blob/master/malloc/malloc.c)。

版本号只代表上游基线；发行版可能回移检查，实战时请按附件的 Build ID 对照源码确认。

## PoC

- [`poc_2.23_2.25.c`](./poc_2.23_2.25.c)：验证 2.23–2.25 分支，成功判据见源码头部。
- [`poc_2.26_2.29.c`](./poc_2.26_2.29.c)：验证 2.26–2.29 分支，成功判据见源码头部。
- [`poc_2.30_2.31.c`](./poc_2.30_2.31.c)：验证 2.30–2.31 分支，成功判据见源码头部。
- [`poc_2.32_2.42.c`](./poc_2.32_2.42.c)：验证 2.32–2.42 分支，成功判据见源码头部。
- [`poc_2.43.c`](./poc_2.43.c)：验证 2.43 分支，成功判据见源码头部。

下面的 PoC 都是 x86-64 教学程序，其中的 UAF、越界或 double free 都是特意模拟出来的漏洞行为。快速验证：

```bash
# 在目录根运行；把版本和文件替换为要测的分支
./tools/run_in_docker.sh 2.39 house_of_einherjar/poc_2.43.c
```

迁移到具体题目时，堆排布和检查绕过的思路不用改，只需要把漏洞模拟部分换成题目实际提供的 edit/UAF/overflow 原语；写死的地址和最终目标都要按题目重新计算。

## 调试

通用的断点位置和排查顺序见[根目录调试顺序](../README.md#调试顺序)。
