# House of Gods

## 结论

- 适用范围：**glibc 2.23～2.26；2.27 起失效**。
- 原语效果：把 `thread_arena` 劫持到一份伪造的 fake arena 上，之后这个线程发起的所有分配都会受伪 arena 控制。
- 前置能力：需要 heap/libc 地址泄露、能发出任意大小的申请，并且能改写 main_arena.next、system_mem、narenas 这三个字段。

<!-- PRIMITIVE_REQUIREMENTS:START -->
## 原语要求与版本边界

| 项目 | 本手法要求 |
|---|---|
| 最小输入原语 / 信息 | 原版：一个 unsorted UAF、heap/libc leak、可控 chunk 前 5 个 qword、若干任意 size 申请 |
| 关键环境与不变量 | binmap qword 能作 size；main_arena 的 fastbin 重叠能继续 fake 链；能进入 `reused_arena` |
| 最终输出原语 | 劫持 `thread_arena`/fake arena，控制后续分配 |
| 版本边界应如何理解 | 已严格实跑 2.23～2.25。2.26 主要是 tcache 路由+隐藏偏移的构建适配，不能把旧 PoC 原样外推。2.27 `have_fastchunks` 令 main_arena+8 不再是可用 size，且单线程 malloc 绕 thread_arena：原版弱前置链硬失效；已有 AAW 时仍可直接投递 fake arena，但那是更强实现。 |
<!-- PRIMITIVE_REQUIREMENTS:END -->

## 版本变化

- 2.23 和 2.24～2.26 之间，arena 相关字段的偏移与布局略有区别。
- glibc 2.27 对 arena/fastbin 做了一致性加固，how2heap 因此把适用范围标注为 `< 2.27`；不过参考文章的表格把边界写到 2.27，存在一点歧义，本表按实际跑通的 PoC 与源码结论，把 2.26 定为最后一个可用版本。

## 从源码看

关键函数是 `reused_arena`、`arena_get_retry`，以及 thread_arena 和伪造 malloc_state 之间的关系。本目录的判断以 GNU glibc 对应 tag/提交为准：[2.26 arena.c](https://github.com/bminor/glibc/blob/glibc-2.26/malloc/arena.c)、[上游原始说明](https://github.com/Milo-D/house-of-gods)。

版本号只代表上游基线；发行版可能回移检查。实战请按附件 Build ID 对照源码。

## PoC

- [`poc_2.23.c`](./poc_2.23.c)：验证 2.23 分支，成功判据见源码头部。
- [`poc_2.24_2.25.c`](./poc_2.24_2.25.c)：验证 2.24～2.25 分支，成功判据见源码头部。

PoC 是 x86-64 教学程序，里面故意包含 UAF、越界或 double free。快速验证方法：

```bash
# 在目录根运行；把版本和文件替换为要测的分支
./tools/run_in_docker.sh 2.39 house_of_gods/poc_2.24_2.25.c
```

迁移到具体题目时，堆排布和检查绕过的思路保持不变，只需要把漏洞模拟部分换成题目实际的 edit/UAF/overflow 能力；固定写死的地址和最终目标都要重新计算。

## 调试

通用的断点位置和排查顺序见 [根目录调试顺序](../README.md#调试顺序)。
