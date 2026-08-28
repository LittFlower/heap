# House of Gods

## 结论

- 适用范围：**glibc 2.23～2.26；2.27 起失效**。
- 原语效果：劫持 `thread_arena` 到 fake arena，然后控制这个线程的分配。
- 前置能力：heap/libc 泄露、任意大小申请、可改 main_arena.next/system_mem/narenas。

<!-- PRIMITIVE_REQUIREMENTS:START -->
## 原语要求与版本边界

| 项目 | 本手法要求 |
|---|---|
| 最小输入原语 / 信息 | 原版：一个 unsorted UAF、heap/libc leak、可控 chunk 前 5 个 qword、若干任意 size 申请 |
| 关键环境与不变量 | binmap qword 能作 size；main_arena 的 fastbin 重叠能继续 fake 链；能进入 `reused_arena` |
| 最终输出原语 | 劫持 `thread_arena`/fake arena，控制后续分配 |
| 版本边界应如何理解 | 已严格实跑 2.23～2.25。2.26 主要是 tcache 路由+隐藏偏移的构建适配，不能把旧 PoC 原样外推。2.27 `have_fastchunks` 令 main_arena+8 不再是可用 size，且单线程 malloc 绕 thread_arena：原版弱前置链硬失效；已有 AAW 时仍可直接投递 fake arena，但那是更强实现。 |
<!-- PRIMITIVE_REQUIREMENTS:END -->

<!-- CHUNK_SIZE_REQUIREMENTS:START -->
## Chunk size 要求

- **原版要求“任意/多尺寸申请”，不能只控制一个固定 size class。** 已验证 PoC 至少使用 request `0x18/0x38/0x68/0x88/0x98/0x1f8`，对应物理 `0x20/0x40/0x70/0x90/0xa0/0x200`。
- 这些尺寸分别用于 main_arena fastbin 重叠、binmap 和 fake arena 链，部分还由目标构建的 arena 字段偏移决定；少掉其中一种精确 request，通常不能只用等长 chunk 替换。
- 原版还要把两次超大失败申请（PoC 传入 `0xffffffffffffffc0`）真正送到 `malloc`，借失败后的 arena retry/reuse 推进 `thread_arena`；若菜单先按上限拒绝该 request，这个触发阶段也无法复现。
<!-- CHUNK_SIZE_REQUIREMENTS:END -->

## 版本变化

- 2.23 与 2.24～2.26 的 arena 字段偏移/布局略有区别。
- glibc 2.27 的 arena/fastbin 一致性加固让 how2heap 把范围标成 `< 2.27`；参考文章表格写到 2.27 是边界歧义，本表按实际 PoC 与源码取 2.26 为末版。

## 从源码看

`reused_arena`、`arena_get_retry`、thread_arena 与 fake malloc_state。本目录判断以 GNU glibc 对应 tag/提交为准：[2.26 arena.c](https://github.com/bminor/glibc/blob/glibc-2.26/malloc/arena.c)、[上游原始说明](https://github.com/Milo-D/house-of-gods)。

版本号只代表上游基线；发行版可能回移检查。实战请按附件 Build ID 对照源码。

## PoC

- [`poc_2.23.c`](./poc_2.23.c)：验证 2.23 分支；成功判据见源码头部。
- [`poc_2.24_2.25.c`](./poc_2.24_2.25.c)：验证 2.24–2.25 分支；成功判据见源码头部。

PoC 为 x86-64 教学程序，故意包含 UAF、越界或 double free。快速验证：

```bash
# 在目录根运行；把版本和文件替换为要测的分支
./tools/run_in_docker.sh 2.39 house_of_gods/poc_2.24_2.25.c
```

迁移时保留堆排布和检查绕过，只把漏洞模拟替换为题目的 edit/UAF/overflow；固定地址和最终目标必须重算。

## 调试

通用断点和排查顺序见 [根目录调试顺序](../README.md#调试顺序)。
