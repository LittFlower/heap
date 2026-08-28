# Fastbin Dup Into Stack

## 结论

- 适用范围：**glibc 2.23～2.42；2.43 失效**。
- 原语效果：把 fastbin 的后继改到栈/全局区 fake chunk，取得近似任意地址分配。
- 前置能力：double free + UAF 写 fd；目标 0x10 对齐；使用 calloc 时目标附近需有匹配 size。

<!-- PRIMITIVE_REQUIREMENTS:START -->
## 原语要求与版本边界

| 项目 | 本手法要求 |
|---|---|
| 最小输入原语 / 信息 | fastbin UAF 改 `fd`，通常还要 double free |
| 关键环境与不变量 | fake size、0x10 对齐；2.32+ `PROTECT_PTR`；2.42 refill size |
| 最终输出原语 | AAF 到栈/全局 fake chunk |
| 版本边界应如何理解 | 2.26/2.32/2.41/2.42 都是实现适配；2.43 fastbin 删除为硬边界。相同 AAF 可改用 tcache poisoning，不代表 fastbin 版仍在。 |
<!-- PRIMITIVE_REQUIREMENTS:END -->

<!-- CHUNK_SIZE_REQUIREMENTS:START -->
## Chunk size 要求

- 真实 victim、fake chunk 的 `size` 和最终 `malloc/calloc` 必须对应**同一个 fastbin class**，即物理 `chunksize` 位于 `[MINSIZE, get_max_fast()]`。
- 没有固定的唯一 class；PoC 选 `malloc(8)`/`calloc(1,8)`，物理 `0x20`。fake header 中应写该物理尺寸并保留所需标志位，不能把用户 request `8` 直接写进 header。
<!-- CHUNK_SIZE_REQUIREMENTS:END -->

## 版本变化

- 2.26 起先处理 tcache。
- 2.32 引入 `PROTECT_PTR` 与对齐检查，fd 需写成 `(pos >> 12) ^ target`。
- 2.33 示例把返回点移到 fake header 后 0x10，以免 calloc 清零破坏 fake size。
- 2.41 calloc/tcache 顺序改变；2.43 fastbin 消失。

## 从源码看

`REMOVE_FB`、`fastbin_index(chunksize(victim))` 与 `aligned_OK` 决定 fake chunk 能否被取出。本目录判断以 GNU glibc 对应 tag/提交为准：[safe-linking 提交](https://sourceware.org/git/?p=glibc.git;a=commit;h=a1a486d70ebcc47a686ff5846875eacad0940e41)、[2.41 calloc tcache 提交](https://sourceware.org/git/?p=glibc.git;a=commit;h=226e3b0a413673c0d6691a0ae6dd001fe05d21cd)。

版本号只代表上游基线；发行版可能回移检查。实战请按附件 Build ID 对照源码。

## PoC

- [`poc_2.23_2.25.c`](./poc_2.23_2.25.c)：验证 2.23–2.25 分支；成功判据见源码头部。
- [`poc_2.26_2.31.c`](./poc_2.26_2.31.c)：验证 2.26–2.31 分支；成功判据见源码头部。
- [`poc_2.32.c`](./poc_2.32.c)：验证 2.32 分支；成功判据见源码头部。
- [`poc_2.33_2.40.c`](./poc_2.33_2.40.c)：验证 2.33–2.40 分支；成功判据见源码头部。
- [`poc_2.41_2.42.c`](./poc_2.41_2.42.c)：验证 2.41–2.42 分支；成功判据见源码头部。

PoC 为 x86-64 教学程序，故意包含 UAF、越界或 double free。快速验证：

```bash
# 在目录根运行；把版本和文件替换为要测的分支
./tools/run_in_docker.sh 2.39 fastbin_dup_into_stack/poc_2.41_2.42.c
```

迁移时保留堆排布和检查绕过，只把漏洞模拟替换为题目的 edit/UAF/overflow；固定地址和最终目标必须重算。

## 调试

通用断点和排查顺序见 [根目录调试顺序](../README.md#调试顺序)。
