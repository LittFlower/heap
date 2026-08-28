# Fastbin Dup Consolidate

## 结论

- 适用范围：**glibc 2.23～2.42；2.43 失效**。
- 原语效果：令同一 chunk 同时可从 fastbin 与合并后的 top/unsorted 路径取出。
- 前置能力：double free 或可制造重复引用，并能触发 `malloc_consolidate`。

<!-- PRIMITIVE_REQUIREMENTS:START -->
## 原语要求与版本边界

| 项目 | 本手法要求 |
|---|---|
| 最小输入原语 / 信息 | double free/重复引用，可触发 `malloc_consolidate` |
| 关键环境与不变量 | fastbin 与 top/unsorted 合并顺序可控 |
| 最终输出原语 | 同一块同时从两条路径返回，形成 overlap |
| 版本边界应如何理解 | 到 2.42 主要是 tcache/safe-linking 适配；2.43 无 fastbin，也无这条 consolidate 输入，核心硬失效。 |
<!-- PRIMITIVE_REQUIREMENTS:END -->

<!-- CHUNK_SIZE_REQUIREMENTS:START -->
## Chunk size 要求

- 被重复引用的 chunk 必须是 fastbin 尺寸：`MINSIZE <= chunksize <= get_max_fast()`，同一条链上的请求必须映射到同一物理 size class。
- 还必须能发出一次会触发 `malloc_consolidate` 的 **large request**；x86-64 上要求其物理 `nb >= MIN_LARGE_SIZE (0x400)`。PoC 用 `malloc(0x400)`，物理尺寸为 `0x410`。
- 小块和触发大块是两种不同的必需尺寸能力；大申请不是随意的 guard。
<!-- CHUNK_SIZE_REQUIREMENTS:END -->

## 版本变化

- 2.26+ 需要处理 tcache。
- 2.32 的 safe-linking 不影响这个 PoC 的核心，它不伪造任意 fd。
- 2.43 fastbin 收发路径删除，无法保留 fastbin 中的第二份引用。

## 从源码看

`malloc_consolidate` 遍历 fastbins 并执行前后合并，而 fastbin chunk 平时保持 in-use 语义。本目录判断以 GNU glibc 对应 tag/提交为准：[glibc 2.42 malloc_consolidate](https://github.com/bminor/glibc/blob/glibc-2.42/malloc/malloc.c)、[2.43 fastbin 删除](https://sourceware.org/git/?p=glibc.git;a=commit;h=bf1015fb2d7e4057925481960626533f8571a2fb)。

版本号只代表上游基线；发行版可能回移检查。实战请按附件 Build ID 对照源码。

## PoC

- [`poc_2.23_2.25.c`](./poc_2.23_2.25.c)：验证 2.23–2.25 分支；成功判据见源码头部。
- [`poc_2.26_2.42.c`](./poc_2.26_2.42.c)：验证 2.26–2.42 分支；成功判据见源码头部。

PoC 为 x86-64 教学程序，故意包含 UAF、越界或 double free。快速验证：

```bash
# 在目录根运行；把版本和文件替换为要测的分支
./tools/run_in_docker.sh 2.39 fastbin_dup_consolidate/poc_2.26_2.42.c
```

迁移时保留堆排布和检查绕过，只把漏洞模拟替换为题目的 edit/UAF/overflow；固定地址和最终目标必须重算。

## 调试

通用断点和排查顺序见 [根目录调试顺序](../README.md#调试顺序)。
