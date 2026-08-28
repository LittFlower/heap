# House of Spirit

## 结论

- 适用范围：**glibc 整体 2.23～2.43；fastbin 子型止于 2.42，tcache 子型始于 2.26**。
- 原语效果：free 非堆 fake chunk 后，让 malloc 返回栈/全局区地址。
- 前置能力：能控制待 free 指针与 fake size；x86-64 目标 0x10 对齐。

<!-- PRIMITIVE_REQUIREMENTS:START -->
## 原语要求与版本边界

| 项目 | 本手法要求 |
|---|---|
| 最小输入原语 / 信息 | 控制被 free 的非 heap 指针及 fake size |
| 关键环境与不变量 | 目标 0x10 对齐；fastbin 版需邻接 size/处理 tcache；tcache 版检查更少 |
| 最终输出原语 | malloc 返回栈/全局 fake chunk/AAF |
| 版本边界应如何理解 | fastbin 子型 2.43 随 fastbin 硬删除；tcache 子型 2.26～2.43 持续。因此“Spirit 整体失效”是错误说法。 |
<!-- PRIMITIVE_REQUIREMENTS:END -->

<!-- CHUNK_SIZE_REQUIREMENTS:START -->
## Chunk size 要求

- **fastbin 子型：** fake `size` 与最终请求必须精确对应某个 `[MINSIZE, get_max_fast()]` 的 fastbin class；还要在 fake chunk 后准备通过检查的 next-size。PoC 选最小物理 `0x20`。
- **tcache 子型：** fake `size` 必须对应已启用的 tcache class，最终请求使用同一 `tc_idx`；不限于 fastbin 范围。默认环境通常选 small-tcache class，PoC 同样使用物理 `0x20`。
<!-- CHUNK_SIZE_REQUIREMENTS:END -->

## 版本变化

- 2.23～2.25 用 fastbin fake chunk，再准备一个合法的 next-size。
- 2.26+ 可以用检查更少的 tcache spirit；fastbin 版得先填满 tcache。
- 2.41 fastbin 版取出来之前得先耗尽 tcache；2.43 fastbin 版没了，但 tcache 版还能用。

## 从源码看

`_int_free_check`、tcache fast path 和 fastbin next-size 检查。本目录判断以 GNU glibc 对应 tag/提交为准：[2.42 malloc.c](https://github.com/bminor/glibc/blob/glibc-2.42/malloc/malloc.c)、[2.43 fastbin 删除](https://sourceware.org/git/?p=glibc.git;a=commit;h=bf1015fb2d7e4057925481960626533f8571a2fb)。

版本号只代表上游基线；发行版可能回移检查。实战按附件 Build ID 对照源码。

## PoC

- [`poc_fastbin_2.23_2.25.c`](./poc_fastbin_2.23_2.25.c)：验证 fastbin–2.23–2.25 分支；成功判据见源码头部。
- [`poc_fastbin_2.26_2.40.c`](./poc_fastbin_2.26_2.40.c)：验证 fastbin–2.26–2.40 分支；成功判据见源码头部。
- [`poc_fastbin_2.41_2.42.c`](./poc_fastbin_2.41_2.42.c)：验证 fastbin–2.41–2.42 分支；成功判据见源码头部。
- [`poc_tcache_2.26_2.43.c`](./poc_tcache_2.26_2.43.c)：验证 tcache–2.26–2.43 分支；成功判据见源码头部。

PoC 为 x86-64 教学程序，故意包含 UAF、越界或 double free。快速验证：

```bash
# 在目录根运行；把版本和文件替换为要测的分支
./tools/run_in_docker.sh 2.39 house_of_spirit/poc_tcache_2.26_2.43.c
```

迁移时保留堆排布和检查绕过，只把漏洞模拟换成题目的 edit/UAF/overflow；固定地址和最终目标得重算。

## 调试

通用断点和排查顺序见 [根目录调试顺序](../README.md#调试顺序)。
