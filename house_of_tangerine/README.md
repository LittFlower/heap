# House of Tangerine

## 结论

- 适用范围：**glibc 2.26～2.43**。
- 原语效果：利用受损 top/sysmalloc 产生 tcache chunk，再 poisoning 到任意地址。
- 前置能力：覆盖 top 元数据、可反复申请大块；2.32+ 需要堆地址泄露来编码 `next`。

<!-- PRIMITIVE_REQUIREMENTS:START -->
## 原语要求与版本边界

| 项目 | 本手法要求 |
|---|---|
| 最小输入原语 / 信息 | 覆盖 top 元数据并反复申请大块；具备 tcache UAF/poison 能力 |
| 关键环境与不变量 | 利用 sysmalloc 让 old top 进入 tcache；2.32+ 需堆地址泄露来编码；2.43 按新布局适配 |
| 最终输出原语 | 从 top 制造 tcache chunk，再取得 AAF |
| 版本边界应如何理解 | 2.29 封堵 House of Force，但没有封堵合法缩小 top；2.43 删除 fastbin 也不影响 top+tcache 核心。各版本只需实现适配。 |
<!-- PRIMITIVE_REQUIREMENTS:END -->

## 版本变化

- 2.26～2.30 是明文 tcache 链。
- 2.31 的 sysmalloc/top 排布有独立调整。
- 2.32～2.41 使用 safe-linking。
- 2.42 大 tcache 和 top/tcache 初始化重构需要独立 PoC。
- 2.43 虽删除 fastbin，但本手法以 top+tcache 为核心，调整后仍可用。

## 从源码看

`sysmalloc` 的 fencepost/旧 top 处理与 tcache_put/get。本目录判断以 GNU glibc 对应 tag/提交为准：[2.43 malloc.c](https://github.com/bminor/glibc/blob/master/malloc/malloc.c)、[2.42 tcache large bins](https://sourceware.org/git/?p=glibc.git;a=commit;h=cbfd7988107b27b9ff1d0b57fa2c8f13a932e508)。

版本号只代表上游基线；发行版可能回移检查。实战请按附件 Build ID 对照源码。

## PoC

- [`poc_2.26_2.30.c`](./poc_2.26_2.30.c)：验证 2.26–2.30 分支；成功判据见源码头部。
- [`poc_2.31.c`](./poc_2.31.c)：验证 2.31 分支；成功判据见源码头部。
- [`poc_2.32_2.41.c`](./poc_2.32_2.41.c)：验证 2.32–2.41 分支；成功判据见源码头部。
- [`poc_2.42.c`](./poc_2.42.c)：验证 2.42 分支；成功判据见源码头部。
- [`poc_2.43.c`](./poc_2.43.c)：验证 2.43 分支；成功判据见源码头部。

PoC 为 x86-64 教学程序，故意包含 UAF、越界或 double free。快速验证：

```bash
# 在目录根运行；把版本和文件替换为要测的分支
./tools/run_in_docker.sh 2.39 house_of_tangerine/poc_2.43.c
```

迁移时保留堆排布和检查绕过，只把漏洞模拟替换为题目的 edit/UAF/overflow；固定地址和最终目标必须重算。

## 调试

通用断点和排查顺序见 [根目录调试顺序](../README.md#调试顺序)。
