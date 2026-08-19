# House of Tangerine

## 结论

- 适用范围：**glibc 2.26～2.43**。
- 原语效果：利用被破坏的 top chunk 元数据，借 sysmalloc 把旧 top 间接送进 tcache，再通过 tcache poisoning 拿到一次任意地址分配。
- 前置能力：能够覆盖 top 的元数据，并且可以反复申请较大的 chunk；glibc 2.32 起还需要一次堆地址泄露，用来给 `next` 字段编码。

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

- 2.26～2.30：tcache 的 `next` 字段还是明文，拿到 `vuln_tcache` 地址后可以直接写入目标地址。
- 2.31：sysmalloc 和 top 的排布相比之前的分支有独立调整，但 `next` 依然是明文。
- 2.32～2.41：`next` 字段改成了 safe-linking 编码，需要先拿到一次堆地址泄露才能算出正确的密文。
- 2.42：大 tcache 和 top/tcache 初始化逻辑发生了重构，需要单独一份 PoC 来适配新增的搬运路径和目标地址校验。
- 2.43：fastbin 被彻底删除了，但本手法本身就以 top+tcache 为核心，稍作适配之后依然可用。

## 从源码看

本手法的关键在于 `sysmalloc` 处理 fencepost 和旧 top 的那段逻辑，以及 `tcache_put`/`tcache_get` 的实现。本目录的版本结论以 GNU glibc 对应 tag/提交为准，参考：[2.43 malloc.c](https://github.com/bminor/glibc/blob/master/malloc/malloc.c)、[2.42 tcache large bins 提交](https://sourceware.org/git/?p=glibc.git;a=commit;h=cbfd7988107b27b9ff1d0b57fa2c8f13a932e508)。

版本号只代表上游基线；发行版可能会回移某些检查，实战时请按附件的 Build ID 对照源码确认。

## PoC

- [`poc_2.26_2.30.c`](./poc_2.26_2.30.c)：验证 2.26–2.30 分支；成功判据见源码头部。
- [`poc_2.31.c`](./poc_2.31.c)：验证 2.31 分支；成功判据见源码头部。
- [`poc_2.32_2.41.c`](./poc_2.32_2.41.c)：验证 2.32–2.41 分支；成功判据见源码头部。
- [`poc_2.42.c`](./poc_2.42.c)：验证 2.42 分支；成功判据见源码头部。
- [`poc_2.43.c`](./poc_2.43.c)：验证 2.43 分支；成功判据见源码头部。

下面的 PoC 都是 x86-64 教学程序，其中故意包含的 UAF、越界或 double free 都是模拟出来的漏洞行为。快速验证：

```bash
# 在目录根运行；把版本和文件替换为要测的分支
./tools/run_in_docker.sh 2.39 house_of_tangerine/poc_2.43.c
```

迁移到具体题目时，堆排布和检查绕过的思路不用改，只需要把漏洞模拟部分换成题目实际提供的 edit/UAF/overflow 原语；写死的地址和最终目标都要按题目重新计算。

## 调试

通用的断点位置和排查顺序见[根目录调试顺序](../README.md#调试顺序)。
