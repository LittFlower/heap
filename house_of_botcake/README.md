# House of Botcake

## 结论

- 适用范围：**glibc 2.26～2.43**。
- 原语效果：绕开 tcache 的 double-free 检测，制造一个可以反复利用的 chunk overlap，进而做 tcache poisoning。
- 前置能力：一次 UAF；大约 8～10 个同尺寸 chunk；能让 victim 和它的前一个 chunk 在 unsorted bin 里合并。

<!-- PRIMITIVE_REQUIREMENTS:START -->
## 原语要求与版本边界

| 项目 | 本手法要求 |
|---|---|
| 最小输入原语 / 信息 | tcache UAF；能让 victim 与前块在 unsorted 合并 |
| 关键环境与不变量 | 足够同尺寸块；绕 key；按 2.43 的 16-slot 重排 |
| 最终输出原语 | overlap、重复引用，继续做 tcache poisoning |
| 版本边界应如何理解 | 2.26～2.43 是堆排布适配；key/full-bin 扫描没有删除“合并后再次 free 同一物理块”这条身份变化。 |
<!-- PRIMITIVE_REQUIREMENTS:END -->

## 版本变化

- 2.26～2.31：tcache 的 next 字段是明文。
- 2.32 起：覆盖 `victim->next` 时必须按 safe-linking 编码。
- 2.34：tcache key 改成了随机值，但这不影响本手法，因为第二次 free 之前，victim 已经随着合并离开了原来的 tcache 语义。
- 2.42/2.43：tcache 元数据变了，但仍有对应的 PoC。

## 从源码看

tcache 的 key 检查只会搜索当前这一个 bin；而 unsorted bin 的向前合并会改变覆盖范围，这就是本手法能绕过检查的关键。本目录的版本结论以 GNU glibc 对应 tag/提交为准，参考：[2.43 malloc.c](https://github.com/bminor/glibc/blob/master/malloc/malloc.c)、[2.29 tcache double-free 检查](https://sourceware.org/git/?p=glibc.git;a=commit;h=bcdaad21d4635931d1bd3b54a7894276925d081d)。

版本号只代表上游基线；发行版可能回移检查，实战时请按附件的 Build ID 对照源码确认。

## PoC

- [`poc_2.26_2.31.c`](./poc_2.26_2.31.c)：验证 2.26–2.31 分支，成功判据见源码头部。
- [`poc_2.32_2.42.c`](./poc_2.32_2.42.c)：验证 2.32–2.42 分支，成功判据见源码头部。
- [`poc_2.43.c`](./poc_2.43.c)：验证 2.43 分支，成功判据见源码头部。

下面的 PoC 都是 x86-64 教学程序，其中的 UAF、越界或 double free 都是特意模拟出来的漏洞行为。快速验证：

```bash
# 在目录根运行；把版本和文件替换为要测的分支
./tools/run_in_docker.sh 2.39 house_of_botcake/poc_2.43.c
```

迁移到具体题目时，堆排布和检查绕过的思路不用改，只需要把漏洞模拟部分换成题目实际提供的 edit/UAF/overflow 原语；写死的地址和最终目标都要按题目重新计算。

## 调试

通用的断点位置和排查顺序见[根目录调试顺序](../README.md#调试顺序)。
