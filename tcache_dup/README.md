# Tcache Dup

## 结论

- 适用范围：**glibc 2.26～2.28；从 2.29 开始，直接连续两次 free 就会失效**。
- 原语效果：让同一个 chunk 被 tcache 重复分配出来，两个指针最终指向同一块内存。
- 前置能力：能对同一个悬空指针连续调用两次 free，中间不需要做任何 edit。

<!-- PRIMITIVE_REQUIREMENTS:START -->
## 原语要求与版本边界

| 项目 | 本手法要求 |
|---|---|
| 最小输入原语 / 信息 | 对同一指针连续 free，无中间 edit |
| 关键环境与不变量 | 2.26～2.28 tcache 无 key 扫描 |
| 最终输出原语 | 同一 chunk 重复返回 |
| 版本边界应如何理解 | 2.29 key+链扫描硬封住“只有连续 double free”这个最小模型。若能清 key、改 size 或合并再 free，可用 Botcake/Kauri 等绕法，但已经增加输入原语。 |
<!-- PRIMITIVE_REQUIREMENTS:END -->

## 版本变化

- 2.26 引入的初版 tcache 还没有 double-free key。
- 2.29 的提交 `bcdaad2` 给 `tcache_entry` 加上了 key 字段，free 时如果怀疑是重复释放，就会遍历对应的 bin 检查。

## 从源码看

`tcache_put` 会写入 `e->key`，`_int_free` 释放前先比较这个 key，再遍历链表确认是否重复。本目录的版本结论以 GNU glibc 对应 tag/提交为准，参考：[tcache 引入](https://sourceware.org/git/?p=glibc.git;a=commit;h=d5c3fafc4307c9b7a4c7d5cb381fcdbfad340bcc)、[double-free 检查](https://sourceware.org/git/?p=glibc.git;a=commit;h=bcdaad21d4635931d1bd3b54a7894276925d081d)。

版本号只代表上游基线；发行版可能回移检查，实战时请按附件的 Build ID 对照源码确认。

## PoC

- [`poc_2.26_2.28.c`](./poc_2.26_2.28.c)：验证 2.26–2.28 分支，成功判据见源码头部。

下面的 PoC 都是 x86-64 教学程序，其中的 UAF、越界或 double free 都是特意模拟出来的漏洞行为。快速验证：

```bash
# 在目录根运行；把版本和文件替换为要测的分支
./tools/run_in_docker.sh 2.39 tcache_dup/poc_2.26_2.28.c
```

迁移到具体题目时，堆排布和检查绕过的思路不用改，只需要把漏洞模拟部分换成题目实际提供的 edit/UAF/overflow 原语；写死的地址和最终目标都要按题目重新计算。

## 调试

通用的断点位置和排查顺序见[根目录调试顺序](../README.md#调试顺序)。
