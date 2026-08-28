# Tcache Dup

## 结论

- 适用范围：**glibc 2.26～2.28；2.29 起直接 double free 失效**。
- 原语效果：同一 chunk 多次从 tcache 返回。
- 前置能力：能够对同一悬挂指针连续 free。

<!-- PRIMITIVE_REQUIREMENTS:START -->
## 原语要求与版本边界

| 项目 | 本手法要求 |
|---|---|
| 最小输入原语 / 信息 | 对同一指针连续 free，无中间 edit |
| 关键环境与不变量 | 2.26～2.28 tcache 无 key 扫描 |
| 最终输出原语 | 同一 chunk 重复返回 |
| 版本边界应如何理解 | 2.29 key+链扫描硬封住“只有连续 double free”这个最小模型。若能清 key、改 size 或合并再 free，可用 Botcake/Kauri 等绕法，但已经增加输入原语。 |
<!-- PRIMITIVE_REQUIREMENTS:END -->

<!-- CHUNK_SIZE_REQUIREMENTS:START -->
## Chunk size 要求

- double-free victim 与两次取回请求必须是**同一个已启用的 tcache class**；默认环境下选任意 small-tcache 物理尺寸即可。
- 没有固定唯一值；PoC 用 `malloc(8) -> chunksize 0x20`。若换 class，所有 free/malloc 与对应 `tc_idx` 必须同步，且不能让 chunk 先落到非 tcache 路径。
<!-- CHUNK_SIZE_REQUIREMENTS:END -->

## 版本变化

- 2.26 初版 tcache 没有 double-free key。
- 2.29 提交 `bcdaad2` 给 `tcache_entry` 增加 key，疑似重复释放时还会遍历这个 bin。

## 从源码看

`tcache_put` 写 `e->key`；`_int_free` 比较 key 后遍历链表。本目录判断以 GNU glibc 对应 tag/提交为准：[tcache 引入](https://sourceware.org/git/?p=glibc.git;a=commit;h=d5c3fafc4307c9b7a4c7d5cb381fcdbfad340bcc)、[double-free 检查](https://sourceware.org/git/?p=glibc.git;a=commit;h=bcdaad21d4635931d1bd3b54a7894276925d081d)。

版本号只代表上游基线；发行版可能回移检查。实战请按附件 Build ID 对照源码。

## PoC

- [`poc_2.26_2.28.c`](./poc_2.26_2.28.c)：验证 2.26–2.28 分支；成功判据见源码头部。

PoC 为 x86-64 教学程序，故意包含 UAF、越界或 double free。快速验证：

```bash
# 在目录根运行；把版本和文件替换为要测的分支
./tools/run_in_docker.sh 2.39 tcache_dup/poc_2.26_2.28.c
```

迁移时保留堆排布和检查绕过，只把漏洞模拟替换为题目的 edit/UAF/overflow；固定地址和最终目标必须重算。

## 调试

通用断点和排查顺序见 [根目录调试顺序](../README.md#调试顺序)。
