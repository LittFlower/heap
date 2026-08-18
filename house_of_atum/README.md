# House of Atum

## 结论

- 适用范围：**2.26～2.29；2.30 起原始 count/entry 错位链失效**。
- 原语/效果：重复 tcache free 与 fastbin→tcache stash 配合，让分配落到 victim-0x10 并修改原 chunk header。
- 版本变化：2.29 起重复 free 方案需绕 key，但纯 edit-after-free 子原语仍成立；**2.30** 的 malloc 快路径改以 `counts[tc_idx] > 0` 为准，原链依赖的 entries/counts 错位失效。

<!-- PRIMITIVE_REQUIREMENTS:START -->
## 原语要求与版本边界

| 项目 | 本手法要求 |
|---|---|
| 最小输入原语 / 信息 | tcache/fastbin UAF、重复 free，能形成 count=0 但 entry 非空 |
| 关键环境与不变量 | 2.29 需绕 key；依赖 malloc 只检查 `entries!=NULL` |
| 最终输出原语 | 分配到 victim-0x10 并改原 chunk header |
| 版本边界应如何理解 | 2.30 malloc 改查 `counts>0`，原 entry/count desync 的弱前置硬失效。若还能写 count，就转为 metadata poisoning，不能说 Atum 原链只需调偏移。 |
<!-- PRIMITIVE_REQUIREMENTS:END -->

## 从源码看

决定边界的不是 `tcache_get` 函数体，而是 `__libc_malloc` 调用它之前的条件：

```text
2.26～2.29: tcache->entries[tc_idx] != NULL
2.30 起:    tcache->counts[tc_idx] > 0
```

Atum 让 count 已经归零时 entries 仍指向伪节点；前一分支继续返回伪 chunk，后一分支直接跳过 tcache。参考综述同一节展示的源码注释也写明 `glibc >= 2.30`，故不能把文字中的“2.31 之后”当作准确 tag 边界。

源码中仍能走到最终触发点，不等于旧利用链仍成立：投递方式、私有结构和控制流终点都要按附件 libc/ld 的 Build ID 复核。

源码与背景：

- [GNU glibc 2.29 malloc.c](https://github.com/bminor/glibc/blob/glibc-2.29/malloc/malloc.c)
- [GNU glibc 2.30 malloc.c](https://github.com/bminor/glibc/blob/glibc-2.30/malloc/malloc.c)
- [House of Atum 原作者 / BCTF 2018 three 题解](https://changochen.github.io/2018-11-26-bctf-2018.html)
- [GNU glibc 当前开发分支](https://github.com/bminor/glibc/tree/master)
- [House of all 综述](https://roderickchan.github.io/zh-cn/2023-02-27-house-of-all-about-glibc-heap-exploitation/)
- [高版本 heap exploitation](https://roderickchan.github.io/zh-cn/2023-03-01-analysis-of-glibc-heap-exploitation-in-high-version/)

## PoC

- [`poc_entry_count_desync_2.26_2.29.c`](./poc_entry_count_desync_2.26_2.29.c)：可执行最小 PoC；只用一次 edit-after-free，真实取得 `a-0x10` 并修改原 size 字段。

BCTF 2018 原题从堆泄漏、unsorted 泄漏到 hook 终点的菜单级衔接，已改写为 C 文件末尾的中文伪代码；可执行主体仍只验证 Atum 的核心 entry/count 错位。

## 迁移与调试

1. 先确认投递路径和最终触发点在目标 Build ID 中都存在。
2. 把占位地址和 add/edit/free 顺序替换成题目能力。
3. 在消费函数下断点，逐字段核对 size、对齐、safe-linking、FILE/link_map 私有布局。

负测试：把 C PoC 原样放到 glibc 2.30，第二次 `malloc(0x30)` 会取得普通 chunk，`header_as_user == a-0x10` 断言按预期失败。
