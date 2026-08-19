# House of Atum

## 结论

- 适用范围：**2.26～2.29；2.30 起原始的 count/entry 错位链失效**。
- 原语/效果：靠重复 tcache free 配合 fastbin→tcache stash，让下一次分配落到 `victim-0x10`，也就是原 chunk 的 header 位置，从而改写它。
- 版本变化：2.29 起如果还想走重复 free 就需要绕过 key 检查，但单纯的 edit-after-free 子原语仍然成立；到了 **2.30**，malloc 快路径改成检查 `counts[tc_idx] > 0`，原链依赖的 entries/counts 错位彻底失效。

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

决定版本边界的不是 `tcache_get` 这个函数体本身，而是 `__libc_malloc` 在调用它之前做的判断：

```text
2.26～2.29: tcache->entries[tc_idx] != NULL
2.30 起:    tcache->counts[tc_idx] > 0
```

Atum 的核心思路是让 count 已经归零，但 entries 仍然指向一个伪造节点。旧分支只看 entries 是否非空，所以还会继续返回伪 chunk；新分支改成看 count，一旦为零就直接跳过 tcache，不会再消费 entries 里的值。参考综述同一节展示的源码注释也写明是 `glibc >= 2.30`，所以不能把文字里出现的“2.31 之后”当成精确的 tag 边界。

源码里仍然能走到这个最终触发点，不代表旧的利用链就还成立：投递方式、私有结构和控制流终点，都需要按附件 libc/ld 的 Build ID 重新核实。

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

1. 先确认投递路径和最终触发点在目标 Build ID 上都确实存在。
2. 把 PoC 里的占位地址和 add/edit/free 顺序，替换成题目实际给出的能力。
3. 在消费函数处下断点，逐字段核对 size、对齐、safe-linking，以及 FILE/link_map 等私有结构的布局。

负面测试：把这份 C PoC 原样放到 glibc 2.30 上跑，第二次 `malloc(0x30)` 会拿到一个普通 chunk，`header_as_user == a-0x10` 这条断言会按预期失败，这正好验证了版本边界的判断。
