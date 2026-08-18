# House of Rabbit

## 结论

- 适用范围：**2.23～2.26；2.27 起经典跨尺寸链失效**。
- 原语/效果：fastbin 中的小 victim 指向大 fake chunk，再由 malloc_consolidate 把 fake chunk 转入 unsorted/largebin。
- 版本变化：2.26 引入 tcache，须先填满；2.27 在 malloc_consolidate 增加 fastbin_index(chunksize(p)) 一致性检查；2.43 删除 fastbin。

<!-- PRIMITIVE_REQUIREMENTS:START -->
## 原语要求与版本边界

| 项目 | 本手法要求 |
|---|---|
| 最小输入原语 / 信息 | fastbin UAF 把小 victim 指向大 fake chunk，可触发 consolidate |
| 关键环境与不变量 | 跨 size fastbin 链在 consolidate 时不被 index/size 拒绝 |
| 最终输出原语 | 把大 fake chunk 转入 unsorted/largebin，取得大范围 overlap |
| 版本边界应如何理解 | 2.27 fastbin size/index 一致性检查硬封经典跨尺寸链。改用真实同尺寸节点再造 overlap 是另一实现，不能只改偏移。 |
<!-- PRIMITIVE_REQUIREMENTS:END -->

## 从源码看

malloc/malloc.c 的 malloc_consolidate，对比 glibc-2.26 与 glibc-2.27。

源码中仍能走到最终触发点，不等于旧利用链仍成立：投递方式、私有结构和控制流终点都要按附件 libc/ld 的 Build ID 复核。

源码与背景：

- [glibc 2.26 `malloc_consolidate`](https://github.com/bminor/glibc/blob/glibc-2.26/malloc/malloc.c)
- [glibc 2.27 `malloc_consolidate`](https://github.com/bminor/glibc/blob/glibc-2.27/malloc/malloc.c)
- [GNU glibc 当前开发分支](https://github.com/bminor/glibc/tree/master)
- [House of all 综述](https://roderickchan.github.io/zh-cn/2023-02-27-house-of-all-about-glibc-heap-exploitation/)
- [高版本 heap exploitation](https://roderickchan.github.io/zh-cn/2023-03-01-analysis-of-glibc-heap-exploitation-in-high-version/)

## PoC

- [`poc_2.23_2.25.c`](./poc_2.23_2.25.c)：无 tcache
- [`poc_2.26.c`](./poc_2.26.c)：填满 tcache

C 文件验证真实堆管理器路径；需要题目专属布局时，直接按 PoC 末尾的中文注释迁移，不能把局部原语成功当成脱离题目的 RCE。

## 迁移与调试

1. 先确认投递路径和最终触发点在目标 Build ID 中都存在。
2. 把占位地址和 add/edit/free 顺序替换成题目能力。
3. 在消费函数下断点，逐字段核对 size、对齐、safe-linking、FILE/link_map 私有布局。
