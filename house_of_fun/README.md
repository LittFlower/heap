# House of Fun

## 结论

- 适用范围：**2.23～2.29；2.30 起原始四指针 largebin 写失效**。
- 原语/效果：旧 largebin 插入时信任 fd/bk/fd_nextsize/bk_nextsize；本质是早期 Large Bin Attack 的历史名称。
- 版本变化：2.30 增加 nextsize 链检查，旧 Fun 失效；应切换到 2.30～2.41 的“更小 victim”largebin attack；2.42 连后者也被封堵。

<!-- PRIMITIVE_REQUIREMENTS:START -->
## 原语要求与版本边界

| 项目 | 本手法要求 |
|---|---|
| 最小输入原语 / 信息 | 旧 largebin UAF 控制 `fd/bk/fd_nextsize/bk_nextsize` |
| 关键环境与不变量 | 2.23～2.29 旧插入逻辑 |
| 最终输出原语 | 多个 heap/libc 指针写 |
| 版本边界应如何理解 | 2.30 硬封旧四指针形式，但 2.30～2.41 可迁移到现代“更小 victim”Large Bin Attack；这是家族换实现。2.42 再封经典任意目标写。 |
<!-- PRIMITIVE_REQUIREMENTS:END -->

## 从源码看

malloc.c largebin sorted insertion 及 2.30/2.42 完整性检查。

源码中仍能走到最终触发点，不等于旧利用链仍成立：投递方式、私有结构和控制流终点都要按附件 libc/ld 的 Build ID 复核。

源码与背景：

- [glibc 2.29 `malloc.c`：旧 largebin 插入](https://github.com/bminor/glibc/blob/glibc-2.29/malloc/malloc.c)
- [glibc 2.30 `malloc.c`：现代较小 victim 分支](https://github.com/bminor/glibc/blob/glibc-2.30/malloc/malloc.c)
- [glibc 2.42 largebin nextsize 加固](https://sourceware.org/git/?p=glibc.git;a=commit;h=4cf2d869367e3813c6c8f662915dedb1f3830c53)
- [GNU glibc 当前开发分支](https://github.com/bminor/glibc/tree/master)
- [House of all 综述](https://roderickchan.github.io/zh-cn/2023-02-27-house-of-all-about-glibc-heap-exploitation/)
- [高版本 heap exploitation](https://roderickchan.github.io/zh-cn/2023-03-01-analysis-of-glibc-heap-exploitation-in-high-version/)

## PoC

- [`poc_2.23_2.29.c`](./poc_2.23_2.29.c)：旧 largebin attack 可执行 PoC

C 文件验证真实堆管理器路径；需要题目专属布局时，直接按 PoC 末尾的中文注释迁移，不能把局部原语成功当成脱离题目的 RCE。

## 迁移与调试

1. 先确认投递路径和最终触发点在目标 Build ID 中都存在。
2. 把占位地址和 add/edit/free 顺序替换成题目能力。
3. 在消费函数下断点，逐字段核对 size、对齐、safe-linking、FILE/link_map 私有布局。
