# House of Kauri

## 结论

- 适用范围：**2.26～2.41；2.42 全 bin 扫描硬封“改 size 换 tcache bin”的 Kauri 绕过**。若还能清 key、合并或直接改 metadata，可用其他 dup 手法取得相似输出，但已增加前置能力。
- 原语/效果：修改已释放 chunk 的 size，再 free 到另一条 tcache bin，使两个 bin 同时返回同一地址。
- 版本变化：2.29～2.41 key 命中时只扫描当前 tc_idx，改 size 可绕过；2.32 safe-linking 不影响单节点链；2.42 改为扫描全部 TCACHE_MAX_BINS。

<!-- PRIMITIVE_REQUIREMENTS:START -->
## 原语要求与版本边界

| 项目 | 本手法要求 |
|---|---|
| 最小输入原语 / 信息 | UAF 改已释放 chunk size，再次 free 同一物理块 |
| 关键环境与不变量 | 让第二次 free 落到另一 tcache bin；绕 key |
| 最终输出原语 | 两个 bin 返回同一地址/overlap |
| 版本边界应如何理解 | 2.42 double-free 验证扫描所有 tcache bins，硬封“改 size 换 bin”身份绕过。清 key 或合并再 free 是其他 dup 手法。 |
<!-- PRIMITIVE_REQUIREMENTS:END -->

## 从源码看

对比 glibc-2.41 tcache_double_free_verify(e, tc_idx) 与 2.42 的全 bin 循环。

源码中仍能走到最终触发点，不等于旧利用链仍成立：投递方式、私有结构和控制流终点都要按附件 libc/ld 的 Build ID 复核。

源码与背景：

- [glibc 2.41 `malloc.c`：只扫描当前 bin](https://github.com/bminor/glibc/blob/glibc-2.41/malloc/malloc.c)
- [glibc 2.42 全 bin double-free 扫描提交](https://sourceware.org/git/?p=glibc.git;a=commit;h=eff1f680cffb005a5623d1c8a952d095b988d6a2)
- [GNU glibc 当前开发分支](https://github.com/bminor/glibc/tree/master)
- [House of all 综述](https://roderickchan.github.io/zh-cn/2023-02-27-house-of-all-about-glibc-heap-exploitation/)
- [高版本 heap exploitation](https://roderickchan.github.io/zh-cn/2023-03-01-analysis-of-glibc-heap-exploitation-in-high-version/)

## PoC

- [`poc_2.26_2.41.c`](./poc_2.26_2.41.c)：真实 malloc/free 微型 PoC

C 文件验证真实堆管理器路径；需要题目专属布局时，直接按 PoC 末尾的中文注释迁移，不能把局部原语成功当成脱离题目的 RCE。

## 迁移与调试

1. 先确认投递路径和最终触发点在目标 Build ID 中都存在。
2. 把占位地址和 add/edit/free 顺序替换成题目能力。
3. 在消费函数下断点，逐字段核对 size、对齐、safe-linking、FILE/link_map 私有布局。
