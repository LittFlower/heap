# House of Kauri

## 结论

**一句话**：能改已释放 chunk 的 size 再 free 一次，让它落到另一条 tcache bin，就有 House of Kauri；2.42 起这条路被彻底堵死。

- 适用范围：**glibc 2.26～2.41**。2.42 起 double free 校验扫描全部 tcache bin，"改 size 换 bin"失效；清 key、触发合并或直接篡改 metadata 属于其他 double free 手法，前置能力要求更强。
- 原语/效果：两条 tcache bin 先后分配出同一地址，形成重叠。
- 版本变化：2.29～2.41 的 key 校验只扫描新 size 对应的 tc_idx，改 size 就能绕过。2.32 的 safe-linking 只加密多节点链表，这里链上只有一个节点，不受影响。

<!-- PRIMITIVE_REQUIREMENTS:START -->
## 原语要求与版本边界

| 项目 | 本手法要求 |
|---|---|
| 最小输入原语 / 信息 | UAF 改已释放 chunk size，再次 free 同一物理块 |
| 关键环境与不变量 | 让第二次 free 落到另一 tcache bin；绕 key |
| 最终输出原语 | 两个 bin 返回同一地址/overlap |
| 版本边界应如何理解 | 2.42 double-free 验证扫描所有 tcache bins，硬封“改 size 换 bin”身份绕过。清 key 或合并再 free 是其他 dup 手法。 |
<!-- PRIMITIVE_REQUIREMENTS:END -->

<!-- CHUNK_SIZE_REQUIREMENTS:START -->
## Chunk size 要求

- 必须有**两个不同但都可进入 tcache 的对齐物理尺寸** `C1`、`C2`，并能把已释放 victim 的 size 从 `C1|flags` 改成 `C2|flags`；两次 malloc 分别请求这两个 class。
- PoC 使用 `malloc(0x18) -> chunksize 0x20` 和 `malloc(0x28) -> chunksize 0x30`，只改 size 低字节即可换 bin。差值不必固定为 `0x10`，但两者都必须落在有效 tcache 索引内且不能越过真实可访问边界。
<!-- CHUNK_SIZE_REQUIREMENTS:END -->

## 从源码看

对比 glibc 2.41 的 `tcache_double_free_verify(e, tc_idx)` 和 2.42 改成的全 bin 循环，就能看清这条绕过路径是怎么被堵上的。

最终触发点还在，不代表旧链成立：投递方式（怎么把伪造数据送到目标位置）、私有结构和控制流终点，都要按附件 libc/ld 的 Build ID 重新核对。

源码与背景：

- [glibc 2.41 `malloc.c`：只扫描当前 bin](https://github.com/bminor/glibc/blob/glibc-2.41/malloc/malloc.c)
- [glibc 2.42 全 bin double-free 扫描提交](https://sourceware.org/git/?p=glibc.git;a=commit;h=eff1f680cffb005a5623d1c8a952d095b988d6a2)
- [GNU glibc 当前开发分支](https://github.com/bminor/glibc/tree/master)
- [House of all 综述](https://roderickchan.github.io/zh-cn/2023-02-27-house-of-all-about-glibc-heap-exploitation/)
- [高版本 heap exploitation](https://roderickchan.github.io/zh-cn/2023-03-01-analysis-of-glibc-heap-exploitation-in-high-version/)

## PoC

- [`poc_2.26_2.41.c`](./poc_2.26_2.41.c)：用真实的 malloc/free 调用跑一遍完整流程的微型 PoC。

这个 C 文件走真实堆管理器的代码路径；题目有专属堆布局时，参考 PoC 末尾的中文注释迁移就行。注意：这里只是验证局部原语，成功不等于脱离题目就能直接 RCE。

## 迁移与调试

1. 先确认投递路径和最终触发点在目标程序的 Build ID 中都确实存在。
2. 把占位地址，以及 add/edit/free 的调用顺序，替换成题目实际提供的能力。
3. 在读取这些字段的消费函数处下断点，逐字段核对 size、对齐、safe-linking 编码、FILE/link_map 私有结构布局。
