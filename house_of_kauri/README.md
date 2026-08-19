# House of Kauri

## 结论

- 适用范围：**glibc 2.26～2.41**。从 2.42 开始，double free 校验会扫描全部 tcache bin，Kauri 这种“改 size 换 bin”的绕过方式被彻底堵死；如果还能清空 key、触发合并或直接篡改 metadata，可以换用其他 double free 手法达到类似效果，但那样需要更强的前置能力。
- 原语/效果：先改写一个已释放 chunk 的 size 字段，再把它 free 到另一条 tcache bin 里，这样两条 bin 会先后把同一个地址分配出去，形成重叠。
- 版本变化：2.29～2.41 期间，key 校验命中时只会扫描新 size 对应的那一个 tc_idx，所以改 size 能绕过检测；2.32 引入的 safe-linking 只处理多节点链表的加密，这里链上只有一个节点，不受影响；2.42 起改成遍历所有 TCACHE_MAX_BINS，这个绕过方式就失效了。

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

对比 glibc 2.41 的 `tcache_double_free_verify(e, tc_idx)` 和 2.42 改成的全 bin 循环，就能看清这条绕过路径具体是怎么被堵上的。

源码里仍然能走到最终触发点，不代表旧的利用链还成立：投递方式（也就是怎么把伪造数据送到目标位置）、私有结构和控制流终点，都要按题目附件 libc/ld 的实际 Build ID 重新核对。

源码与背景：

- [glibc 2.41 `malloc.c`：只扫描当前 bin](https://github.com/bminor/glibc/blob/glibc-2.41/malloc/malloc.c)
- [glibc 2.42 全 bin double-free 扫描提交](https://sourceware.org/git/?p=glibc.git;a=commit;h=eff1f680cffb005a5623d1c8a952d095b988d6a2)
- [GNU glibc 当前开发分支](https://github.com/bminor/glibc/tree/master)
- [House of all 综述](https://roderickchan.github.io/zh-cn/2023-02-27-house-of-all-about-glibc-heap-exploitation/)
- [高版本 heap exploitation](https://roderickchan.github.io/zh-cn/2023-03-01-analysis-of-glibc-heap-exploitation-in-high-version/)

## PoC

- [`poc_2.26_2.41.c`](./poc_2.26_2.41.c)：用真实的 malloc/free 调用跑一遍完整流程的微型 PoC。

这个 C 文件走的是真实堆管理器的代码路径；如果题目有专属的堆布局，直接参考 PoC 末尾的中文注释去迁移即可，但要注意不能把这里验证出的局部原语成功，当成脱离具体题目就能直接执行代码的 RCE。

## 迁移与调试

1. 先确认投递路径和最终触发点在目标程序的 Build ID 中都确实存在。
2. 把占位地址，以及 add/edit/free 的调用顺序，替换成题目实际提供的能力。
3. 在真正读取这些字段的消费函数处下断点，逐个字段核对 size、对齐、safe-linking 编码、FILE/link_map 私有结构布局是否符合预期。
