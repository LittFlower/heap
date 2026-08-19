# House of Fun

## 结论

- 适用范围：**2.23～2.29；2.30 起原始的四指针 largebin 写法失效**。
- 原语/效果：早期 largebin 插入时会直接信任 fd/bk/fd_nextsize/bk_nextsize 这四个指针；本质上，House of Fun 只是早期 Large Bin Attack 的历史名称。
- 版本变化：2.30 增加了 nextsize 链的完整性检查，旧版 Fun 因此失效，应该切换到 2.30～2.41 期间可用的“更小 victim”largebin attack；2.42 连这种改进版打法也一并封堵了。

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

关键是 malloc.c 里 largebin 的排序插入逻辑，以及 2.30 和 2.42 各自新增的完整性检查。

源码里仍然能走到最终触发点，不代表旧的利用链还成立：投递方式（也就是怎么把伪造数据送到目标位置）、私有结构和控制流终点，都要按题目附件 libc/ld 的实际 Build ID 重新核对。

源码与背景：

- [glibc 2.29 `malloc.c`：旧 largebin 插入](https://github.com/bminor/glibc/blob/glibc-2.29/malloc/malloc.c)
- [glibc 2.30 `malloc.c`：现代较小 victim 分支](https://github.com/bminor/glibc/blob/glibc-2.30/malloc/malloc.c)
- [glibc 2.42 largebin nextsize 加固](https://sourceware.org/git/?p=glibc.git;a=commit;h=4cf2d869367e3813c6c8f662915dedb1f3830c53)
- [GNU glibc 当前开发分支](https://github.com/bminor/glibc/tree/master)
- [House of all 综述](https://roderickchan.github.io/zh-cn/2023-02-27-house-of-all-about-glibc-heap-exploitation/)
- [高版本 heap exploitation](https://roderickchan.github.io/zh-cn/2023-03-01-analysis-of-glibc-heap-exploitation-in-high-version/)

## PoC

- [`poc_2.23_2.29.c`](./poc_2.23_2.29.c)：可直接执行的旧版 largebin attack PoC。

这个 C 文件走的是真实堆管理器的代码路径；如果题目有专属的堆布局，直接参考 PoC 末尾的中文注释去迁移即可，但要注意不能把这里验证出的局部原语成功，当成脱离具体题目就能直接执行代码的 RCE。

## 迁移与调试

1. 先确认投递路径和最终触发点在目标程序的 Build ID 中都确实存在。
2. 把占位地址，以及 add/edit/free 的调用顺序，替换成题目实际提供的能力。
3. 在真正读取这些字段的消费函数处下断点，逐个字段核对 size、对齐、safe-linking 编码、FILE/link_map 私有结构布局是否符合预期。
