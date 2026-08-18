# House of Corrosion

## 结论

- 适用范围：**原始完整链针对特定 Ubuntu glibc 2.27；原作者 Addendum A 另给特定 Ubuntu glibc 2.29 链**。超大尺寸 fastbin 越界索引带来的相对写与指针搬运，结构性窗口最迟止于 2.36；2.32～2.36 还须处理 safe-linking；2.37 已硬失效。
- 原语/效果：放大 global_max_fast，把 main_arena.fastbinsY 当作 libc 内的相对读写/数据搬运数组。
- 版本变化：2.28 同时加固 unsorted removal 并删除旧 `_IO_strfile` 回调，原版 2.27 链结束；2.29 的补充方案改用 tcache 与命名空间/vtable 绕过；2.32 的 safe-linking 要求对搬运中的 `fd` 编码，因此需知道堆页地址；2.37 将 `global_max_fast` 缩为 `uint8_t`，远端 fastbin 指针搬运结束。2.43 删除 fastbin 是更晚的变化，不应误标为首个边界。

<!-- PRIMITIVE_REQUIREMENTS:START -->
## 原语要求与版本边界

| 项目 | 本手法要求 |
|---|---|
| 最小输入原语 / 信息 | 能写大 `global_max_fast`；fastbin UAF/double free；libc 地址泄露/相对布局 |
| 关键环境与不变量 | 目标必须落在可由超大尺寸 fastbin 越界索引覆盖的 libc/ld 区域；与 Build ID 强相关 |
| 最终输出原语 | 在 libc 内按相对偏移写入堆指针，以及“源槽→可编辑中转区→目标槽”的指针搬运 |
| 版本边界应如何理解 | 2.32 的 safe-linking 只是额外适配；2.37 将 `global_max_fast` 缩为 `uint8_t`，无法再用远端 fastbin 索引越过 `main_arena`，核心投递就此失效。2.27/2.29 完整链仍只对作者的构建负责。 |
<!-- PRIMITIVE_REQUIREMENTS:END -->

## 从源码看

### 共同堆管理器原语

在 x86-64 上：

```c
fastbin_index(size) = (size >> 4) - 2;
target - &fastbinsY[0] = fastbin_index(size) * 8;
size = 2 * (target - &fastbinsY[0]) + 0x20;
```

当攻击者把 `global_max_fast` 放大到足够大时，free 一个具有上述伪 size 的 victim，会让 `fastbinsY[index]` 这个“数组槽”落在任意后续 libc/ld 地址。WAF 再反复改 victim size，就能把某个槽的旧值带入 `victim->fd`、搬到另一槽。

2.32 起只有 fastbin 头槽仍保存原始 chunk 指针，chunk 内 `fd` 变成 `raw ^ (&fd >> 12)`；因此 2.27/2.29 直接搬运明文指针的写法不能原样延长。2.37 起 `global_max_fast` 是 `uint8_t`，最大 0xff；代回公式只够覆盖 `fastbinsY` 后约 0x6f 字节，无法再到达 stderr、rtld 或一般 libc 目标。这是原语的真正硬终点。

### 两条已发布完整链

- **2.27 原版**：原文固定 Ubuntu 18.04 Build ID `b417c0ba7cc5cf06d1d1bed6652cedb9253c60d0`。用 unsortedbin attack 放大 `global_max_fast`，搬运 stderr 字段，最后利用 2.27 仍会消费的 `_IO_strfile._allocate_buffer` 回调和构建相关 one_gadget。
- **2.29 Addendum A**：固定 Ubuntu 19.04 Build ID `d561ec515222887a1e004555981169199d841024`。用 WAF tcache poison 取代 unsorted 写；搬运 `_rtld_global/link_map` 字段制造非默认命名空间，绕过 `_IO_vtable_check` 后使用 heap fake vtable。原作者还明确说明该 Ubuntu 构建的 IO vtable 段权限存在异常，不能外推。

“原语可改造”不等于“完整链跨版本”：2.30/2.31 需要重做投递和最终 gadget，2.32～2.36 又必须解决 safe-linking；本项目没有找到作者发布的这些版本端到端链，所以不再把 2.29～2.33 标成统一可用。

源码中仍能走到最终触发点，不等于旧利用链仍成立：投递方式、私有结构和控制流终点都要按附件 libc/ld 的 Build ID 复核。

源码与背景：

- [House of Corrosion 原始仓库](https://github.com/CptGibbon/House-of-Corrosion)
- [ptr-yudai 的 2.27 sample challenge/exploit](https://github.com/ptr-yudai/House-of-Corrosion)
- [glibc 2.36 `malloc.c`：fastbinsY/global_max_fast](https://github.com/bminor/glibc/blob/glibc-2.36/malloc/malloc.c)
- [glibc 2.37：`global_max_fast` 改为 `uint8_t`](https://sourceware.org/git/?p=glibc.git;a=commit;h=15a94e6668a6d7c5697e805d8d67f1d102d0d52e)
- [glibc 2.43：删除 fastbin 基础设施](https://sourceware.org/git/?p=glibc.git;a=commit;h=bf1015fb2d7e4057925481960626533f8571a2fb)
- [GNU glibc 当前开发分支](https://github.com/bminor/glibc/tree/master)
- [House of all 综述](https://roderickchan.github.io/zh-cn/2023-02-27-house-of-all-about-glibc-heap-exploitation/)
- [高版本 heap exploitation](https://roderickchan.github.io/zh-cn/2023-03-01-analysis-of-glibc-heap-exploitation-in-high-version/)

## PoC

- [`poc_fastbin_pointer_move_2.27_2.36.c`](./poc_fastbin_pointer_move_2.27_2.36.c)：一个线性 `main` 同时演示 2.27～2.31 的明文 fd 和 2.32～2.36 的 safe-linking 搬运；严格断言 size 反算和“源槽→中转区→目标槽”。

原版 2.27、Addendum 2.29 的完整阶段清单和 2.37 硬边界已放在该 C 文件末尾的中文伪代码中。它保留构建专属条件，但不冒充通用端到端 RCE。

## 迁移与调试

1. 先确认投递路径和最终触发点在目标 Build ID 中都存在。
2. 把占位地址和 add/edit/free 顺序替换成题目能力。
3. 在消费函数下断点，逐字段核对 size、对齐、safe-linking、FILE/link_map 私有布局。
