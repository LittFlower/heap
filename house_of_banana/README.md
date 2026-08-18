# House of Banana

## 结论

- 适用范围：**`exit→_dl_fini→DT_FINI_ARRAY` 最终触发点为 2.23～2.43；Ha1vk 原始公开 exploit 针对 glibc 2.30**。经典 largebin 可作为 2.30～2.41 常见投递，2.42～2.43 必须另有任意写/overlap。
- 原语/效果：改写 rtld 命名空间/link_map，在 exit→_dl_fini 中消费伪 DT_FINI/DT_FINI_ARRAY。
- 版本变化：2.42 不能再用经典 largebin 写任意目标；2.43 的 `_dl_fini` 把具体调用拆到 `_dl_call_fini`，消费语义仍在。`link_map` 是 ld.so 私有 ABI，同一 glibc 版本不同构建也必须重新量偏移。

<!-- PRIMITIVE_REQUIREMENTS:START -->
## 原语要求与版本边界

| 项目 | 本手法要求 |
|---|---|
| 最小输入原语 / 信息 | 能改 rtld 命名空间/`link_map` 指针并布置 fake map；libc/ld leak |
| 关键环境与不变量 | 私有 `link_map` 布局、`l_real/l_init_called`、DT_FINI_ARRAY/SZ；exit |
| 最终输出原语 | `_dl_fini` 调受控 fini array，获得 CF |
| 版本边界应如何理解 | 最终触发点持续到 2.43，但强依赖 Build ID；经典 largebin 投递止于 2.41。2.42+ 若另有 AAW 仍可用 Banana，这是投递断裂而非思想硬封。 |
<!-- PRIMITIVE_REQUIREMENTS:END -->

## 从源码看

`elf/dl-fini.c` 先按命名空间的 `_ns_loaded` 链枚举对象，要求计数与 `_ns_nloaded` 一致，并只把 `l == l_real` 的节点收入 `maps[]`。排序完成后，它只消费 `l_init_called` 为真的节点；2.43 把下面逻辑移到 `elf/dl-call_fini.c`，关键数据流没有改变：

```c
array = (ElfW(Addr) *)
  (map->l_addr + map->l_info[DT_FINI_ARRAY]->d_un.d_ptr);
size_t count =
  map->l_info[DT_FINI_ARRAYSZ]->d_un.d_val / sizeof (ElfW(Addr));
while (count-- > 0)
  ((fini_t) array[count]) ();
```

因此 fake map 至少不能漏掉以下条件：

1. `l_next` 使遍历后的有效节点数仍等于 `_ns_nloaded`；
2. `l_real == fake_map`；
3. 目标 Build ID 对应的 `l_init_called` bit 为 1；
4. `l_info[26]` 和 `l_info[28]` 分别指向真实 `Elf64_Dyn`，后者的 `d_val` 至少为 8；
5. `_dl_sort_maps` 会读写的 `l_idx`、open count、依赖字段和 fake map 内存均可接受。

旧模板只设置 `l_info[26]`、没有设置随后必解引用的 `l_info[28]`，并漏掉 `l_real` 与 `l_init_called`，已删除。新版生成器要求显式传入所有私有偏移。

###最终触发点、布局与投递三层

- [`poc_fini_array_sink_2.23_2.43.c`](./poc_fini_array_sink_2.23_2.43.c) 不猜私有偏移：它在线性 `main` 中修改主程序真实 link_map 对应的两项 `Elf64_Dyn`，再直接进入 `exit→_dl_fini`。受控回调用 `_exit(0)`；未命中则保留 `exit(113)` 的失败状态。它已在 2.23、精确 2.30、2.43 通过。
- 同一 C 文件末尾列出 fake `link_map` 的 `l_real/l_next/l_info[26]/l_info[28]/Elf64_Dyn/fini_array` 伪代码；私有 bitfield 偏移仍必须来自附件 ld.so。
- 原文 glibc 2.30 用 largebin attack 投递堆地址。2.30～2.41 可按各自 largebin 分支适配；2.42 的 nextsize 完整性检查封住这条公开投递，但不会删除加载器最终触发点。

源码中仍能走到最终触发点，不等于旧利用链仍成立：投递方式、私有结构和控制流终点都要按附件 libc/ld 的 Build ID 复核。

源码与背景：

- [glibc 2.43 `elf/dl-fini.c`](https://sourceware.org/cgit/glibc/tree/elf/dl-fini.c?h=release/2.43/master)
- [glibc 2.43 `elf/dl-call_fini.c`](https://sourceware.org/cgit/glibc/tree/elf/dl-call_fini.c?h=release/2.43/master)
- [glibc 2.43 私有 `link_map` 扩展](https://sourceware.org/cgit/glibc/tree/include/link.h?h=release/2.43/master)
- [glibc 2.41 `malloc.c`：末代经典 largebin 投递](https://github.com/bminor/glibc/blob/glibc-2.41/malloc/malloc.c)
- [GNU glibc 当前开发分支](https://github.com/bminor/glibc/tree/master)
- [House of all 综述](https://roderickchan.github.io/zh-cn/2023-02-27-house-of-all-about-glibc-heap-exploitation/)
- [高版本 heap exploitation](https://roderickchan.github.io/zh-cn/2023-03-01-analysis-of-glibc-heap-exploitation-in-high-version/)
- [Ha1vk 原始 House of Banana（glibc 2.30）](https://www.anquanke.com/post/id/222948)

## PoC

- [`poc_fini_array_sink_2.23_2.43.c`](./poc_fini_array_sink_2.23_2.43.c)：线性展示真实 `exit→_dl_fini` 消费受控 fini_array

可执行部分不猜私有偏移；需要伪造独立 link_map 时，直接按文件末尾的中文伪代码和附件 ld.so 重算。

## 迁移与调试

1. 先确认投递路径和最终触发点在目标 Build ID 中都存在。
2. 把占位地址和 add/edit/free 顺序替换成题目能力。
3. 在消费函数下断点，逐字段核对 size、对齐、safe-linking、FILE/link_map 私有布局。
