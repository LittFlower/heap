# House of Banana

## 结论

**一句话**：改写 rtld 命名空间或 link_map，让 `exit→_dl_fini` 这条路径去消费伪造的 `DT_FINI/DT_FINI_ARRAY`；最终触发点覆盖 2.23～2.43，断的只是投递。

| 版本 | 你能拿到什么 | 备注 |
|---|---|---|
| **2.23～2.43** | `exit→_dl_fini→DT_FINI_ARRAY` 最终触发点 | `link_map` 属 ld.so 私有 ABI，同一版本不同构建也要重新量偏移 |
| 2.30～2.41 | 经典 largebin attack 投递窗口 | Ha1vk 最初公开的 exploit 针对 2.30；2.42 起不能再用经典 largebin 写任意目标 |
| 2.42～2.43 | 仅剩最终触发点 | 必须另找任意写或 chunk overlap 投递；2.43 的 `_dl_fini` 把具体调用逻辑拆到 `_dl_call_fini`，消费语义不变 |

<!-- PRIMITIVE_REQUIREMENTS:START -->
## 原语要求与版本边界

| 项目 | 本手法要求 |
|---|---|
| 最小输入原语 / 信息 | 能改 rtld 命名空间/`link_map` 指针并布置 fake map；libc/ld leak |
| 关键环境与不变量 | 私有 `link_map` 布局、`l_real/l_init_called`、DT_FINI_ARRAY/SZ；exit |
| 最终输出原语 | `_dl_fini` 调受控 fini array，获得 CF |
| 版本边界应如何理解 | 最终触发点持续到 2.43，但强依赖 Build ID；经典 largebin 投递止于 2.41。2.42+ 若另有 AAW 仍可用 Banana，这是投递断裂而非思想硬封。 |
<!-- PRIMITIVE_REQUIREMENTS:END -->

<!-- CHUNK_SIZE_REQUIREMENTS:START -->
## Chunk size 要求

- **`_dl_fini`/fake link_map 最终触发点本身没有 chunk size 要求**；fake map 与 fini array 只需放在足够大、可写且地址已知的区域。
- 经典 2.30～2.41 投递若采用 Large Bin Attack，就必须能申请、释放至少两个物理 `chunksize >= 0x400` 且满足对应 largebin 排序关系的 chunk；2.42+ 换成 AAW/overlap 后，应按新投递原语的尺寸条件判断。
<!-- CHUNK_SIZE_REQUIREMENTS:END -->

## 从源码看

`elf/dl-fini.c` 先按命名空间的 `_ns_loaded` 链枚举对象，要求枚举计数与 `_ns_nloaded` 一致，且只把 `l == l_real` 的节点收进 `maps[]`。排序后只消费 `l_init_called` 为真的节点。2.43 把下面这段逻辑挪到 `elf/dl-call_fini.c`，关键数据流不变：

```c
array = (ElfW(Addr) *)
  (map->l_addr + map->l_info[DT_FINI_ARRAY]->d_un.d_ptr);
size_t count =
  map->l_info[DT_FINI_ARRAYSZ]->d_un.d_val / sizeof (ElfW(Addr));
while (count-- > 0)
  ((fini_t) array[count]) ();
```

因此伪造的 fake map 至少不能漏掉下面这几条：

1. `l_next` 要让遍历出来的有效节点数仍然等于 `_ns_nloaded`；
2. `l_real == fake_map`；
3. 目标 Build ID 对应的 `l_init_called` 这一位要是 1；
4. `l_info[26]` 和 `l_info[28]` 分别要指向真实的 `Elf64_Dyn`，其中后者的 `d_val` 至少要是 8；
5. `_dl_sort_maps` 会读写的 `l_idx`、open count、依赖字段以及 fake map 本身的内存，都要能被接受。

旧模板只设置了 `l_info[26]`，漏掉了随后必然被解引用的 `l_info[28]`，以及 `l_real` 和 `l_init_called`，因此已被删除。新版生成器要求显式传入所有私有偏移。

### 最终触发点、布局与投递三层

- [`poc_fini_array_sink_2.23_2.43.c`](./poc_fini_array_sink_2.23_2.43.c) 不需要猜私有偏移。它在线性的 `main` 里直接修改主程序真实 link_map 的两项 `Elf64_Dyn`，再进入 `exit→_dl_fini`。命中后受控回调调用 `_exit(0)`；未命中保留 `exit(113)` 失败状态以便判断。已在 2.23、精确到小版本的 2.30 和 2.43 上验证通过。
- 同一个 C 文件末尾还列出了伪造 `link_map` 所需的 `l_real/l_next/l_info[26]/l_info[28]/Elf64_Dyn/fini_array` 中文伪代码。具体私有 bitfield 偏移仍须从附件 ld.so 重新提取。
- 原文的 glibc 2.30 靠 largebin attack 投递堆地址。2.30～2.41 可按各自版本的 largebin 分支适配。2.42 引入的 nextsize 完整性检查封住了这条公开投递路径，但没有删除加载器本身的最终触发点。

源码里还能走到这个最终触发点，不代表旧利用链还能用。投递方式、私有结构和控制流终点都要按附件 libc/ld 的 Build ID 复核。

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

1. 先确认投递路径和最终触发点在目标 Build ID 上都确实存在。
2. 把占位地址和 add/edit/free 顺序，替换成题目实际给出的能力。
3. 在消费函数处下断点，逐字段核对 size、对齐、safe-linking，以及 FILE/link_map 等私有结构的布局。
