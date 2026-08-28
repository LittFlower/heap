# calloc 相关堆利用手法速查（glibc 2.23～2.43）

`calloc` 在这些手法里通常不是一个独立的写原语，而是一个**分配路由选择器**：在特定版本中，它能绕过 `malloc` 前端的 tcache 直接取出，进入 `_int_malloc` 的 fastbin、smallbin 或 unsorted 路径。另一个必须单独考虑的效果是：分配成功后，`calloc` 会清零返回的用户区。

本文只收录本仓库中真实出现 `calloc`，或利用链明确依赖 calloc 路由差异的手法。仅仅把普通 `malloc` 写成 `calloc`、但不影响利用路径的 PoC，会单独标成“非核心依赖”。

## 先记住版本边界

| glibc | `calloc` 与 tcache 的关系 | 对利用的影响 |
|---|---|---|
| 2.23～2.25 | 尚无 tcache；`calloc` 与 `malloc` 最终都进入 `_int_malloc` | 没有“绕 tcache”价值，主要差别是返回后清零 |
| 2.26～2.40 | `free` 会优先放入 tcache，但 `calloc` 不从 tcache 头直接取块，而是进入 `_int_malloc` | 可在 tcache 还有节点/空槽时强制触发 fastbin、exact-smallbin、unsorted 等后端路径 |
| 2.41～2.42 | `calloc` 也优先从 tcache 取块 | 想继续进入 fastbin，必须先耗尽同尺寸 tcache；旧 smallbin stashing 循环又在 2.41 被独立删除，清空 tcache 也救不回 TSU |
| 2.43 | 继续使用 tcache；默认每 bin 16 槽，且 fastbin 已删除 | 旧 calloc→fastbin 与 calloc→smallbin-stashing 手法都没有原消费路径了 |

关键提交与完整时间线见 [SOURCE_TIMELINE.md](./SOURCE_TIMELINE.md)：2.41 的 `226e3b0` 让 calloc 使用 tcache，同版本的 `e2436d6` 重构时删掉了经典 smallbin stashing 路径。这是两条独立边界。

“2.26～2.40 calloc 绕过 tcache”只表示它不执行前端的 **tcache get**，不表示 tcache 整体不存在：

- `free` 还是会优先把同尺寸 chunk 放进 tcache；要让 victim 进入 fastbin/smallbin/unsorted，还是得先填满或避开对应 tcache。
- `_int_malloc` 从 fastbin/smallbin 取块时，还可能把剩余节点 stash 到 tcache。
- 2.41+ 若同尺寸 tcache 非空，`calloc` 会先消费它；只有先耗尽这个 bin，才能继续观察后端分支。

## 核心依赖 calloc 路由的手法

| 手法 | calloc 的具体作用 | 关键尺寸/堆状态 | 版本结论与 PoC |
|---|---|---|---|
| [Tcache Stashing Unlink Attack](./tcache_stashing_unlink_attack/README.md) | tcache 中还留 5 个节点、尚有 2 个空槽时，绕过 tcache get，直接进入 exact-smallbin；旧循环把额外节点 stash 回 tcache | PoC：`calloc(1,0x90)`，物理 `0xa0`；真实 smallbin 节点与触发请求同 class | **2.26～2.40**；[`poc_2.26_2.40.c`](./tcache_stashing_unlink_attack/poc_2.26_2.40.c) |
| [TSU+](./tcache_stashing_unlink_attack_plus/README.md) | 与 TSU 相同，但让 stashing 遍历 fake `bk`，把任意对齐地址放入 tcache | PoC：`calloc(1,0x100)`，物理 `0x110`；触发前 tcache 留 2 个空槽 | **2.26～2.40**；[`poc_2.26_2.40.c`](./tcache_stashing_unlink_attack_plus/poc_2.26_2.40.c) |
| [TSU++](./tcache_stashing_unlink_attack_plus_plus/README.md) | 一次 calloc 触发的 stashing 同时产生 fake chunk 入 tcache 和另一处 main_arena 指针写 | PoC：`calloc(1,0x100)`，物理 `0x110`；触发前 tcache 恰有 2 个节点、smallbin 有 5 个真实节点 | **2.26～2.40**；[`poc_2.26_2.40.c`](./tcache_stashing_unlink_attack_plus_plus/poc_2.26_2.40.c) |
| [House of Rust](./house_of_rust/README.md) | Rust 前半的 TSU+/TSU 两阶段都靠 calloc 绕过还没取空的 tcache，进入旧 exact-smallbin stashing | 组件分别用 `calloc(1,0x100) -> 0x110` 与 `calloc(1,0x90) -> 0xa0` | 原版完整链为 **2.32**，calloc 相关组件到 **2.40**；[`TSU+`](./house_of_rust/poc_component_tsu_plus_2.32_2.40.c)、[`TSU`](./house_of_rust/poc_component_tsu_2.32_2.40.c) |
| [House of Storm](./house_of_storm/README.md) | 2.26～2.27 在对应 tcache 已满时，绕过 tcache get，消费 unsorted/largebin 交叉写生成的 fake chunk | `calloc(size,1)` 的总 request 由写入 fake size 的 heap 指针高位动态反算，不是固定 class | 完整手法 **2.23～2.27**；calloc 的 tcache 绕过作用只在 **2.26～2.27**；[`poc_2.23_2.27.c`](./house_of_storm/poc_2.23_2.27.c) |
| [House of Roman](./house_of_roman/README.md) | 2.26～2.27 保持物理 `0x90` 的 tcache 已满，用 calloc 直接处理 exact-size unsorted victim，完成受约束写入 | `calloc(1,0x80)`，物理 `0x90`；这个 tcache 必须保持满，不能先由 malloc 取空 | 完整手法 **2.23～2.27**；calloc 适配用于 **2.26～2.27**；[`poc_2.23_2.27.c`](./house_of_roman/poc_2.23_2.27.c) |

[Small Bin Attack 汇总](./small_bin_attack/README.md)中的 tcache-stashing 子型就是上表第一项，不是另一种独立 calloc attack；[`poc_tcache_stash_2.26_2.40.c`](./small_bin_attack/poc_tcache_stash_2.26_2.40.c) 是同一路径的检索入口。

## 把 calloc 当作便捷绕路工具的 fastbin 手法

下列手法的核心仍是 fastbin。2.26～2.40 使用 calloc 可以省去“先把同尺寸 tcache 全部取空”的步骤；即使没有可调用的 calloc，只要题目能耗尽 tcache，再用 malloc 进入 fastbin，原语还可能成立。所以它们属于**强相关，但不是思想上的硬依赖**。

| 手法 | 2.26～2.40 | 2.41～2.42 | 尺寸要求与 PoC |
|---|---|---|---|
| [Fastbin Dup](./fastbin_dup/README.md) | 填满 tcache 后，A→B→A 进入 fastbin；calloc 绕过 tcache get 并按 A→B→A 取回 | calloc 会先看 tcache，PoC 先用 7 次 malloc 耗尽它，再混用 malloc/calloc 从 fastbin 取回 | 同一 fastbin class；[`poc_2.26_2.40.c`](./fastbin_dup/poc_2.26_2.40.c)、[`poc_2.41_2.42.c`](./fastbin_dup/poc_2.41_2.42.c) |
| [Fastbin Dup Into Stack](./fastbin_dup_into_stack/README.md) | calloc 直接沿被投毒的 fastbin 链取出 fake chunk | 必须先耗尽同尺寸 tcache；随后 calloc 才能到 fastbin | PoC 用 `calloc(1,8) -> chunksize 0x20`；[`2.26～2.31`](./fastbin_dup_into_stack/poc_2.26_2.31.c)、[`2.32`](./fastbin_dup_into_stack/poc_2.32.c)、[`2.33～2.40`](./fastbin_dup_into_stack/poc_2.33_2.40.c)、[`2.41～2.42`](./fastbin_dup_into_stack/poc_2.41_2.42.c) |
| [House of Spirit（fastbin 子型）](./house_of_spirit/README.md) | tcache 填满后把 fake chunk free 到 fastbin，再用 calloc 绕过 tcache get 取回 | 先用 7 次 malloc 耗尽 tcache，再调用 calloc 取 fake chunk | PoC 用 `calloc(1,0x30) -> chunksize 0x40`；[`2.26～2.40`](./house_of_spirit/poc_fastbin_2.26_2.40.c)、[`2.41～2.42`](./house_of_spirit/poc_fastbin_2.41_2.42.c) |

2.43 删除 fastbin，所以即使把 tcache 清空，也不能恢复这些 fastbin 子型。House of Spirit 的 tcache 子型还在，但它不依赖 calloc 绕路。

## 只是在 PoC 中出现、不是 calloc 攻击

- [Fastbin Dup Consolidate](./fastbin_dup_consolidate/README.md) 的 [`poc_2.23_2.25.c`](./fastbin_dup_consolidate/poc_2.23_2.25.c) 用 `calloc(1,0x40)` 创建初始 fastbin chunk。这个版本没有 tcache，换成等尺寸 malloc 不改变核心的 `malloc_consolidate` 路径。
- House of Storm 在 2.23～2.25 也调用 `calloc(size,1)`，但当时没有 tcache；真正与 calloc 路由相关的是 2.26～2.27 的兼容分支。
- House of Rust 汇总 PoC 中的 calloc 调用只是它 TSU/TSU+ 组件的内联版本，别再计成新的手法。
- [Ltfall 笔记中的“off-by-null 三明治 revenge（calloc）”](https://ltfa1l.top/2023/12/28/system/tricks/tricks/)本质还是重复构造 overlap/unsorted 与 stale alias，让后续 calloc 清零时还有另一条编辑路径；calloc 不是制造重叠的原因。它归入 [Poison Null Byte](./poison_null_byte/README.md) 的题目级布局变体，尺寸、`prev_size`/unlink 检查和版本边界继续以后者为准，本页不另计一种 calloc attack。

## size、清零与伪 chunk 注意事项

### 总 request 如何换算

路由判断使用的是 `n * elem_size` 这个总 request，再经过 `request2size` 得到物理 chunk size：

```text
bytes = n * elem_size
nb    = request2size(bytes)
```

因此 `calloc(1,0x90)` 与 `calloc(0x90,1)` 在不溢出的情况下都对应总 request `0x90`、物理 `0xa0`。glibc 会检查乘法溢出；不能靠让 `n * elem_size` 环绕成小数来稳定取得错误尺寸。

### 清零发生在分配成功之后

`calloc` 返回 fake chunk 后会清零它的用户区，这会带来三个实战约束：

1. fake `size` 等 header 应位于返回 user pointer 之前，不能放进 allocator 即将清零的用户区。
2. 若目标是函数指针、链表字段或已准备好的 payload，calloc 可能在“成功返回”后立刻把它们清掉；必要时只用 calloc 触发后端路径，再用 malloc 取最终目标。TSU/TSU+/TSU++ 正是 calloc 负责触发 stashing、随后 malloc 负责取回 fake target。
3. fake target 后必须有足够可写空间容纳清零长度。glibc 清理的字节数可能按物理 chunk 的 usable 区域计算，并不保证恰好等于 `n*elem_size`；返回栈/BSS 地址时，只满足 0x10 对齐并不够。

## 题目筛选

拿到题目后按下面顺序判断：

1. 程序是否提供可控的 calloc 路径，或内部操作最终会调用 calloc？只有 add→malloc 而没有 calloc 时，不能凭空使用这条路由。
2. libc 是否在 2.26～2.40？如果是，确认 calloc 时对应 tcache 应保持“满”“部分有空槽”还是只需非空；不同手法要求相反。
3. libc 为 2.41～2.42 时，先确认能否耗尽同尺寸 tcache；这只可能恢复 fastbin 路由，不能恢复已删除的 TSU stashing 循环。
4. 用 `request2size(n*elem_size)` 核对物理 class，不要把 `calloc` 的两个参数、用户 request 和 header size 混为一谈。
5. 在 calloc 返回后检查目标区域是否被清零；只看到返回地址正确，不代表后续元数据或 payload 仍然完整。

## 调试断点

- 在 `__libc_calloc`、`_int_malloc` 和目标版本的 `tcache_get/tcache_get_n` 下断点。
- 调用前检查目标 `tc_idx` 的 count/head；2.26～2.40 应看到 calloc 跳过直接 tcache get，2.41+ 则会优先消费非空 tcache。
- TSU 系列还要在 exact-smallbin 分支观察 stashing 循环、tcache 剩余容量和 `bck->fd`；2.41+ 就别指望走进旧循环了。
- 返回后立即检查 user area，确认 calloc 的清零范围没有覆盖 fake header、下一节点或最终 payload。

用户 request、物理 chunk size 和 bin index 的统一换算见 [MALLOC_SIZE_BIN_MAP.md](./MALLOC_SIZE_BIN_MAP.md)。
