# 技术名称覆盖映射

本页说明指定文章、本地笔记和 how2heap 里的名字分别对应哪个目录，以及哪些只是别名、组合链或最终触发点，不需要另建手法目录。

审计日期为 **2026-08-18**。目录版本边界仍以对应 README、GNU glibc 源码和 [198 项实跑矩阵](./VALIDATION.md) 为准，本页只做名称覆盖导航。

## `House of all` 文章

[用户指定综述](https://roderickchan.github.io/zh-cn/2023-02-27-house-of-all-about-glibc-heap-exploitation/) 的 30 个 House 均已有独立目录：

| 原文名称 | 本项目目录 | 名称/边界提示 |
|---|---|---|
| Spirit | [`house_of_spirit/`](./house_of_spirit/README.md) | fastbin 与 tcache 子型分开 |
| Einherjar | [`house_of_einherjar/`](./house_of_einherjar/README.md) | 2.26、2.29 完整性检查分段 |
| Force | [`house_of_force/`](./house_of_force/README.md) | 2.29 起 top/system_mem 检查终止经典链 |
| Lore | [`house_of_lore/`](./house_of_lore/README.md) | 也由 [`small_bin_attack/`](./small_bin_attack/README.md) 汇总命名差异 |
| Orange | [`house_of_orange/`](./house_of_orange/README.md) |堆管理器、触发器、FSOP 最终触发点分开标版本 |
| Rabbit | [`house_of_rabbit/`](./house_of_rabbit/README.md) | 经典跨尺寸 fastbin 链止于 2.26 |
| Roman | [`house_of_roman/`](./house_of_roman/README.md) | 2.26/2.27 需 tcache 重排，2.28 起失效 |
| Storm | [`house_of_storm/`](./house_of_storm/README.md) | 2.28 首道 unsorted 双链检查已封住 |
| Corrosion | [`house_of_corrosion/`](./house_of_corrosion/README.md) | 原版 2.27、Addendum 2.29，强 Build-ID 绑定 |
| Husk | [`house_of_husk/`](./house_of_husk/README.md) | printf 最终触发点与 largebin 投递窗口分开 |
| Atum | [`house_of_atum/`](./house_of_atum/README.md) | 原链止于 2.29，不是 2.30/2.31 |
| Kauri | [`house_of_kauri/`](./house_of_kauri/README.md) | 2.42 全 bin double-free 扫描终止改-size 绕过 |
| Fun | [`house_of_fun/`](./house_of_fun/README.md) | legacy largebin 四指针写 |
| Mind | [`house_of_mind/`](./house_of_mind/README.md) | 本项目覆盖 fastbin arena 劫持版 |
| Muney | [`house_of_muney/`](./house_of_muney/README.md) | 等价于 how2heap 的 mmap overlapping chunks |
| Botcake | [`house_of_botcake/`](./house_of_botcake/README.md) | tcache double-free 绕过 |
| Rust | [`house_of_rust/`](./house_of_rust/README.md) | 只有 2.32 原版可称完整 Rust，其余为组件窗口 |
| Crust | [`house_of_crust/`](./house_of_crust/README.md) | 超大尺寸 fastbin 越界索引在 2.37 已有硬边界 |
| IO | [`house_of_io/`](./house_of_io/README.md) | 2.29～2.33 的 tcache key/leak 语境 |
| Banana | [`house_of_banana/`](./house_of_banana/README.md) | `_dl_fini`/fake `link_map` 最终触发点|
| Kiwi | [`house_of_kiwi/`](./house_of_kiwi/README.md) | 专属 malloc-assert 触发器止于 2.35 |
| Emma | [`house_of_emma/`](./house_of_emma/README.md) | fopencookie 回调；2.24 起 PTR_MANGLE |
| Pig | [`house_of_pig/`](./house_of_pig/README.md) | 2.28 是旧回调与现代 str-overflow 最终触发点分界 |
| Obstack | [`house_of_obstack/`](./house_of_obstack/README.md) | 经典 FILE 链止于 2.36 |
| Apple 1 | [`house_of_apple1/`](./house_of_apple1/README.md) | `_IO_wstrn_overflow`，2.37 删除 |
| Apple 2 | [`house_of_apple2/`](./house_of_apple2/README.md) | wide doallocate 最终触发点，三套 ABI |
| Apple 3 | [`house_of_apple3/`](./house_of_apple3/README.md) | codecvt 最终触发点，三套 ABI |
| Gods | [`house_of_gods/`](./house_of_gods/README.md) | 原版最小链实跑至 2.25；2.26 需 tcache/构建适配，2.27 起原版 main_arena fake-size 链硬失效 |
| Lys | [`house_of_lys/`](./house_of_lys/README.md) | 部分文章误写为 Lyn；exit→obstack 链止于 2.36 |
| Snake | [`house_of_snake/`](./house_of_snake/README.md) | 2.37+ printf_buffer obstack 最终触发点|

文章发表后出现、但用户本地笔记已指向的两条新链也已补齐：[`house_of_some/`](./house_of_some/README.md) 与 [`house_of_illusion/`](./house_of_illusion/README.md)。二者原始代码汇总仓库实际名为 [Some-of-House](https://github.com/CsomePro/Some-of-House)，不是一个名为“House of House”的第三种算法。

## `高版本 glibc heap exploitation` 文章

[第二篇指定文章](https://roderickchan.github.io/zh-cn/2023-03-01-analysis-of-glibc-heap-exploitation-in-high-version/) 中重复的 House 沿用上表；其余标题按下表映射：

| 文章标题/主题 | 本项目落地 | 说明 |
|---|---|---|
| Tcache attacks | [`tcache_dup/`](./tcache_dup/README.md)、[`tcache_poisoning/`](./tcache_poisoning/README.md)、[`tcache_metadata_poisoning/`](./tcache_metadata_poisoning/README.md)、[`house_of_botcake/`](./house_of_botcake/README.md) | 按 double free、链投毒、metadata 和组合绕过拆开 |
| Tcache Reverse Into Fastbin | [`fastbin_reverse_into_tcache/`](./fastbin_reverse_into_tcache/README.md) | 原文步骤实际是 fastbin 链被 malloc 反向填入 tcache；标题词序容易误导 |
| Tcache Stashing Unlink | [`tcache_stashing_unlink_attack/`](./tcache_stashing_unlink_attack/README.md)、[`tcache_stashing_unlink_attack_plus/`](./tcache_stashing_unlink_attack_plus/README.md)、[`tcache_stashing_unlink_attack_plus_plus/`](./tcache_stashing_unlink_attack_plus_plus/README.md) | 三种效果分别实跑；2.41 重构是硬边界 |
| `link_map` | [`house_of_banana/`](./house_of_banana/README.md) | 是 rtld 最终触发点/私有布局，不另造堆管理器 attack |
| `libc.got` | 各复合 House README | 是候选最终写目标，受 RELRO、构建和消费路径约束 |
| `environ` | [`house_of_some/`](./house_of_some/README.md) 等任意读链 | 用于栈泄露，不是独立 bin/House 算法 |
| `heap_info` / `malloc_state` | [`house_of_mind/`](./house_of_mind/README.md)、[`house_of_gods/`](./house_of_gods/README.md) | arena 劫持相关数据结构 |
| `mp_` / tcache TLS / `thread_arena` / pointer guard | 对应 metadata、Emma 与 arena README | 都是攻击面或秘密值，不应仅凭“能写”命名新 House |

## how2heap 2.23～2.43 差集

以下以 shellphish/how2heap 提交 `02da6aa26a44e5af2a67057876d7c6669a207f56` 为快照，将 2.23～2.43 目录中出现过的示例文件去重。每一项都有语义对应，不要求目录名逐字一致：

| how2heap 示例 | 本项目目录 |
|---|---|
| `fastbin_dup*` | [`fastbin_dup/`](./fastbin_dup/README.md)、[`fastbin_dup_into_stack/`](./fastbin_dup_into_stack/README.md)、[`fastbin_dup_consolidate/`](./fastbin_dup_consolidate/README.md) |
| `fastbin_reverse_into_tcache` | [`fastbin_reverse_into_tcache/`](./fastbin_reverse_into_tcache/README.md) |
| `tcache_poisoning` / `tcache_metadata_*` / `tcache_relative_write` | 同名 [`tcache_poisoning/`](./tcache_poisoning/README.md)、[`tcache_metadata_poisoning/`](./tcache_metadata_poisoning/README.md)、[`tcache_metadata_hijacking/`](./tcache_metadata_hijacking/README.md)、[`tcache_relative_write/`](./tcache_relative_write/README.md) |
| `tcache_stashing_unlink_attack` | [`tcache_stashing_unlink_attack/`](./tcache_stashing_unlink_attack/README.md) 及 Plus/Plus Plus |
| `decrypt_safe_linking` / `safe_link_double_protect` | [`safe_linking/`](./safe_linking/README.md) |
| `large_bin_attack` / `unsorted_bin_attack` / `unsorted_bin_into_stack` | 对应同名目录 |
| `overlapping_chunks` / `overlapping_chunks_2` | [`chunk_overlap/`](./chunk_overlap/README.md) |
| `poison_null_byte` / `unsafe_unlink` | 对应同名目录 |
| `sysmalloc_int_free` | [`sysmalloc_free_old_top/`](./sysmalloc_free_old_top/README.md) |
| `mmap_overlapping_chunks` | [`house_of_muney/`](./house_of_muney/README.md) |
| `house_of_mind_fastbin` | [`house_of_mind/`](./house_of_mind/README.md) |
| `tcache_house_of_spirit` / `house_of_spirit` | [`house_of_spirit/`](./house_of_spirit/README.md) |
| `house_of_botcake/einherjar/force/gods/io/lore/orange/roman/storm/tangerine/water` | 对应同名 House 目录 |

## 本地笔记与博客的别名

| 笔记中的写法 | 处理方式 |
|---|---|
| House of House / Illusion | 前者实际指 Some-of-House 项目；拆成 Some 与 Illusion 两个真实调用链 |
| House of 一骑当千 | 指 `setcontext/ucontext → mprotect → shellcode/ROP` 控制流载体，常与 Apple2/Apple3 等写原语组合；不是 ptmalloc 独立 House |
| tcache stash with fastbin double free | [`fastbin_dup/poc_tcache_stash_2.26_2.42.c`](./fastbin_dup/poc_tcache_stash_2.26_2.42.c) 显式演示 fastbin `A→B→A` 经 refill 产生重复 tcache 节点 |
| House of Lyn | House of Lys 的拼写漂移 |
| House of Enherjar | House of Einherjar 的拼写漂移 |
| “高版本 House of Rust” | 若没有原版完整 TSU+/largebin/FSOP/终点链，只能称 Rust 派生组件，不能把任意新题组合自动回写为原版跨版本 PoC |

ALateFall 的 `fastbin_attack`、bins 与 unlink 系列分别落在 Fastbin Dup/Into Stack、各 bin attack 和 Unsafe Unlink；其 `house_of_enherjar` 属于上述拼写差异。看雪存档中的 FILE、setcontext、exit hook 和 one_gadget 内容则分别属于数据流最终触发点、控制流载体与最终落点，不会重复建成堆管理器目录。

## 不在 2.23～2.43 硬造 PoC 的历史名

House of Prime 原始前提依赖 glibc 2.3.5 年代的 arena 布局，House of Chaos 在 Malloc Maleficarum 中没有形成可复现的独立算法；详见 [HISTORICAL_NAME_BOUNDARIES.md](./HISTORICAL_NAME_BOUNDARIES.md)。本项目的覆盖标准是“有明确数据结构不变量、可定位源码消费路径、且至少一个对应运行时可复现”，而不是收集所有博客标题或比赛昵称。
