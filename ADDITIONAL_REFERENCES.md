# 补充资料审计记录

本页记录 2026-08-14 对两份用户指定补充资料的吸收方式。它的目的不是给文章“判分”，而是说明哪些内容已经落进 cheatsheet、哪些历史结论必须由 glibc 源码收窄。

## 资料快照

### 看雪《CTF 中 glibc 堆利用及 IO_FILE 总结》

- 本地存档：[thread-272098-1.html](/Users/flower/Zotero/storage/QPI8VQE6/thread-272098-1.html)
- 原页面：`https://bbs.kanxue.com/thread-272098-1.htm`
- 文中自述初稿完成于 2022-02-01。
- 本次读取文件 SHA-256：`77ecd728de768db147fff47a6aaa6f5ba8fe468680defe6eaf6c4f372f03969a`。

文章覆盖基础 bins、经典 House、IO_FILE、setcontext/exit hook，以及截至当时的 tcache/safe-linking/Pig/Kiwi 等高版本思路。它很适合作为利用链地图，但 2022 年的“高版本/至今”当然不能直接外推到 2.43。

### ALateFall/blogs `system`

- 在线目录：[ALateFall/blogs/system](https://github.com/ALateFall/blogs/tree/main/system)
- 本次审阅提交：`5edc73a2d873cc4f0eb5d4814d8e4f36e1a5bfd0`（2025-09-19）。
- 重点阅读：`system/Heap` 与 `system/IO_FILE`，包括 bins 实验、各 bin attack、Lore/Force/Storm/Rabbit/Einherjar、Orange、vtable check 与 FILE 任意读写。

这个仓库的优势是把链表方向、FILE 偏移和触发条件拆成小实验；版本矩阵不是它的目标，所以本项目没有把文章标题中的 `Latest` 当作版本证明。

## 已吸收的增量

| 增量 | 落地位置 | 源码复核结果 |
|---|---|---|
| stdin/stdout 字段劫持任意读写 | [`io_file_arbitrary_read_write/`](./io_file_arbitrary_read_write/README.md) | x86-64 FILE 关键偏移和 `fileops.c` 数据流在 2.23～2.43 保持；保留合法 vtable，2.24 白名单不直接阻断 |
| freed size 与 in-use size overlap 的消歧 | [`chunk_overlap/`](./chunk_overlap/README.md) | `b90ddd` 从 2.29 封住旧 unsorted 变体；跨过中间 chunk 指向真实 top 的 in-use 变体还能运行到 2.43 |
| 缩小 top、由 sysmalloc 间接 free old top | [`sysmalloc_free_old_top/`](./sysmalloc_free_old_top/README.md) | 2.29 top/system_mem 加固封住 Force，但未删除合法 fencepost + `_int_free(old_top)` 分支；2.23 与 2.43 都实跑 |
| House of Pig PLUS | [`house_of_pig/`](./house_of_pig/README.md) | `_IO_str_overflow` 数据流还在；2.34 的 Ubuntu 构建存在可定位的 memset IFUNC IRELATIVE 槽，但可写性和地址属于 Build ID/RELRO 条件，所以只给布局模板和审计清单 |
| FILE 字段与 vtable 白名单的关系 | IO_FILE 目录及 Orange/Pig 说明 | 2.24 检查的是 jump table 来源；不应误写成“一切 FILE corruption 都失效” |

ALateFall 的 House of Storm、Lore、largebin/unsortedbin 说明也已和现有目录逐项对照过。最终的提交级复核又找到 2.28 的 `bdc3009`，所以把经典 Unsorted Bin Attack/Into Stack/Roman/Storm 都从旧的"到 2.28"纠正为"到 2.27"。Storm 第一轮的 target 预置修不了第二轮 fake-victim 摘链的双链失配。

## 明确没有照搬的结论

### “unsorted chunk 改 size 后取出时不再检查”

这个说法只适合作为旧版本语境，而且要分两道检查：2.28 的 [`bdc3009`](https://sourceware.org/git/?p=glibc.git;a=commitdiff;h=bdc3009b8ff0effdbbfb05eb6b10966753cbf9b8) 先加入 `bck->fd == victim`，让无条件经典 unsorted attack、单 fake-node into stack、Roman 和 Storm 止于 2.27；2.29 的 [`b90ddd`](https://sourceware.org/git/?p=glibc.git;a=commitdiff;h=b90ddd08f6dd688e651df9ee89ca3a69ff88cd0c) 再加入 `next size`、`next->prev_size` 等检查，收窄 freed-size overlap。

### 固定 `main_arena/__malloc_hook` 差值与固定 gadget

这些是某个构建的调试捷径，不是 glibc 版本 ABI。2.34 又移除了 hooks 的正常消费路径。cheatsheet 只保留字段关系和源码分支，所有绝对/相对偏移都要按附件 Build ID 重新提取。

### “tcache_perthread_struct 各版本基本无差异”

这在 2.42 后不成立：large tcache 与 metadata 重构改变 counts/entries 的组织和索引；2.43 又删除 fastbin 路径并继续改动 TLS/tcache。相应 PoC 已在 metadata poisoning/hijacking 目录按 2.42、2.43 分文件。

### “有 `_IO_str_overflow` 就有完整 House of Pig”

不成立。最终触发点、投递、终点是三个独立条件：2.34 hooks 结束；2.41/2.42 又先后改变 stashing 与经典 largebin 投递。PLUS 的 memset IFUNC/GOT 还受 RELRO 和 libc 构建影响，所以不能标成无条件 RCE。

### “vtable check 让 IO_FILE 利用整体失效”

不成立。glibc 2.24 封的是任意 heap vtable；已有合法 vtable 里还有很多数据流，标准流任意读写甚至完全不改 vtable。另一方面，2.23 的 heap fake-vtable Orange 也不能因为"FILE 字段还能改"而错误延长。

## 口径

本项目采用以下证据优先级：

1. 题目附件的 `libc.so.6`、`ld.so`、Build ID 与实际反汇编；
2. GNU glibc 对应 tag/release branch 的源码与提交；
3. 对应运行时的可执行 PoC；
4. how2heap 与公开题目 exploit；
5. 博客文章的原理说明。

博客用于发现技巧和理解利用链；最终版本边界必须回到源码与运行时。这也是这轮补充没有机械复制"latest/高版本"字样的原因。

## 后续互联网扩展审计

在用户允许继续联网补充后，又以 GNU glibc 提交、how2heap 和技术原始仓库为主完成一轮增量：

| 发现 | 落地位置 | 结论 |
|---|---|---|
| 2.42 large tcache 实际默认关闭 | [`large_tcache_attack/`](./large_tcache_attack/README.md)、[`MALLOC_SIZE_BIN_MAP.md`](./MALLOC_SIZE_BIN_MAP.md) | 需启动前提高 `glibc.malloc.tcache_max`；2.42 接受同 log-bin 的较大 chunk，2.43 改精确 size |
| tcache metadata 头指针并未整体 safe-link | tcache poisoning/metadata README 与生成脚本 | `entries[idx]` 还是明文；chunk 内 `next` 和 large 链中间槽位才按位置编码 |
| 2.43 默认 count 与 mmap layout 又变 | 源码时间线、House of Muney | 默认容量 7→16；mmap chunk 可在启用 large tcache 时入缓存，旧 mmap header 说明不能直接延伸 |
| House of Error | [`house_of_error/`](./house_of_error/README.md) | `_IO_mem_sync` 最终触发点到 2.43 还在；原始 largebin+assert 完整链只应标 2.35 特定构建 |
| House of Cat 与 wide-data ABI | [`house_of_cat/`](./house_of_cat/README.md)、Apple2、Kiwi |最终触发点到 2.43 还在；`_wide_vtable` 字段在 2.30 与 2.31 连续改变，旧模板不能统一写 `+0xe0` |
| Poison Null Byte 独立版本链 | [`poison_null_byte/`](./poison_null_byte/README.md) | 2.26、2.29、2.43 都得改变排布，不能只用"等价 Einherjar"一笔带过 |
| House of Lemon 与 Prime 消歧 | [`house_of_lemon/`](./house_of_lemon/README.md)、[`HISTORICAL_NAME_BOUNDARIES.md`](./HISTORICAL_NAME_BOUNDARIES.md) | 2.23 超大尺寸 fastbin 越界写→stdout vtable 已实跑；Prime 原版依赖 glibc 2.3.5 的 arena 布局，不能伪造 2.23+ PoC |
| TSU+ / TSU++ | [`tcache_stashing_unlink_attack_plus/`](./tcache_stashing_unlink_attack_plus/README.md)、[`tcache_stashing_unlink_attack_plus_plus/`](./tcache_stashing_unlink_attack_plus_plus/README.md) | 用户指定资料的 “2.23～latest” 已按源码收窄为 2.26～2.40；2.27/2.40 正向、2.41 负向实测 |
| House of Atum 精确边界 | [`house_of_atum/`](./house_of_atum/README.md) | 综述文字写 2.31 起失效，但它引用的源码与上游 tag 都显示变化进入 2.30；2.27/2.29 正向、2.30 负向实测 |
| House of IO 低版本布局与硬边界 | [`house_of_io/`](./house_of_io/README.md) | 补齐 2.29 的 `char counts[64]` PoC；2.30～2.33 改用 `uint16_t`，2.34 的随机 `tcache_key` 由正反向运行确认失效 |
| House of Emma 回调加固 | [`house_of_emma/`](./house_of_emma/README.md) | 2.23 回调为明文；`983fd5c` 从 2.24 起 mangle。两条真实 fopencookie 覆盖 PoC 分别实跑到 2.43 |
| Apple2 三套 wide ABI | [`house_of_apple2/`](./house_of_apple2/README.md) | 不再只给布局生成器；2.24～2.29 `+0x130`、2.30 `+0xf0`、2.31～2.43 `+0xe0` 都真实调用 fake doallocate |
| Apple1 原文再审计 | [`house_of_apple1/`](./house_of_apple1/README.md) | 原文核心是 `_IO_wstrn_overflow` 而不是 `_IO_wstr_overflow`；`118816d` 在 2.37 删除前者，所以版本从误标的 2.23～2.43 收窄到 2.23～2.36，还新增了八字段严格写入 C PoC |
| Apple3 codecvt ABI | [`house_of_apple3/`](./house_of_apple3/README.md) | 补齐此前参数化模板遗漏的三段：2.23～2.29 直接 `do_in+0x18`、2.30 `step@+0x8`、2.31+ `step@+0x0`；都经真实 `fgetwc→_IO_wfile_underflow` 回调实跑 |
| Kiwi 触发器硬边界 | [`house_of_kiwi/`](./house_of_kiwi/README.md) | top size corruption 在 2.23/2.35 真实进入 `__malloc_assert→fflush(stderr)`；2.36 的 `ac8047c` 改走 `__libc_message`，同一 PoC 退出 134 且无回调 |
| Obstack / Snake 分界 | [`house_of_obstack/`](./house_of_obstack/README.md)、[`house_of_snake/`](./house_of_snake/README.md) | `5365acc` 进入 2.37：旧 `_IO_obstack_jumps` 止于 2.36，新 printf_buffer 最终触发点始于 2.37；两侧都以真实 chunkfun 回调实跑 |
| Lys 布局/错位调用纠错 | [`house_of_lys/`](./house_of_lys/README.md)、[`house_of_obstack/`](./house_of_obstack/README.md) | `_IO_obstack_file+0xe0` 是 obstack 指针而不是内嵌结构；exit 链要用 `_IO_obstack_jumps+0x20` 把 overflow 错位到 xsputn，第三参数 `rdx` 也单独审计过 |
| Lore/Smallbin 假阳性审计 | [`house_of_lore/`](./house_of_lore/README.md)、[`small_bin_attack/`](./small_bin_attack/README.md) | 删除旧示例按栈帧差值直接改返回地址的步骤；2.43 因默认 count=16 单独排布，所有分支只以 malloc 返回 fake 地址为成功 |
| Pig 2.28 硬分界 | [`house_of_pig/`](./house_of_pig/README.md) | `4e8a6346` 前的 2.23～2.27 是 FILE 尾部 allocate/free 回调最终触发点；2.28 起才是现代 Pig 的直接 malloc/memcpy/free 数据流。两侧新增真实 C PoC，旧 PoC 在 2.28 负测试退出 134 |
| Banana fake map 缺项纠错 | [`house_of_banana/`](./house_of_banana/README.md) | 旧模板缺 `l_info[DT_FINI_ARRAYSZ]`、`l_real` 与 `l_init_called`，无法通过真实 `_dl_fini`；已重写布局，并用 fork 退出码在 2.23/2.30/2.43 实跑最终触发点|
| Corrosion/Crust 首个失效点 | [`house_of_corrosion/`](./house_of_corrosion/README.md)、[`house_of_crust/`](./house_of_crust/README.md) | 原文 Corrosion 是特定 2.27，Addendum 是特定 2.29；`global_max_fast` 在 2.37 缩成 uint8_t，已封住远端 fastbin 指针搬运，比 2.43 删除 fastbin 更早；所以 Crust 止于 2.36 而不是 2.40 |
| Rust 完整链与组件消歧 | [`house_of_rust/`](./house_of_rust/README.md) | 原作者只给 2.32 完整链且最终使用 `__free_hook`；2.33～2.40 仅能称 TSU+/TSU/largebin 组件窗口，2.34+ 若无另行验证的终点不能标成完整 Rust |
| Unsorted 2.28 off-by-one | [`unsorted_bin_attack/`](./unsorted_bin_attack/README.md)、[`unsorted_bin_into_stack/`](./unsorted_bin_into_stack/README.md) | 首道 `bck->fd==victim` 检查由 `bdc3009` 进入 2.28，不是 2.29；经典任意初值 target/单 fake-node 止于 2.27，但预置 `target==victim` 的强约束写还能到 2.43 |
| Roman 的 tcache 重排 | [`house_of_roman/`](./house_of_roman/README.md) | 原 PoC 只实测 2.23～2.25；2.26/2.27 必须用 count=3 tcache 链取代旧 fastbin 段，并用满 tcache + `calloc` 取 exact-size unsorted victim；2.28 负测试报 `corrupted unsorted chunks 3` |
| Storm 的第二轮 unsorted 检查 | [`house_of_storm/`](./house_of_storm/README.md) | how2heap 注释和汇总表误标至 2.28；精确 2.28 在 fake 成为第二个 victim 时报 `corrupted unsorted chunks 3`，所以经典链止于 2.27；2.27 PoC 已改为 heap-byte steering + strict target 判据 |
| Unsafe Unlink 2.29 off-by-one | [`unsafe_unlink/`](./unsafe_unlink/README.md) | `d6db68e` 已进入 2.29：旧布局只到 2.28，2.29+ 必须伪造 fake size 匹配后一边界 `prev_size`；精确 2.29 正反向都已实跑 |
| Husk Build-ID 假阳性 | [`house_of_husk/`](./house_of_husk/README.md) | 2.41 旧常量能把堆指针写入某个 libc 可写地址并通过局部 assert，但不是真表；已从当前 `libc6-dbg` Build ID 提取隐藏符号偏移，5 条完整投递链都以真实回调判据通过 |
| House of Some / Illusion | [`house_of_some/`](./house_of_some/README.md)、[`house_of_illusion/`](./house_of_illusion/README.md) | 本地笔记的“House of House”实际指 Some-of-House 项目；两条合法 jump-table 消费路径已拆开。2.30/2.31 wide ABI 与 2.40 `_IO_list_all` 双链断点分别实跑 |
| fastbin double free→tcache stash | [`fastbin_dup/`](./fastbin_dup/README.md) | 本地笔记中的独立标题实际是 Fastbin Dup 的 refill 子型；新增 `A→B→A` 经 fastbin refill 形成重复 tcache 节点的 2.26～2.42 PoC |
| 现代 Husk 交叉审计 | [`house_of_husk/`](./house_of_husk/README.md) | [4xura/house-of-husk](https://github.com/4xura/house-of-husk) 的现代样例覆盖 2.35/2.37/2.39/2.41，没有提供 2.42+ 经典 largebin 投递；与本项目在 2.42 加固处收口一致 |
| 输入/输出原语与失效性质 | [`PRIMITIVE_REQUIREMENTS_MATRIX.md`](./PRIMITIVE_REQUIREMENTS_MATRIX.md) | 60 种手法逐项拆成最小输入、源码不变量和输出；不再把“PoC 需重排”“投递/终点断裂”“需要更强 AAW 才能修检查”统一写成不可用 |
| House of Gods 范围纠错 | [`house_of_gods/`](./house_of_gods/README.md) | 公开源码的 `<2.27` 不能直接代表所有 stock 2.26：tcache 与隐藏 `narenas` 偏移都需迁移。2.27 的 `have_fastchunks` 使 main_arena fake-size 不变量真正失效，单线程快路径又不消费 thread_arena；arena 劫持上层思想还可以由更强 AAW 投递 |

主要新增原始资料：[FSOPAgain](https://github.com/un1c0rn-the-pwnie/FSOPAgain)、[Some-of-House](https://github.com/CsomePro/Some-of-House)、[House of Some 原文](https://blog.csome.cc/p/house-of-some/)、[House of Illusion 原文](https://enllus1on.github.io/2024/01/22/new-read-write-primitive-in-glibc-2-38/)、[how2heap](https://github.com/shellphish/how2heap)、[GNU glibc sourceware](https://sourceware.org/git/?p=glibc.git)。

how2heap 的最终差集审计固定在提交 `02da6aa26a44e5af2a67057876d7c6669a207f56`（2026-05-14）：它的 `glibc_2.43/` 里 16 个样例都已经有了本目录对应分支；本目录另按 glibc release branch 覆盖 large tcache、fastbin 删除、默认 tcache count 和 mmap layout 等 2.43 新变化。指定文章、本地笔记与 how2heap 的逐名对应见 [TECHNIQUE_COVERAGE_MAP.md](./TECHNIQUE_COVERAGE_MAP.md)。
