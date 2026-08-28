# 堆利用手法：输入原语、输出原语与真实失效边界

本表回答两个问题：题目至少要提供什么能力；glibc 变化后，是重新排布即可，还是原来的最小前置已经无法到达消费路径。

## 判定口径

| 标记 | 含义 |
|---|---|
| **适配** | 消费路径和关键不变量仍在；调整 tcache 数量、结构偏移、safe-linking 编码或触发顺序即可。 |
| **环境/构建** | 取决于 Build ID、RELRO、tunable、多线程状态、隐藏符号或私有结构；版本号本身不是充分条件。 |
| **弱前置封堵** | 原 PoC 依赖的赋值有时仍在，但新增检查要求预先构造更多反向指针/目标内容。若新增能力已接近任意写，就不能说原攻击仍以原最小前置成立。 |
| **消费路径硬边界** | 关键 bin、循环、函数或回调槽被删除或不再调用；改走另一条消费路径就是换手法。 |
| **完整链断裂** | 投递、触发器或最终触发点只有一段失效；仍可用的子原语必须单独标注。 |

这里的"不可用"始终是相对于表中列出的**最小输入原语**。如果先额外假设任意写，再用这份任意写修好所有双链检查，技术上可能还会经过同一行赋值——但这不能证明原 attack 还可用，因为新增的前置已经包含甚至超过它原本要产出的能力。同理，"另一个手法能取得相同输出"也不代表旧手法的思路没有被封堵。

缩写：`AAR/AAW` 为任意地址读/写，`AAF` 为近似任意地址分配，`CF` 为控制流，`UAF` 为释放后使用，`WAF` 为释放后写，`RCE` 为取得代码执行。

## Bin attack 与堆管理器原语

| 手法 | 最小输入原语 / 信息 | 关键环境与不变量 | 最终输出原语 | 版本边界应如何理解 |
|---|---|---|---|---|
| [Chunk Overlap](./chunk_overlap/README.md) | 相邻 heap overflow/UAF，可改 chunk `size` | 伪边界最终必须落到合法 next/top，并满足 `prev_size`/`system_mem` | 两个活动指针覆盖同一物理区域，继而改对象字段 | freed-unsorted 子型 2.29 被完整性检查封住；这是该弱布局的硬边界。free 前改 in-use size→真实 top 的同一“重叠目标”仍到 2.43，属于换布局而非只改偏移。 |
| [Fastbin Dup](./fastbin_dup/README.md) | A-B-A double free；2.26+ 可绕/耗尽 tcache | 同尺寸；2.32+ 后续 poisoning 需 heap page | 重复活动指针/别名 chunk | 2.26～2.42 是 tcache 路由与 safe-linking **适配**；2.43 删除 fastbin，形成消费路径硬边界。Botcake/tcache dup 能给相似输出，但属于另一条路径。 |
| [Fastbin Dup Consolidate](./fastbin_dup_consolidate/README.md) | double free/重复引用，可触发 `malloc_consolidate` | fastbin 与 top/unsorted 合并顺序可控 | 同一块同时从两条路径返回，形成 overlap | 到 2.42 主要是 tcache/safe-linking 适配；2.43 无 fastbin，也无这条 consolidate 输入，核心硬失效。 |
| [Fastbin Dup Into Stack](./fastbin_dup_into_stack/README.md) | fastbin UAF 改 `fd`，通常还要 double free | fake size、0x10 对齐；2.32+ `PROTECT_PTR`；2.42 refill size | AAF 到栈/全局 fake chunk | 2.26/2.32/2.41/2.42 都是实现适配；2.43 fastbin 删除为硬边界。相同 AAF 可改用 tcache poisoning，不代表 fastbin 版仍在。 |
| [Fastbin Reverse Into Tcache](./fastbin_reverse_into_tcache/README.md) | UAF 改 fastbin `fd`；堆地址泄露；可填满/耗尽 tcache | fake 节点同尺寸，2.42 通过 refill size 检查 | 目标进入 tcache，并产生受控元数据写/AAF | 2.42 只是额外 size 适配；2.43 删除 fastbin→tcache refill 来源，消费路径硬失效。 |
| [IO_FILE 标准流任意读写](./io_file_arbitrary_read_write/README.md) | 可覆盖现有 stdin/stdout，或投递字段等价且 vtable 合法的 FILE | libc/FILE 地址；可用 fd；触发实际读写函数 | fd→内存 AAW；内存→fd AAR/leak | 2.24 vtable 白名单不阻止“保留合法 vtable”的字段劫持；2.23～2.43 是布局/触发适配，没有已知核心删除。 |
| [Large Bin Attack](./large_bin_attack/README.md) | UAF 改 largebin 节点的 nextsize 指针 | 两个同 bin、有序 chunk；目标可写 | 把 victim heap 指针写到目标 | 2.30 是同一家族的新插入分支，属于换实现；2.42 检查 nextsize 反向环，经典“只改一个 `bk_nextsize`、任意初值目标”被封堵。若能预构造整套 fake ring，赋值仍可能发生，但那是**强前置残余**。 |
| [Large Tcache Attack](./large_tcache_attack/README.md) | large-tcache UAF/overlap 改 `next`，heap page leak | 2.42+；启动前提高默认关闭的 `tcache_max`；fake size 合法 | 大尺寸 AAF | 2.42 才引入该消费路径；2.43 从同 log-bin `>=` 改精确 size，是**适配**而非失效。默认关闭属于环境条件。 |
| [Poison Null Byte](./poison_null_byte/README.md) | 对相邻 `size` 的单 NUL；现代链还需 large chunk 排布和低字节改写 | fake previous chunk 的 size/prev_size 与 fd/bk 自洽 | 后向合并造成 overlap | 2.26、2.29、2.43 都改变实现不变量，但 off-by-null→合并的思想未消失；四套 PoC 是适配，不应写成中间版本“不可用”。 |
| [Safe-Linking 配套原语](./safe_linking/README.md) | 泄露 encoded next；double-protect 需控制两层链/metadata | 已知存储槽地址或可构造两次 XOR | 恢复 heap pointer；生成合法 encoded pointer；无泄露重链接 | 2.32 前不是“失效”，而是没有这项缓解、也不需要解码；2.42/2.43 只改具体 metadata/链位置。 |
| [Small Bin Attack 汇总](./small_bin_attack/README.md) | direct/Lore：UAF 改 `bk` 并布置完整 fake 双链；TSU：可控 `bk` | direct 要双链自洽；2.43 tcache count=16；TSU 依赖旧 stashing loop | direct AAF；TSU 还可写 libc 指针 | direct/Lore 到 2.43 仅需排布适配。只改一个 `bk` 的“无条件任意写”早已是强约束。TSU 消费路径在 2.41 被重构掉，不能把 direct 的存活当作 TSU 存活。 |
| [Sysmalloc Free Old Top](./sysmalloc_free_old_top/README.md) | 缩小 top size，并触发超过伪 top 的申请 | top size 合法对齐、`PREV_INUSE`、最低尺寸；sysmalloc 能扩展 | 无显式 free 地制造 old-top unsorted/small/tcache chunk | 2.29 封的是 Force 的超大 top，不是合法缩小 top；2.43 fastbin 删除也不删 old-top 回收。属于持续适配。 |
| [Tcache Dup](./tcache_dup/README.md) | 对同一指针连续 free，无中间 edit | 2.26～2.28 tcache 无 key 扫描 | 同一 chunk 重复返回 | 2.29 key+链扫描硬封住“只有连续 double free”这个最小模型。若能清 key、改 size 或合并再 free，可用 Botcake/Kauri 等绕法，但已经增加输入原语。 |
| [Tcache Metadata Hijacking](./tcache_metadata_hijacking/README.md) | tcache 初始化前的大块顺向溢出 | 2.42+ 延迟/邻接初始化布局；能控制紧邻 metadata | 覆盖 `entries`，得到 AAF | 这是 2.42 新布局产生的手法；更早版本可做普通 metadata poisoning，但不存在同一个“延迟初始化后相邻落位”消费路径。 |
| [Tcache Metadata Poisoning](./tcache_metadata_poisoning/README.md) | 能直接覆盖 `tcache_perthread_struct` | 先泄露/定位 metadata；按版本计算 counts/entries | 任意 size class 的下一次返回地址/AAF | 2.26～2.43 思想持续；2.30、2.42、2.43 主要是字段宽度、bin 数与语义适配。头指针并未整体 safe-link。 |
| [Tcache Poisoning](./tcache_poisoning/README.md) | freed-chunk UAF/overlap 改 `next` | 2.32+ 要 heap page 或 double-protect；目标 0x10 对齐 | small-tcache AAF | safe-linking 是前置增强，不是核心删除；2.26～2.43 的消费路径持续存在。 |
| [Tcache Relative Write](./tcache_relative_write/README.md) | libc/unsorted leak；能增大 `mp_.tcache_bins`；可申请精确超界 size | 2.30～2.41 外层用可扩大的 `mp_` 界，metadata 仍固定 64 槽 | metadata 后相对位置的半字计数写或 heap-pointer 写 | 2.42 把结构扩为 76 bins、改 count-down 并重写 size→idx/边界，原“放大 `mp_.tcache_bins` 让固定数组 OOB”消费路径硬失效；普通 metadata overflow 仍可能，但不是本算法。 |
| [Tcache Stashing Unlink Attack](./tcache_stashing_unlink_attack/README.md) | UAF 改 smallbin victim `bk` | 目标附近可写/对齐；目标 tcache 有空位；通常 calloc 触发 | main_arena 指针写 + fake 节点进 tcache/AAF | 2.41 删除旧 exact-smallbin stashing 循环，形成消费路径硬边界；Lore 直接 smallbin unlink 仍活，但不是 TSU。 |
| [TSU+](./tcache_stashing_unlink_attack_plus/README.md) | 控制 smallbin victim `bk`，布置 fake `bk` | 同上，且 fake chunk/反向链满足具体返回路径 | 任意对齐地址进 tcache 并返回 | 2.26～2.40 为排布窗口；2.41 核心 stashing 消费路径消失。加任意写去重建 tcache 头会退化成 metadata poisoning。 |
| [TSU++](./tcache_stashing_unlink_attack_plus_plus/README.md) | TSU+ 条件，再控制另一 fake `bk` | 两个目标区可写、对齐、链关系自洽 | 一次取得 AAF + 另一地址的 libc 指针写 | 与 TSU+ 同一 2.41 硬边界；两个输出可由其他原语组合获得，但不代表一次 stashing 双效果仍在。 |
| [Unsafe Unlink](./unsafe_unlink/README.md) | heap overflow 伪造 free chunk 并清 `PREV_INUSE` | `fd->bk==P && bk->fd==P`；2.26+/2.29+ size/prev_size 一致 | 改写受害者指针，升级为受约束 AAW | 本范围没有删除 unlink 消费路径；2.26、2.29 是必须补齐的不变量，属于适配。若题目只有单字段写而不能建双链，则从一开始就不满足前置。 |
| [Unsorted Bin Attack](./unsorted_bin_attack/README.md) | UAF 改 victim `bk` | 经典版目标任意初值；2.28+ 目标必须预先等于 victim | 向目标写 unsorted head/libc 指针 | 2.28 硬封“只改 `bk`、目标任意初值”的弱前置；赋值语句仍在，预置 `target==victim` 可到 2.43，但这应标**强约束残余**，不能冒充经典 AAW。 |
| [Unsorted Bin Into Stack](./unsorted_bin_into_stack/README.md) | UAF 改 `bk`；目标区 fake size | 经典单 fake node，不预建完整反向关系 | malloc 返回栈/全局地址 | 2.28 `bck->fd==victim` 封住单 fake-node 最小链。若先能写出完整自洽链，可转 Lore/受约束 unsorted，但那增加了接近 AAW 的前置。 |

## House of 系列

| 手法 | 最小输入原语 / 信息 | 关键环境与不变量 | 最终输出原语 | 版本边界应如何理解 |
|---|---|---|---|---|
| [House of Apple 1](./house_of_apple1/README.md) | 可控 FILE、wide data、`_IO_wstrnfile` 尾部；可触发对应宽输出 | libc leak；primary vtable/字段满足宽流检查 | 一次产生 8 个互相关联的已知地址指针写 | 2.37 删除 `_IO_wstrn_overflow/_IO_wstrn_jumps`，形成消费路径硬边界；其他已知值写不等于 Apple1 存活。 |
| [House of Apple 2](./house_of_apple2/README.md) | 能覆盖/投递 fake FILE 与 wide data；能触发 wide overflow | 合法 `_IO_wfile_jumps`；可控 fake wide vtable；x86-64 wide ABI | `doallocate(fp)` 间接调用/CF | 2.30、2.31 只改 `_wide_vtable` 偏移，属于适配；2.42 切断经典 largebin 投递，但最终触发点到 2.43 仍在。 |
| [House of Apple 3](./house_of_apple3/README.md) | 控制 FILE `_codecvt` 及 fake gconv step；触发宽字符 underflow | codecvt/step 三代布局；合法 primary vtable | codecvt 函数指针间接调用 | 2.30/2.31 是 ABI 适配；经典 largebin 2.42 结束只影响常见投递，不证明 codecvt 最终触发点失效。 |
| [House of Atum](./house_of_atum/README.md) | tcache/fastbin UAF、重复 free，能形成 count=0 但 entry 非空 | 2.29 需绕 key；依赖 malloc 只检查 `entries!=NULL` | 分配到 victim-0x10 并改原 chunk header | 2.30 malloc 改查 `counts>0`，原 entry/count desync 的弱前置硬失效。若还能写 count，就转为 metadata poisoning，不能说 Atum 原链只需调偏移。 |
| [House of Banana](./house_of_banana/README.md) | 能改 rtld 命名空间/`link_map` 指针并布置 fake map；libc/ld leak | 私有 `link_map` 布局、`l_real/l_init_called`、DT_FINI_ARRAY/SZ；exit | `_dl_fini` 调受控 fini array，获得 CF | 最终触发点持续到 2.43，但强依赖 Build ID；经典 largebin 投递止于 2.41。2.42+ 若另有 AAW 仍可用 Banana，这是投递断裂而非思想硬封。 |
| [House of Botcake](./house_of_botcake/README.md) | tcache UAF；能让 victim 与前块在 unsorted 合并 | 足够同尺寸块；绕 key；按 2.43 的 16-slot 重排 | overlap、重复引用，继续做 tcache poisoning | 2.26～2.43 是堆排布适配；key/full-bin 扫描没有删除“合并后再次 free 同一物理块”这条身份变化。 |
| [House of Cat](./house_of_cat/README.md) | fake FILE/wide data，能投递到可调用 `seekoff` 的流 | 合法偏移 primary vtable；wide vtable 不单独验证；调用约定可用 | 未检查 wide vtable 的 `__overflow(fp,WEOF)` 间接调用 | 三代 wide ABI 是适配；原题只验证 2.35，不代表最终触发点仅存在于 2.35。当前上游到 2.43 仍存活。 |
| [House of Corrosion](./house_of_corrosion/README.md) | 能写大 `global_max_fast`；fastbin UAF/double free；libc 地址泄露/相对布局 | 目标必须落在可由超大尺寸 fastbin 越界索引覆盖的 libc/ld 区域；与 Build ID 强相关 | 在 libc 内按相对偏移写入堆指针，以及“源槽→可编辑中转区→目标槽”的指针搬运 | 2.32 的 safe-linking 只是额外适配；2.37 将 `global_max_fast` 缩为 `uint8_t`，无法再用远端 fastbin 索引越过 `main_arena`，核心投递就此失效。2.27/2.29 完整链仍只对作者的构建负责。 |
| [House of Crust](./house_of_crust/README.md) | House of Rust 的 TSU/largebin 原语 + House of Corrosion 的 fastbin 指针搬运 + stderr FSOP | 特定自编译 2.32 的布局、gadget 和调用约定 | 无泄露组合链，最终取得 CF/RCE | 它不是一条独立的消费路径。2.37 先封堵 House of Corrosion 的超大尺寸 fastbin 指针搬运，2.41 再删除 TSU；2.34 起还要替换 hook 终点。组件仍可用，不等于完整 Crust 仍可用。 |
| [House of Einherjar](./house_of_einherjar/README.md) | off-by-null/overflow 改 `prev_size` 与 `PREV_INUSE`；堆地址泄露 | fake 前块的双向链完整，且 size/prev_size 一致；现代版本还需处理 tcache | 后向合并产生 overlap/AAF | 2.26、2.29、2.32、2.43 都只是检查或路由适配；fake 前块后向合并的核心思想到 2.43 仍可满足。 |
| [House of Emma](./house_of_emma/README.md) | 控制 cookie FILE/回调表并投递/触发；2.24+需 pointer_guard | 合法 `_IO_cookie_jumps`；回调参数与 mangle 正确 | cookie read/write/seek/close 间接调用 | 2.24 PTR_MANGLE 只是新增信息/编码前置；2.42 只切断经典 largebin 投递，cookie 最终触发点到 2.43 仍在。 |
| [House of Error](./house_of_error/README.md) | libc leak、fake memstream、能把流指针/链投向它 | 合法 section 内错位 vtable；`write_ptr!=write_end`；两目标可写 | 一次触发两个相关 qword 写 | `_IO_mem_sync` 最终触发点到 2.43 仍在；2.36 切断旧 assert 触发，2.42 切断 largebin 投递。第二次写受差值约束，不是两次独立 AAW。 |
| [House of Force](./house_of_force/README.md) | 覆盖 top `size` 为超大值；可发出计算后的大申请 | 目标在 top 线性地址空间；申请不能先被其他限制拒绝 | 下一次 malloc 落到近似任意前向地址 | 2.29 `top<=system_mem` 硬封超大环绕距离。缩小合法 top 后走 sysmalloc 仍可用，但输出变成 old-top 回收，应归 Tangerine/sysmalloc，而非 Force。 |
| [House of Fun](./house_of_fun/README.md) | 旧 largebin UAF 控制 `fd/bk/fd_nextsize/bk_nextsize` | 2.23～2.29 旧插入逻辑 | 多个 heap/libc 指针写 | 2.30 硬封旧四指针形式，但 2.30～2.41 可迁移到现代“更小 victim”Large Bin Attack；这是家族换实现。2.42 再封经典任意目标写。 |
| [House of Gods](./house_of_gods/README.md) | 原版：一个 unsorted UAF、heap/libc leak、可控 chunk 前 5 个 qword、若干任意 size 申请 | binmap qword 能作 size；main_arena 的 fastbin 重叠能继续 fake 链；能进入 `reused_arena` | 劫持 `thread_arena`/fake arena，控制后续分配 | 已严格实跑 2.23～2.25。2.26 主要是 tcache 路由+隐藏偏移的构建适配，不能把旧 PoC 原样外推。2.27 `have_fastchunks` 令 main_arena+8 不再是可用 size，且单线程 malloc 绕 thread_arena：原版弱前置链硬失效；已有 AAW 时仍可直接投递 fake arena，但那是更强实现。 |
| [House of Husk](./house_of_husk/README.md) | 能写两张隐藏 printf 表；有可控格式串触发 | `__printf_function_table/__printf_arginfo_table` 真实偏移、表项与参数 ABI | printf 解析时受控回调/CF | 最终触发点到 2.43 仍在；2.42 只封常用的经典 largebin 投递。隐藏偏移是 Build-ID 条件，局部写到“某个可写地址”不算成功。 |
| [House of Illusion](./house_of_illusion/README.md) | libc leak；能挂 fake FILE 到 `_IO_list_all`；可写对象/lock；可用 fd | 合法 `_IO_file_jumps` 或其 section 内 `-8`；2.40+ `_prevchain` | fd→目标 AAW + 目标→fd AAR，可串联 | 2.24 白名单允许 section 内部错位；2.40 是双链字段适配。上游 2.23～2.43 的消费路径持续存在；题目私有扩大校验属于环境变化。 |
| [House of IO](./house_of_io/README.md) | 能把 `tcache_perthread_struct` 当作 free chunk，或制造下溢；无需堆地址泄露 | 区分 2.29/2.30 的元数据布局；依赖 UAF 读取 `key` 泄露 tcache 地址 | 控制明文 `entries`，取得无堆地址泄露的 AAF | 2.34 将 `key` 改为随机值，原“`key` 就是元数据地址”的信息通道硬失效。若另有元数据地址泄露/AAW，仍可通过普通 metadata poisoning 取得相同输出，但那已不是原始 House of IO。 |
| [House of Kauri](./house_of_kauri/README.md) | UAF 改已释放 chunk size，再次 free 同一物理块 | 让第二次 free 落到另一 tcache bin；绕 key | 两个 bin 返回同一地址/overlap | 2.42 double-free 验证扫描所有 tcache bins，硬封“改 size 换 bin”身份绕过。清 key 或合并再 free 是其他 dup 手法。 |
| [House of Kiwi](./house_of_kiwi/README.md) | 能伪造/覆盖 stderr FILE；能破坏 top 触发 malloc assert | 旧 `__malloc_assert→__fxprintf/fflush(stderr)`；wide 布局正确 | 借错误路径触发 FSOP/CF | 2.36 assert 改走 `__libc_message`，Kiwi 专属消费路径硬失效；Apple/Cat 等正常 IO 最终触发点仍在，但不是 Kiwi 触发器。 |
| [House of Lemon](./house_of_lemon/README.md) | 写大 `global_max_fast`；free 超大 chunk；stdout 邻接目标；旧版可控 vtable | fastbin index 越界能到标准流；最终 vtable/trigger 可用 | OOB heap-pointer 写到 stdout 并劫持 CF | 2.24 先硬封 heap fake-vtable 终点，但 2.24～2.36 底层 OOB 投递仍可换目标；2.37 uint8_t `global_max_fast` 再硬封投递本身。必须分两层。 |
| [House of Lore](./house_of_lore/README.md) | UAF 改 smallbin `bk`；布置至少两组互指 fake chunk | 完整 fd/bk 反向关系、对齐；处理 tcache 容量 | malloc 返回栈/全局 fake chunk/AAF | 2.26 tcache、2.43 16-slot 都只是排布适配；safe-linking 不编码 smallbin 双链。到 2.43 核心仍可用。 |
| [House of Lys](./house_of_lys/README.md) | fake FILE + fake obstack；能挂到 exit/flush 链 | `_IO_obstack_jumps+0x20` 错位；残留 `rdx` 是可用长度 | `chunkfun(extra_arg,size)` 间接调用 | 2.37 删除旧 `_IO_obstack_xsputn` 消费路径，Lys 硬失效；2.37+ 可迁移到 Snake 的新 printf_buffer 消费路径，但应改名且前置不同。 |
| [House of Mind（Fastbin 版）](./house_of_mind/README.md) | heap/libc leak；对齐 fake heap_info/malloc_state；改 `NON_MAIN_ARENA`/arena | fake arena 的 fastbin 槽和 system_mem 可读写；现代 size 检查满足 | free 向 fake_arena.fastbinsY 写 heap 指针 | 2.27 后是完整 fake arena 适配，2.32 safe-linking 不影响第一写；2.43 删除 fastbin 消费路径，Fastbin 版硬失效。其他 arena 攻击不等于本版存活。 |
| [House of Muney](./house_of_muney/README.md) | 可申请 mmap 阈值以上 chunk 并改其 size/flags | 相邻映射、页对齐、`IS_MMAPPED`；重新映射地址受 ASLR | 跨 mmap 区域 overlap | 2.43 mmap header/layout 重写需要适配，但 munmap 过量区域→重映射思想仍成立。映射邻接是环境概率，不是版本保证。 |
| [House of Obstack](./house_of_obstack/README.md) | 可控 obstack FILE/对象，并能触发旧 printf 后端 | 使用合法 `_IO_obstack_jumps`；`chunkfun`/`extra_arg` 字段正确 | 经 `_obstack_newchunk→chunkfun` 间接调用 | 2.37 移除旧 libio obstack 后端，消费路径彻底消失；House of Snake 使用的是新路径，不是偏移修复。 |
| [House of Orange](./house_of_orange/README.md) | 覆盖 top size；无 free 触发 sysmalloc 回收 old top；unsorted 写；fake FILE | 2.23 可用任意 vtable，2.24/2.25 需合法 str vtable；malloc 报错时能 flush | 无显式 free 回收 old top，并通过 FSOP 取得 CF | 这是多段链：2.24 只封堵任意 vtable，可换合法表；2.26 删除 malloc-error→flush 触发；2.28 删除旧 str 回调；2.29 再封堵 House of Force 式 top。old top 回收本身仍是可用的 sysmalloc 原语。 |
| [House of Pig](./house_of_pig/README.md) | fake `_IO_strfile`/字段，能投递并触发 overflow；现代链还需可控复制源/长度 | 旧版尾部回调或 2.28+直接 malloc/memcpy/free；终点 Build-ID/RELRO | 旧版间接回调；现代版分配+拷贝+free 组合写/CF 链 | 2.28 不是简单偏移，而是从可控回调换成直接函数调用；现代 Pig 最终触发点到 2.43 仍在，但 2.34 hooks、2.42 largebin 分别切断旧终点和投递。 |
| [House of Rabbit](./house_of_rabbit/README.md) | fastbin UAF 把小 victim 指向大 fake chunk，可触发 consolidate | 跨 size fastbin 链在 consolidate 时不被 index/size 拒绝 | 把大 fake chunk 转入 unsorted/largebin，取得大范围 overlap | 2.27 fastbin size/index 一致性检查硬封经典跨尺寸链。改用真实同尺寸节点再造 overlap 是另一实现，不能只改偏移。 |
| [House of Roman](./house_of_roman/README.md) | 无完整泄露；fastbin/tcache 相对覆盖 + unsorted 写 + 低位猜测 | hook 仍消费；经典 unsorted 目标无需预置；ASLR 低位命中 | 无完整 libc 地址下把分配导向 hook 并低字节 CF | 2.26/2.27 可通过 tcache 重排，属适配；2.28 硬封经典 unsorted 中段，所以完整 Roman 止于 2.27。额外预置 target/AAW 会破坏其“弱泄露”前提。 |
| [House of Rust](./house_of_rust/README.md) | TSU+、TSU、两次现代 largebin、stdout FSOP；原版无需堆地址泄露 | 绕过 safe-linking；精确控制堆布局；使用匹配 2.32 的构建与终点 | 无泄露地控制 libc/heap，并取得 RCE | 原版完整链只验证到 2.32。2.34 起 hook 终点失效，但可研究替代终点；2.41 删除 TSU 消费路径后，组合链的核心失效。组件仍可用，不等于完整 Rust 仍可用。 |
| [House of Snake](./house_of_snake/README.md) | 能影响 `__printf_buffer_obstack` 所持 obstack 并触发 printf flush | 2.37+ 新 printf_buffer 后端；chunkfun ABI 正确 | `_obstack_newchunk→chunkfun` 间接调用 | 2.37 才引入该消费路径；更早版本应使用 Obstack/Lys。到 2.43 最终触发点仍在，投递方式取决于题目。 |
| [House of Some](./house_of_some/README.md) | libc leak；已知可写区；一次 libc 内指针写挂 FILE 链；退出/flush | 合法 primary 与 section 内 shifted wide vtable；2.40+维护 prevchain | W primitive，可编排 RWRWR、泄露 environ/栈并写 ROP | 2.30/2.31 wide ABI 和 2.40 双链是适配；消费路径到 2.43 仍在。完整 RWRWR 的交互顺序、栈偏移和 ROP 仍题目相关。 |
| [House of Spirit](./house_of_spirit/README.md) | 控制被 free 的非 heap 指针及 fake size | 目标 0x10 对齐；fastbin 版需邻接 size/处理 tcache；tcache 版检查更少 | malloc 返回栈/全局 fake chunk/AAF | fastbin 子型 2.43 随 fastbin 硬删除；tcache 子型 2.26～2.43 持续。因此“Spirit 整体失效”是错误说法。 |
| [House of Storm](./house_of_storm/README.md) | 同时 UAF 控制 unsorted 与 largebin 节点 | 交叉 fd/bk/nextsize 链、目标附近 fake size；旧 unsorted 无需反向预置 | 在目标附近生成可分配 fake chunk/AAF | 2.28 首道 `bck->fd==victim` 使第二轮 fake-victim 摘链不自洽，经典弱前置链硬失效。用额外 AAW 补整套反向关系会变成更强 Lore/largebin 组合。 |
| [House of Tangerine](./house_of_tangerine/README.md) | 覆盖 top 元数据并反复申请大块；具备 tcache UAF/poison 能力 | 利用 sysmalloc 让 old top 进入 tcache；2.32+ 需堆地址泄露来编码；2.43 按新布局适配 | 从 top 制造 tcache chunk，再取得 AAF | 2.29 封堵 House of Force，但没有封堵合法缩小 top；2.43 删除 fastbin 也不影响 top+tcache 核心。各版本只需实现适配。 |
| [House of Water](./house_of_water/README.md) | tcache UAF/double free；可精确修改 `counts`/`entries` 附近字节 | 利用元数据自身的值形成 fake chunk，并接入 unsorted/libc 指针；按版本适配布局 | 无地址泄露地控制 tcache 元数据，并获得 libc/heap 指针 | 2.32 是这套布局和技巧的定义起点；2.42/2.43 需要适配元数据布局，核心思想到 2.43 仍可满足。 |

## 不能写成“通用可用/绝对不可用”的区间

这些条目有明确的子原语结论，但缺少跨构建端到端证据。保留“不承诺”比制造统一版本范围更准确：

| 手法/区间 | 已确定 | 尚不能承诺 |
|---|---|---|
| House of Gods 2.26 | tcache 路由和隐藏 `narenas` 偏移是可迁移问题；arena/reused_arena 消费路径仍在 | 尚无本项目默认 stock 2.26 的原版最小前置严格 PoC，故既不标“通用可用”，也不标“思想失效” |
| Corrosion 2.30～2.36 | 超大尺寸 fastbin 越界索引的结构窗口尚在；2.37 才由 uint8_t 硬封 | 没有作者发布的这些版本完整链；safe-linking、投递与终点均需重做 |
| Crust 2.33～2.36 | 三个组件在源码上有共同窗口 | 原作者连不同 2.32 自编译构建都只有部分成功，不能外推完整 RCE |
| Rust 2.33～2.40 | TSU+/TSU/现代 largebin 组件仍在，2.41 明确结束 | 2.34+ 原 hook 终点已失效；没有验证替代终点，就不能称为完整 Rust |
| Pig PLUS 2.34～2.41 | `_IO_str_overflow` 数据流仍在 | memset IFUNC/GOT 可写性、RELRO、地址与最终消费均绑定 Build ID |
| Banana/Husk/Emma/Apple/Cat/Error 的高版本 | 各自 rtld/printf/FILE 最终触发点可单独到 2.43 | 经典 largebin 或 assert 触发失效后，必须由题目另给 AAW/FILE 投递；最终触发点 PoC 不是端到端 heap exploit |
| House of Muney 全范围 | mmap size/munmap/re-map 消费路径持续，2.43 布局已有分支 | 地址邻接和重新映射命中受 ASLR、mmap 阈值与进程映射状态影响，不是版本号保证 |

## 实战判断顺序

拿到题目后，不要先按版本号背手法，按下面顺序裁剪：

1. 写出题目真正提供的最小漏洞原语：能改已释放还是仅未释放 chunk、字节数、是否可重复、是否有 show/leak。
2. 确认目标消费路径是否仍在对应 Build ID：fastbin、smallbin stashing loop、旧 assert→stdio、具体 FILE/obstack 回调。
3. 把所有新增检查写成等式，例如 `bck->fd==victim`、`fd->bk==P`、encoded next、target 初值。逐项标出题目现有能力能否满足。
4. 若“绕过”要求先取得与输出等价的 AAW/AAF，应改记为另一手法的投递，不要宣称原弱前置 attack 仍通用。
5. 最后才选择终点：hooks、FILE、rtld、printf tables、environ/stack 与 ROP。终点变化不能反向修改堆原语的版本结论。

每个目录 README 给出对应源码函数、提交与可执行 PoC；提交级总览见 [SOURCE_TIMELINE.md](./SOURCE_TIMELINE.md)，正向/负向实跑记录见 [VALIDATION.md](./VALIDATION.md)。
