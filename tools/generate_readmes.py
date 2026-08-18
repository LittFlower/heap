#!/usr/bin/env python3
"""生成基础分配器/核心 House 目录的 README。

内容数据是人工整理的源码结论；脚本只负责统一排版和枚举 PoC 文件。
"""

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
GLIBC = "https://github.com/bminor/glibc/blob"
COMMITS = "https://sourceware.org/git/?p=glibc.git;a=commit;h="


DATA = {
    "fastbin_dup": {
        "title": "Fastbin Dup",
        "range": "2.23～2.42；2.43 失效",
        "effect": "通过 A→B→A 的 double free 环，让两个活动指针别名到同一 chunk。",
        "requirements": "double free；2.26+ 还要能避开或耗尽 tcache；2.32+ 的后续链投毒需要堆地址泄露。",
        "changes": [
            "2.26 引入 tcache：free 默认先进入 tcache，PoC 用填满 tcache 与 `calloc` 绕到 fastbin。",
            "2.41 的 `calloc` 也走 tcache 快路径，必须在取 fastbin 前显式耗尽 tcache。",
            "2.43 开发分支提交 `bf1015f` 删除 fastbin 的分配与释放路径，A→B→A 不再可消费。",
        ],
        "source": "`_int_free_chunk` 的 fastbin 入链、`_int_malloc` 的 fastbin 出链，以及 2.43 删除它们的提交。",
        "links": [("glibc 2.42 malloc.c", f"{GLIBC}/glibc-2.42/malloc/malloc.c"), ("2.43 fastbin 删除", f"{COMMITS}bf1015fb2d7e4057925481960626533f8571a2fb")],
    },
    "fastbin_dup_into_stack": {
        "title": "Fastbin Dup Into Stack",
        "range": "2.23～2.42；2.43 失效",
        "effect": "把 fastbin 的后继改到栈/全局区 fake chunk，取得近似任意地址分配。",
        "requirements": "double free + UAF 写 fd；目标 0x10 对齐；使用 calloc 时目标附近需有匹配 size。",
        "changes": ["2.26 起先处理 tcache。", "2.32 引入 `PROTECT_PTR` 与对齐检查，fd 需写成 `(pos >> 12) ^ target`。", "2.33 示例把返回点移到 fake header 后 0x10，以免 calloc 清零破坏 fake size。", "2.41 calloc/tcache 顺序改变；2.43 fastbin 消失。"],
        "source": "`REMOVE_FB`、`fastbin_index(chunksize(victim))` 与 `aligned_OK` 决定 fake chunk 能否被取出。",
        "links": [("safe-linking 提交", f"{COMMITS}a1a486d70ebcc47a686ff5846875eacad0940e41"), ("2.41 calloc tcache 提交", f"{COMMITS}226e3b0a413673c0d6691a0ae6dd001fe05d21cd")],
    },
    "fastbin_dup_consolidate": {
        "title": "Fastbin Dup Consolidate",
        "range": "2.23～2.42；2.43 失效",
        "effect": "令同一 chunk 同时可从 fastbin 与合并后的 top/unsorted 路径取出。",
        "requirements": "double free 或可制造重复引用，并能触发 `malloc_consolidate`。",
        "changes": ["2.26+ 需要处理 tcache。", "2.32 的 safe-linking 不改变该 PoC 的核心，因为它不伪造任意 fd。", "2.43 fastbin 收发路径删除，无法保留 fastbin 中的第二份引用。"],
        "source": "`malloc_consolidate` 遍历 fastbins 并执行前后合并，而 fastbin chunk 平时保持 in-use 语义。",
        "links": [("glibc 2.42 malloc_consolidate", f"{GLIBC}/glibc-2.42/malloc/malloc.c"), ("2.43 fastbin 删除", f"{COMMITS}bf1015fb2d7e4057925481960626533f8571a2fb")],
    },
    "fastbin_reverse_into_tcache": {
        "title": "Fastbin Reverse Into Tcache",
        "range": "2.26～2.42；2.43 失效",
        "effect": "借 fastbin→tcache stash 产生受控元数据写，并把目标地址放进 tcache。",
        "requirements": "UAF 修改 fastbin `fd`、堆地址泄露（2.32+）、可填满并耗尽 tcache。",
        "changes": ["2.26～2.31 是明文 fd。", "2.32～2.41 fastbin fd 使用 safe-linking。", "2.42 large-tcache 链中间 next 槽可被 mangling（metadata 头仍为明文），且 stash 时增加 chunk-size 一致性检查。", "2.43 `_int_malloc` 不再从 fastbin 分配。"],
        "source": "`_int_malloc` 的 fastbin 分支在返回 victim 前将剩余同尺寸节点 `tcache_put`。",
        "links": [("2.42 malloc.c", f"{GLIBC}/glibc-2.42/malloc/malloc.c"), ("2.42 前置 size 检查", f"{COMMITS}d10176c0ffeadbc0bcd443741f53ebd85e70db44")],
    },
    "unsorted_bin_attack": {
        "title": "Unsorted Bin Attack",
        "range": "2.23～2.27；2.28 起经典形式失效",
        "effect": "向目标写入 `unsorted_chunks(av)`；2.23～2.27 target 初值任意，2.28+ 要求 target 预置 victim。",
        "requirements": "UAF 改写 unsorted victim 的 `bk`；2.28+ 另需建立 `target == victim_chunk`。",
        "changes": ["2.23～2.27 摘链时信任 `victim->bk`，可令 `bck->fd` 指向任意初值 target。", "2.28 提交 `bdc3009` 检查 `bck->fd == victim`，经典无条件单指针写结束；2.29 再加入 next-size 等检查。"],
        "source": "unsorted 遍历中的 `bck = victim->bk; if (bck->fd != victim) ...; bck->fd = unsorted_chunks(av)`。",
        "links": [("2.28 首次 harden removal", f"{COMMITS}bdc3009b8ff0effdbbfb05eb6b10966753cbf9b8"), ("2.29 后续加固", f"{COMMITS}b90ddd08f6dd688e651df9ee89ca3a69ff88cd0c")],
    },
    "unsorted_bin_into_stack": {
        "title": "Unsorted Bin Into Stack",
        "range": "2.23～2.27；2.28 起失效",
        "effect": "让 malloc 从伪造在栈/全局区的 unsorted 节点返回地址。",
        "requirements": "UAF 改 `bk`，并在目标附近布置可通过 size 判断的 fake chunk。",
        "changes": ["2.28 新增 `bck->fd == victim`，经典单 fake node 无法通过；2.29 再加入 next-size 等检查。"],
        "source": "unsorted first-fit 分支在精确大小匹配后将 `chunk2mem(victim)` 返回。",
        "links": [("2.28 malloc.c", f"{GLIBC}/glibc-2.28/malloc/malloc.c"), ("2.29 加固", f"{COMMITS}b90ddd08f6dd688e651df9ee89ca3a69ff88cd0c")],
    },
    "large_bin_attack": {
        "title": "Large Bin Attack",
        "range": "2.23～2.41；2.42 起经典 `bk_nextsize` 写失效",
        "effect": "把新插入 victim 的堆地址写到目标。",
        "requirements": "UAF 改写 largebin 节点的 `bk_nextsize`；两个属于同一 largebin 且大小有序的 chunk。",
        "changes": ["2.30 以前可同时改 `bk` 与 `bk_nextsize`，写条件更宽松。", "2.30～2.41 使用“比当前最小节点更小”的插入分支，只需劫持最小节点的 `bk_nextsize`。", "2.42 提交 `4cf2d86` 增加 `fwd->fd->bk_nextsize->fd_nextsize == fwd->fd`，目标不再能只是任意可写地址。"],
        "source": "`_int_malloc` 将 unsorted victim 排入 largebin 时维护 `fd_nextsize/bk_nextsize` 的分支。",
        "links": [("2.41 malloc.c", f"{GLIBC}/glibc-2.41/malloc/malloc.c"), ("2.42 nextsize 检查", f"{COMMITS}4cf2d869367e3813c6c8f662915dedb1f3830c53")],
    },
    "tcache_dup": {
        "title": "Tcache Dup",
        "range": "2.26～2.28；2.29 起直接 double free 失效",
        "effect": "同一 chunk 多次从 tcache 返回。",
        "requirements": "能够对同一悬挂指针连续 free。",
        "changes": ["2.26 初版 tcache 没有 double-free key。", "2.29 提交 `bcdaad2` 给 `tcache_entry` 增加 key，并在疑似重复释放时遍历该 bin。"],
        "source": "`tcache_put` 写 `e->key`；`_int_free` 比较 key 后遍历链表。",
        "links": [("tcache 引入", f"{COMMITS}d5c3fafc4307c9b7a4c7d5cb381fcdbfad340bcc"), ("double-free 检查", f"{COMMITS}bcdaad21d4635931d1bd3b54a7894276925d081d")],
    },
    "tcache_poisoning": {
        "title": "Tcache Poisoning",
        "range": "2.26～2.43",
        "effect": "覆盖 tcache `next` 后获得任意 0x10 对齐地址分配。",
        "requirements": "UAF/重叠写；2.32+ 需要泄露 next 的存储地址所在 heap page。",
        "changes": ["2.26～2.31 直接写 target。", "2.32 起写 `PROTECT_PTR(&e->next, target)`，并检查取出地址对齐。", "2.42 large tcache 为有序链；metadata 头仍为明文，chunk 内 next/链中间槽才 mangled。"],
        "source": "`tcache_put_n/tcache_get_n` 的 PROTECT_PTR/REVEAL_PTR。",
        "links": [("safe-linking 提交", f"{COMMITS}a1a486d70ebcc47a686ff5846875eacad0940e41"), ("2.42 tcache large bins", f"{COMMITS}cbfd7988107b27b9ff1d0b57fa2c8f13a932e508")],
    },
    "tcache_metadata_poisoning": {
        "title": "Tcache Metadata Poisoning",
        "range": "2.26～2.43；偏移随版本变化",
        "effect": "直接篡改 tcache_perthread_struct，控制某尺寸下一次返回地址。",
        "requirements": "对 tcache 元数据的堆溢出、重叠或 UAF。",
        "changes": ["2.30 前 counts 是 `char`，2.30 起为 `uint16_t`。", "2.42 counts 改成向下计数的 `num_slots`，small+large 共 76 bins；entries 头为明文。", "2.43 tcache 使用 TLS inactive/disabled 哨兵且结构位置改变，示例索引不同。"],
        "source": "`tcache_perthread_struct`、`tcache_put_n`、`tcache_get_n`。",
        "links": [("2.41 malloc.c", f"{GLIBC}/glibc-2.41/malloc/malloc.c"), ("2.42 count down", f"{COMMITS}7e10e30e64aa2cc8ba50f2f83cb7cc2cdad134ad"), ("2.42 large tcache", f"{COMMITS}cbfd7988107b27b9ff1d0b57fa2c8f13a932e508")],
    },
    "tcache_metadata_hijacking": {
        "title": "Tcache Metadata Hijacking（延迟初始化）",
        "range": "2.42～2.43",
        "effect": "把 tcache_perthread_struct 放到攻击者大块之后，再用顺向溢出改 entries。",
        "requirements": "tcache 初始化前先走非 tcache 大块分配；可溢出到后续元数据。",
        "changes": ["2.42 重构取消部分非 tcache 路径中的 `MAYBE_INIT_TCACHE`，tcache 不再必定位于 heap 顶部。", "2.43 tcache 结构/TLS 哨兵使目标 entry 相对偏移从示例的 21 个 qword 变为 25 个 qword。"],
        "source": "`tcache_init` 调用时机与 `tcache_perthread_struct` 的 2.42/2.43 布局。",
        "links": [("2.42 large tcache/初始化重构", f"{COMMITS}cbfd7988107b27b9ff1d0b57fa2c8f13a932e508"), ("2.42 malloc.c", f"{GLIBC}/glibc-2.42/malloc/malloc.c")],
    },
    "tcache_stashing_unlink_attack": {
        "title": "Tcache Stashing Unlink Attack（Smallbin Attack）",
        "range": "2.26～2.40；2.41 起该 PoC 失效",
        "effect": "任意地址写 main_arena 指针，并可把假节点 stash 到 tcache 后分配。",
        "requirements": "控制 smallbin 的 `bk`；目标附近可写；对应 tcache 为空；常用 calloc 触发。",
        "changes": ["2.26～2.39/2.40 利用 smallbin→tcache 预填充循环。", "2.32+ 目标必须对齐，但 smallbin 双链本身不使用 safe-linking。", "2.41 提交 `e2436d6` 重构释放小块/预填充流程，how2heap 不再提供该 PoC。"],
        "source": "smallbin 精确大小分支中的 tcache stashing 循环及 `bck->fd` 更新。",
        "links": [("2.40 malloc.c", f"{GLIBC}/glibc-2.40/malloc/malloc.c"), ("2.41 smallbin 重构", f"{COMMITS}e2436d6f5aa47ce8da80c2ba0f59dfb9ffde08f3")],
    },
    "tcache_relative_write": {
        "title": "Tcache Relative Write",
        "range": "2.30～2.41；2.42 元数据重构后失效",
        "effect": "把 tcache 计数或 chunk 指针作为受限值写到相邻 heap 目标。",
        "requirements": "相对越界到 tcache_perthread_struct，且知道目标相对偏移。",
        "changes": ["2.30/2.31 的 counts 为 16 位。", "2.32 增加 safe-linking。", "2.35 和 2.38 的 tcache 元数据在初始化/分配细节上有偏移调整。", "2.42 counts 改为向下计数 `num_slots` 且结构扩成 76 bins，旧原语终止。"],
        "source": "tcache 结构内 counts/entries 的相邻布局和 get/put 的增减操作。",
        "links": [("2.41 malloc.c", f"{GLIBC}/glibc-2.41/malloc/malloc.c"), ("2.42 count-down", f"{COMMITS}7e10e30e64aa2cc8ba50f2f83cb7cc2cdad134ad")],
    },
    "safe_linking": {
        "title": "Safe-Linking 配套原语",
        "range": "2.32～2.43",
        "effect": "恢复受保护的 heap 指针，或通过 double-protect 无泄露地重新链接。",
        "requirements": "至少泄露编码指针；double-protect 还需要控制 tcache 元数据/链表。",
        "changes": ["2.32 将 `(pos >> 12) ^ ptr` 用于 fastbin/tcache 单链，并检查 0x10 对齐。", "2.42 引入 `tcache_put_n/get_n` 和 large tcache 后，`entries[idx]` 头指针仍是明文；只有 chunk `next` 链中间槽按存储地址保护。double-protect 的 metadata 索引改变。", "2.43 tcache TLS 哨兵/布局再变，使用独立 PoC。"],
        "source": "`PROTECT_PTR` 与 `REVEAL_PTR` 宏，以及 `tcache_put_n/get_n`。",
        "links": [("safe-linking 提交", f"{COMMITS}a1a486d70ebcc47a686ff5846875eacad0940e41"), ("2.43 开发分支 malloc.c", f"{GLIBC}/master/malloc/malloc.c")],
    },
    "unsafe_unlink": {
        "title": "Unsafe Unlink（现代约束版）",
        "range": "2.23～2.43",
        "effect": "借后向合并改写一个受害者指针，进而形成可控写。",
        "requirements": "溢出伪造 free chunk、清 PREV_INUSE，并满足 `fd->bk == P && bk->fd == P`。",
        "changes": ["现代 glibc 均有双向链检查，因此不再是古早任意 `FD/BK` 的无条件两次写。", "2.29 增加 `chunksize(p) == prev_size(next_chunk(p))`，off-by-null 链需额外伪造/合并。", "该双链 unlink 本身不使用 safe-linking，故 2.32 不会直接封堵它。"],
        "source": "`unlink_chunk` 的 size/prev_size 与 fd/bk 两组一致性检查。",
        "links": [("2.43 开发分支 unlink_chunk", f"{GLIBC}/master/malloc/malloc.c"), ("2.29 null-byte 加固", f"{COMMITS}d6db68e66dff25d12c3bc5641b60cbd7fb6ab44f")],
    },
    "house_of_spirit": {
        "title": "House of Spirit",
        "range": "整体 2.23～2.43；fastbin 子型止于 2.42，tcache 子型始于 2.26",
        "effect": "free 非堆 fake chunk 后，让 malloc 返回栈/全局区地址。",
        "requirements": "能控制待 free 指针与 fake size；x86-64 目标 0x10 对齐。",
        "changes": ["2.23～2.25 使用 fastbin fake chunk，并准备合法 next-size。", "2.26+ 可用检查更少的 tcache spirit；fastbin 版需先填 tcache。", "2.41 fastbin 版取出前需耗尽 tcache；2.43 fastbin 版消失，但 tcache 版仍可用。"],
        "source": "`_int_free_check`、tcache fast path 和 fastbin next-size 检查。",
        "links": [("2.42 malloc.c", f"{GLIBC}/glibc-2.42/malloc/malloc.c"), ("2.43 fastbin 删除", f"{COMMITS}bf1015fb2d7e4057925481960626533f8571a2fb")],
    },
    "house_of_einherjar": {
        "title": "House of Einherjar",
        "range": "2.23～2.43",
        "effect": "off-by-null 触发伪造后向合并，制造 chunk overlap/任意分配。",
        "requirements": "off-by-null、堆地址泄露、可伪造前块双向链；高版本还需 tcache 链投毒。",
        "changes": ["2.23～2.28 主要绕过 unlink 双链检查。", "2.29 起还要满足 fake chunk size 等于后一块 prev_size。", "2.32 起 tcache poisoning 需要 safe-linking 编码。", "2.43 因 tcache 元数据布局变化调整布局，但原理仍成立。"],
        "source": "`_int_free_merge_chunk` 的 PREV_INUSE 分支与 `unlink_chunk`。",
        "links": [("2.29 null-byte 加固", f"{COMMITS}d6db68e66dff25d12c3bc5641b60cbd7fb6ab44f"), ("2.43 malloc.c", f"{GLIBC}/master/malloc/malloc.c")],
    },
    "house_of_force": {
        "title": "House of Force",
        "range": "2.23～2.28；2.29 起失效",
        "effect": "通过 top chunk 的环绕距离使下一次 malloc 落到近似任意地址。",
        "requirements": "可覆盖 top->size，且能提出超大但不触发别的限制的申请。",
        "changes": ["2.29 提交 `30a17d8` 在使用 top 前验证 `size <= av->system_mem`；把 size 改为 -1 会直接报 `corrupted top size`。"],
        "source": "`_int_malloc` 使用 top 的分支。",
        "links": [("2.28 malloc.c", f"{GLIBC}/glibc-2.28/malloc/malloc.c"), ("top-size 修复", f"{COMMITS}30a17d8c95fbfb15c52d1115803b63aaa73a285c")],
    },
    "house_of_lore": {
        "title": "House of Lore / Small Bin Attack",
        "range": "2.23～2.43",
        "effect": "控制 smallbin 双链后在栈/全局区取得 fake chunk 分配。",
        "requirements": "UAF 改 victim->bk；布置至少两组相互引用的 fake chunk；目标对齐。",
        "changes": ["所有版本都要求摘链一致性（现代 PoC 显式构造 `victim->fd->bk == victim`）。", "2.26+ tcache 会截走同尺寸 free，需先填满对应 tcache。", "2.41 smallbin→tcache stash 重构影响 TSU，但直接 smallbin 摘链的 Lore 仍可用。", "2.43 fastbin 删除与本手法无关。"],
        "source": "`_int_malloc` 的 smallbin 精确大小分支及 `unlink_chunk`。",
        "links": [("2.43 malloc.c", f"{GLIBC}/master/malloc/malloc.c")],
    },
    "house_of_orange": {
        "title": "House of Orange（经典链）",
        "range": "2.23～2.25；2.26 起经典端到端链失效",
        "effect": "无 free 地回收旧 top，再经 `_IO_list_all` FSOP 劫持执行流。",
        "requirements": "top size overflow、unsorted metadata 写、可伪造 FILE。",
        "changes": ["2.24/2.25 需使用落在合法 vtable 区间内的 `_IO_str_jumps` 变体。", "2.26 的 abort/stdio 清理路径变化使经典触发链失效。", "即使只保留 top 技巧，2.29 的 top-size 检查也会封堵。"],
        "source": "`sysmalloc` 处理旧 top、unsorted 摘链、libio vtable 验证与 abort 清理路径。",
        "links": [("2.25 malloc.c", f"{GLIBC}/glibc-2.25/malloc/malloc.c"), ("2.26 stdlib/abort.c", f"{GLIBC}/glibc-2.26/stdlib/abort.c")],
    },
    "house_of_roman": {
        "title": "House of Roman",
        "range": "2.23～2.27；2.28 起经典链失效",
        "effect": "在无完整地址泄露时，用相对覆盖把 fake fastbin 导向 hook。",
        "requirements": "UAF/溢出、fastbin attack、unsorted-bin attack、若干低位地址猜测。",
        "changes": ["2.23～2.25 使用原 fastbin 路径。", "2.26～2.27 改为 count=3 tcache 链，并用 calloc 处理 exact-size unsorted victim。", "2.28 的 bdc3009 `bck->fd==victim` 检查切断 hook 投递。", "2.34 又删除 malloc/free hooks。"],
        "source": "fastbin freelist、unsorted `bck->fd` 写和 `__malloc_hook` 调用点的组合。",
        "links": [("2.26 tcache", f"{COMMITS}d5c3fafc4307c9b7a4c7d5cb381fcdbfad340bcc"), ("2.28 unsorted 加固", f"{COMMITS}bdc3009b8ff0effdbbfb05eb6b10966753cbf9b8"), ("2.34 hooks 删除", f"{GLIBC}/glibc-2.34/malloc/malloc.c")],
    },
    "house_of_storm": {
        "title": "House of Storm",
        "range": "2.23～2.27；2.28 起失效",
        "effect": "组合 unsorted 与 largebin 元数据，在目标附近生成可分配 fake chunk。",
        "requirements": "同时 UAF 控制一个 unsorted chunk 与一个 largebin chunk。",
        "changes": ["2.26～2.27 需填满对应 tcache 并用 calloc 绕前端快速路径。", "2.28 的 bdc3009 使第二次 fake-victim 摘链无法满足 bck->fd==victim。", "不要同 2.30+ 的单独 largebin attack 混淆。"],
        "source": "unsorted 摘链写与 largebin nextsize 插入写的交叉结果。",
        "links": [("2.28 首次 unsorted 加固", f"{COMMITS}bdc3009b8ff0effdbbfb05eb6b10966753cbf9b8"), ("2.28 malloc.c", f"{GLIBC}/glibc-2.28/malloc/malloc.c")],
    },
    "house_of_mind": {
        "title": "House of Mind（Fastbin 版）",
        "range": "2.23～2.42；2.43 失效",
        "effect": "伪造 heap_info/malloc_state，让 free 向任意 fake_arena.fastbinsY 槽写堆指针。",
        "requirements": "heap/libc 泄露、大量对齐布局、单字节/元数据覆盖 NON_MAIN_ARENA 与 arena。",
        "changes": ["2.27 后 arena/size 检查要求更严，PoC 使用更完整 fake arena。", "2.32 fastbin fd safe-linking 不影响“arena 槽写 victim”的第一步。", "2.37 global_max_fast 变成 uint8_t，但正常 fastbin 尺寸仍够用。", "2.43 删除 fastbin 分配/释放路径，fastbin 版本终止。"],
        "source": "`heap_for_ptr`/`arena_for_chunk` 与 `_int_free_chunk` 选择 `av->fastbinsY[idx]` 的路径。",
        "links": [("2.42 malloc.c", f"{GLIBC}/glibc-2.42/malloc/malloc.c"), ("2.43 fastbin 删除", f"{COMMITS}bf1015fb2d7e4057925481960626533f8571a2fb")],
    },
    "house_of_gods": {
        "title": "House of Gods",
        "range": "2.23～2.26；2.27 起失效",
        "effect": "劫持 `thread_arena` 到 fake arena，随后控制该线程的分配。",
        "requirements": "heap/libc 泄露、任意大小申请、可改 main_arena.next/system_mem/narenas。",
        "changes": ["2.23 与 2.24～2.26 的 arena 字段偏移/布局略有区别。", "glibc 2.27 的 arena/fastbin 一致性加固使 how2heap 将范围标为 `< 2.27`；参考文章表格写到 2.27 是边界歧义，本表按实际 PoC 与源码取 2.26 为末版。"],
        "source": "`reused_arena`、`arena_get_retry`、thread_arena 与 fake malloc_state。",
        "links": [("2.26 arena.c", f"{GLIBC}/glibc-2.26/malloc/arena.c"), ("上游原始说明", "https://github.com/Milo-D/house-of-gods")],
    },
    "house_of_botcake": {
        "title": "House of Botcake",
        "range": "2.26～2.43",
        "effect": "绕过 tcache double-free 检测并制造可反复利用的 chunk overlap/poisoning。",
        "requirements": "UAF；约 8～10 个同尺寸 chunk；能让 victim 与前块在 unsorted 合并。",
        "changes": ["2.26～2.31 使用明文 tcache next。", "2.32 起覆盖 victim->next 时必须 safe-linking 编码。", "2.34 tcache key 改随机值不封堵本法，因为第二次 free 前 victim 已随合并离开原 tcache 语义。", "2.42/2.43 tcache 元数据变化后仍有对应 PoC。"],
        "source": "tcache key 检查只搜索当前 bin；unsorted 后向合并改变覆盖范围。",
        "links": [("2.43 malloc.c", f"{GLIBC}/master/malloc/malloc.c"), ("2.29 tcache double-free 检查", f"{COMMITS}bcdaad21d4635931d1bd3b54a7894276925d081d")],
    },
    "house_of_io": {
        "title": "House of IO",
        "range": "原始 PoC 2.31～2.33；2.34 起失效",
        "effect": "控制 `tcache_perthread_struct` 中未编码的 `entries`，无需堆地址泄露即可任意分配。",
        "requirements": "能把 tcache 管理结构当作 free chunk（特定 underflow/UAF/错误 free）。",
        "changes": ["2.32 safe-linking 只保护 chunk 内 next，不保护当时的 tcache entries 头，因此形成旁路。", "2.34 tcache key 改为随机进程值并调整相关初始化/检查；how2heap 的原始链范围止于 2.33。", "2.42 后出现的是不同的 metadata hijacking，不应继续称原始 House of IO。"],
        "source": "2.31～2.33 `tcache_entry.key=tcache` 与明文 `tcache->entries[idx]`。",
        "links": [("2.33 malloc.c", f"{GLIBC}/glibc-2.33/malloc/malloc.c"), ("2.34 malloc.c", f"{GLIBC}/glibc-2.34/malloc/malloc.c")],
    },
    "house_of_water": {
        "title": "House of Water",
        "range": "2.32～2.43",
        "effect": "无地址泄露地控制 tcache 元数据，并把 libc/unsorted 指针链入 tcache。",
        "requirements": "UAF 或 double free；能精确控制 tcache counts/entries 附近字节。",
        "changes": ["最低版本 2.32，因为手法的目标就是 leakless 绕过 safe-linking。", "2.42 tcache 改为 76 bins、num_slots 向下计数和大块缓存，布局独立。", "2.43 TLS inactive/disabled 哨兵与结构位置变化，再用独立 PoC。"],
        "source": "tcache_perthread_struct 字节布局与 unsorted 链写入的组合。",
        "links": [("2.42 malloc.c", f"{GLIBC}/glibc-2.42/malloc/malloc.c"), ("2.43 malloc.c", f"{GLIBC}/master/malloc/malloc.c")],
    },
    "house_of_tangerine": {
        "title": "House of Tangerine",
        "range": "2.26～2.43",
        "effect": "利用受损 top/sysmalloc 产生 tcache chunk，再 poisoning 到任意地址。",
        "requirements": "覆盖 top 元数据、可反复申请大块；2.32+ 需要堆地址泄露来编码 `next`。",
        "changes": ["2.26～2.30 是明文 tcache 链。", "2.31 的 sysmalloc/top 排布有独立调整。", "2.32～2.41 使用 safe-linking。", "2.42 大 tcache 和 top/tcache 初始化重构需要独立 PoC。", "2.43 虽删除 fastbin，但本手法以 top+tcache 为核心，调整后仍可用。"],
        "source": "`sysmalloc` 的 fencepost/旧 top 处理与 tcache_put/get。",
        "links": [("2.43 malloc.c", f"{GLIBC}/master/malloc/malloc.c"), ("2.42 tcache large bins", f"{COMMITS}cbfd7988107b27b9ff1d0b57fa2c8f13a932e508")],
    },
    "house_of_muney": {
        "title": "House of Muney / Mmap Overlap",
        "range": "mmap overlap 原语 2.23～2.43",
        "effect": "扩大 mmapped chunk 的 size，munmap 超额区域后重新映射，制造跨映射重叠。",
        "requirements": "申请 mmap 阈值以上 chunk；能改其 size 且保留 IS_MMAPPED；映射位置满足相邻关系。",
        "changes": ["2.29 前后 ptmalloc 主链加固与该原语关系不大。", "2.43 `munmap_chunk` 的页对齐/映射检查仍允许 PoC 构造的合法扩大范围。", "完整“steal libc mapping”高度依赖 ASLR、内核 mmap 布局和目标 ELF，目录 PoC 只把稳定的 overlap 原语作为成功判据。"],
        "source": "`munmap_chunk` 使用 chunk 的 `prev_size/size` 计算要解除的映射区间。",
        "links": [("2.43 malloc.c", f"{GLIBC}/master/malloc/malloc.c")],
    },
}


def make_readme(name: str, d: dict) -> str:
    pocs = sorted((ROOT / name).glob("poc_*.c"))
    poc_lines = []
    for poc in pocs:
        label = poc.stem.removeprefix("poc_").replace("_", "–")
        poc_lines.append(
            f"- [`{poc.name}`](./{poc.name})：验证 {label} 分支；"
            "成功判据见源码头部。"
        )
    changes = "\n".join(f"- {x}" for x in d["changes"])
    links = "、".join(f"[{label}]({url})" for label, url in d["links"])
    return f"""# {d['title']}

## 结论

- 适用范围：**glibc {d['range']}**。
- 原语效果：{d['effect']}
- 前置能力：{d['requirements']}

## 版本变化

{changes}

## 从源码看

{d['source']}本目录判断以 GNU glibc 对应 tag/提交为准：{links}。

版本号只代表上游基线；发行版可能回移检查。实战请按附件 Build ID 对照源码。

## PoC

{chr(10).join(poc_lines)}

PoC 为 x86-64 教学程序，故意包含 UAF、越界或 double free。快速验证：

```bash
# 在目录根运行；把版本和文件替换为要测的分支
./tools/run_in_docker.sh 2.39 {name}/{pocs[-1].name if pocs else 'poc_xxx.c'}
```

迁移时保留堆排布和检查绕过，只把漏洞模拟替换为题目的 edit/UAF/overflow；固定地址和最终目标必须重算。

## 调试

通用断点和排查顺序见 [根目录调试顺序](../README.md#调试顺序)。
"""


for name, data in DATA.items():
    directory = ROOT / name
    if not directory.is_dir():
        continue
    (directory / "README.md").write_text(make_readme(name, data), encoding="utf-8")

# 生成基础 README 后，立即把总表中的输入原语、输出原语和版本边界下沉。
# 这样重复运行本生成器也不会擦掉由总表统一维护的章节。
from sync_primitive_requirements import sync_readmes

sync_readmes(ROOT)
