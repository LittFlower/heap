#!/usr/bin/env python3
"""给机械导入的上游 PoC 添加统一、可检索的中文导读。

脚本是幂等的：已有“中文导读”标记的源码不会重复处理。它只负责注释，
不会改动利用语句，便于之后同 how2heap 上游做 diff。
"""

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]

NOTES = {
    "fastbin_dup": (
        "double free；程序保留释放后的指针。",
        "先构造 A→B→A 的 fastbin 环；有 tcache 时先填满/耗尽对应 tcache；连续三次申请会两次拿到 A。",
        "最后的 assert(a == c) 成立，说明同一物理 chunk 同时被两个活动指针引用。",
    ),
    "fastbin_dup_into_stack": (
        "double free 加 UAF，可改写已经重新取回的 fastbin chunk 的 fd。",
        "先得到 A→B→A，再把 A->fd 改成伪造 chunk 头；2.32 起写入的是 (存储位置>>12)^目标地址。",
        "最后一次 malloc/calloc 返回栈上预期地址；目标的对齐与伪造 size 必须通过当前版本检查。",
    ),
    "fastbin_dup_consolidate": (
        "double free，且能触发 malloc_consolidate。",
        "让同一 chunk 一份仍在 fastbin、一份随 consolidate 并入 top/unsorted，从两个分配路径重复取出。",
        "两个活动申请返回同一地址；2.43 删除 fastbin 收发路径后该原语终止。",
    ),
    "fastbin_reverse_into_tcache": (
        "UAF 改写 fastbin 的 fd，并可耗尽 tcache。",
        "malloc 从 fastbin 取一个节点时会把其余节点反向 stash 到 tcache；伪造末端节点可获得一次受控写并最终分配目标。",
        "目标槽被写入 chunk/tcache 元数据且 malloc 返回目标地址；2.42 large 链中间 next 槽需 mangling，但 metadata 头仍为明文。",
    ),
    "unsorted_bin_attack": (
        "UAF 改写 unsorted chunk 的 bk。",
        "从 unsorted 摘链时执行 bck->fd = unsorted_chunks(av)，把 main_arena 地址写到 target。",
        "target 由 0 变为非零的 main_arena 指针；2.29 的双向链一致性检查封堵此经典形式。",
    ),
    "unsorted_bin_into_stack": (
        "UAF 改写 unsorted chunk 的 bk，并在目标附近布置伪造 size。",
        "让 unsorted 链把栈上 fake chunk 当候选，再以匹配大小的请求取出。",
        "malloc 返回栈地址；2.29 的 unsorted 完整性检查使本 PoC 失效。",
    ),
    "large_bin_attack": (
        "UAF 改写已入 largebin 节点的 bk_nextsize。",
        "插入更小 victim 时走最小节点分支，将 victim 地址写入 fake->fd_nextsize 指向的目标。",
        "target 等于新 victim 的 chunk 头；2.30 前后所需链字段不同，2.42 新增 nextsize 反向检查后经典写原语失效。",
    ),
    "tcache_dup": (
        "最原始的 tcache double free。",
        "2.26~2.28 的 tcache_entry 没有 key，连续 free 同一指针即可成环。",
        "两次 malloc 返回相同地址；2.29 引入 key 与链表遍历检查后直接失效。",
    ),
    "tcache_poisoning": (
        "UAF/重叠写，可覆盖已释放 tcache chunk 的 next。",
        "把 next 指向目标；2.32 起必须按 PROTECT_PTR(pos, ptr) 编码，并保证目标 0x10 对齐。",
        "第二次 malloc 返回 target。这个原语只解决任意分配，最终劫持点需按题目另选。",
    ),
    "tcache_metadata_poisoning": (
        "能越界写或重叠到 tcache_perthread_struct。",
        "直接改 counts/num_slots 与 entries；2.42 的 metadata 头仍为明文，large 链中间 next 槽使用安全链接；2.43 结构体偏移再次变化。",
        "目标大小的下一次分配返回任意对齐地址。不要把旧版 counts/entries 偏移套到 2.42+。",
    ),
    "tcache_metadata_hijacking": (
        "在 tcache 延迟初始化前分配大块，并能从该大块溢出到随后创建的 tcache 元数据。",
        "2.42 起非 tcache 路径不再总是先 MAYBE_INIT_TCACHE，可让 tcache_perthread_struct 落在可控 chunk 之后。",
        "覆盖 entries 后下一次小块申请返回 target；2.43 因结构体/TLS 哨兵变化使用不同索引。",
    ),
    "tcache_stashing_unlink_attack": (
        "可改 smallbin chunk 的 bk；对应 tcache 必须为空。",
        "calloc/malloc 从 smallbin 服务请求时把额外节点 stash 入 tcache，过程中执行 bck->fd 写入并可把假节点链入 tcache。",
        "目标地址被写 main_arena 指针且可被后续申请取回；2.41 重构 smallbin→tcache 流程后本形式失效。",
    ),
    "tcache_relative_write": (
        "对 tcache_perthread_struct 的相对越界写。",
        "通过修改计数与头指针，把十进制计数值或 chunk 指针写到堆内相邻目标。版本差异来自 counts 宽度、safe-linking 和元数据布局。",
        "assert 验证目标字段得到预期相对值；2.42 的 num_slots/entries 重构终止旧布局原语。",
    ),
    "safe_linking": (
        "泄露一个受保护单链指针，或能让同一指针经历两次 PROTECT_PTR。",
        "解密 PoC 逐 12 位恢复地址；double-protect PoC 利用 xor 自反性把已知目标重新变成可用链指针。",
        "恢复出的地址/最终分配地址与真实值相等。它是 2.32+ tcache/fastbin 攻击的配套原语。",
    ),
    "unsafe_unlink": (
        "可伪造空闲 chunk 的 fd/bk，并清除后一 chunk 的 PREV_INUSE。",
        "满足 fd->bk==P 与 bk->fd==P 后触发后向合并；unlink 的两次写把受控指针表改成指向自身附近。",
        "随后经被改写的指针完成任意写。现代版本仍可用，但不再是古早的无条件 write-what-where。",
    ),
    "house_of_spirit": (
        "能 free 一个指向伪造 user area 的指针，并控制其前方 size 字段。",
        "把栈/全局区伪造成合法 chunk 后 free；fastbin 版需处理 tcache 与 next-size，tcache 版只要求索引和对齐。",
        "malloc 返回 fake chunk 的 user area。2.43 只封掉 fastbin 版，tcache 版仍成立。",
    ),
    "house_of_einherjar": (
        "off-by-null/off-by-one 清除 PREV_INUSE，且可伪造 prev_size 与前块双向链。",
        "让 free 误认为前方存在 fake free chunk，后向合并出覆盖活动 chunk 的大块，再借 tcache poisoning 定位目标。",
        "重分配得到重叠或目标地址。2.29 起 prev_size 必须与前块 size 相等，2.32 起 poisoning 需安全链接。",
    ),
    "house_of_force": (
        "可覆盖 top chunk 的 size。",
        "把 top->size 改成极大值，再申请 target-top-headers 的环绕距离，使新 top 落到目标前方。",
        "下一次 malloc 返回 target；2.29 的 top size <= system_mem 检查使经典形式失效。",
    ),
    "house_of_lore": (
        "可改 smallbin victim 的 bk，并在目标附近伪造两组相互引用的 chunk。",
        "smallbin 从尾部摘取 victim；构造 victim->bk 和 bck->fd/bk 通过 unlink 检查，连续申请落到栈/目标。",
        "malloc 返回目标地址。tcache 存在时先填满相同 size，且所有假节点需 0x10 对齐。",
    ),
    "house_of_orange": (
        "无 free 条件下可覆盖 top size，并能伪造 FILE。",
        "先让 sysmalloc 把旧 top 放入 unsorted，再用 unsorted write 劫持 _IO_list_all，最后触发旧式 FSOP。",
        "PoC 的函数指针被调用；2.26 的 abort/stdio 路径变化终止这条经典端到端链，2.29 又封掉 top 部分。",
    ),
    "house_of_roman": (
        "无泄露场景下的 UAF/堆溢出，可做 fastbin 与 unsorted 相对覆盖。",
        "组合 fastbin attack、unsorted bin attack 和低字节猜测，把分配导向 __malloc_hook 并写 one-gadget。",
        "经典链在 2.29 unsorted 完整性检查后失效；PoC 含 ASLR 猜测，失败需重跑。",
    ),
    "house_of_storm": (
        "同时可改一个 unsorted chunk 和一个 largebin chunk 的链指针。",
        "利用两条链在排序/插入时产生交叉写，伪造出落在任意目标附近的 chunk。",
        "malloc 返回目标地址；2.29 的 unsorted 完整性检查封掉该组合链。",
    ),
    "house_of_mind": (
        "可按 HEAP_MAX_SIZE 对齐布局并单字节改 NON_MAIN_ARENA/arena 归属。",
        "伪造 heap_info/malloc_state，使 free 把 chunk 写入 fake_arena.fastbinsY 对应的任意位置。",
        "target 得到堆指针。2.43 删除 fastbin 收发路径后 fastbin 版本终止。",
    ),
    "house_of_gods": (
        "泄露 heap/libc 且能劫持 main_arena.next、system_mem 与 narenas。",
        "把 binmap 当 fake chunk，构造 fake arena，再经 arena 重用逻辑让 thread_arena 指向它。",
        "后续 malloc 受 fake arena 控制；2.27 的 arena/fastbin 加固终止本链。",
    ),
    "house_of_botcake": (
        "UAF，并能制造同一 chunk 先入 unsorted、后入 tcache。",
        "填满 tcache 后释放 victim 到 unsorted，与前块合并；取走一个 tcache 节点后再次 free victim，形成大小不同的重叠管理。",
        "覆盖 victim->next 后 tcache poisoning 返回 target；2.32+ 必须编码 next，2.43 仍可用。",
    ),
    "house_of_io": (
        "能把 tcache_perthread_struct 本身当作已释放 tcache chunk 操作。",
        "通过其未加密 entries 取得任意分配，是早期 safe-linking 的无泄露旁路。",
        "malloc 返回 target；2.34 的随机 tcache_key 与布局/初始化变化使原始 PoC 终止。",
    ),
    "house_of_water": (
        "UAF 或 double free，可控制 tcache 元数据附近的伪造 chunk。",
        "把 tcache counts/entries 字节拼成 fake chunk，借 unsorted 链获得无泄露 libc 链接，再控制 tcache。",
        "PoC 同时验证 leakless libc link 与任意分配；2.42、2.43 元数据布局变化各有独立版本。",
    ),
    "house_of_tangerine": (
        "可覆盖 top chunk 元数据；不依赖传统 House of Force 的巨大 top。",
        "反复让 sysmalloc 处理受损 top，把旧 top 切成可进入 tcache 的块，再 poison 其 next 实现任意分配。",
        "malloc 返回 target；2.32 起编码 next，2.42 大 tcache/头指针变化、2.43 fastbin 移除均需不同布局。",
    ),
    "house_of_muney": (
        "可覆盖 mmap chunk 的 size，并保持 IS_MMAPPED 位。",
        "把一个 mmap chunk 的长度扩大到覆盖相邻映射，free/munmap 后重新 mmap 取得重叠区域。",
        "新旧指针观察到同一内存。该 PoC 展示 mmap overlap 原语；完整“偷 libc 映射”还依赖映射相邻关系。",
    ),
}


def version_label(path: Path) -> str:
    return path.stem.removeprefix("poc_").replace("_", " ~ ")


for path in sorted(ROOT.glob("*/poc_*.c")):
    text = path.read_text(encoding="utf-8")
    if "中文导读（CTF 版）" in text:
        continue
    tech = path.parent.name
    if tech not in NOTES:
        continue
    bug, flow, success = NOTES[tech]
    header = f"""/*
 * 中文导读（CTF 版）
 *
 * 手法：{tech}
 * 文件标注范围：{version_label(path)}
 * 模拟漏洞：{bug}
 * 核心流程：{flow}
 * 成功判据：{success}
 *
 * 阅读约定：malloc 返回的是 user data；源码里 p[-1] 通常是 size，p[-2]
 * 是 prev_size。所有故意的 UAF、越界和 double free 都是漏洞模拟，不是正常 C 用法。
 * 版本范围以本目录 README 和验证矩阵为准；发行版回移补丁时应按实际 libc 源码判断。
 */

"""
    # 保留上游利用语句，仅翻译最重要的漏洞边界标记。
    text = text.replace("/*VULNERABILITY*/", "/* 漏洞模拟开始/结束 */")
    text = text.replace("/* VULNERABILITY */", "/* 漏洞模拟开始/结束 */")
    path.write_text(header + text, encoding="utf-8")
