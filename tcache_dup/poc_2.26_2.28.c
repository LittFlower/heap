/*
 * 中文导读（CTF 版）
 *
 * 手法：tcache_dup
 * 文件标注范围：2.26 ~ 2.28
 * 模拟漏洞：最原始的 tcache double free。
 * 核心流程：2.26~2.28 的 tcache_entry 没有 key，连续 free 同一指针即可成环。
 * 成功判据：两次 malloc 返回相同地址；2.29 引入 key 与链表遍历检查后直接失效。
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
	// 申请一个会进入最小 tcache bin 的 chunk，并保留释放后的悬空指针 a。
	int *a = malloc(8);

	/* 漏洞模拟：2.26～2.28 的 tcache_entry 只有 next 字段，没有 key。
	 * 第二次 free 不会遍历链表检查重复节点，因此链表会变成 a→a。
	 */
	free(a);
	free(a);

	// 两次分配依次消费链表中的两个 a；此时 b、c 同时指向同一物理 chunk。
	void *b = malloc(8);
	void *c = malloc(8);

	// 不依赖打印地址，直接把“同一 chunk 被返回两次”作为成功判据。
	assert((long)b == (long)c);
	return 0;
}
