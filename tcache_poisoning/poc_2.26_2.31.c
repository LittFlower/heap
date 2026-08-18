/*
 * 中文导读（CTF 版）
 *
 * 手法：tcache_poisoning
 * 文件标注范围：2.26 ~ 2.31
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

	size_t stack_var;

	// 两个同尺寸 chunk 释放后会按 LIFO 顺序形成 b→a。
	intptr_t *a = malloc(128);
	intptr_t *b = malloc(128);

	free(a);
	free(b);

	/* 漏洞模拟：通过 UAF/重叠写覆盖已释放 b 的 next。
	 * 2.26～2.31 尚未启用 safe-linking，所以这里直接写目标明文地址。
	 */
	b[0] = (intptr_t)&stack_var;

	// 第一次分配正常取出表头 b；此后被篡改的目标地址成为新的 tcache 表头。
	intptr_t *first = malloc(128);
	assert(first == b);

	intptr_t *c = malloc(128);

	// 第二次分配应返回栈目标，而不是原链中的 a。
	assert((long)&stack_var == (long)c);
	return 0;
}
