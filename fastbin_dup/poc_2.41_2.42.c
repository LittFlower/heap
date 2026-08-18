/*
 * 中文导读（CTF 版）
 *
 * 手法：fastbin_dup
 * 文件标注范围：2.41 ~ 2.42
 * 模拟漏洞：double free；程序保留释放后的指针。
 * 核心流程：先构造 A→B→A 的 fastbin 环；有 tcache 时先填满/耗尽对应 tcache；连续三次申请会两次拿到 A。
 * 成功判据：最后的 assert(a == c) 成立，说明同一物理 chunk 同时被两个活动指针引用。
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

	// 预先准备 7 个 chunk，稍后用它们填满对应尺寸的 tcache bin。
	void *ptrs[7];

	for (int i=0; i<7; i++) {
		ptrs[i] = malloc(8);
	}

	// a、b、c 是 fastbin double-free 链所需的相邻候选块。
	int *a = calloc(1, 8);
	int *b = calloc(1, 8);
	int *c = calloc(1, 8);

	// 填满 tcache 后，下面三次 free 才会进入 fastbin 而不是 tcache。
	for (int i=0; i<7; i++) {
		free(ptrs[i]);
	}

	free(a);
	// free(a);  // 错误示例：连续释放当前 fastbin 表头会被检测。
	free(b);

	// 漏洞模拟：隔着 b 再次释放 a，构造 a→b→a。
	free(a);

	// 先耗尽 tcache，确保后续申请真正消费刚才伪造的 fastbin 链。
	for (int i = 0; i < 7; i++) {
		ptrs[i] = malloc(8);
	}

	// 依次弹出 a、b、a；首尾两个活动指针必须重合。
	a = malloc(8);
	b = calloc(1, 8);
	c = calloc(1, 8);

	assert(a == c);
}
