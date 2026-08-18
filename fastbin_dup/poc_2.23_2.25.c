/*
 * 中文导读（CTF 版）
 *
 * 手法：fastbin_dup
 * 文件标注范围：2.23 ~ 2.25
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
	// a、b 属于同一 fastbin；c 只用于稳定相邻布局，避免 b 靠近 top。
	int *a = malloc(8);
	int *b = malloc(8);
	int *c = malloc(8);

	// 第一次释放后 fastbin 为 a。若此处立刻 free(a)，表头重复检查会终止进程。
	free(a);
	// free(a);  // 错误示例：连续释放当前 fastbin 表头。

	// 插入 b 后表头不再是 a，因此再次释放 a 可构造 a→b→a。
	free(b);
	free(a);

	// 依次弹出 a、b、a；首尾两个活动指针因此指向同一物理 chunk。
	a = malloc(8);
	b = malloc(8);
	c = malloc(8);

	// 直接断言重复分配结果，避免依赖 how2heap 风格的地址打印。
	assert(a == c);
}
