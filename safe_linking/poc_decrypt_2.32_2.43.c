/*
 * 中文导读（CTF 版）
 *
 * 手法：safe_linking（decrypt 分支）
 * 文件标注范围：glibc 2.32～2.43
 * 模拟漏洞：泄露出一个受 safe-linking 保护的单链指针。
 * 核心流程：从最高位开始逐 12 位恢复出真实地址，每恢复一段就用它更新
 *   下一轮解密所需的 key。
 * 成功判据：恢复出的地址与真实值完全相等。这是 2.32 之后利用 tcache/
 *   fastbin 时常用的配套原语。
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
	 * safe-linking 的密文满足 cipher = plain ^ (storage >> 12)。它的最低
	 * 12 位不受 key 影响，而指针的高位又和它所在页的 ASLR 页号相关，所以
	 * 可以从最高位开始，每一轮恢复出 12 位明文，再用已经恢复的部分去更新
	 * key，迭代几轮之后就能还原出完整的指针。
	 *
	 * 这个例子里 storage 和 plain 位于同一页，页差为 0，所以这层关系最直
	 * 观。如果二者不在同一页，只要知道相对页偏移，同样可以在每轮计算里加
	 * 上这个偏移继续恢复。更一般的推导和示例可以参考：
	 * https://github.com/n132/Dec-Safe-Linking
	 */

	setbuf(stdin, NULL);
	setbuf(stdout, NULL);

	// 第一步：申请同尺寸的 a、b 两个块，再用一个保护块阻止它们和 top 合并。
	long *a = malloc(0x20);
	long *b = malloc(0x20);

	malloc(0x10);

	// 第二步：先释放 a 再释放 b，这样 b->next 里保存的就是指向 a 的
	// safe-linking 密文。
	free(a);
	free(b);

	// 第三步：把泄露出来的 b[0] 当作这段 safe-linking 密文。
	long cipher = b[0];
	long key = 0;
	long plaintext = 0;

	// 从地址最高位开始，每一轮恢复出 12 位明文，再用它更新下一轮所需的
	// 页号 key。
	for(int i = 1; i < 6; i++) {
		int bits = 64 - 12 * i;
		if(bits < 0)
			bits = 0;

		plaintext = ((cipher ^ key) >> bits) << bits;
		key = plaintext >> 12;
	}

	assert(plaintext == (long)a);
}
