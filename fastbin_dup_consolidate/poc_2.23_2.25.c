/*
 * 中文导读（CTF 版）
 *
 * 手法：fastbin_dup_consolidate
 * 文件标注范围：2.23 ~ 2.25
 * 模拟漏洞：double free，且能触发 malloc_consolidate。
 * 核心流程：让同一 chunk 一份仍在 fastbin、一份随 consolidate 并入 top/unsorted，从两个分配路径重复取出。
 * 成功判据：两个活动申请返回同一地址；2.43 删除 fastbin 收发路径后该原语终止。
 *
 * 阅读约定：malloc 返回的是 user data；源码里 p[-1] 通常是 size，p[-2]
 * 是 prev_size。所有故意的 UAF、越界和 double free 都是漏洞模拟，不是正常 C 用法。
 * 版本范围以本目录 README 和验证矩阵为准；发行版回移补丁时应按实际 libc 源码判断。
 */

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

/*
 * 本例说明 malloc_consolidate 如何把一个 fastbin double-free 转化为大块
 * 重复指针。普通 large chunk 受 PREV_INUSE 等检查约束，直接 double free
 * 较难；但 fastbin chunk 被 consolidate 并与 top 合并后，旧指针仍存活，
 * 随后从合并区域切出的较大块可能再次与旧指针重合。
 *
 * malloc_consolidate 会遍历所有 fastbin，把节点与相邻 free chunk 合并，
 * 结果送入 unsorted，并在可能时继续并入 top。2.35 源码参考：
 * https://elixir.bootlin.com/glibc/glibc-2.35/source/malloc/malloc.c#L4714
 *
 * 主要触发位置有五类：
 * 1. _int_malloc 处理 large-size 请求；
 * 2. 没有合适 bin 且 top 太小时，_int_malloc 再尝试 consolidate；
 * 3. _int_free 释放不小于 FASTBIN_CONSOLIDATION_THRESHOLD（65536）的块；
 * 4. 调用堆收缩接口 mtrim；
 * 5. 调用内部参数设置接口 __libc_mallopt。
 *
 * 本 PoC 选择第一类，申请 chunk size 不小于 0x400，使 _int_malloc 进入
 * smallbin 之外的分支并先 consolidate fastbin。带 tcache 的版本利用最大
 * 常规 tcache chunk size 0x410，让合并后切出的块还能进入 tcache，从而得到
 * 两个活动指针指向同一 tcache-sized chunk。
 *
 * 原始参考：
 * https://valsamaras.medium.com/the-toddlers-introduction-to-heap-exploitation-fastbin-dup-consolidate-part-4-2-ce6d68136aa8
 */

int main() {

	void* p1 = calloc(1,0x40);

  	free(p1);

  	void* p3 = malloc(0x400);

	assert(p1 == p3);

free(p1); // 漏洞模拟：旧 p1 已被 consolidate 后重新分配为 p3，此处形成语义上的 double free。

	void *p4 = malloc(0x400);

	assert(p4 == p3);

	return 0;
}
